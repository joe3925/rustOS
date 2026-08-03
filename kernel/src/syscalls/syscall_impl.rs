use crate::executable::program::{
    Message, MessageId, ProgramHandle, RoutingAction, RoutingRule, UserHandle, PROGRAM_MANAGER,
};
use crate::memory::io_buffer::{MappedIoBufferBacking, UserBufferAccess};
use crate::memory::paging::stack::StackSize;
use crate::memory::paging::{base_page_size, kernel_space_base};
use crate::platform;
use crate::scheduling::scheduler::SCHEDULER;
use crate::scheduling::task::Task;
use crate::structs::completion_queue::{CompletionQueue, CompletionQueueError};
use crate::structs::io_request::{
    FileObject, IoOpcode, KernelIoOp, MessageDelivery, RequestId, UserIoCompletion, UserIoOp,
};
use crate::{format, print};
use crate::{scheduling::task::TaskHandle, util::generate_guid};
use alloc::slice;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use kernel_executor::global_async::{
    ExecutorDomainClass, ExecutorDomainConfig, ExecutorDomainState, GlobalAsyncExecutor,
};
use kernel_types::arch::{PhysAddr, VirtAddr};
use kernel_types::dma::IoBufferError;
use kernel_types::executor::{
    USER_EXECUTOR_UPDATE_MAX_ACTIVE, UserExecutorDomainCreate, UserExecutorDomainInfo,
    UserExecutorDomainUpdate,
};
use kernel_types::fs::{OpenFlags, Path};
use kernel_types::object_manager::ObjectTag;

use crate::object_manager::{
    AccessContext, InterfaceMask, Object, ObjectOperation, ObjectPayload, TaskQueueRef,
    OBJECT_MANAGER,
};
use crate::structs::executor_domain::UserExecutorDomain;

fn ensure_process_object(pid: u64, prog: &ProgramHandle) -> alloc::sync::Arc<Object> {
    let process_dir = alloc::format!("\\Process\\{}", pid);
    let path = alloc::format!("{}\\Program", process_dir);
    if let Ok(o) = OBJECT_MANAGER.open(path.clone()) {
        return o.clone();
    }
    let _ = OBJECT_MANAGER.mkdir_p(process_dir);
    let obj = Object::with_name(
        ObjectTag::Program,
        "Program".to_string(),
        ObjectPayload::Program(prog.clone()),
    );
    let _ = OBJECT_MANAGER.link(path.clone(), &obj);
    obj
}

#[inline]
pub fn guid_to_string(g: &[u8; 16]) -> String {
    let d1 = u32::from_le_bytes([g[0], g[1], g[2], g[3]]);
    let d2 = u16::from_le_bytes([g[4], g[5]]);
    let d3 = u16::from_le_bytes([g[6], g[7]]);
    alloc::format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        d1,
        d2,
        d3,
        g[8],
        g[9],
        g[10],
        g[11],
        g[12],
        g[13],
        g[14],
        g[15]
    )
}

fn ensure_default_queue_object(
    pid: u64,
    prog: &ProgramHandle,
) -> (alloc::sync::Arc<Object>, TaskQueueRef) {
    let path = alloc::format!("\\Process\\{}\\Resources\\Queues\\Default", pid);
    if let Ok(o) = OBJECT_MANAGER.open(path.clone()) {
        if let ObjectPayload::Queue(q) = &o.payload {
            return (o.clone(), q.clone());
        }
    }
    let queue_dir = alloc::format!("\\Process\\{}\\Resources\\Queues", pid);
    let _ = OBJECT_MANAGER.mkdir_p(queue_dir);
    let q = prog.read().default_queue.clone();
    let obj = Object::with_name(
        ObjectTag::Queue,
        "DefaultQueue".to_string(),
        ObjectPayload::Queue(q.clone()),
    );
    let _ = OBJECT_MANAGER.link(path.clone(), &obj);
    (obj, q)
}

fn ensure_thread_object(pid: u64, th: &TaskHandle) -> alloc::sync::Arc<Object> {
    let tid = th.task_id();
    let dir = alloc::format!("\\Process\\{}\\Resources\\Threads", pid);
    let path = alloc::format!("{}\\{}", dir, tid);
    if let Ok(o) = OBJECT_MANAGER.open(path.clone()) {
        return o.clone();
    }
    let _ = OBJECT_MANAGER.mkdir_p(dir.clone());
    let obj = Object::with_name(
        ObjectTag::Thread,
        tid.to_string(),
        ObjectPayload::Thread(th.clone()),
    );
    let _ = OBJECT_MANAGER.link(path.clone(), &obj);
    obj
}

fn print_wrapper(message_ptr: String) {
    let message = &*message_ptr;
    print!("{}", message);
}
fn u64_to_str_ptr(value: *const u8) -> Option<String> {
    if value.is_null() {
        return None;
    }
    let mut len = 0;
    unsafe {
        while *value.add(len) != 0 {
            len += 1;
        }
        let slice = slice::from_raw_parts(value, len);
        String::from_utf8(Vec::from(slice)).ok()
    }
}
#[inline]
fn resolve_with_working_dir(caller: &ProgramHandle, raw: &str) -> Path {
    let base = caller.read().working_dir.clone();
    Path::parse(raw, Some(&base))
}
#[inline(always)]
fn is_user_addr(addr: u64) -> bool {
    (base_page_size()..kernel_space_base().as_u64()).contains(&addr)
}
#[inline(always)]
pub fn user_ptr_ok<T>(ptr: *const T, bytes: usize) -> bool {
    let a = ptr as u64;
    is_user_addr(a)
        && a.checked_add(bytes as u64)
            .is_some_and(|end| is_user_addr(end - 1))
}
#[inline(always)]
fn user_ptr<T>(ptr: *const T) -> bool {
    is_user_addr(ptr as u64)
}

const ERR_FLAG: u64 = 1u64 << 63;
#[inline]
pub fn is_err(v: u64) -> bool {
    (v & ERR_FLAG) != 0
}
#[inline]
pub fn err_class(v: u64) -> u16 {
    ((v >> 48) & 0xFFFF) as u16
}
#[inline]
pub fn err_code(v: u64) -> u16 {
    ((v >> 32) & 0xFFFF) as u16
}
#[inline]
pub fn err_arg(v: u64) -> u32 {
    (v & 0xFFFF_FFFF) as u32
}
#[repr(u16)]
pub enum ErrClass {
    Common = 0x0001,
    TaskClass = 0x0002,
    File = 0x0003,
    Message = 0x0004,
    Program = 0x0005,
    Memory = 0x0006,
    Route = 0x0007,
}
#[repr(u16)]
pub enum CommonErr {
    InvalidPtr = 1,
    InvalidHandle = 2,
    BufferTooSmall = 3,
    NotImplemented = 4,
    AccessDenied = 5,
}
#[repr(u16)]
pub enum TaskErr {
    NotFound = 1,
}
#[repr(u16)]
pub enum FileErr {
    PathInvalid = 1,
    Io = 2,
    NotFound = 3,
    ReadZeroLen = 4,
    AllocFailed = 5,
    MapFailed = 6,
    WriteFailed = 7,
    DeleteFailed = 8,
}
#[repr(u16)]
pub enum MsgErr {
    TargetHandleInvalid = 1,
    TargetResolveFailed = 2,
    TargetProcessMissing = 3,
    UnsupportedTargetType = 4,
    NoMessageInQueue = 5,
}
#[repr(u16)]
pub enum ProgErr {
    NotFound = 1,
}
#[repr(u16)]
pub enum MemErr {
    MapFailed = 1,
    AllocFailed = 2,
}
#[repr(u16)]
pub enum RouteErr {
    InvalidPtr = 1,
    InvalidHandle = 2,
    NotOwner = 3,
    DuplicateReroute = 4,
    UnsupportedTargetType = 5,
}

#[repr(C)]
pub struct UserRoutingRule {
    pub msg_id: MessageId,
    pub from_pid: u64,
    pub action_type: u32,
    pub queue_handle: UserHandle,
    pub thread_handle: UserHandle,
}

#[inline]
pub fn make_err(class: ErrClass, code: u16, arg: u32) -> u64 {
    ERR_FLAG | ((class as u64) << 48) | ((code as u64) << 32) | (arg as u64)
}

fn current_process() -> Result<(u64, ProgramHandle), u64> {
    let caller_pid = SCHEDULER
        .get_current_task(platform::current_cpu_id())
        .unwrap()
        .inner
        .read()
        .parent_pid;

    match PROGRAM_MANAGER.get(caller_pid) {
        Some(handle) => Ok((caller_pid, handle)),
        None => Err(make_err(
            ErrClass::Program,
            ProgErr::NotFound as u16,
            caller_pid as u32,
        )),
    }
}

fn resolve_completion_queue(
    handle: UserHandle,
    caller_pid: u64,
    caller: &ProgramHandle,
) -> Result<Arc<CompletionQueue>, u64> {
    let obj = caller.read().resolve_handle(handle).ok_or_else(|| {
        make_err(
            ErrClass::Common,
            CommonErr::InvalidHandle as u16,
            handle as u32,
        )
    })?;

    let queue = match &obj.payload {
        ObjectPayload::CompletionQueue(queue) => queue.clone(),
        _ => {
            return Err(make_err(
                ErrClass::Common,
                CommonErr::InvalidHandle as u16,
                handle as u32,
            ));
        }
    };

    if queue.owner_pid != caller_pid {
        return Err(make_err(
            ErrClass::Common,
            CommonErr::AccessDenied as u16,
            handle as u32,
        ));
    }

    Ok(queue)
}

fn resolve_file_object(handle: UserHandle, caller: &ProgramHandle) -> Result<Arc<FileObject>, u64> {
    let obj = caller.read().resolve_handle(handle).ok_or_else(|| {
        make_err(
            ErrClass::Common,
            CommonErr::InvalidHandle as u16,
            handle as u32,
        )
    })?;

    match &obj.payload {
        ObjectPayload::File(file) => Ok(file.clone()),
        _ => Err(make_err(
            ErrClass::Common,
            CommonErr::InvalidHandle as u16,
            handle as u32,
        )),
    }
}

fn resolve_io_buffer_backing(
    caller: &ProgramHandle,
    handle: UserHandle,
) -> Result<Arc<MappedIoBufferBacking>, u64> {
    let entry = caller.read().resolve_handle_entry(handle).ok_or_else(|| {
        make_err(
            ErrClass::Common,
            CommonErr::InvalidHandle as u16,
            handle as u32,
        )
    })?;
    if !entry
        .object
        .behavior()
        .matches(entry.interface, ObjectOperation::Submit)
    {
        return Err(make_err(
            ErrClass::Common,
            CommonErr::AccessDenied as u16,
            handle as u32,
        ));
    }
    match &entry.object.payload {
        ObjectPayload::IoBufferBacking(backing) => Ok(backing.clone()),
        _ => Err(make_err(
            ErrClass::Common,
            CommonErr::InvalidHandle as u16,
            handle as u32,
        )),
    }
}

fn map_io_buffer_error(error: IoBufferError) -> u64 {
    match error {
        IoBufferError::AllocationFailed
        | IoBufferError::LeaseCapacityExceeded { .. }
        | IoBufferError::DmaRecordCapacityExceeded { .. }
        | IoBufferError::PageCapacityExceeded { .. }
        | IoBufferError::ExtentCapacityExceeded { .. }
        | IoBufferError::SegmentCapacityExceeded { .. } => {
            make_err(ErrClass::Memory, MemErr::AllocFailed as u16, 0)
        }
        IoBufferError::LeaseConflict { .. } | IoBufferError::ActiveLeases => {
            make_err(ErrClass::Common, CommonErr::AccessDenied as u16, 0)
        }
        IoBufferError::TranslationFailed { .. } | IoBufferError::PhysicalDescriptionMissing => {
            make_err(ErrClass::Memory, MemErr::MapFailed as u16, 0)
        }
        IoBufferError::InvalidBackingKind => {
            make_err(ErrClass::Common, CommonErr::AccessDenied as u16, 0)
        }
        _ => make_err(ErrClass::Common, CommonErr::InvalidPtr as u16, 0),
    }
}

pub(crate) fn sys_io_buffer_register(user_address: u64, length: usize, access: u32) -> u64 {
    let (caller_pid, caller) = match current_process() {
        Ok(current) => current,
        Err(error) => return error,
    };
    let access = match UserBufferAccess::from_raw(access) {
        Some(access) => access,
        None => return make_err(ErrClass::Common, CommonErr::InvalidPtr as u16, access),
    };
    if length == 0 || !user_ptr_ok(user_address as *const u8, length) {
        return make_err(ErrClass::Common, CommonErr::InvalidPtr as u16, 0);
    }

    let page_size = base_page_size();
    let first_page = user_address - user_address % page_size;
    let end = match user_address.checked_add(length as u64) {
        Some(end) => end,
        None => return make_err(ErrClass::Common, CommonErr::InvalidPtr as u16, 0),
    };
    let mapped_end = match crate::memory::paging::align_up_to_base_page(end) {
        Some(end) => end,
        None => return make_err(ErrClass::Common, CommonErr::InvalidPtr as u16, 0),
    };
    let page_count = ((mapped_end - first_page) / page_size) as usize;
    let mut physical_pages = Vec::new();
    if physical_pages.try_reserve_exact(page_count).is_err() {
        return make_err(ErrClass::Memory, MemErr::AllocFailed as u16, 0);
    }

    let user_pin = {
        let program = caller.read();
        let mut user_memory = program.user_memory.lock();
        for index in 0..page_count {
            let virt = VirtAddr::new(first_page + index as u64 * page_size);
            let Some(mapping) =
                crate::platform::resolve_mapping_in_root(program.address_space_root, virt)
            else {
                return make_err(ErrClass::Memory, MemErr::MapFailed as u16, index as u32);
            };
            if !mapping.user_accessible
                || (access == UserBufferAccess::ReadWrite && !mapping.writable)
            {
                return make_err(
                    ErrClass::Common,
                    CommonErr::AccessDenied as u16,
                    index as u32,
                );
            }
            physical_pages.push(PhysAddr::new(mapping.phys_addr.as_u64() & !(page_size - 1)));
        }
        match user_memory.pin(first_page, mapped_end) {
            Ok(pin) => pin,
            Err(()) => return make_err(ErrClass::Memory, MemErr::AllocFailed as u16, 0),
        }
    };

    let backing = match MappedIoBufferBacking::new(
        physical_pages,
        (user_address - first_page) as usize,
        length,
        access,
        user_pin,
    ) {
        Ok(backing) => Arc::new(backing),
        Err(error) => return map_io_buffer_error(error),
    };
    publish_io_buffer_backing(caller_pid, &caller, backing)
}

fn resolve_executor_domain(
    handle: UserHandle,
    caller_pid: u64,
    caller: &ProgramHandle,
    operation: ObjectOperation,
) -> Result<Arc<UserExecutorDomain>, u64> {
    let entry = caller.read().resolve_handle_entry(handle).ok_or_else(|| {
        make_err(
            ErrClass::Common,
            CommonErr::InvalidHandle as u16,
            handle as u32,
        )
    })?;
    if !entry.object.behavior().matches(entry.interface, operation) {
        return Err(make_err(
            ErrClass::Common,
            CommonErr::AccessDenied as u16,
            handle as u32,
        ));
    }
    let domain = match &entry.object.payload {
        ObjectPayload::ExecutorDomain(domain) => domain.clone(),
        _ => {
            return Err(make_err(
                ErrClass::Common,
                CommonErr::InvalidHandle as u16,
                handle as u32,
            ));
        }
    };
    if domain.owner_pid() != caller_pid {
        return Err(make_err(
            ErrClass::Common,
            CommonErr::AccessDenied as u16,
            handle as u32,
        ));
    }
    Ok(domain)
}

fn publish_io_buffer_backing(
    caller_pid: u64,
    caller: &ProgramHandle,
    backing: Arc<MappedIoBufferBacking>,
) -> u64 {
    let directory = alloc::format!("\\Process\\{}\\Resources\\IoBufferBackings", caller_pid);
    if OBJECT_MANAGER.mkdir_p(directory.clone()).is_err() {
        return make_err(ErrClass::Memory, MemErr::AllocFailed as u16, 0);
    }
    let name = guid_to_string(&generate_guid());
    let object = Object::with_name(
        ObjectTag::IoBufferBacking,
        name.clone(),
        ObjectPayload::IoBufferBacking(backing),
    );
    if OBJECT_MANAGER
        .link(alloc::format!("{}\\{}", directory, name), &object)
        .is_err()
    {
        return make_err(ErrClass::Memory, MemErr::AllocFailed as u16, 0);
    }
    caller.read().create_user_handle_for_object(object)
}

fn resolve_message_queue(
    handle: UserHandle,
    caller_pid: u64,
    caller: &ProgramHandle,
) -> Result<TaskQueueRef, u64> {
    if handle == 0 {
        return Ok(ensure_default_queue_object(caller_pid, caller).1);
    }

    let obj = caller.read().resolve_handle(handle).ok_or_else(|| {
        make_err(
            ErrClass::Message,
            MsgErr::TargetHandleInvalid as u16,
            handle as u32,
        )
    })?;

    match &obj.payload {
        ObjectPayload::Queue(queue) => Ok(queue.clone()),
        _ => Err(make_err(
            ErrClass::Message,
            MsgErr::TargetHandleInvalid as u16,
            handle as u32,
        )),
    }
}

fn copy_user_bytes(addr: u64, len: usize) -> Result<Vec<u8>, u64> {
    if len == 0 {
        return Ok(Vec::new());
    }
    let ptr = addr as *const u8;
    if ptr.is_null() || !user_ptr_ok(ptr, len) {
        return Err(make_err(ErrClass::Common, CommonErr::InvalidPtr as u16, 0));
    }

    Ok(unsafe { slice::from_raw_parts(ptr, len) }.to_vec())
}

fn copy_user_string(addr: u64, len: usize) -> Result<String, u64> {
    if len == 0 {
        return Err(make_err(ErrClass::File, FileErr::PathInvalid as u16, 0));
    }

    let bytes = copy_user_bytes(addr, len)?;
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    core::str::from_utf8(&bytes[..end])
        .map(|s| s.to_string())
        .map_err(|_| make_err(ErrClass::File, FileErr::PathInvalid as u16, 0))
}

fn open_flags_from_bits(bits: u32) -> Vec<OpenFlags> {
    let mut out = Vec::new();
    let flags = [
        OpenFlags::ReadOnly,
        OpenFlags::WriteOnly,
        OpenFlags::ReadWrite,
        OpenFlags::Create,
        OpenFlags::CreateNew,
        OpenFlags::Open,
        OpenFlags::WriteThrough,
    ];

    for flag in flags {
        if bits & flag as u32 != 0 {
            out.push(flag);
        }
    }

    out
}

fn validate_user_buffer(addr: u64, len: usize) -> Result<(), u64> {
    if len == 0 {
        return Ok(());
    }

    let ptr = addr as *const u8;
    if ptr.is_null() || !user_ptr_ok(ptr, len) {
        return Err(make_err(ErrClass::Common, CommonErr::InvalidPtr as u16, 0));
    }
    Ok(())
}

fn build_kernel_io_op(
    caller_pid: u64,
    caller: &ProgramHandle,
    op: UserIoOp,
) -> Result<KernelIoOp, u64> {
    let opcode = IoOpcode::from_raw(op.opcode).ok_or_else(|| {
        make_err(
            ErrClass::Common,
            CommonErr::NotImplemented as u16,
            op.opcode,
        )
    })?;

    match opcode {
        IoOpcode::FileOpen => {
            let path = copy_user_string(op.buffer, op.length as usize)?;
            if path.is_empty() {
                return Err(make_err(ErrClass::File, FileErr::PathInvalid as u16, 0));
            }

            Ok(KernelIoOp::FileOpen {
                owner_pid: caller_pid,
                owner: caller.clone(),
                path: resolve_with_working_dir(caller, &path),
                flags: open_flags_from_bits(op.flags),
                user_token: op.user_token,
            })
        }
        IoOpcode::FileRead => {
            let length = usize::try_from(op.length)
                .map_err(|_| make_err(ErrClass::Common, CommonErr::InvalidPtr as u16, 0))?;
            let backing = resolve_io_buffer_backing(caller, op.buffer)?;
            let buffer = backing
                .create_from_device(op.extra0 as usize, length)
                .map_err(map_io_buffer_error)?;
            Ok(KernelIoOp::FileRead {
                file: resolve_file_object(op.target_handle, caller)?,
                buffer,
                offset: op.offset,
                user_token: op.user_token,
            })
        }
        IoOpcode::FileWrite => {
            let length = usize::try_from(op.length)
                .map_err(|_| make_err(ErrClass::Common, CommonErr::InvalidPtr as u16, 0))?;
            let backing = resolve_io_buffer_backing(caller, op.buffer)?;
            let buffer = backing
                .create_to_device(op.extra0 as usize, length)
                .map_err(map_io_buffer_error)?;
            Ok(KernelIoOp::FileWrite {
                file: resolve_file_object(op.target_handle, caller)?,
                buffer,
                offset: op.offset,
                user_token: op.user_token,
            })
        }
        IoOpcode::FileDelete => {
            if op.target_handle != 0 {
                return Ok(KernelIoOp::FileDeleteHandle {
                    file: resolve_file_object(op.target_handle, caller)?,
                    user_token: op.user_token,
                });
            }

            let path = copy_user_string(op.buffer, op.length as usize)?;
            if path.is_empty() {
                return Err(make_err(ErrClass::File, FileErr::PathInvalid as u16, 0));
            }

            Ok(KernelIoOp::FileDeletePath {
                path: resolve_with_working_dir(caller, &path),
                user_token: op.user_token,
            })
        }
        IoOpcode::ListDir => {
            let path = copy_user_string(op.buffer, op.length as usize)?;
            if path.is_empty() {
                return Err(make_err(ErrClass::File, FileErr::PathInvalid as u16, 0));
            }

            Ok(KernelIoOp::ListDir {
                owner: caller.clone(),
                path: resolve_with_working_dir(caller, &path),
                user_token: op.user_token,
            })
        }
        IoOpcode::ChangeDirectory => {
            let path = copy_user_string(op.buffer, op.length as usize)?;
            if path.is_empty() {
                return Err(make_err(ErrClass::File, FileErr::PathInvalid as u16, 0));
            }

            Ok(KernelIoOp::ChangeDirectory {
                owner: caller.clone(),
                path: resolve_with_working_dir(caller, &path),
                user_token: op.user_token,
            })
        }
        IoOpcode::MqReceive => {
            let length = usize::try_from(op.length)
                .map_err(|_| make_err(ErrClass::Common, CommonErr::InvalidPtr as u16, 0))?;
            let backing = resolve_io_buffer_backing(caller, op.buffer)?;
            let buffer = backing
                .create_from_device(op.extra0 as usize, length)
                .map_err(map_io_buffer_error)?;
            Ok(KernelIoOp::MqReceive {
                queue: resolve_message_queue(op.target_handle, caller_pid, caller)?,
                buffer,
                user_token: op.user_token,
            })
        }
        IoOpcode::ObjectDestroy => {
            let entry = caller
                .read()
                .resolve_handle_entry(op.target_handle)
                .ok_or_else(|| {
                    make_err(
                        ErrClass::Common,
                        CommonErr::InvalidHandle as u16,
                        op.target_handle as u32,
                    )
                })?;
            if !entry
                .object
                .behavior()
                .matches(entry.interface, ObjectOperation::Destroy)
            {
                return Err(make_err(
                    ErrClass::Common,
                    CommonErr::AccessDenied as u16,
                    op.target_handle as u32,
                ));
            }
            Ok(KernelIoOp::ObjectDestroy {
                object: entry.object,
                user_token: op.user_token,
            })
        }
        IoOpcode::MessageSendAwait => {
            let length = usize::try_from(op.length)
                .map_err(|_| make_err(ErrClass::Common, CommonErr::InvalidPtr as u16, 0))?;
            if length < core::mem::size_of::<Message>() {
                return Err(make_err(
                    ErrClass::Common,
                    CommonErr::BufferTooSmall as u16,
                    length as u32,
                ));
            }
            let backing = resolve_io_buffer_backing(caller, op.buffer)?;
            let buffer = backing
                .create_to_device(op.extra0 as usize, length)
                .map_err(map_io_buffer_error)?;
            let entry = caller
                .read()
                .resolve_handle_entry(op.target_handle)
                .ok_or_else(|| {
                    make_err(
                        ErrClass::Message,
                        MsgErr::TargetHandleInvalid as u16,
                        op.target_handle as u32,
                    )
                })?;
            if !entry
                .object
                .behavior()
                .matches(entry.interface, ObjectOperation::Message)
            {
                return Err(make_err(
                    ErrClass::Common,
                    CommonErr::AccessDenied as u16,
                    op.target_handle as u32,
                ));
            }
            let target = match &entry.object.payload {
                ObjectPayload::Program(program) => program.clone(),
                _ => {
                    return Err(make_err(
                        ErrClass::Message,
                        MsgErr::UnsupportedTargetType as u16,
                        0,
                    ));
                }
            };
            let sender_object = ensure_process_object(caller_pid, caller);
            let sender = target.read().create_user_handle_for_object(sender_object);
            Ok(KernelIoOp::MessageSendAwait {
                target,
                buffer,
                sender,
                user_token: op.user_token,
            })
        }
        IoOpcode::SocketRecv
        | IoOpcode::SocketSend
        | IoOpcode::TimerWait
        | IoOpcode::ProcessWait
        | IoOpcode::Ioctl => Err(make_err(
            ErrClass::Common,
            CommonErr::NotImplemented as u16,
            op.opcode,
        )),
    }
}

fn map_cq_error(err: CompletionQueueError) -> u64 {
    match err {
        CompletionQueueError::InvalidCapacity => {
            make_err(ErrClass::Common, CommonErr::InvalidPtr as u16, 0)
        }
        CompletionQueueError::RequestTableFull | CompletionQueueError::CompletionQueueFull => {
            make_err(ErrClass::Common, CommonErr::BufferTooSmall as u16, 0)
        }
        CompletionQueueError::RequestNotFound => {
            make_err(ErrClass::Common, CommonErr::InvalidHandle as u16, 0)
        }
        CompletionQueueError::RequestAlreadyComplete => {
            make_err(ErrClass::Common, CommonErr::InvalidHandle as u16, 1)
        }
        CompletionQueueError::Closed => {
            make_err(ErrClass::Common, CommonErr::InvalidHandle as u16, 2)
        }
        CompletionQueueError::DomainUnavailable => {
            make_err(ErrClass::Common, CommonErr::InvalidHandle as u16, 3)
        }
    }
}

pub(crate) fn sys_print(ptr: *const u8) -> u64 {
    if ptr.is_null() || !user_ptr(ptr) {
        return make_err(ErrClass::Common, CommonErr::InvalidPtr as u16, 0);
    }
    let c_str = unsafe { core::ffi::CStr::from_ptr(ptr as *const i8) };
    if let Ok(s) = c_str.to_str() {
        print_wrapper(s.to_string());
        0
    } else {
        make_err(ErrClass::Common, CommonErr::InvalidPtr as u16, 1)
    }
}

pub(crate) fn sys_destroy_task(task_handle: UserHandle) -> u64 {
    let caller_pid = SCHEDULER
        .get_current_task(platform::current_cpu_id())
        .unwrap()
        .inner
        .read()
        .parent_pid;

    let caller = match PROGRAM_MANAGER.get(caller_pid) {
        Some(program) => program,
        None => {
            return make_err(
                ErrClass::Program,
                ProgErr::NotFound as u16,
                caller_pid as u32,
            );
        }
    };

    let obj = match caller.read().resolve_handle(task_handle) {
        Some(o) => o,
        None => {
            return make_err(
                ErrClass::Common,
                CommonErr::InvalidHandle as u16,
                task_handle as u32,
            );
        }
    };
    let th = match &obj.payload {
        ObjectPayload::Thread(th) => th.clone(),
        _ => {
            return make_err(
                ErrClass::Common,
                CommonErr::InvalidHandle as u16,
                task_handle as u32,
            );
        }
    };
    if th.inner.read().parent_pid != caller_pid {
        return make_err(
            ErrClass::Common,
            CommonErr::AccessDenied as u16,
            task_handle as u32,
        );
    }
    let tid = th.task_id();
    match SCHEDULER.delete_task(tid) {
        Ok(_) => {
            let _ = OBJECT_MANAGER.unlink_object(&obj);
            obj.mark_dead();
            0
        }
        Err(_) => make_err(ErrClass::TaskClass, TaskErr::NotFound as u16, tid as u32),
    }
}

pub(crate) fn sys_create_task(entry: usize) -> UserHandle {
    let stack_size = StackSize::Medium.as_bytes();
    let caller_pid = SCHEDULER
        .get_current_task(platform::current_cpu_id())
        .unwrap()
        .inner
        .read()
        .parent_pid;
    let caller = match PROGRAM_MANAGER.get(caller_pid) {
        Some(p) => p,
        None => {
            return make_err(
                ErrClass::Program,
                ProgErr::NotFound as u16,
                caller_pid as u32,
            );
        }
    };
    let managed = { caller.read().managed_threads.lock().len() };
    let stack = if let Some(range) = caller.write().tracker.alloc_auto(stack_size) {
        unsafe {
            let _ = caller
                .write()
                .virtual_map(range.into(), stack_size as usize);
        };
        range + stack_size
    } else {
        return make_err(
            ErrClass::Memory,
            MemErr::AllocFailed as u16,
            stack_size as u32,
        );
    };
    let task = Task::new_user_mode(
        unsafe { *(entry as *const extern "C" fn(usize)) },
        0,
        stack_size,
        format!("{} Worker {}", caller.read().title, managed),
        stack.into(),
        caller_pid,
    );
    SCHEDULER.add_task(task.clone());

    let obj = ensure_thread_object(caller_pid, &task);
    caller.read().create_user_handle_for_object(obj)
}

pub(crate) fn sys_executor_domain_create(
    config_ptr: *const UserExecutorDomainCreate,
) -> UserHandle {
    if config_ptr.is_null()
        || !user_ptr_ok(config_ptr, core::mem::size_of::<UserExecutorDomainCreate>())
    {
        return make_err(ErrClass::Common, CommonErr::InvalidPtr as u16, 0);
    }
    let config = unsafe { *config_ptr };
    let (caller_pid, caller) = match current_process() {
        Ok(current) => current,
        Err(err) => return err,
    };
    let domain_id = GlobalAsyncExecutor::global().create_executor_domain(ExecutorDomainConfig {
        class: ExecutorDomainClass::ProcessIo,
        max_active: if config.max_active_tasks == 0 {
            usize::MAX
        } else {
            config.max_active_tasks
        },
        quantum: ExecutorDomainClass::ProcessIo.default_quantum(),
        weight: ExecutorDomainClass::ProcessIo.default_weight(),
        future_arena: Default::default(),
        ready_shards: if config.ready_shards == 0 {
            GlobalAsyncExecutor::global().worker_count()
        } else {
            config.ready_shards
        },
    });
    let Some(domain) = GlobalAsyncExecutor::global().get_executor_domain(domain_id) else {
        return make_err(ErrClass::Memory, MemErr::AllocFailed as u16, 0);
    };
    let user_domain = UserExecutorDomain::new(caller_pid, domain_id, domain);
    let object = Object::new(
        ObjectTag::ExecutorDomain,
        ObjectPayload::ExecutorDomain(user_domain),
    );
    caller.read().create_user_handle_for_object(object)
}

pub(crate) fn sys_executor_domain_configure(
    handle: UserHandle,
    update_ptr: *const UserExecutorDomainUpdate,
) -> u64 {
    if update_ptr.is_null()
        || !user_ptr_ok(update_ptr, core::mem::size_of::<UserExecutorDomainUpdate>())
    {
        return make_err(ErrClass::Common, CommonErr::InvalidPtr as u16, 0);
    }
    let update = unsafe { *update_ptr };
    if update.fields != USER_EXECUTOR_UPDATE_MAX_ACTIVE {
        return make_err(
            ErrClass::Common,
            CommonErr::InvalidPtr as u16,
            update.fields,
        );
    }
    let (caller_pid, caller) = match current_process() {
        Ok(current) => current,
        Err(err) => return err,
    };
    let domain =
        match resolve_executor_domain(handle, caller_pid, &caller, ObjectOperation::Configure) {
            Ok(domain) => domain,
            Err(err) => return err,
        };
    if domain.is_draining() {
        return make_err(ErrClass::Common, CommonErr::InvalidHandle as u16, 0);
    }
    let max_active = (update.fields & USER_EXECUTOR_UPDATE_MAX_ACTIVE != 0).then_some(
        if update.max_active_tasks == 0 {
            usize::MAX
        } else {
            update.max_active_tasks
        },
    );
    domain.update_config(max_active);
    0
}

pub(crate) fn sys_executor_domain_query(
    handle: UserHandle,
    info_ptr: *mut UserExecutorDomainInfo,
) -> u64 {
    if info_ptr.is_null() || !user_ptr_ok(info_ptr, core::mem::size_of::<UserExecutorDomainInfo>())
    {
        return make_err(ErrClass::Common, CommonErr::InvalidPtr as u16, 0);
    }
    let (caller_pid, caller) = match current_process() {
        Ok(current) => current,
        Err(err) => return err,
    };
    let domain =
        match resolve_executor_domain(handle, caller_pid, &caller, ObjectOperation::Observe) {
            Ok(domain) => domain,
            Err(err) => return err,
        };
    let stats = domain.stats();
    let info = UserExecutorDomainInfo {
        state: match stats.state {
            ExecutorDomainState::Active => 0,
            ExecutorDomainState::Draining => 1,
            ExecutorDomainState::Dead => 2,
        },
        max_active_tasks: (stats.max_active != usize::MAX)
            .then_some(stats.max_active)
            .unwrap_or(0),
        queued_tasks: stats.queued_count,
        active_tasks: stats.active_count,
        live_tasks: stats.live_task_count,
        live_futures: stats.live_future_count,
        live_future_bytes: stats.live_future_bytes,
        ready_shards: stats.ready_shards,
    };
    unsafe { info_ptr.write(info) };
    0
}

pub(crate) fn sys_completion_queue_create(
    executor_domain_handle: UserHandle,
    request_capacity: usize,
    completion_capacity: usize,
    flags: u64,
) -> UserHandle {
    let (caller_pid, caller) = match current_process() {
        Ok(current) => current,
        Err(err) => return err,
    };

    if request_capacity == 0 || completion_capacity == 0 {
        return make_err(ErrClass::Common, CommonErr::InvalidPtr as u16, 0);
    }

    ensure_process_object(caller_pid, &caller);
    let executor_domain = match resolve_executor_domain(
        executor_domain_handle,
        caller_pid,
        &caller,
        ObjectOperation::Submit,
    ) {
        Ok(domain) if !domain.is_draining() => domain,
        Ok(_) => {
            return make_err(
                ErrClass::Common,
                CommonErr::InvalidHandle as u16,
                executor_domain_handle as u32,
            );
        }
        Err(err) => return err,
    };

    let queue = match CompletionQueue::new(
        caller_pid,
        executor_domain,
        request_capacity,
        completion_capacity,
        flags,
    ) {
        Ok(queue) => queue,
        Err(err) => return map_cq_error(err),
    };

    let dir = alloc::format!("\\Process\\{}\\Resources\\CompletionQueues", caller_pid);
    if OBJECT_MANAGER.mkdir_p(dir.clone()).is_err() {
        return make_err(ErrClass::Common, CommonErr::InvalidHandle as u16, 0);
    }

    let name = guid_to_string(&generate_guid());
    let object = Object::with_name(
        ObjectTag::CompletionQueue,
        name.clone(),
        ObjectPayload::CompletionQueue(queue),
    );
    if OBJECT_MANAGER
        .link(alloc::format!("{}\\{}", dir, name), &object)
        .is_err()
    {
        return make_err(ErrClass::Common, CommonErr::InvalidHandle as u16, 1);
    }

    let handle = caller.read().create_user_handle_for_object(object);
    handle
}

pub(crate) fn sys_io_enqueue(completion_queue_handle: UserHandle, op_ptr: *const UserIoOp) -> u64 {
    if op_ptr.is_null() || !user_ptr_ok(op_ptr, core::mem::size_of::<UserIoOp>()) {
        return make_err(ErrClass::Common, CommonErr::InvalidPtr as u16, 0);
    }

    let (caller_pid, caller) = match current_process() {
        Ok(current) => current,
        Err(err) => return err,
    };
    let queue = match resolve_completion_queue(completion_queue_handle, caller_pid, &caller) {
        Ok(queue) => queue,
        Err(err) => return err,
    };

    let user_op = unsafe { core::ptr::read_unaligned(op_ptr) };
    let op = match build_kernel_io_op(caller_pid, &caller, user_op) {
        Ok(op) => op,
        Err(err) => return err,
    };

    queue.enqueue(op).map_or_else(map_cq_error, |id| id)
}

pub(crate) fn sys_io_enqueue_many(
    completion_queue_handle: UserHandle,
    ops_ptr: *const UserIoOp,
    count: usize,
    out_request_ids: *mut RequestId,
) -> u64 {
    if count == 0 {
        return 0;
    }

    let ops_bytes = match count.checked_mul(core::mem::size_of::<UserIoOp>()) {
        Some(bytes) => bytes,
        None => return make_err(ErrClass::Common, CommonErr::InvalidPtr as u16, 0),
    };
    let ids_bytes = match count.checked_mul(core::mem::size_of::<RequestId>()) {
        Some(bytes) => bytes,
        None => return make_err(ErrClass::Common, CommonErr::InvalidPtr as u16, 1),
    };

    if ops_ptr.is_null()
        || out_request_ids.is_null()
        || !user_ptr_ok(ops_ptr, ops_bytes)
        || !user_ptr_ok(out_request_ids, ids_bytes)
    {
        return make_err(ErrClass::Common, CommonErr::InvalidPtr as u16, 0);
    }

    let (caller_pid, caller) = match current_process() {
        Ok(current) => current,
        Err(err) => return err,
    };
    let queue = match resolve_completion_queue(completion_queue_handle, caller_pid, &caller) {
        Ok(queue) => queue,
        Err(err) => return err,
    };

    let mut submitted = 0usize;
    for idx in 0..count {
        let user_op = unsafe { core::ptr::read_unaligned(ops_ptr.add(idx)) };
        let op = match build_kernel_io_op(caller_pid, &caller, user_op) {
            Ok(op) => op,
            Err(err) => {
                return if submitted == 0 {
                    err
                } else {
                    submitted as u64
                };
            }
        };

        let request_id = match queue.enqueue(op) {
            Ok(request_id) => request_id,
            Err(err) => {
                return if submitted == 0 {
                    map_cq_error(err)
                } else {
                    submitted as u64
                };
            }
        };

        unsafe {
            core::ptr::write_unaligned(out_request_ids.add(idx), request_id);
        }
        submitted += 1;
    }

    submitted as u64
}

pub(crate) fn sys_completion_poll(
    completion_queue_handle: UserHandle,
    out_completions: *mut UserIoCompletion,
    max: usize,
) -> u64 {
    if max == 0 {
        return 0;
    }

    let bytes = match max.checked_mul(core::mem::size_of::<UserIoCompletion>()) {
        Some(bytes) => bytes,
        None => return make_err(ErrClass::Common, CommonErr::InvalidPtr as u16, 0),
    };
    if out_completions.is_null() || !user_ptr_ok(out_completions, bytes) {
        return make_err(ErrClass::Common, CommonErr::InvalidPtr as u16, 0);
    }

    let (caller_pid, caller) = match current_process() {
        Ok(current) => current,
        Err(err) => return err,
    };
    let queue = match resolve_completion_queue(completion_queue_handle, caller_pid, &caller) {
        Ok(queue) => queue,
        Err(err) => return err,
    };

    let out = unsafe { slice::from_raw_parts_mut(out_completions, max) };
    queue.poll_completions(out) as u64
}

pub(crate) fn sys_completion_wait(
    completion_queue_handle: UserHandle,
    out_completions: *mut UserIoCompletion,
    max: usize,
    timeout_ns: u64,
) -> u64 {
    if max == 0 {
        return 0;
    }

    let bytes = match max.checked_mul(core::mem::size_of::<UserIoCompletion>()) {
        Some(bytes) => bytes,
        None => return make_err(ErrClass::Common, CommonErr::InvalidPtr as u16, 0),
    };
    if out_completions.is_null() || !user_ptr_ok(out_completions, bytes) {
        return make_err(ErrClass::Common, CommonErr::InvalidPtr as u16, 0);
    }

    let (caller_pid, caller) = match current_process() {
        Ok(current) => current,
        Err(err) => return err,
    };
    let queue = match resolve_completion_queue(completion_queue_handle, caller_pid, &caller) {
        Ok(queue) => queue,
        Err(err) => return err,
    };

    let out = unsafe { slice::from_raw_parts_mut(out_completions, max) };
    queue.wait_completions(out, timeout_ns) as u64
}

pub(crate) fn sys_io_cancel(completion_queue_handle: UserHandle, request_id: RequestId) -> u64 {
    let (caller_pid, caller) = match current_process() {
        Ok(current) => current,
        Err(err) => return err,
    };
    let queue = match resolve_completion_queue(completion_queue_handle, caller_pid, &caller) {
        Ok(queue) => queue,
        Err(err) => return err,
    };

    queue.cancel(request_id).map_or_else(map_cq_error, |_| 0)
}

pub(crate) fn sys_get_thread() -> UserHandle {
    let task = SCHEDULER
        .get_current_task(platform::current_cpu_id())
        .unwrap();
    let caller_pid = task.inner.read().parent_pid;
    let Some(caller) = PROGRAM_MANAGER.get(caller_pid) else {
        return 0;
    };
    let obj = ensure_thread_object(caller_pid, &task);
    caller.read().create_user_handle_for_object(obj)
}

pub(crate) fn sys_mq_request(target: UserHandle, message_ptr: *mut Message) -> u64 {
    if message_ptr.is_null() || !user_ptr(message_ptr) {
        return make_err(ErrClass::Common, CommonErr::InvalidPtr as u16, 0);
    }
    let msg = unsafe { &mut *message_ptr };

    let sender_pid = SCHEDULER
        .get_current_task(platform::current_cpu_id())
        .unwrap()
        .inner
        .read()
        .parent_pid;
    let sender_prog = match PROGRAM_MANAGER.get(sender_pid) {
        Some(p) => p,
        None => {
            return make_err(
                ErrClass::Program,
                ProgErr::NotFound as u16,
                sender_pid as u32,
            );
        }
    };
    let tgt = match sender_prog.read().resolve_handle(target) {
        Some(o) => o,
        None => return make_err(ErrClass::Message, MsgErr::TargetHandleInvalid as u16, 0),
    };

    match &tgt.payload {
        ObjectPayload::Program(ph) => {
            let sender_obj = ensure_process_object(sender_pid, &sender_prog);
            msg.sender = Some(ph.read().create_user_handle_for_object(sender_obj));
            ph.write().receive_message(msg.clone());
            0
        }
        ObjectPayload::Queue(qh) => {
            // A bare queue has no owning process metadata yet, so sender
            // authority cannot be installed into its receiver here.
            msg.sender = None;
            qh.write().push_message(msg.clone());
            0
        }
        _ => make_err(ErrClass::Message, MsgErr::UnsupportedTargetType as u16, 0),
    }
}

pub(crate) fn sys_rule_add(rule_ptr: *const UserRoutingRule) -> u64 {
    if rule_ptr.is_null() || !user_ptr(rule_ptr) {
        return make_err(ErrClass::Common, CommonErr::InvalidPtr as u16, 0);
    }
    let rule_u = unsafe { &*rule_ptr };

    let caller_pid = SCHEDULER
        .get_current_task(platform::current_cpu_id())
        .unwrap()
        .inner
        .read()
        .parent_pid;
    let caller = match PROGRAM_MANAGER.get(caller_pid) {
        Some(p) => p,
        None => {
            return make_err(
                ErrClass::Program,
                ProgErr::NotFound as u16,
                caller_pid as u32,
            );
        }
    };

    let krule = match rule_u.action_type {
        0 => RoutingRule {
            msg_id: rule_u.msg_id,
            from_pid: if rule_u.from_pid == 0 {
                None
            } else {
                Some(rule_u.from_pid)
            },
            action: RoutingAction::Block,
        },
        1 => RoutingRule {
            msg_id: rule_u.msg_id,
            from_pid: if rule_u.from_pid == 0 {
                None
            } else {
                Some(rule_u.from_pid)
            },
            action: RoutingAction::Allow,
        },
        2 => {
            let obj = match caller.read().resolve_handle(rule_u.queue_handle) {
                Some(o) => o,
                None => return make_err(ErrClass::Route, RouteErr::InvalidHandle as u16, 0),
            };
            let qh = match &obj.payload {
                ObjectPayload::Queue(q) => q.clone(),
                _ => return make_err(ErrClass::Route, RouteErr::UnsupportedTargetType as u16, 0),
            };
            RoutingRule {
                msg_id: rule_u.msg_id,
                from_pid: if rule_u.from_pid == 0 {
                    None
                } else {
                    Some(rule_u.from_pid)
                },
                action: RoutingAction::Reroute(qh),
            }
        }
        3 => {
            let qh_opt = if rule_u.queue_handle != 0 {
                let o = match caller.read().resolve_handle(rule_u.queue_handle) {
                    Some(o) => o,
                    None => return make_err(ErrClass::Route, RouteErr::InvalidHandle as u16, 0),
                };
                match &o.payload {
                    ObjectPayload::Queue(q) => Some(q.clone()),
                    _ => {
                        return make_err(
                            ErrClass::Route,
                            RouteErr::UnsupportedTargetType as u16,
                            0,
                        );
                    }
                }
            } else {
                None
            };

            let th = {
                let o = match caller.read().resolve_handle(rule_u.thread_handle) {
                    Some(o) => o,
                    None => return make_err(ErrClass::Route, RouteErr::InvalidHandle as u16, 0),
                };
                match &o.payload {
                    ObjectPayload::Thread(t) => t.clone(),
                    _ => {
                        return make_err(
                            ErrClass::Route,
                            RouteErr::UnsupportedTargetType as u16,
                            0,
                        );
                    }
                }
            };

            RoutingRule {
                msg_id: rule_u.msg_id,
                from_pid: if rule_u.from_pid == 0 {
                    None
                } else {
                    Some(rule_u.from_pid)
                },
                action: RoutingAction::Callback(th, qh_opt),
            }
        }
        _ => return make_err(ErrClass::Route, RouteErr::InvalidPtr as u16, 1),
    };

    caller.write().add_routing_rule(krule);
    0
}

pub(crate) fn sys_rule_clear(rule_ptr: *const UserRoutingRule) -> u64 {
    if rule_ptr.is_null() || !user_ptr(rule_ptr) {
        return make_err(ErrClass::Common, CommonErr::InvalidPtr as u16, 0);
    }
    let rule_u = unsafe { &*rule_ptr };

    let caller_pid = SCHEDULER
        .get_current_task(platform::current_cpu_id())
        .unwrap()
        .inner
        .read()
        .parent_pid;
    let caller = match PROGRAM_MANAGER.get(caller_pid) {
        Some(p) => p,
        None => {
            return make_err(
                ErrClass::Program,
                ProgErr::NotFound as u16,
                caller_pid as u32,
            );
        }
    };

    caller.write().clear_routing_rule(
        rule_u.msg_id,
        if rule_u.from_pid == 0 {
            None
        } else {
            Some(rule_u.from_pid)
        },
    );
    0
}

pub(crate) fn sys_mq_peek(qh: UserHandle, msg_ptr: *mut Message) -> u64 {
    if msg_ptr.is_null() || !user_ptr(msg_ptr) {
        return make_err(ErrClass::Common, CommonErr::InvalidPtr as u16, 0);
    }

    let caller_pid = SCHEDULER
        .get_current_task(platform::current_cpu_id())
        .unwrap()
        .inner
        .read()
        .parent_pid;
    let prog = match PROGRAM_MANAGER.get(caller_pid) {
        Some(p) => p,
        None => {
            return make_err(
                ErrClass::Program,
                ProgErr::NotFound as u16,
                caller_pid as u32,
            );
        }
    };

    let qref = if qh == 0 {
        ensure_default_queue_object(caller_pid, &prog).1
    } else {
        let o = match prog.read().resolve_handle(qh) {
            Some(o) => o,
            None => return make_err(ErrClass::Message, MsgErr::TargetHandleInvalid as u16, 0),
        };
        match &o.payload {
            ObjectPayload::Queue(q) => q.clone(),
            _ => return make_err(ErrClass::Message, MsgErr::TargetHandleInvalid as u16, 0),
        }
    };

    let q = qref.write();
    match q.peek_message() {
        Some(m) => unsafe {
            core::ptr::write_unaligned(msg_ptr, m.clone());
            0
        },
        None => make_err(ErrClass::Message, MsgErr::TargetResolveFailed as u16, 0),
    }
}

pub(crate) fn sys_get_default_mq_handle() -> UserHandle {
    let caller_pid = SCHEDULER
        .get_current_task(platform::current_cpu_id())
        .unwrap()
        .inner
        .read()
        .parent_pid;
    let prog = match PROGRAM_MANAGER.get(caller_pid) {
        Some(p) => p,
        None => return 0,
    };
    let (obj, _q) = ensure_default_queue_object(caller_pid, &prog);
    prog.read().create_user_handle_for_object(obj)
}

pub(crate) fn sys_create_mq() -> UserHandle {
    let caller_pid = SCHEDULER
        .get_current_task(platform::current_cpu_id())
        .unwrap()
        .inner
        .read()
        .parent_pid;
    let prog = match PROGRAM_MANAGER.get(caller_pid) {
        Some(p) => p,
        None => return 0,
    };

    let dir = alloc::format!("\\Process\\{}\\Resources\\Queues", caller_pid);
    let _ = OBJECT_MANAGER.mkdirp(dir.clone());

    let name = guid_to_string(&generate_guid());
    let qh: TaskQueueRef = alloc::sync::Arc::new(spin::RwLock::new(
        crate::executable::program::MessageQueue::new(),
    ));
    let obj = Object::with_name(ObjectTag::Queue, name.clone(), ObjectPayload::Queue(qh));
    let _ = OBJECT_MANAGER.link(alloc::format!("{}\\{}", dir, name), &obj);
    prog.read().create_user_handle_for_object(obj)
}

pub(crate) fn sys_get_working_dir(target_prog: UserHandle) -> u64 {
    let caller_pid = SCHEDULER
        .get_current_task(platform::current_cpu_id())
        .unwrap()
        .inner
        .read()
        .parent_pid;
    let caller = match PROGRAM_MANAGER.get(caller_pid) {
        Some(p) => p,
        None => {
            return make_err(
                ErrClass::Program,
                ProgErr::NotFound as u16,
                caller_pid as u32,
            );
        }
    };

    let target_arc = if target_prog == 0 {
        caller.clone()
    } else {
        match caller
            .read()
            .resolve_handle(target_prog)
            .and_then(|o| match &o.payload {
                ObjectPayload::Program(ph) => Some(ph.clone()),
                _ => None,
            }) {
            Some(p) => p,
            None => {
                return make_err(
                    ErrClass::Common,
                    CommonErr::InvalidHandle as u16,
                    target_prog as u32,
                );
            }
        }
    };

    let s = target_arc.read().working_dir.to_string();
    let bytes = s.as_bytes();
    let total = bytes.len() + 1;

    let va = {
        let pg = caller.write();
        let Some(dst) = pg.tracker.alloc_auto(total as u64) else {
            return make_err(ErrClass::Memory, MemErr::AllocFailed as u16, total as u32);
        };
        if unsafe { pg.virtual_map(dst.into(), total) }.is_err() {
            return make_err(ErrClass::Memory, MemErr::MapFailed as u16, 0);
        }
        dst
    };

    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), va.as_mut_ptr::<u8>(), bytes.len());
        *va.as_mut_ptr::<u8>().add(bytes.len()) = 0;
    }
    va.as_u64()
}

fn object_tag_from_raw(raw: u32) -> Option<ObjectTag> {
    match raw {
        0 => Some(ObjectTag::Directory),
        1 => Some(ObjectTag::Symlink),
        2 => Some(ObjectTag::Generic),
        3 => Some(ObjectTag::Program),
        4 => Some(ObjectTag::Thread),
        5 => Some(ObjectTag::Queue),
        6 => Some(ObjectTag::CompletionQueue),
        7 => Some(ObjectTag::File),
        8 => Some(ObjectTag::Module),
        9 => Some(ObjectTag::Device),
        10 => Some(ObjectTag::IoBufferBacking),
        11 => Some(ObjectTag::ExecutorDomain),
        _ => None,
    }
}

pub(crate) fn sys_object_acquire(
    path_ptr: u64,
    path_len: usize,
    expected_tag: u32,
    interface_bits: u64,
) -> UserHandle {
    let (caller_pid, caller) = match current_process() {
        Ok(current) => current,
        Err(err) => return err,
    };
    let path = match copy_user_string(path_ptr, path_len) {
        Ok(path) => path,
        Err(err) => return err,
    };
    let normalized = path.replace('/', "\\").to_ascii_lowercase();
    if !(normalized == "\\process"
        || normalized.starts_with("\\process\\")
        || normalized == "\\links"
        || normalized.starts_with("\\links\\"))
    {
        return make_err(ErrClass::Common, CommonErr::AccessDenied as u16, 0);
    }

    let (object, available) = if normalized.starts_with("\\links\\") {
        match OBJECT_MANAGER.namespace_entry(&path) {
            Ok(entry) => match &entry.payload {
                ObjectPayload::Symlink(link) => (link.target.clone(), link.exposed),
                _ => {
                    return make_err(ErrClass::Common, CommonErr::InvalidHandle as u16, 0);
                }
            },
            Err(_) => {
                return make_err(ErrClass::Common, CommonErr::InvalidHandle as u16, 0);
            }
        }
    } else {
        match OBJECT_MANAGER.open(&path) {
            Ok(object) => {
                let available = object.behavior().supported_interfaces();
                (object, available)
            }
            Err(_) => {
                return make_err(ErrClass::Common, CommonErr::InvalidHandle as u16, 0);
            }
        }
    };
    let Some(tag) = object_tag_from_raw(expected_tag) else {
        return make_err(
            ErrClass::Common,
            CommonErr::InvalidHandle as u16,
            expected_tag,
        );
    };
    if object.tag != tag || !object.is_alive() {
        return make_err(
            ErrClass::Common,
            CommonErr::InvalidHandle as u16,
            expected_tag,
        );
    }
    if normalized.starts_with("\\process\\") {
        let owner_prefix = alloc::format!("\\process\\{}\\", caller_pid);
        if !normalized.starts_with(&owner_prefix) && object.tag != ObjectTag::Program {
            return make_err(ErrClass::Common, CommonErr::AccessDenied as u16, 0);
        }
    }

    let requested = InterfaceMask::from_raw(tag, interface_bits);
    if interface_bits == 0 || !available.contains(requested) {
        return make_err(ErrClass::Common, CommonErr::AccessDenied as u16, 0);
    }
    if OBJECT_MANAGER
        .policy()
        .authorize(AccessContext { caller_pid }, object.behavior(), requested)
        .is_err()
    {
        return make_err(ErrClass::Common, CommonErr::AccessDenied as u16, 0);
    }

    caller
        .read()
        .create_user_handle_with_interface(object, requested)
}

pub(crate) fn sys_object_close(handle: UserHandle) -> u64 {
    let (_, caller) = match current_process() {
        Ok(current) => current,
        Err(err) => return err,
    };
    if caller.read().close_user_handle(handle).is_some() {
        0
    } else {
        make_err(
            ErrClass::Common,
            CommonErr::InvalidHandle as u16,
            handle as u32,
        )
    }
}

pub(crate) fn sys_object_duplicate(handle: UserHandle, interface_bits: u64) -> UserHandle {
    if interface_bits == 0 {
        return make_err(ErrClass::Common, CommonErr::AccessDenied as u16, 0);
    }
    let (_, caller) = match current_process() {
        Ok(current) => current,
        Err(err) => return err,
    };
    let tag = match caller.read().resolve_handle(handle) {
        Some(object) => object.tag,
        None => {
            return make_err(
                ErrClass::Common,
                CommonErr::InvalidHandle as u16,
                handle as u32,
            );
        }
    };
    let duplicated = caller
        .read()
        .duplicate_user_handle(handle, InterfaceMask::from_raw(tag, interface_bits));
    if duplicated == 0 {
        make_err(
            ErrClass::Common,
            CommonErr::AccessDenied as u16,
            handle as u32,
        )
    } else {
        duplicated
    }
}

pub(crate) fn sys_symlink_create(
    name_ptr: u64,
    name_len: usize,
    target_handle: UserHandle,
    exposed_bits: u64,
) -> UserHandle {
    let (_, caller) = match current_process() {
        Ok(current) => current,
        Err(err) => return err,
    };
    let relative = match copy_user_string(name_ptr, name_len) {
        Ok(name) => name,
        Err(err) => return err,
    };
    if relative.is_empty()
        || relative.starts_with(['\\', '/'])
        || relative
            .split(['\\', '/'])
            .any(|component| component == "..")
    {
        return make_err(ErrClass::Common, CommonErr::AccessDenied as u16, 0);
    }

    let entry = match caller.read().resolve_handle_entry(target_handle) {
        Some(entry) => entry,
        None => {
            return make_err(
                ErrClass::Common,
                CommonErr::InvalidHandle as u16,
                target_handle as u32,
            );
        }
    };
    let exposed = InterfaceMask::from_raw(entry.object.tag, exposed_bits);
    if exposed_bits == 0 || !entry.interface.contains(exposed) {
        return make_err(ErrClass::Common, CommonErr::AccessDenied as u16, 0);
    }

    let path = alloc::format!("\\Links\\Applications\\{}", relative);
    let control = match OBJECT_MANAGER.symlink_object(&path, entry.object, exposed, true) {
        Ok(control) => control,
        Err(_) => return make_err(ErrClass::Common, CommonErr::InvalidHandle as u16, 0),
    };
    caller.read().create_user_handle_with_interface(
        control,
        InterfaceMask::from_raw(
            ObjectTag::Symlink,
            crate::object_manager::behavior::DESTROY_BIT,
        ),
    )
}

pub(crate) fn sys_symlink_withdraw(control_handle: UserHandle) -> u64 {
    let (_, caller) = match current_process() {
        Ok(current) => current,
        Err(err) => return err,
    };
    let entry = match caller.read().resolve_handle_entry(control_handle) {
        Some(entry) => entry,
        None => {
            return make_err(
                ErrClass::Common,
                CommonErr::InvalidHandle as u16,
                control_handle as u32,
            );
        }
    };
    let required = InterfaceMask::from_raw(
        ObjectTag::Symlink,
        crate::object_manager::behavior::DESTROY_BIT,
    );
    if entry.object.tag != ObjectTag::Symlink || !entry.interface.contains(required) {
        return make_err(ErrClass::Common, CommonErr::AccessDenied as u16, 0);
    }
    match OBJECT_MANAGER.unlink_object(&entry.object) {
        Ok(()) => 0,
        Err(_) => make_err(
            ErrClass::Common,
            CommonErr::InvalidHandle as u16,
            control_handle as u32,
        ),
    }
}

pub(crate) fn sys_message_complete(delivery_handle: UserHandle, status: u64, result: u64) -> u64 {
    let (_, caller) = match current_process() {
        Ok(current) => current,
        Err(err) => return err,
    };
    let delivery = {
        let program = caller.read();
        let Some(entry) = program.resolve_handle_entry(delivery_handle) else {
            return make_err(
                ErrClass::Common,
                CommonErr::InvalidHandle as u16,
                delivery_handle as u32,
            );
        };
        if !entry
            .object
            .behavior()
            .matches(entry.interface, ObjectOperation::Configure)
        {
            return make_err(ErrClass::Common, CommonErr::AccessDenied as u16, 0);
        }
        let Some(delivery) = entry.object.downcast_arc::<MessageDelivery>() else {
            return make_err(ErrClass::Message, MsgErr::UnsupportedTargetType as u16, 0);
        };
        delivery
    };
    if !delivery.complete(crate::structs::io_request::IoRequestOutput {
        status,
        result,
        extra: 0,
    }) {
        return make_err(
            ErrClass::Common,
            CommonErr::InvalidHandle as u16,
            delivery_handle as u32,
        );
    }
    let _ = caller.read().close_user_handle(delivery_handle);
    0
}
