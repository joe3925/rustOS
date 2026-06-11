use crate::drivers::interrupt_index::current_cpu_id;
use crate::executable::program::{
    Message, MessageId, PROGRAM_MANAGER, ProgramHandle, RoutingAction, RoutingRule, UserHandle,
};
use crate::memory::paging::constants::KERNEL_SPACE_BASE;
use crate::memory::paging::stack::StackSize;
use crate::scheduling::scheduler::SCHEDULER;
use crate::scheduling::task::Task;
use crate::structs::completion_queue::{CompletionQueue, CompletionQueueError};
use crate::structs::io_request::{
    FileObject, IoOpcode, KernelIoOp, RequestId, UserIoCompletion, UserIoOp,
};
use crate::{format, print};
use crate::{scheduling::scheduler::TaskHandle, util::generate_guid};
use alloc::slice;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use kernel_types::fs::{OpenFlags, Path};
use kernel_types::object_manager::ObjectTag;

use crate::object_manager::{OBJECT_MANAGER, Object, ObjectPayload, TaskQueueRef};

fn ensure_process_object(pid: u64, prog: &ProgramHandle) -> alloc::sync::Arc<Object> {
    let path = alloc::format!("\\Process\\{}", pid);
    if let Ok(o) = OBJECT_MANAGER.open(path.clone()) {
        return o.clone();
    }
    let _ = OBJECT_MANAGER.mkdir_p("\\Process");
    let obj = Object::with_name(
        ObjectTag::Program,
        pid.to_string(),
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
    let path = alloc::format!("\\Process\\{}\\DefaultQueue", pid);
    if let Ok(o) = OBJECT_MANAGER.open(path.clone()) {
        if let ObjectPayload::Queue(q) = &o.payload {
            return (o.clone(), q.clone());
        }
    }
    let proc_dir = alloc::format!("\\Process\\{}", pid);
    let _ = OBJECT_MANAGER.mkdir_p(proc_dir.clone());
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
    let dir = alloc::format!("\\Process\\{}\\Threads", pid);
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
    (0x1000..KERNEL_SPACE_BASE).contains(&addr)
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
        .get_current_task(current_cpu_id())
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
) -> Result<Arc<CompletionQueue>, u64> {
    let obj = OBJECT_MANAGER.open_by_id(handle).ok_or_else(|| {
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

fn resolve_file_object(handle: UserHandle) -> Result<Arc<FileObject>, u64> {
    let obj = OBJECT_MANAGER.open_by_id(handle).ok_or_else(|| {
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

fn resolve_message_queue(
    handle: UserHandle,
    caller_pid: u64,
    caller: &ProgramHandle,
) -> Result<TaskQueueRef, u64> {
    if handle == 0 {
        return Ok(ensure_default_queue_object(caller_pid, caller).1);
    }

    let obj = OBJECT_MANAGER.open_by_id(handle).ok_or_else(|| {
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
            let length = op.length as usize;
            validate_user_buffer(op.buffer, length)?;
            Ok(KernelIoOp::FileRead {
                owner: caller.clone(),
                file: resolve_file_object(op.target_handle)?,
                buffer: op.buffer,
                length,
                offset: op.offset,
                user_token: op.user_token,
            })
        }
        IoOpcode::FileWrite => {
            let data = copy_user_bytes(op.buffer, op.length as usize)?;
            Ok(KernelIoOp::FileWrite {
                file: resolve_file_object(op.target_handle)?,
                data,
                offset: op.offset,
                user_token: op.user_token,
            })
        }
        IoOpcode::FileDelete => {
            if op.target_handle != 0 {
                return Ok(KernelIoOp::FileDeleteHandle {
                    file: resolve_file_object(op.target_handle)?,
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
            let length = op.length as usize;
            validate_user_buffer(op.buffer, length)?;
            Ok(KernelIoOp::MqReceive {
                owner: caller.clone(),
                queue: resolve_message_queue(op.target_handle, caller_pid, caller)?,
                buffer: op.buffer,
                length,
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
        .get_current_task(current_cpu_id())
        .unwrap()
        .inner
        .read()
        .parent_pid;

    let obj = match OBJECT_MANAGER.open_by_id(task_handle) {
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
    let _ = th.inner.read().parent_pid != caller_pid;
    let tid = th.task_id();
    match SCHEDULER.delete_task(tid) {
        Ok(_) => 0,
        Err(_) => make_err(ErrClass::TaskClass, TaskErr::NotFound as u16, tid as u32),
    }
}

pub(crate) fn sys_create_task(entry: usize) -> UserHandle {
    let stack_size = StackSize::Medium.as_bytes();
    let caller_pid = SCHEDULER
        .get_current_task(current_cpu_id())
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
            let _ = caller.write().virtual_map(range, stack_size as usize);
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
        // TODO: check this
        unsafe { *(entry as *const extern "C" fn(usize)) },
        0,
        stack_size,
        format!("{} Worker {}", caller.read().title, managed),
        stack,
        caller_pid,
    );
    SCHEDULER.add_task(task.clone());

    let obj = ensure_thread_object(caller_pid, &task);
    obj.id
}

pub(crate) fn sys_completion_queue_create(
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

    let queue = match CompletionQueue::new(caller_pid, request_capacity, completion_capacity, flags)
    {
        Ok(queue) => queue,
        Err(err) => return map_cq_error(err),
    };

    let dir = alloc::format!("\\Process\\{}\\CompletionQueues", caller_pid);
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
    let queue = match resolve_completion_queue(completion_queue_handle, caller_pid) {
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
    let queue = match resolve_completion_queue(completion_queue_handle, caller_pid) {
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

    let (caller_pid, _) = match current_process() {
        Ok(current) => current,
        Err(err) => return err,
    };
    let queue = match resolve_completion_queue(completion_queue_handle, caller_pid) {
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

    let (caller_pid, _) = match current_process() {
        Ok(current) => current,
        Err(err) => return err,
    };
    let queue = match resolve_completion_queue(completion_queue_handle, caller_pid) {
        Ok(queue) => queue,
        Err(err) => return err,
    };

    let out = unsafe { slice::from_raw_parts_mut(out_completions, max) };
    queue.wait_completions(out, timeout_ns) as u64
}

pub(crate) fn sys_io_cancel(completion_queue_handle: UserHandle, request_id: RequestId) -> u64 {
    let (caller_pid, _) = match current_process() {
        Ok(current) => current,
        Err(err) => return err,
    };
    let queue = match resolve_completion_queue(completion_queue_handle, caller_pid) {
        Ok(queue) => queue,
        Err(err) => return err,
    };

    queue.cancel(request_id).map_or_else(map_cq_error, |_| 0)
}

pub(crate) fn sys_get_thread() -> UserHandle {
    let task = SCHEDULER.get_current_task(current_cpu_id()).unwrap();
    let caller_pid = task.inner.read().parent_pid;
    let obj = ensure_thread_object(caller_pid, &task);
    obj.id
}

pub(crate) fn sys_mq_request(target: UserHandle, message_ptr: *mut Message) -> u64 {
    if message_ptr.is_null() || !user_ptr(message_ptr) {
        return make_err(ErrClass::Common, CommonErr::InvalidPtr as u16, 0);
    }
    let msg = unsafe { &mut *message_ptr };

    let sender_pid = SCHEDULER
        .get_current_task(current_cpu_id())
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
    let sender_obj = ensure_process_object(sender_pid, &sender_prog);
    msg.sender = Some(sender_obj.id);

    let tgt = match OBJECT_MANAGER.open_by_id(target) {
        Some(o) => o,
        None => return make_err(ErrClass::Message, MsgErr::TargetHandleInvalid as u16, 0),
    };

    match &tgt.payload {
        ObjectPayload::Program(ph) => {
            ph.write().receive_message(msg.clone());
            0
        }
        ObjectPayload::Queue(qh) => {
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
        .get_current_task(current_cpu_id())
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
            let obj = match OBJECT_MANAGER.open_by_id(rule_u.queue_handle) {
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
                let o = match OBJECT_MANAGER.open_by_id(rule_u.queue_handle) {
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
                let o = match OBJECT_MANAGER.open_by_id(rule_u.thread_handle) {
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
        .get_current_task(current_cpu_id())
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
        .get_current_task(current_cpu_id())
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
        let o = match OBJECT_MANAGER.open_by_id(qh) {
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
        .get_current_task(current_cpu_id())
        .unwrap()
        .inner
        .read()
        .parent_pid;
    let prog = match PROGRAM_MANAGER.get(caller_pid) {
        Some(p) => p,
        None => return 0,
    };
    let (obj, _q) = ensure_default_queue_object(caller_pid, &prog);
    obj.id
}

pub(crate) fn sys_create_mq() -> UserHandle {
    let caller_pid = SCHEDULER
        .get_current_task(current_cpu_id())
        .unwrap()
        .inner
        .read()
        .parent_pid;
    let prog = match PROGRAM_MANAGER.get(caller_pid) {
        Some(p) => p,
        None => return 0,
    };

    let dir = alloc::format!("\\Process\\{}\\Queues", caller_pid);
    let _ = OBJECT_MANAGER.mkdirp(dir.clone());

    let name = guid_to_string(&generate_guid());
    let qh: TaskQueueRef = alloc::sync::Arc::new(spin::RwLock::new(
        crate::executable::program::MessageQueue::new(),
    ));
    let obj = Object::with_name(ObjectTag::Queue, name.clone(), ObjectPayload::Queue(qh));
    let _ = OBJECT_MANAGER.link(alloc::format!("{}\\{}", dir, name), &obj);
    obj.id
}

pub(crate) fn sys_get_working_dir(target_prog: UserHandle) -> u64 {
    let caller_pid = SCHEDULER
        .get_current_task(current_cpu_id())
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
        match OBJECT_MANAGER
            .open_by_id(target_prog)
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
        if unsafe { pg.virtual_map(dst, total) }.is_err() {
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
