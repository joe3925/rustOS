use crate::drivers::interrupt_index::current_cpu_id;
use crate::executable::program::{
    Message, MessageId, ProgramHandle, RoutingAction, RoutingRule, UserHandle, PROGRAM_MANAGER,
};
use crate::file_system::file::File;
use crate::file_system::path::Path;
use crate::format;
use crate::memory::paging::constants::{KERNEL_SPACE_BASE, KERNEL_STACK_SIZE};
use crate::println;
use crate::scheduling::scheduler::SCHEDULER;
use crate::scheduling::task::Task;
use crate::{scheduling::scheduler::TaskHandle, util::generate_guid};
use alloc::slice;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use kernel_types::fs::OpenFlags;
use x86_64::instructions::{hlt, interrupts};

use crate::object_manager::{Object, ObjectPayload, ObjectTag, TaskQueueRef, OBJECT_MANAGER};

fn ensure_process_object(pid: u64, prog: &ProgramHandle) -> alloc::sync::Arc<Object> {
    let path = alloc::format!("\\Process\\{}", pid);
    if let Ok(o) = OBJECT_MANAGER.open(path.clone()) {
        return o.clone();
    }
    let _ = OBJECT_MANAGER.mkdir_p("\\Process".to_string());
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
    let tid = th.read().id;
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

fn println_wrapper(message_ptr: String) {
    let message = &*message_ptr;
    println!("{}", message);
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
fn resolve_with_working_dir(caller: &ProgramHandle, raw: &str) -> String {
    let base = caller.read().working_dir.clone();
    let p = Path::parse(raw, Some(&base));
    p.to_string()
}
#[inline(always)]
fn is_user_addr(addr: u64) -> bool {
    addr < KERNEL_SPACE_BASE && addr >= 0x1000
}
#[inline(always)]
pub fn user_ptr_ok<T>(ptr: *const T, bytes: usize) -> bool {
    let a = ptr as u64;
    is_user_addr(a)
        && a.checked_add(bytes as u64)
            .map_or(false, |end| is_user_addr(end - 1))
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
const NOWAIT: u32 = 0x01;

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

pub(crate) fn sys_print(ptr: *const u8) -> u64 {
    if ptr.is_null() || !user_ptr(ptr) {
        return make_err(ErrClass::Common, CommonErr::InvalidPtr as u16, 0);
    }
    let c_str = unsafe { core::ffi::CStr::from_ptr(ptr as *const i8) };
    if let Ok(s) = c_str.to_str() {
        println_wrapper(s.to_string());
        0
    } else {
        make_err(ErrClass::Common, CommonErr::InvalidPtr as u16, 1)
    }
}

pub(crate) fn sys_destroy_task(task_handle: UserHandle) -> u64 {
    let caller_pid = SCHEDULER
        .get_current_task(current_cpu_id())
        .unwrap()
        .read()
        .parent_pid;

    let obj = match OBJECT_MANAGER.open_by_id(task_handle) {
        Some(o) => o,
        None => {
            return make_err(
                ErrClass::Common,
                CommonErr::InvalidHandle as u16,
                task_handle as u32,
            )
        }
    };
    let th = match &obj.payload {
        ObjectPayload::Thread(th) => th.clone(),
        _ => {
            return make_err(
                ErrClass::Common,
                CommonErr::InvalidHandle as u16,
                task_handle as u32,
            )
        }
    };
    if th.read().parent_pid != caller_pid {}
    let tid = th.read().id;
    match SCHEDULER.delete_task(tid) {
        Ok(_) => 0,
        Err(_) => make_err(ErrClass::TaskClass, TaskErr::NotFound as u16, tid as u32),
    }
}

pub(crate) fn sys_create_task(entry: usize) -> UserHandle {
    let caller_pid = SCHEDULER
        .get_current_task(current_cpu_id())
        .unwrap()
        .read()
        .parent_pid;
    let caller = match PROGRAM_MANAGER.get(caller_pid) {
        Some(p) => p,
        None => {
            return make_err(
                ErrClass::Program,
                ProgErr::NotFound as u16,
                caller_pid as u32,
            )
        }
    };
    let managed = { caller.read().managed_threads.lock().len() };
    let stack = if let Some(range) = caller.write().tracker.alloc_auto(KERNEL_STACK_SIZE) {
        unsafe {
            caller
                .write()
                .virtual_map(range, KERNEL_STACK_SIZE as usize)
        };
        range + KERNEL_STACK_SIZE
    } else {
        return make_err(
            ErrClass::Memory,
            MemErr::AllocFailed as u16,
            KERNEL_STACK_SIZE as u32,
        );
    };
    let task = Task::new_user_mode(
        entry,
        KERNEL_STACK_SIZE,
        format!("{} Worker {}", caller.read().title, managed),
        stack,
        caller_pid,
    );
    SCHEDULER.add_task(task.clone());

    let obj = ensure_thread_object(caller_pid, &task);
    obj.id
}

pub(crate) fn sys_file_read(file: *mut File, max_len: usize) -> u64 {
    if file.is_null() || !user_ptr(file) {
        return make_err(ErrClass::Common, CommonErr::InvalidPtr as u16, 0);
    }
    if max_len == 0 {
        return make_err(ErrClass::File, FileErr::ReadZeroLen as u16, 0);
    }
    let f = unsafe { &mut *file };
    let data = match f.read() {
        Ok(d) => d,
        Err(_) => return make_err(ErrClass::File, FileErr::Io as u16, 0),
    };
    let len = core::cmp::min(data.len(), max_len);

    let pid = SCHEDULER
        .get_current_task(current_cpu_id())
        .unwrap()
        .read()
        .parent_pid;
    let handle = match PROGRAM_MANAGER.get(pid) {
        Some(h) => h,
        None => return make_err(ErrClass::Program, ProgErr::NotFound as u16, pid as u32),
    };

    {
        let mut prog = handle.write();
        let va = match prog.tracker.alloc_auto(len as u64) {
            Some(v) => v,
            None => return make_err(ErrClass::Memory, MemErr::AllocFailed as u16, len as u32),
        };
        if unsafe { prog.virtual_map(va, len) }.is_err() {
            return make_err(ErrClass::Memory, MemErr::MapFailed as u16, 0);
        }
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), va.as_mut_ptr::<u8>(), len);
        }
        va.as_u64()
    }
}

pub(crate) fn sys_file_write(file: *mut File, buf: *const u8, len: usize) -> u64 {
    if file.is_null() || !user_ptr(file) || buf.is_null() || !user_ptr_ok(buf, len) {
        return make_err(ErrClass::Common, CommonErr::InvalidPtr as u16, 0);
    }
    if len == 0 {
        return 0;
    }
    let f = unsafe { &mut *file };
    let src = unsafe { core::slice::from_raw_parts(buf, len) };
    match f.write(src) {
        Ok(_) => len as u64,
        Err(_) => make_err(ErrClass::File, FileErr::WriteFailed as u16, 0),
    }
}

pub(crate) fn list_dir(path: *const u8) -> u64 {
    if path.is_null() || !user_ptr(path) {
        return make_err(ErrClass::Common, CommonErr::InvalidPtr as u16, 0);
    }
    let pname = unsafe { core::ffi::CStr::from_ptr(path as *const i8) }
        .to_str()
        .unwrap_or("");
    if pname.is_empty() {
        return make_err(ErrClass::File, FileErr::PathInvalid as u16, 0);
    }

    let caller_pid = SCHEDULER
        .get_current_task(current_cpu_id())
        .unwrap()
        .read()
        .parent_pid;
    let caller = match PROGRAM_MANAGER.get(caller_pid) {
        Some(p) => p,
        None => {
            return make_err(
                ErrClass::Program,
                ProgErr::NotFound as u16,
                caller_pid as u32,
            )
        }
    };
    let abs_path = resolve_with_working_dir(&caller, pname);
    let entries = match File::list_dir(&abs_path) {
        Ok(v) => v,
        Err(_) => return make_err(ErrClass::File, FileErr::Io as u16, 0),
    };
    let joined = if entries.is_empty() {
        String::new()
    } else {
        entries.join("\n")
    };
    let bytes = joined.as_bytes();
    let total = bytes.len() + 1;

    let va = {
        let mut prog = caller.write();
        let Some(dst) = prog.tracker.alloc_auto(total as u64) else {
            return make_err(ErrClass::Memory, MemErr::AllocFailed as u16, total as u32);
        };
        if unsafe { prog.virtual_map(dst, total) }.is_err() {
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

pub(crate) fn sys_file_open(
    path: *const u8,
    flags: *const OpenFlags,
    n: usize,
    out: *mut File,
) -> u64 {
    if path.is_null()
        || !user_ptr(path)
        || flags.is_null()
        || !user_ptr(flags)
        || out.is_null()
        || !user_ptr(out)
        || !user_ptr_ok(flags, n * core::mem::size_of::<OpenFlags>())
    {
        return make_err(ErrClass::Common, CommonErr::InvalidPtr as u16, 0);
    }
    let pname = unsafe { core::ffi::CStr::from_ptr(path as *const i8) }
        .to_str()
        .unwrap_or("");
    if pname.is_empty() {
        return make_err(ErrClass::File, FileErr::PathInvalid as u16, 0);
    }

    let caller_pid = SCHEDULER
        .get_current_task(current_cpu_id())
        .unwrap()
        .read()
        .parent_pid;
    let caller = match PROGRAM_MANAGER.get(caller_pid) {
        Some(p) => p,
        None => {
            return make_err(
                ErrClass::Program,
                ProgErr::NotFound as u16,
                caller_pid as u32,
            )
        }
    };
    let abs_path = resolve_with_working_dir(&caller, pname);
    let flg = unsafe { core::slice::from_raw_parts(flags, n) };
    match File::open(&abs_path, flg) {
        Ok(f) => unsafe {
            core::ptr::write_unaligned(out, f);
            0
        },
        Err(_) => make_err(ErrClass::File, FileErr::Io as u16, 0),
    }
}

pub(crate) fn sys_file_delete(file: *mut File) -> u64 {
    if file.is_null() || !user_ptr(file) {
        return make_err(ErrClass::Common, CommonErr::InvalidPtr as u16, 0);
    }
    let f = unsafe { &mut *file };
    match f.delete() {
        Ok(_) => 0,
        Err(_) => make_err(ErrClass::File, FileErr::DeleteFailed as u16, 0),
    }
}

pub(crate) fn sys_get_thread() -> UserHandle {
    let task = SCHEDULER.get_current_task(current_cpu_id()).unwrap();
    let caller_pid = task.read().parent_pid;
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
        .read()
        .parent_pid;
    let sender_prog = match PROGRAM_MANAGER.get(sender_pid) {
        Some(p) => p,
        None => {
            return make_err(
                ErrClass::Program,
                ProgErr::NotFound as u16,
                sender_pid as u32,
            )
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
            qh.write().queue.push_back(msg.clone());
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
        .read()
        .parent_pid;
    let caller = match PROGRAM_MANAGER.get(caller_pid) {
        Some(p) => p,
        None => {
            return make_err(
                ErrClass::Program,
                ProgErr::NotFound as u16,
                caller_pid as u32,
            )
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
                        return make_err(ErrClass::Route, RouteErr::UnsupportedTargetType as u16, 0)
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
                        return make_err(ErrClass::Route, RouteErr::UnsupportedTargetType as u16, 0)
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
        .read()
        .parent_pid;
    let caller = match PROGRAM_MANAGER.get(caller_pid) {
        Some(p) => p,
        None => {
            return make_err(
                ErrClass::Program,
                ProgErr::NotFound as u16,
                caller_pid as u32,
            )
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
        .read()
        .parent_pid;
    let prog = match PROGRAM_MANAGER.get(caller_pid) {
        Some(p) => p,
        None => {
            return make_err(
                ErrClass::Program,
                ProgErr::NotFound as u16,
                caller_pid as u32,
            )
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
    match q.queue.front() {
        Some(m) => unsafe {
            core::ptr::write_unaligned(msg_ptr, m.clone());
            0
        },
        None => make_err(ErrClass::Message, MsgErr::TargetResolveFailed as u16, 0),
    }
}

pub(crate) fn sys_mq_receive(qh: UserHandle, msg_ptr: *mut Message, flags: u32) -> u64 {
    if msg_ptr.is_null() || !user_ptr(msg_ptr) {
        return make_err(ErrClass::Common, CommonErr::InvalidPtr as u16, 0);
    }

    let caller_pid = SCHEDULER
        .get_current_task(current_cpu_id())
        .unwrap()
        .read()
        .parent_pid;
    let prog = match PROGRAM_MANAGER.get(caller_pid) {
        Some(p) => p,
        None => {
            return make_err(
                ErrClass::Program,
                ProgErr::NotFound as u16,
                caller_pid as u32,
            )
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

    loop {
        if let Some(m) = qref.write().queue.pop_front() {
            unsafe {
                core::ptr::write_unaligned(msg_ptr, m);
            }
            return 0;
        }
        if flags & NOWAIT == NOWAIT {
            return make_err(ErrClass::Message, MsgErr::NoMessageInQueue as u16, 1);
        }
        hlt();
    }
}

pub(crate) fn sys_get_default_mq_handle() -> UserHandle {
    let caller_pid = SCHEDULER
        .get_current_task(current_cpu_id())
        .unwrap()
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
        crate::executable::program::MessageQueue {
            queue: alloc::collections::vec_deque::VecDeque::new(),
        },
    ));
    let obj = Object::with_name(ObjectTag::Queue, name.clone(), ObjectPayload::Queue(qh));
    let _ = OBJECT_MANAGER.link(alloc::format!("{}\\{}", dir, name), &obj);
    obj.id
}

pub(crate) fn sys_change_directory(path: *const u8) -> u64 {
    if path.is_null() || !user_ptr(path) {
        return make_err(ErrClass::Common, CommonErr::InvalidPtr as u16, 0);
    }
    let caller_pid = SCHEDULER
        .get_current_task(current_cpu_id())
        .unwrap()
        .read()
        .parent_pid;
    let caller = match PROGRAM_MANAGER.get(caller_pid) {
        Some(p) => p,
        None => {
            return make_err(
                ErrClass::Program,
                ProgErr::NotFound as u16,
                caller_pid as u32,
            )
        }
    };
    let c = unsafe { core::ffi::CStr::from_ptr(path as *const i8) };
    let raw = match c.to_str() {
        Ok(s) if !s.is_empty() => s,
        _ => return make_err(ErrClass::File, FileErr::PathInvalid as u16, 0),
    };
    let abs_str = {
        let base = caller.read().working_dir.clone();
        let newp = Path::parse(raw, Some(&base));
        newp.to_string()
    };
    if File::list_dir(&abs_str).is_err() {
        return make_err(ErrClass::File, FileErr::PathInvalid as u16, 1);
    }
    caller.write().working_dir = Path::parse(&abs_str, None);
    0
}

pub(crate) fn sys_get_working_dir(target_prog: UserHandle) -> u64 {
    let caller_pid = SCHEDULER
        .get_current_task(current_cpu_id())
        .unwrap()
        .read()
        .parent_pid;
    let caller = match PROGRAM_MANAGER.get(caller_pid) {
        Some(p) => p,
        None => {
            return make_err(
                ErrClass::Program,
                ProgErr::NotFound as u16,
                caller_pid as u32,
            )
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
                )
            }
        }
    };

    let s = target_arc.read().working_dir.to_string();
    let bytes = s.as_bytes();
    let total = bytes.len() + 1;

    let va = {
        let mut pg = caller.write();
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
