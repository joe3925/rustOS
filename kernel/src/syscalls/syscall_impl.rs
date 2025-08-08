use crate::executable::program::{
    HandleTarget, Message, MessageId, ProgramHandle, RoutingAction, RoutingRule, UserHandle,
    PROGRAM_MANAGER,
};
use crate::file_system::file::{File, OpenFlags};
use crate::file_system::path::Path;
use crate::format;
use crate::memory::paging::constants::{KERNEL_SPACE_BASE, KERNEL_STACK_SIZE};
use crate::println;
use crate::scheduling::scheduler::SCHEDULER;
use crate::scheduling::task::Task;
use alloc::slice;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use x86_64::instructions::{hlt, interrupts};

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
        make_err(ErrClass::Common, CommonErr::InvalidPtr as u16, 1) // bad utf8
    }
}

pub(crate) fn sys_destroy_task(task_handle: UserHandle) -> u64 {
    use ErrClass::*;

    let caller_pid = SCHEDULER.lock().get_current_task().read().parent_pid;

    let program = match PROGRAM_MANAGER.get(caller_pid) {
        Some(p) => p,
        None => return make_err(Program, ProgErr::NotFound as u16, caller_pid as u32),
    };

    let target = match program.read().resolve_handle(task_handle) {
        Some(HandleTarget::Thread(task)) => task,
        _ => return make_err(Common, CommonErr::InvalidHandle as u16, task_handle as u32),
    };

    let tid = target.read().id;

    match SCHEDULER.lock().delete_task(tid) {
        Ok(_) => 0,
        Err(_) => make_err(TaskClass, TaskErr::NotFound as u16, tid as u32),
    }
}

pub(crate) fn sys_create_task(_entry: usize) -> UserHandle {
    use ErrClass::*;
    let caller_pid = SCHEDULER.lock().get_current_task().read().parent_pid;
    let caller = match PROGRAM_MANAGER.get(caller_pid) {
        Some(p) => p,
        None => return make_err(Program, ProgErr::NotFound as u16, caller_pid as u32),
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
        return 0;
    };
    let task = Task::new_user_mode(
        _entry,
        KERNEL_STACK_SIZE,
        format!("{} Worker {}", caller.read().title, managed),
        stack,
        caller_pid,
    );
    SCHEDULER.lock().add_task(task.clone());
    let x = caller
        .write()
        .create_user_handle(HandleTarget::Thread(task));
    x
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

    let pid = SCHEDULER.lock().get_current_task().read().parent_pid;
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

    let caller_pid = SCHEDULER.lock().get_current_task().read().parent_pid;
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

    let caller_pid = SCHEDULER.lock().get_current_task().read().parent_pid;
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
            core::ptr::write(out, f);
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
    let binding = SCHEDULER.lock().get_current_task();
    let caller_task = binding.read();
    let caller_pid = caller_task.parent_pid;
    let caller = match PROGRAM_MANAGER.get(caller_pid) {
        Some(p) => p,
        None => return 0,
    };
    let x = caller
        .write()
        .create_user_handle(HandleTarget::Thread(SCHEDULER.lock().get_current_task()));
    x
}

pub(crate) fn sys_mq_request(target: UserHandle, message_ptr: *mut Message) -> u64 {
    use ErrClass::*;
    use MsgErr::*;
    use ProgErr::*;
    if message_ptr.is_null() || !user_ptr(message_ptr) {
        return make_err(ErrClass::Common, CommonErr::InvalidPtr as u16, 0);
    }
    let message = unsafe { &mut *message_ptr };
    let sender_pid = SCHEDULER.lock().get_current_task().read().parent_pid;
    let sender_proc = match PROGRAM_MANAGER.get(sender_pid) {
        Some(p) => p,
        None => return make_err(Program, NotFound as u16, sender_pid as u32),
    };

    let target_obj = match sender_proc.read().resolve_handle(target) {
        Some(o) => o,
        None => return make_err(Message, TargetHandleInvalid as u16, 0),
    };

    match target_obj {
        HandleTarget::Program(prog_h) => {
            let sender_handle_for_recipient = {
                if let Some(h) = prog_h.read().has_handle(sender_pid) {
                    h
                } else {
                    prog_h
                        .write()
                        .create_user_handle(HandleTarget::Program(sender_proc))
                }
            };
            message.sender = Some(sender_handle_for_recipient);

            prog_h.write().receive_message(message.clone());
            0
        }

        HandleTarget::MessageQueue(owner_pid, qh) => {
            let owner_proc = match PROGRAM_MANAGER.get(owner_pid) {
                Some(p) => p,
                None => return make_err(Program, NotFound as u16, owner_pid as u32),
            };

            let sender_handle_for_owner = {
                if let Some(h) = owner_proc.read().has_handle(sender_pid) {
                    h
                } else {
                    owner_proc
                        .write()
                        .create_user_handle(HandleTarget::Program(sender_proc))
                }
            };
            message.sender = Some(sender_handle_for_owner);

            qh.write().queue.push_back(message.clone());
            0
        }

        _ => make_err(Message, UnsupportedTargetType as u16, 0),
    }
}
pub(crate) fn sys_rule_add(rule_ptr: *const UserRoutingRule) -> u64 {
    use ErrClass::*;
    if rule_ptr.is_null() || !user_ptr(rule_ptr) {
        return make_err(Common, CommonErr::InvalidPtr as u16, 0);
    }

    let rule_u = unsafe { &*rule_ptr };

    // Caller / owner process
    let caller_pid = SCHEDULER.lock().get_current_task().read().parent_pid;
    let caller = match PROGRAM_MANAGER.get(caller_pid) {
        Some(p) => p,
        None => return make_err(Program, ProgErr::NotFound as u16, caller_pid as u32),
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
            let qh = {
                let handle_opt = {
                    let p_guard = caller.read();
                    let htab = p_guard.handle_table.read();
                    htab.resolve(rule_u.queue_handle)
                };

                match handle_opt {
                    Some(HandleTarget::MessageQueue(owner_pid, qh)) if owner_pid == caller_pid => {
                        qh
                    }
                    _ => return make_err(Route, RouteErr::NotOwner as u16, 0),
                }
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
            let qh = {
                let handle_opt = {
                    let p_guard = caller.read();
                    let htab = p_guard.handle_table.read();
                    htab.resolve(rule_u.queue_handle)
                };

                match handle_opt {
                    Some(HandleTarget::MessageQueue(owner_pid, qh)) if owner_pid == caller_pid => {
                        Some(qh)
                    }
                    None => None,
                    _ => return make_err(Route, RouteErr::NotOwner as u16, 0),
                }
            };
            let th = {
                let handle_opt = {
                    let p_guard = caller.read();
                    let htab = p_guard.handle_table.read();
                    htab.resolve(rule_u.thread_handle)
                };

                match handle_opt {
                    Some(HandleTarget::Thread(th)) if th.read().parent_pid == caller_pid => th,
                    Some(HandleTarget::MessageQueue(..)) => {
                        return make_err(Route, RouteErr::UnsupportedTargetType as u16, 0)
                    }
                    _ => return make_err(Route, RouteErr::NotOwner as u16, 0),
                }
            };
            RoutingRule {
                msg_id: rule_u.msg_id,
                from_pid: if rule_u.from_pid == 0 {
                    None
                } else {
                    Some(rule_u.from_pid)
                },
                action: RoutingAction::Callback(th, qh),
            }
        }
        _ => return make_err(Route, RouteErr::InvalidPtr as u16, 1),
    };

    // Insert, enforcing “one reroute per msg_id”
    caller.write().add_routing_rule(krule);
    0
}

pub(crate) fn sys_rule_clear(rule_ptr: *const UserRoutingRule) -> u64 {
    use ErrClass::*;
    if rule_ptr.is_null() || !user_ptr(rule_ptr) {
        return make_err(Common, CommonErr::InvalidPtr as u16, 0);
    }

    let rule_u = unsafe { &*rule_ptr };

    let caller_pid = SCHEDULER.lock().get_current_task().read().parent_pid;
    let caller = match PROGRAM_MANAGER.get(caller_pid) {
        Some(p) => p,
        None => return make_err(Program, ProgErr::NotFound as u16, caller_pid as u32),
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
    use ErrClass::*;
    use MsgErr::*;

    if msg_ptr.is_null() || !user_ptr(msg_ptr) {
        return make_err(Common, CommonErr::InvalidPtr as u16, 0);
    }

    let caller_pid = SCHEDULER.lock().get_current_task().read().parent_pid;
    let prog = match PROGRAM_MANAGER.get(caller_pid) {
        Some(p) => p,
        None => return make_err(Program, ProgErr::NotFound as u16, caller_pid as u32),
    };

    let q_handle = if qh == 0 {
        prog.read().default_queue.clone()
    } else {
        let handle_opt = {
            let pg = prog.read();
            let htab = pg.handle_table.read();
            htab.resolve(qh)
        };

        match handle_opt {
            Some(HandleTarget::MessageQueue(owner_pid, qh_arc)) if owner_pid == caller_pid => {
                qh_arc
            }
            _ => return make_err(Message, TargetHandleInvalid as u16, 0),
        }
    };

    let q = q_handle.write();
    match q.queue.front() {
        Some(m) => unsafe {
            core::ptr::write(msg_ptr, m.clone());
            0
        },
        None => make_err(Message, TargetResolveFailed as u16, 0),
    }
}

pub(crate) fn sys_mq_receive(qh: UserHandle, msg_ptr: *mut Message, flags: u32) -> u64 {
    use ErrClass::*;
    use MsgErr::*;

    if msg_ptr.is_null() || !user_ptr(msg_ptr) {
        return make_err(Common, CommonErr::InvalidPtr as u16, 0);
    }

    let caller_pid = SCHEDULER.lock().get_current_task().read().parent_pid;
    let prog = match PROGRAM_MANAGER.get(caller_pid) {
        Some(p) => p,
        None => return make_err(Program, ProgErr::NotFound as u16, caller_pid as u32),
    };

    let q_handle = if qh == 0 {
        prog.read().default_queue.clone()
    } else {
        let handle_opt = {
            let pg = prog.read();
            let htab = pg.handle_table.read();
            htab.resolve(qh)
        };

        match handle_opt {
            Some(HandleTarget::MessageQueue(owner_pid, qh_arc)) if owner_pid == caller_pid => {
                qh_arc
            }
            _ => return make_err(Message, TargetHandleInvalid as u16, 0),
        }
    };

    loop {
        if let Some(m) = q_handle.write().queue.pop_front() {
            // TODO: find a way to yield this till there are items in the queue
            unsafe {
                core::ptr::write(msg_ptr, m);
            }
            return 0;
        }

        if flags & NOWAIT == NOWAIT {
            return make_err(Message, NoMessageInQueue as u16, 1); // empty + NOWAIT
        }
        hlt();
    }
}
pub(crate) fn sys_get_default_mq_handle() -> UserHandle {
    let caller_pid = SCHEDULER.lock().get_current_task().read().parent_pid;
    let caller = match PROGRAM_MANAGER.get(caller_pid) {
        Some(p) => p,
        None => return 0,
    };
    let mq = caller.read().default_queue.clone();
    let handle = caller
        .write()
        .create_user_handle(HandleTarget::MessageQueue(caller.read().pid, mq));
    handle
}
pub(crate) fn sys_create_mq() -> UserHandle {
    let caller_pid = SCHEDULER.lock().get_current_task().read().parent_pid;
    let caller = match PROGRAM_MANAGER.get(caller_pid) {
        Some(p) => p,
        None => return 0,
    };
    let handle = caller.write().new_mq();
    let x = caller.write().create_user_handle(handle);
    x
}
pub(crate) fn sys_change_directory(path: *const u8) -> u64 {
    if path.is_null() || !user_ptr(path) {
        return make_err(ErrClass::Common, CommonErr::InvalidPtr as u16, 0);
    }

    let caller_pid = SCHEDULER.lock().get_current_task().read().parent_pid;
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
    use ErrClass::*;

    let caller_pid = SCHEDULER.lock().get_current_task().read().parent_pid;
    let caller = match PROGRAM_MANAGER.get(caller_pid) {
        Some(p) => p,
        None => return make_err(Program, ProgErr::NotFound as u16, caller_pid as u32),
    };

    let target_arc = if target_prog == 0 {
        caller.clone()
    } else {
        let opt = caller.read().resolve_handle(target_prog);
        match opt {
            Some(HandleTarget::Program(p)) => p,
            _ => return make_err(Common, CommonErr::InvalidHandle as u16, target_prog as u32),
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
