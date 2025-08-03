
use crate::executable::program::{ PROGRAM_MANAGER};
use crate::file_system::file::{File, OpenFlags};
use crate::memory::paging::constants::KERNEL_SPACE_BASE;
use crate::println;
use crate::scheduling::scheduler::SCHEDULER;
use alloc::slice;
use alloc::string::{ String, ToString};
use alloc::vec::Vec;
use x86_64::instructions::interrupts;

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

#[inline(always)]
fn is_user_addr(addr: u64) -> bool { addr < KERNEL_SPACE_BASE && addr >= 0x1000 }

#[inline(always)]
fn user_ptr_ok<T>(ptr: *const T, bytes: usize) -> bool {
    let a = ptr as u64;
    is_user_addr(a) &&
    a.checked_add(bytes as u64)
        .map_or(false, |end| is_user_addr(end - 1))
}

#[inline(always)]
fn user_ptr<T>(ptr: *const T) -> bool { is_user_addr(ptr as u64) }


pub(crate) fn sys_print(ptr: *const u8) -> u64 {
    if ptr.is_null() || !user_ptr(ptr) { return 0; }

    let c_str = unsafe { core::ffi::CStr::from_ptr(ptr as *const i8) };
    if let Ok(s) = c_str.to_str() {
        println_wrapper(s.to_string());
    }
    0
}

pub(crate) fn sys_destroy_task(tid: u64) -> u64 {
    SCHEDULER.lock().delete_task(tid).ok();
    0
}


pub(crate) fn sys_create_task(_entry: usize ) -> u64 { 0 }


pub(crate) fn sys_file_open(
    path:  *const u8,
    flags: *const OpenFlags,
    n:     usize,
    out:   *mut File,
) -> u64 {
    if path.is_null()           || !user_ptr(path)             ||
       flags.is_null()          || !user_ptr(flags)            ||
       out.is_null()            || !user_ptr(out)              ||
       !user_ptr_ok(flags, n * core::mem::size_of::<OpenFlags>())
    {
        return 0;
    }

    let pname = unsafe { core::ffi::CStr::from_ptr(path as *const i8) }
        .to_str().unwrap_or("");
    let flg   = unsafe { core::slice::from_raw_parts(flags, n) };

    match File::open(pname, flg) {
        Ok(f)  => unsafe { core::ptr::write(out, f); 0 },
        Err(_) => 0,
    }
}


pub(crate) fn sys_file_read(file: *mut File, max_len: usize) -> u64 {
    if file.is_null() || !user_ptr(file) || max_len == 0 { return 0; }

    let f    = unsafe { &mut *file };
    let data = match f.read() { Ok(d) => d, Err(_) => return 0 };
    let len  = core::cmp::min(data.len(), max_len);

    let pid = SCHEDULER.lock().get_current_task().parent_pid;
    let pmg = PROGRAM_MANAGER.read();
    let prog = match pmg.get(pid) { Some(p) => p, None => return 0 };

    let va = match prog.tracker.alloc_auto(len as u64) { Some(v) => v, None => return 0 };
    if unsafe { prog.virtual_map(va, len) }.is_err() { return 0; }

    unsafe {
        core::ptr::copy_nonoverlapping(data.as_ptr(), va.as_mut_ptr::<u8>(), len);
    }
    va.as_u64()
}


pub(crate) fn sys_file_write(file: *mut File, buf: *const u8, len: usize) -> u64 {
    if file.is_null() || !user_ptr(file) ||
       buf.is_null()  || !user_ptr_ok(buf, len) ||
       len == 0
    {
        return 0;
    }

    let f   = unsafe { &mut *file };
    let src = unsafe { core::slice::from_raw_parts(buf, len) };
    match f.write(src) { Ok(_) => len as u64, Err(_) => 0 }
}


pub(crate) fn sys_file_delete(file: *mut File) -> u64 {
    if file.is_null() || !user_ptr(file) { return 0; }
    let f = unsafe { &mut *file };
    let _ = f.delete();
    0
}


pub(crate) fn sys_get_tid() -> u64 {
    SCHEDULER.lock().get_current_task().id as u64
}


pub(crate) fn sys_mq_request() -> u64 { 0 }