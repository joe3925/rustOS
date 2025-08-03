#![no_std]
#![allow(dead_code)]

#![cfg_attr(not(feature = "heap"), no_std)]

#[cfg(feature = "heap")]
extern crate alloc;                 

#[cfg(feature = "heap")]
use alloc::{string::String, vec::Vec};


pub const SYS_PRINT:        u32 = 0x00;
pub const SYS_DESTROY_TASK: u32 = 0x01;
pub const SYS_CREATE_TASK:  u32 = 0x02;
pub const SYS_OPEN_FILE:    u32 = 0x03;
pub const SYS_READ_FILE:    u32 = 0x04;
pub const SYS_WRITE_FILE:   u32 = 0x05;
pub const SYS_DELETE_FILE:  u32 = 0x06;
pub const SYS_GET_TASK_ID:  u32 = 0x07;

#[derive(Debug)]
pub enum OpenFlags {
    ReadOnly,
    WriteOnly,
    ReadWrite,
    Create,
    CreateNew,
}
#[cfg(feature = "heap")]
#[derive(Debug)]
pub struct File {
    pub name: String,
    pub extension: String,
    pub size: u64,
    pub starting_cluster: u32,
    pub drive_label: String,
    pub path: String,
    pub deleted: bool,
}
pub fn sys_print(s: &str) {
    unsafe { sys_print_impl(s.as_ptr()); }
}

pub fn sys_destroy_task(tid: u64) {
    unsafe { sys_destroy_task_impl(tid); }
}

pub fn sys_create_task(entry_point: usize, name: &str) {
    unsafe { sys_create_task_impl(entry_point, name.as_ptr()); }
}
#[cfg(feature = "heap")]
pub fn sys_open_file(path: &str, flags: &[OpenFlags]) -> Option<File> {
    use core::mem::MaybeUninit;

    let mut slot = MaybeUninit::<File>::uninit();
    let status = unsafe {
        sys_open_file_impl(
            path.as_ptr(),
            flags.as_ptr(),
            flags.len(),
            slot.as_mut_ptr(),
        )
    };
    if status == 0 { Some(unsafe { slot.assume_init() }) } else { None }
}
#[cfg(feature = "heap")]
pub fn sys_read_file(file: &mut File, buffer: &mut [u8]) -> usize {
    unsafe { sys_read_file_impl(file, buffer.as_mut_ptr(), buffer.len()) }
}
#[cfg(feature = "heap")]
pub fn sys_write_file(file: &mut File, data: &[u8]) -> usize {
    unsafe { sys_write_file_impl(file, data.as_ptr(), data.len()) }
}
#[cfg(feature = "heap")]
pub fn sys_delete_file(file: &mut File) {
    unsafe { sys_delete_file_impl(file); }
}

pub fn sys_get_task_id() -> u64 {
    unsafe { sys_get_task_id_impl() }
}
make_syscall!(fn sys_print_impl(ptr: *const u8)                           -> u64,   SYS_PRINT);
make_syscall!(fn sys_destroy_task_impl(tid: u64)                          -> u64,   SYS_DESTROY_TASK);
make_syscall!(fn sys_create_task_impl(entry: usize, name: *const u8)      -> u64,   SYS_CREATE_TASK);
#[cfg(feature = "heap")]
make_syscall!(fn sys_open_file_impl(path: *const u8,
                                    flags: *const OpenFlags,
                                    len: usize,
                                    out: *mut File)                       -> u64,   SYS_OPEN_FILE);
#[cfg(feature = "heap")]
make_syscall!(fn sys_read_file_impl(file: *mut File,
                                    buf: *mut u8,
                                    len: usize)                           -> usize, SYS_READ_FILE);
#[cfg(feature = "heap")]
make_syscall!(fn sys_write_file_impl(file: *mut File,
                                     data: *const u8,
                                     len: usize)                          -> usize, SYS_WRITE_FILE);
#[cfg(feature = "heap")]
make_syscall!(fn sys_delete_file_impl(file: *mut File)                    -> u64,   SYS_DELETE_FILE);
make_syscall!(fn sys_get_task_id_impl()                                   -> u64,   SYS_GET_TASK_ID);
#[macro_export]
macro_rules! make_syscall {
    (fn $name:ident ( $( $arg:ident : $ty:ty ),* $(,)? )
        -> $ret:ty , $num:expr $(,)?) => {
        #[inline(always)]
        unsafe fn $name( $( $arg : $ty ),* ) -> $ret {
            // Pack the first four arguments (or fewer) into a fixed array.
            let mut regs = [0u64; 4];
            let mut i = 0usize;
            $(
                if i < 4 { regs[i] = $arg as u64; }
                i += 1;
            )*

            let out: u64;
            core::arch::asm!(
                // Load the argument registers from `regs`.
                "mov     rcx,  [rsi]",
                "mov     rdx,  [rsi + 8]",
                "mov     r8,   [rsi + 16]",
                "mov     r9,   [rsi + 24]",
                // Preserve RCX across the call (Windows expects it clobbered).
                "mov     r10, rcx",
                "syscall",
                "mov     rcx, r10",
                in("rsi") regs.as_ptr(),   // pointer to `regs`
                in("eax") $num as u32,     // service number
                lateout("rax") out,
                options(nostack, preserves_flags),
            );
            out as $ret
        }
    };
}
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        use core::fmt::Write;

        // 128 bytes is enough for short diagnostic strings; enlarge if needed.
        let mut buf = [0u8; 128];
        let mut len = 0usize;

        struct Writer<'a>(&'a mut [u8], &'a mut usize);
        impl<'a> Write for Writer<'a> {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let end = *self.1 + s.len();
                if end > self.0.len() { return Err(core::fmt::Error) }
                self.0[*self.1 .. end].copy_from_slice(s.as_bytes());
                *self.1 = end;
                Ok(())
            }
        }

        let mut w = Writer(&mut buf, &mut len);
        core::write!(&mut w, $($arg)*).unwrap();
        $crate::sys_print(core::str::from_utf8(&buf[..len]).unwrap());
    }}
}

/// `println!` – same as `print!` but appends `\n`
#[macro_export]
macro_rules! println {
    () => { $crate::print!("\n") };
    ($fmt:expr) => { $crate::print!(concat!($fmt, "\n")) };
    ($fmt:expr, $($arg:tt)*) => { $crate::print!(concat!($fmt, "\n"), $($arg)* ) };
}