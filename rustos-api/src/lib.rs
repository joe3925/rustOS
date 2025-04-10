#![no_std]
#![allow(dead_code)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::arch::asm;

#[derive(Debug)]
pub enum OpenFlags {
    ReadOnly,
    WriteOnly,
    ReadWrite,
    Create,
    CreateNew,
}
#[derive(Debug)]
pub(crate) struct File {
    pub name: String,
    pub extension: String,
    pub size: u64,
    pub starting_cluster: u32,
    pub drive_label: String,
    pub path: String,
    pub deleted: bool,
}
#[derive(Clone)]
struct SyscallParams {
    param1: u64,
    param2: u64,
    param3: u64,
    param4: u64,
    extra_params: Vec<u64>,
}
impl SyscallParams {
    fn new() -> Self {
        SyscallParams {
            param1: 0,
            param2: 0,
            param3: 0,
            param4: 0,
            extra_params: vec![],
        }
    }
}
pub fn sys_print(string: &str) {
    unsafe {
        asm!(
        "int 0x80",
        in("rax") 1,
        in("r8") string.as_ptr() as u64,
        );
    }
}

pub fn sys_destroy_task(task_id: u64) {
    unsafe {
        asm!(
        "int 0x80",
        in("rax") 2,
        in("r8") task_id,
        );
    }
}

pub fn sys_create_task(entry_point: usize, name: &str) {
    unsafe {
        asm!(
        "int 0x80",
        in("rax") 3,
        in("r8") entry_point as u64,
        in("r9") name.as_ptr() as u64,
        );
    }
}

pub fn sys_open_file(path: &str, flags: &[OpenFlags]) -> *mut Option<File> {
    let mut file_ptr: *mut Option<File> = Box::into_raw(Box::new(None));
    let params: *const SyscallParams = &SyscallParams {
        param1: file_ptr as u64,
        param2: 0,
        param3: 0,
        param4: 0,
        extra_params: vec![],
    };
    unsafe {
        asm!(
        "int 0x80",
        in("rax") 4,
        in("r8") path.as_ptr() as u64,
        in("r9") flags.as_ptr() as u64,
        in("r10") flags.len() as u64,
        in("r11") params as u64,
        );
    }
    unsafe { file_ptr }
}

pub fn sys_read_file(file: &mut File, buffer: &mut [u8]) -> usize {
    let mut bytes_read = 0;
    unsafe {
        asm!(
        "int 0x80",
        in("rax") 5,
        in("r8") file as *mut _ as u64,
        in("r9") buffer.as_mut_ptr() as u64,
        in("r10") buffer.len() as u64,
        lateout("r10") bytes_read,
        );
    }
    bytes_read
}

pub fn sys_write_file(file: &mut File, data: &[u8]) -> usize {
    let mut bytes_written = 0;
    unsafe {
        asm!(
        "int 0x80",
        in("rax") 6,
        in("r8") file as *mut _ as u64,
        in("r9") data.as_ptr() as u64,
        in("r10") data.len() as u64,
        lateout("r10") bytes_written,
        );
    }
    bytes_written
}

pub fn sys_delete_file(file: &mut File) {
    unsafe {
        asm!(
        "int 0x80",
        in("rax") 7,
        in("r8") file as *mut _ as u64,
        );
    }
}

pub fn sys_get_task_id() -> usize {
    let mut task_id = 0;
    unsafe {
        asm!(
        "int 0x80",
        in("rax") 8,
        inout("r8") task_id,
        );
    }
    task_id
}
