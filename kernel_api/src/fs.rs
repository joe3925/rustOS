use alloc::string::String;
use alloc::vec::Vec;
use kernel_sys as ffi;
pub use kernel_types::fs::*;
use kernel_types::fs::{File, OpenFlags};
use kernel_types::status::FileStatus;
pub fn open(path: &str, flags: &[OpenFlags]) -> Result<File, FileStatus> {
    unsafe { ffi::file_open(path, flags) }
}

pub fn read(file: &File) -> Result<Vec<u8>, FileStatus> {
    unsafe { ffi::file_read(file) }
}

pub fn write(file: &mut File, data: &[u8]) -> Result<(), FileStatus> {
    unsafe { ffi::file_write(file, data) }
}

pub fn delete(file: &mut File) -> Result<(), FileStatus> {
    unsafe { ffi::file_delete(file) }
}

pub fn list_dir(path: &str) -> Result<Vec<String>, FileStatus> {
    unsafe { ffi::fs_list_dir(path) }
}

pub fn make_dir(path: &str) -> Result<(), FileStatus> {
    unsafe { ffi::fs_make_dir(path) }
}

pub fn remove_dir(path: &str) -> Result<(), FileStatus> {
    unsafe { ffi::fs_remove_dir(path) }
}
