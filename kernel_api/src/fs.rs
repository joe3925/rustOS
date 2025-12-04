use alloc::string::String;
use alloc::vec::Vec;
use kernel_sys as ffi;
pub use kernel_types::fs::*;
use kernel_types::fs::{File, OpenFlags};
use kernel_types::status::FileStatus;
pub async fn open(path: &str, flags: &[OpenFlags]) -> Result<File, FileStatus> {
    unsafe { ffi::file_open(path, flags).await }
}

pub async fn list_dir(path: &str) -> Result<Vec<String>, FileStatus> {
    unsafe { ffi::fs_list_dir(path).await }
}

pub async fn make_dir(path: &str) -> Result<(), FileStatus> {
    unsafe { ffi::fs_make_dir(path).await }
}

pub async fn remove_dir(path: &str) -> Result<(), FileStatus> {
    unsafe { ffi::fs_remove_dir(path).await }
}
