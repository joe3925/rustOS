use alloc::string::String;
use alloc::vec::Vec;
use kernel_sys as ffi;
pub use kernel_types::fs::*;
use kernel_types::fs::{File, OpenFlags, Path};
use kernel_types::status::FileStatus;
pub async fn open(path: &Path, flags: &[OpenFlags]) -> Result<File, FileStatus> {
    unsafe { ffi::file_open(path, flags).await }
}

pub async fn list_dir(path: &Path) -> Result<Vec<String>, FileStatus> {
    unsafe { ffi::fs_list_dir(path).await }
}

pub async fn make_dir(path: &Path) -> Result<(), FileStatus> {
    unsafe { ffi::fs_make_dir(path).await }
}

pub async fn remove_dir(path: &Path) -> Result<(), FileStatus> {
    unsafe { ffi::fs_remove_dir(path).await }
}

pub fn notify_label_published(label: &str, symlink: &str) {
    unsafe {
        ffi::vfs_notify_label_published(
            label.as_ptr(),
            label.len(),
            symlink.as_ptr(),
            symlink.len(),
        );
    }
}

pub fn notify_label_unpublished(label: &str) {
    unsafe { ffi::vfs_notify_label_unpublished(label.as_ptr(), label.len()) }
}
