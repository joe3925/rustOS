use alloc::string::String;
use alloc::vec::Vec;
use kernel_types::error::KernelError;
pub use kernel_types::fs::*;
use kernel_types::fs::{File, OpenFlags, Path};
pub async fn open(path: &Path, flags: &[OpenFlags]) -> Result<File, KernelError> {
    unsafe { kernel_sys::file_open(path, flags).await }
}

pub async fn list_dir(path: &Path) -> Result<Vec<String>, KernelError> {
    unsafe { kernel_sys::fs_list_dir(path).await }
}

pub async fn make_dir(path: &Path) -> Result<(), KernelError> {
    unsafe { kernel_sys::fs_make_dir(path).await }
}

pub async fn remove_dir(path: &Path) -> Result<(), KernelError> {
    unsafe { kernel_sys::fs_remove_dir(path).await }
}

pub fn notify_label_published(label: &str, symlink: &str) {
    unsafe {
        kernel_sys::vfs_notify_label_published(
            label.as_ptr(),
            label.len(),
            symlink.as_ptr(),
            symlink.len(),
        );
    }
}

pub fn notify_label_unpublished(label: &str) {
    unsafe { kernel_sys::vfs_notify_label_unpublished(label.as_ptr(), label.len()) }
}
