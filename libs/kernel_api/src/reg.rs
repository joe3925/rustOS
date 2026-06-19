use alloc::string::String;
use alloc::vec::Vec;
use kernel_sys as ffi;
use kernel_types::status::{Data, RegError};

pub async fn get_value(key_path: &str, name: &str) -> Option<Data> {
    unsafe { ffi::reg_get_value(key_path, name).await }
}

pub async fn set_value(key_path: &str, name: &str, data: Data) -> Result<(), RegError> {
    unsafe { ffi::reg_set_value(key_path, name, data).await }
}

pub async fn create_key(path: &str) -> Result<(), RegError> {
    unsafe { ffi::reg_create_key(path).await }
}

pub async fn delete_key(path: &str) -> Result<bool, RegError> {
    unsafe { ffi::reg_delete_key(path).await }
}

pub async fn delete_value(key_path: &str, name: &str) -> Result<bool, RegError> {
    unsafe { ffi::reg_delete_value(key_path, name).await }
}

pub async fn list_keys(base_path: &str) -> Result<Vec<String>, RegError> {
    unsafe { ffi::reg_list_keys(base_path).await }
}

pub async fn list_values(base_path: &str) -> Result<Vec<String>, RegError> {
    unsafe { ffi::reg_list_values(base_path).await }
}

pub async unsafe fn switch_to_vfs_async() -> Result<(), RegError> {
    ffi::switch_to_vfs_async().await
}
