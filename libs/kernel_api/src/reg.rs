use alloc::string::String;
use alloc::vec::Vec;
use kernel_types::error::KernelError;
use kernel_types::status::Data;

pub async fn get_value(key_path: &str, name: &str) -> Option<Data> {
    unsafe { kernel_sys::reg_get_value(key_path, name).await }
}

pub async fn set_value(key_path: &str, name: &str, data: Data) -> Result<(), KernelError> {
    unsafe { kernel_sys::reg_set_value(key_path, name, data).await }
}

pub async fn create_key(path: &str) -> Result<(), KernelError> {
    unsafe { kernel_sys::reg_create_key(path).await }
}

pub async fn delete_key(path: &str) -> Result<bool, KernelError> {
    unsafe { kernel_sys::reg_delete_key(path).await }
}

pub async fn delete_value(key_path: &str, name: &str) -> Result<bool, KernelError> {
    unsafe { kernel_sys::reg_delete_value(key_path, name).await }
}

pub async fn list_keys(base_path: &str) -> Result<Vec<String>, KernelError> {
    unsafe { kernel_sys::reg_list_keys(base_path).await }
}

pub async fn list_values(base_path: &str) -> Result<Vec<String>, KernelError> {
    unsafe { kernel_sys::reg_list_values(base_path).await }
}

pub async unsafe fn switch_to_vfs_async() -> Result<(), KernelError> {
    kernel_sys::switch_to_vfs_async().await
}
