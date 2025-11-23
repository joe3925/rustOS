use alloc::string::String;
use alloc::vec::Vec;
use kernel_sys as ffi;
use kernel_types::status::{Data, RegError};

pub fn get_value(key_path: &str, name: &str) -> Option<Data> {
    unsafe { ffi::reg_get_value(key_path, name) }
}

pub fn set_value(key_path: &str, name: &str, data: Data) -> Result<(), RegError> {
    unsafe { ffi::reg_set_value(key_path, name, data) }
}

pub fn create_key(path: &str) -> Result<(), RegError> {
    unsafe { ffi::reg_create_key(path) }
}

pub fn delete_key(path: &str) -> Result<bool, RegError> {
    unsafe { ffi::reg_delete_key(path) }
}

pub fn delete_value(key_path: &str, name: &str) -> Result<bool, RegError> {
    unsafe { ffi::reg_delete_value(key_path, name) }
}

pub fn list_keys(base_path: &str) -> Result<Vec<String>, RegError> {
    unsafe { ffi::reg_list_keys(base_path) }
}

pub fn list_values(base_path: &str) -> Result<Vec<String>, RegError> {
    unsafe { ffi::reg_list_values(base_path) }
}

pub fn switch_to_vfs() -> Result<(), RegError> {
    unsafe { ffi::switch_to_vfs() }
}
