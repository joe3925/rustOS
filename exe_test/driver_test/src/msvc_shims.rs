#![cfg(target_env = "msvc")]
#![allow(non_upper_case_globals)]

use core::ffi::c_void;

#[unsafe(export_name = "_fltused")]
static _FLTUSED: i32 = 0;

#[unsafe(no_mangle)]
pub extern "system" fn __CxxFrameHandler3(_: *mut u8, _: *mut u8, _: *mut u8, _: *mut u8) -> i32 {
    unimplemented!()
}
#[unsafe(no_mangle)]
pub extern "C" fn fma(_x: f64, _y: f64, z: f64) -> f64 {
    z
}

#[unsafe(no_mangle)]
pub extern "C" fn fmaf(_x: f32, _y: f32, z: f32) -> f32 {
    z
}