use kernel_types::async_ffi::FfiFuture;

#[no_mangle]
pub extern "C" fn kernel_spawn_ffi_internal(fut: FfiFuture<()>) {
    super::runtime::spawn_detached(fut);
}
