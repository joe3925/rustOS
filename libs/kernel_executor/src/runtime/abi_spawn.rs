use kernel_types::async_ffi::AbiFuture;

#[unsafe(no_mangle)]
pub extern "C" fn kernel_spawn_abi_internal(fut: AbiFuture<()>) {
    super::runtime::spawn_detached(fut);
}
