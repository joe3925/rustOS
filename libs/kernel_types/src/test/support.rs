extern crate std;

#[unsafe(no_mangle)]
extern "C" fn kernel_abi_future_allocate(
    _size: usize,
    _align: usize,
) -> crate::async_ffi::AbiFutureAllocation {
    crate::async_ffi::AbiFutureAllocation::null()
}

#[unsafe(no_mangle)]
extern "C" fn kernel_abi_future_free(_allocation: crate::async_ffi::AbiFutureAllocation) {}
