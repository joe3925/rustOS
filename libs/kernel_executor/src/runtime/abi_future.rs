use core::{alloc::Layout, ptr::NonNull};
use kernel_types::async_ffi::AbiFutureAllocation;

use crate::future_allocation::FutureAllocation;

#[unsafe(no_mangle)]
pub extern "C" fn kernel_abi_future_allocate(size: usize, align: usize) -> AbiFutureAllocation {
    if size.max(1) > u32::MAX as usize || align.max(1) > u32::MAX as usize {
        return AbiFutureAllocation::null();
    }
    let Some(allocation) = FutureAllocation::allocate(size, align) else {
        return AbiFutureAllocation::null();
    };
    AbiFutureAllocation {
        ptr: allocation.ptr.as_ptr().cast(),
        reserved: [0; 2],
        capacity: allocation.layout.size() as u32,
        align: allocation.layout.align() as u32,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel_abi_future_free(allocation: AbiFutureAllocation) {
    unsafe {
        debug_assert_eq!(allocation.reserved, [0; 2]);
        debug_assert!(!allocation.ptr.is_null());
        debug_assert_ne!(allocation.capacity, 0);
        debug_assert!(
            Layout::from_size_align(allocation.capacity as usize, allocation.align as usize)
                .is_ok()
        );
        FutureAllocation {
            ptr: NonNull::new_unchecked(allocation.ptr.cast::<u8>()),
            layout: Layout::from_size_align_unchecked(
                allocation.capacity as usize,
                allocation.align as usize,
            ),
        }
        .release();
    }
}
