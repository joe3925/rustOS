pub mod allocator;
pub mod buddylocked;
#[cfg(feature = "allocator-mimalloc")]
pub mod mimalloc;

#[global_allocator]
pub static ALLOCATOR: KernelAllocator = KernelAllocator::new();

pub fn enable_mimalloc() {
    ALLOCATOR.enable_mimalloc();
}

pub fn mimalloc_thread_done() {
    ALLOCATOR.mimalloc_thread_done();
}

use crate::memory::heap::allocator::KernelAllocator;
#[cfg(feature = "allocator-mimalloc")]
use crate::memory::paging::frame_alloc::boot_usable_bytes;
use crate::memory::paging::{
    align_up_to_base_page, heap_range_end, heap_range_start, map_range,
};
#[cfg(feature = "allocator-mimalloc")]
use core::sync::atomic::{AtomicUsize, Ordering};
use kernel_types::arch::{PageFlags, VirtAddr};

#[cfg(feature = "allocator-buddy")]
pub const HEAP_SIZE: u64 = 4 * 1024 * 1024 * 1024;
pub const BOOTSTRAP_HEAP_SIZE: u64 = 64 * 1024 * 1024;

#[cfg(feature = "allocator-mimalloc")]
pub fn mimalloc_heap_start() -> usize {
    heap_range_start().as_u64() as usize + BOOTSTRAP_HEAP_SIZE as usize
}
// Minimum pre-arena space. The actual mimalloc OS allocator uses the entire
// pre-arena range because mimalloc uses it for normal segments, not just metadata.
#[cfg(feature = "allocator-mimalloc")]
pub const MIMALLOC_META_HEAP_SIZE: u64 = 64 * 1024 * 1024;
#[cfg(feature = "allocator-mimalloc")]
pub fn mimalloc_arena_start() -> usize {
    align_up_usize(
        mimalloc_heap_start() + MIMALLOC_META_HEAP_SIZE as usize,
        1024 * 1024 * 1024,
    )
}
#[cfg(feature = "allocator-mimalloc")]
pub fn mimalloc_os_heap_size() -> usize {
    mimalloc_arena_start() - mimalloc_heap_start()
}
#[cfg(feature = "allocator-mimalloc")]
pub fn mimalloc_upfront_heap_size() -> u64 {
    BOOTSTRAP_HEAP_SIZE + mimalloc_os_heap_size() as u64
}

#[cfg(feature = "allocator-mimalloc")]
static MIMALLOC_HEAP_RESERVED_BYTES: AtomicUsize = AtomicUsize::new(0);

const fn align_up_usize(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

#[cfg(feature = "allocator-mimalloc")]
pub fn mimalloc_heap_reserved_bytes() -> usize {
    MIMALLOC_HEAP_RESERVED_BYTES.load(Ordering::Acquire)
}

#[cfg(feature = "allocator-mimalloc")]
pub fn mimalloc_heap_end() -> usize {
    heap_range_start()
        .as_u64()
        .saturating_add(mimalloc_heap_reserved_bytes() as u64) as usize
}

#[cfg(feature = "allocator-mimalloc")]
pub fn mimalloc_arena_size() -> usize {
    mimalloc_heap_end().saturating_sub(mimalloc_arena_start())
}

pub fn heap_capacity_bytes() -> u64 {
    cfg_if::cfg_if! {
        if #[cfg(feature = "allocator-mimalloc")] {
            mimalloc_heap_reserved_bytes() as u64
        } else if #[cfg(feature = "allocator-buddy")] {
            HEAP_SIZE
        } else {
            0
        }
    }
}

pub(crate) fn init_heap() {
    let heap_start = VirtAddr::new(
        align_up_to_base_page(heap_range_start().as_u64())
            .expect("invalid platform base page size"),
    );
    let heap_limit = heap_range_end().as_u64();

    let heap_size = {
        cfg_if::cfg_if! {
            if #[cfg(feature = "allocator-mimalloc")] {
                let reserved_heap_size = align_up_to_base_page(boot_usable_bytes())
                    .expect("invalid platform base page size");
                let upfront_heap_size = align_up_to_base_page(mimalloc_upfront_heap_size())
                    .expect("invalid platform base page size");
                assert!(
                    reserved_heap_size >= upfront_heap_size,
                    "mimalloc heap reservation {} bytes is smaller than upfront heap commit {} bytes",
                    reserved_heap_size,
                    upfront_heap_size
                );
                assert!(
                    reserved_heap_size <= heap_limit - heap_start.as_u64(),
                    "mimalloc heap reservation {} bytes exceeds platform heap range {:#x}..{:#x}",
                    reserved_heap_size,
                    heap_start.as_u64(),
                    heap_limit
                );

                MIMALLOC_HEAP_RESERVED_BYTES.store(
                    usize::try_from(reserved_heap_size)
                        .expect("mimalloc heap reservation does not fit usize"),
                    Ordering::Release,
                );
                upfront_heap_size
            } else if #[cfg(feature = "allocator-buddy")] {
                let size = align_up_to_base_page(HEAP_SIZE)
                    .expect("invalid platform base page size");
                assert!(
                    size <= heap_limit - heap_start.as_u64(),
                    "buddy heap exceeds platform heap range"
                );
                size
            } else {
                0
            }
        }
    };

    let heap_end = heap_start + heap_size;

    let flags = PageFlags::PRESENT | PageFlags::WRITABLE;

    unsafe {
        map_range(heap_start.into(), heap_size, flags, false)
            .expect("Heap creation failed, can't recover")
    };
}
