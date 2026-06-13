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

use crate::arch::{
    paging::{PageSize, PageTableFlags, Size1GiB, Size2MiB},
    VirtAddr,
};
use crate::memory::heap::allocator::KernelAllocator;
#[cfg(feature = "allocator-mimalloc")]
use crate::memory::paging::frame_alloc::boot_usable_bytes;
use crate::memory::paging::frame_alloc::BootInfoFrameAllocator;
use crate::memory::paging::paging::{align_up_4k, map_range_with_huge_pages};
use crate::memory::paging::tables::init_mapper;
use crate::util::boot_info;
#[cfg(feature = "allocator-mimalloc")]
use core::sync::atomic::{AtomicUsize, Ordering};

pub const HEAP_START: usize = 0xFFFF_8600_0000_0000;
#[cfg(feature = "allocator-buddy")]
pub const HEAP_SIZE: u64 = Size1GiB::SIZE * 4;
pub const BOOTSTRAP_HEAP_SIZE: u64 = Size2MiB::SIZE * 32;

#[cfg(feature = "allocator-mimalloc")]
pub const MIMALLOC_HEAP_START: usize = HEAP_START + BOOTSTRAP_HEAP_SIZE as usize;
// Minimum pre-arena space. The actual mimalloc OS allocator uses the entire
// pre-arena range because mimalloc uses it for normal segments, not just metadata.
#[cfg(feature = "allocator-mimalloc")]
pub const MIMALLOC_META_HEAP_SIZE: u64 = 64 * 1024 * 1024;
#[cfg(feature = "allocator-mimalloc")]
pub const MIMALLOC_ARENA_START: usize = align_up_usize(
    MIMALLOC_HEAP_START + MIMALLOC_META_HEAP_SIZE as usize,
    Size1GiB::SIZE as usize,
);
#[cfg(feature = "allocator-mimalloc")]
pub const MIMALLOC_OS_HEAP_SIZE: u64 = (MIMALLOC_ARENA_START - MIMALLOC_HEAP_START) as u64;
#[cfg(feature = "allocator-mimalloc")]
pub const MIMALLOC_UPFRONT_HEAP_SIZE: u64 = BOOTSTRAP_HEAP_SIZE + MIMALLOC_OS_HEAP_SIZE;

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
    HEAP_START.saturating_add(mimalloc_heap_reserved_bytes())
}

#[cfg(feature = "allocator-mimalloc")]
pub fn mimalloc_arena_size() -> usize {
    mimalloc_heap_end().saturating_sub(MIMALLOC_ARENA_START)
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
    let heap_start = VirtAddr::new(align_up_4k(HEAP_START as u64));

    let heap_size = {
        cfg_if::cfg_if! {
            if #[cfg(feature = "allocator-mimalloc")] {
                let reserved_heap_size = align_up_4k(boot_usable_bytes());
                let upfront_heap_size = align_up_4k(MIMALLOC_UPFRONT_HEAP_SIZE);
                assert!(
                    reserved_heap_size >= upfront_heap_size,
                    "mimalloc heap reservation {} bytes is smaller than upfront heap commit {} bytes",
                    reserved_heap_size,
                    upfront_heap_size
                );

                MIMALLOC_HEAP_RESERVED_BYTES.store(
                    usize::try_from(reserved_heap_size)
                        .expect("mimalloc heap reservation does not fit usize"),
                    Ordering::Release,
                );
                upfront_heap_size
            } else if #[cfg(feature = "allocator-buddy")] {
                align_up_4k(HEAP_SIZE)
            } else {
                0
            }
        }
    };

    let heap_end = heap_start + heap_size;

    let boot_info = boot_info();
    let recursive_index = boot_info
        .recursive_index
        .into_option()
        .expect("missing recursive page-table mapping");
    let mut mapper = init_mapper(recursive_index);
    let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_regions);

    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;

    unsafe {
        map_range_with_huge_pages(
            &mut mapper,
            heap_start,
            heap_size,
            &mut frame_allocator,
            flags,
            false,
        )
        .expect("Heap creation failed, can't recover")
    };
}
