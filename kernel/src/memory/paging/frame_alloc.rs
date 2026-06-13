use core::sync::atomic::{AtomicUsize, Ordering};

use kernel_abi::{MemoryRegion, MemoryRegionKind};
use kernel_types::arch::PhysAddr as AbiPhysAddr;
use kernel_types::irq::IrqSafeRwLock;

use crate::platform::PageTableFrameAllocator;
use crate::util::boot_info;

use super::frame_bitmap::{
    bit_is_set, bitmap_layout_for_physical_coverage, build_memory_bitmap, clear_range,
    clear_unused_tail_bits, count_set_bits_up_to, first_set_bit_in_range, heap_bitmap,
    low_reserved_frames, mark_unused_tail_bits_allocated, physical_coverage_for_ram,
    preserve_set_bits_limited, range_all_set, range_fits_bitmap, set_bit, set_range,
    set_range_count_new, usable_region_bytes_below, BitmapResizeError, FrameBitmap,
};
use super::layout::base_page_size;
use super::types::MappingSize;

static MEMORY_BITMAP: IrqSafeRwLock<FrameBitmap> = IrqSafeRwLock::new(FrameBitmap::new());
static RECLAIMED_MEMORY_BITMAP: IrqSafeRwLock<FrameBitmap> = IrqSafeRwLock::new(FrameBitmap::new());

static USED_MEMORY_BYTES: AtomicUsize = AtomicUsize::new(0);
static RECLAIMED_MEMORY_BYTES: AtomicUsize = AtomicUsize::new(0);
static NEXT_WORD_BASE: AtomicUsize = AtomicUsize::new(0);

pub struct KernelFrameAllocator;

impl KernelFrameAllocator {
    pub fn init_from_boot_memory_map() {
        let memory_regions = &boot_info().memory_regions;
        init_from_memory_regions(memory_regions);
    }

    pub fn allocate_base_frame() -> Option<AbiPhysAddr> {
        let frame_size = base_page_size();
        let mut bm = MEMORY_BITMAP.write();
        let words = bm.word_len();
        let total_frames = bm.frame_capacity();
        if words == 0 {
            return None;
        }

        let low_frames = low_reserved_frames();
        let start = NEXT_WORD_BASE.load(Ordering::Relaxed) % words;
        for step in 0..words {
            let word_idx = (start + step) % words;
            let word = bm.as_slice()[word_idx];
            if word == u64::MAX {
                continue;
            }

            let free_bit = (!word).trailing_zeros() as usize;
            let frame_idx = word_idx * u64::BITS as usize + free_bit;
            if frame_idx >= total_frames {
                break;
            }

            if frame_idx < low_frames {
                set_bit(bm.as_mut_slice(), frame_idx);
                continue;
            }

            if !frame_range_is_usable(frame_idx, 1) {
                set_bit(bm.as_mut_slice(), frame_idx);
                continue;
            }

            set_bit(bm.as_mut_slice(), frame_idx);
            NEXT_WORD_BASE.store(word_idx, Ordering::Relaxed);

            USED_MEMORY_BYTES.fetch_add(frame_size as usize, Ordering::SeqCst);
            return Some(AbiPhysAddr::new((frame_idx as u64) * frame_size));
        }

        None
    }

    pub fn allocate_mapping_frame(size: MappingSize) -> Option<AbiPhysAddr> {
        let frame_count = base_frame_count_for_mapping(size)?;
        Self::allocate_contiguous_frames_aligned(frame_count, frame_count)
    }

    pub fn allocate_contiguous_frames_aligned(
        frame_count: usize,
        align_frames: usize,
    ) -> Option<AbiPhysAddr> {
        if frame_count == 0 || align_frames == 0 {
            return None;
        }

        let frame_size = base_page_size();
        let low_frames = low_reserved_frames();
        let mut bm = MEMORY_BITMAP.write();
        let total_words = bm.word_len();
        let total_frames = bm.frame_capacity();

        let mut word_idx = 0;
        let mut bit_idx = 0;

        while word_idx < total_words {
            let word = bm.as_slice()[word_idx];

            if word == u64::MAX {
                word_idx += 1;
                bit_idx = 0;
                continue;
            }

            while bit_idx < u64::BITS as usize {
                if (word & (1 << bit_idx)) == 0 {
                    let mut start_idx = word_idx * u64::BITS as usize + bit_idx;

                    let remainder = start_idx % align_frames;
                    if remainder != 0 {
                        start_idx += align_frames - remainder;
                    }

                    if start_idx < low_frames {
                        start_idx = low_frames;
                        let remainder = start_idx % align_frames;
                        if remainder != 0 {
                            start_idx += align_frames - remainder;
                        }
                    }

                    let end_idx = start_idx.checked_add(frame_count)?;

                    if end_idx > total_frames {
                        return None;
                    }

                    if !frame_range_is_usable(start_idx, frame_count) {
                        let next_scan_idx = start_idx.saturating_add(1);
                        word_idx = next_scan_idx / u64::BITS as usize;
                        bit_idx = next_scan_idx % u64::BITS as usize;
                        break;
                    }

                    match first_set_bit_in_range(bm.as_slice(), start_idx, end_idx) {
                        None => {
                            set_range(bm.as_mut_slice(), start_idx, frame_count);
                            USED_MEMORY_BYTES.fetch_add(
                                frame_count.saturating_mul(frame_size as usize),
                                Ordering::SeqCst,
                            );
                            return Some(AbiPhysAddr::new((start_idx as u64) * frame_size));
                        }
                        Some(conflict_idx) => {
                            let next_scan_idx = conflict_idx + 1;
                            word_idx = next_scan_idx / u64::BITS as usize;
                            bit_idx = next_scan_idx % u64::BITS as usize;
                            break;
                        }
                    }
                }
                bit_idx += 1;
            }

            if bit_idx == u64::BITS as usize {
                word_idx += 1;
                bit_idx = 0;
            }
        }

        None
    }

    pub fn free_mapping_frame(base: AbiPhysAddr, size: MappingSize) {
        let Some(len) = base_frame_count_for_mapping(size) else {
            return;
        };
        let Some(base_idx) = frame_index(base.as_u64()) else {
            return;
        };

        let mut bm = MEMORY_BITMAP.write();
        if !range_fits_bitmap(&bm, base_idx, len) {
            return;
        }

        clear_range(bm.as_mut_slice(), base_idx, len);
        USED_MEMORY_BYTES.fetch_sub(size.bytes as usize, Ordering::SeqCst);
    }

    pub fn release_reserved_mapping_frame(base: AbiPhysAddr, size: MappingSize) {
        let Some(len) = base_frame_count_for_mapping(size) else {
            return;
        };
        let Some(base_idx) = frame_index(base.as_u64()) else {
            return;
        };

        if base_idx < low_reserved_frames() {
            return;
        }

        let mut bm = MEMORY_BITMAP.write();
        if !range_fits_bitmap(&bm, base_idx, len) {
            return;
        }

        if !frame_range_is_boot_info_usable(base_idx, len) {
            let mut reclaimed = RECLAIMED_MEMORY_BITMAP.write();
            let reclaimed_frames = reclaimed.frame_capacity();
            let newly_reclaimed =
                set_range_count_new(reclaimed.as_mut_slice(), reclaimed_frames, base_idx, len);
            if newly_reclaimed != 0 {
                RECLAIMED_MEMORY_BYTES.fetch_add(
                    newly_reclaimed.saturating_mul(base_page_size() as usize),
                    Ordering::SeqCst,
                );
            }
        }

        clear_range(bm.as_mut_slice(), base_idx, len);
    }

    pub fn total_usable_bytes() -> u64 {
        total_usable_bytes()
    }

    pub fn used_bytes() -> u64 {
        used_bytes()
    }
}

pub struct KernelPageTableFrameAllocator;

impl PageTableFrameAllocator for KernelPageTableFrameAllocator {
    fn allocate_page_table_frame(&mut self) -> Option<AbiPhysAddr> {
        KernelFrameAllocator::allocate_base_frame()
    }

    fn free_page_table_frame(&mut self, phys: AbiPhysAddr) {
        KernelFrameAllocator::free_mapping_frame(
            phys,
            MappingSize {
                bytes: base_page_size(),
            },
        );
    }
}

pub fn init_from_memory_regions(memory_regions: &[MemoryRegion]) {
    let mut bm = MEMORY_BITMAP.write();
    bm.reset_to_boot_storage();

    for word in bm.as_mut_slice().iter_mut() {
        *word = u64::MAX;
    }

    let frame_size = base_page_size();
    let max_frames = bm.frame_capacity();
    for region in memory_regions
        .iter()
        .filter(|r| r.kind == MemoryRegionKind::Usable)
    {
        let start_frame = core::cmp::min((region.start / frame_size) as usize, max_frames);
        let end_frame = core::cmp::min((region.end / frame_size) as usize, max_frames);
        if end_frame > start_frame {
            clear_range(bm.as_mut_slice(), start_frame, end_frame - start_frame);
        }
    }

    let low_frames = low_reserved_frames();
    if low_frames != 0 {
        set_range(bm.as_mut_slice(), 0, core::cmp::min(low_frames, max_frames));
    }

    mark_unused_tail_bits_allocated(bm.as_mut_slice(), max_frames);

    NEXT_WORD_BASE.store(0, Ordering::Release);
    RECLAIMED_MEMORY_BYTES.store(0, Ordering::Release);

    let mut reclaimed = RECLAIMED_MEMORY_BITMAP.write();
    reclaimed.reset_to_boot_storage();
    for word in reclaimed.as_mut_slice().iter_mut() {
        *word = 0;
    }
    let cap = reclaimed.frame_capacity();
    clear_unused_tail_bits(reclaimed.as_mut_slice(), cap);
}

pub fn total_usable_bytes() -> u64 {
    let max_phys = {
        let bm = MEMORY_BITMAP.read();
        (bm.frame_capacity() as u64).saturating_mul(base_page_size())
    };

    let boot_usable: u64 = boot_info()
        .memory_regions
        .iter()
        .filter(|r| r.kind == MemoryRegionKind::Usable)
        .map(|r| usable_region_bytes_below(r, max_phys))
        .sum();

    boot_usable + RECLAIMED_MEMORY_BYTES.load(Ordering::Acquire) as u64
}

pub fn boot_usable_bytes() -> u64 {
    boot_info()
        .memory_regions
        .iter()
        .filter(|r| r.kind == MemoryRegionKind::Usable)
        .map(|r| r.end.saturating_sub(r.start))
        .sum()
}

pub fn used_bytes() -> u64 {
    USED_MEMORY_BYTES.load(Ordering::Acquire) as u64
}

pub fn resize_bitmap_for_ram(total_ram_bytes: u64) -> Result<(), BitmapResizeError> {
    let memory_regions = &boot_info().memory_regions;
    let physical_coverage_bytes = physical_coverage_for_ram(memory_regions, total_ram_bytes)?;
    let (new_frames, new_words) = bitmap_layout_for_physical_coverage(physical_coverage_bytes)?;

    let mut new_bitmap = build_memory_bitmap(memory_regions, new_frames, new_words)?;
    let mut new_reclaimed = heap_bitmap(new_words, 0)?;

    let old_bitmap_heap;
    let old_reclaimed_heap;

    {
        let mut bm = MEMORY_BITMAP.write();
        let mut reclaimed = RECLAIMED_MEMORY_BITMAP.write();

        if allocated_usable_frame_exists_at_or_above(&bm, &reclaimed, new_frames) {
            return Err(BitmapResizeError::AllocatedFramesWouldBeTruncated);
        }

        preserve_set_bits_limited(
            new_bitmap.as_mut_slice(),
            bm.as_slice(),
            core::cmp::min(bm.frame_capacity(), new_frames),
        );
        mark_unused_tail_bits_allocated(new_bitmap.as_mut_slice(), new_frames);

        preserve_set_bits_limited(
            new_reclaimed.as_mut_slice(),
            reclaimed.as_slice(),
            core::cmp::min(reclaimed.frame_capacity(), new_frames),
        );
        clear_unused_tail_bits(new_reclaimed.as_mut_slice(), new_frames);

        let reclaimed_frames = count_set_bits_up_to(new_reclaimed.as_slice(), new_frames);

        old_bitmap_heap = bm.replace_with_heap_storage(new_bitmap, new_frames);
        old_reclaimed_heap = reclaimed.replace_with_heap_storage(new_reclaimed, new_frames);

        NEXT_WORD_BASE.store(0, Ordering::Release);
        RECLAIMED_MEMORY_BYTES.store(
            reclaimed_frames.saturating_mul(base_page_size() as usize),
            Ordering::Release,
        );
    }

    drop(old_bitmap_heap);
    drop(old_reclaimed_heap);

    Ok(())
}

fn allocated_usable_frame_exists_at_or_above(
    memory: &FrameBitmap,
    reclaimed: &FrameBitmap,
    start_frame: usize,
) -> bool {
    if start_frame >= memory.frame_capacity() {
        return false;
    }

    let low_frames = low_reserved_frames();
    for frame_idx in start_frame..memory.frame_capacity() {
        if !bit_is_set(memory.as_slice(), frame_idx) {
            continue;
        }

        if frame_idx < low_frames {
            return true;
        }

        if frame_is_boot_info_usable(frame_idx) {
            return true;
        }

        if frame_idx < reclaimed.frame_capacity() && bit_is_set(reclaimed.as_slice(), frame_idx) {
            return true;
        }
    }

    false
}

fn frame_range_is_usable(base_idx: usize, len: usize) -> bool {
    if frame_range_is_boot_info_usable(base_idx, len) {
        return true;
    }

    let reclaimed = RECLAIMED_MEMORY_BITMAP.read();
    range_all_set(
        reclaimed.as_slice(),
        reclaimed.frame_capacity(),
        base_idx,
        len,
    )
}

fn frame_range_is_boot_info_usable(base_idx: usize, len: usize) -> bool {
    let frame_size = base_page_size();
    let base = (base_idx as u64).saturating_mul(frame_size);
    let end_excl = (base_idx.saturating_add(len) as u64).saturating_mul(frame_size);

    boot_info().memory_regions.iter().any(|region| {
        if region.kind != MemoryRegionKind::Usable {
            return false;
        }
        base >= region.start && end_excl <= region.end
    })
}

fn frame_is_boot_info_usable(frame_idx: usize) -> bool {
    frame_range_is_boot_info_usable(frame_idx, 1)
}

fn base_frame_count_for_mapping(size: MappingSize) -> Option<usize> {
    let frame_size = base_page_size();
    if size.bytes == 0 || size.bytes % frame_size != 0 {
        return None;
    }
    usize::try_from(size.bytes / frame_size).ok()
}

fn frame_index(phys: u64) -> Option<usize> {
    let frame_size = base_page_size();
    if phys % frame_size != 0 {
        return None;
    }
    usize::try_from(phys / frame_size).ok()
}
