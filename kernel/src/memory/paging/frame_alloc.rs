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
    preserve_reclaimed_free_bits_limited, preserve_set_bits_limited, range_fits_bitmap, set_range,
    set_range_count_new, usable_region_bytes_below, BitmapResizeError, FrameBitmap,
};
use super::layout::base_page_size;
use super::types::MappingSize;

const WORD_BITS: usize = u64::BITS as usize;

static MEMORY_BITMAP: IrqSafeRwLock<FrameBitmap> = IrqSafeRwLock::new(FrameBitmap::new());
static RECLAIMED_MEMORY_BITMAP: IrqSafeRwLock<FrameBitmap> = IrqSafeRwLock::new(FrameBitmap::new());

static USED_MEMORY_BYTES: AtomicUsize = AtomicUsize::new(0);
static RECLAIMED_MEMORY_BYTES: AtomicUsize = AtomicUsize::new(0);
static BOOT_USABLE_BYTES_COVERED: AtomicUsize = AtomicUsize::new(0);
static BOOT_USABLE_BYTES_TOTAL: AtomicUsize = AtomicUsize::new(0);
static NEXT_WORD_BASE: AtomicUsize = AtomicUsize::new(0);
static NEXT_CONTIG_WORD_BASE: AtomicUsize = AtomicUsize::new(0);
static FRAME_SIZE_BYTES: AtomicUsize = AtomicUsize::new(0);
static LOW_RESERVED_FRAME_COUNT: AtomicUsize = AtomicUsize::new(0);

pub struct KernelFrameAllocator;

impl KernelFrameAllocator {
    pub fn init_from_boot_memory_map() {
        let memory_regions = &boot_info().memory_regions;
        init_from_memory_regions(memory_regions);
    }

    pub fn allocate_base_frame() -> Option<AbiPhysAddr> {
        let frame_size = cached_frame_size();
        let low_frames = cached_low_reserved_frames();
        let mut bm = MEMORY_BITMAP.write();
        let words = bm.word_len();
        let total_frames = bm.frame_capacity();
        if words == 0 {
            return None;
        }

        let start = NEXT_WORD_BASE.load(Ordering::Relaxed) % words;
        for step in 0..words {
            let word_idx = (start + step) % words;
            let mut free = !bm.as_slice()[word_idx];

            while free != 0 {
                let free_bit = free.trailing_zeros() as usize;
                let frame_idx = word_idx * WORD_BITS + free_bit;
                let bit = 1u64 << free_bit;

                if frame_idx >= total_frames || frame_idx < low_frames {
                    bm.as_mut_slice()[word_idx] |= bit;
                    free &= free - 1;
                    continue;
                }

                bm.as_mut_slice()[word_idx] |= bit;
                NEXT_WORD_BASE.store(word_idx, Ordering::Relaxed);
                USED_MEMORY_BYTES.fetch_add(frame_size as usize, Ordering::Relaxed);

                return Some(AbiPhysAddr::new((frame_idx as u64) * frame_size));
            }
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

        let frame_size = cached_frame_size();
        let low_frames = cached_low_reserved_frames();
        let mut bm = MEMORY_BITMAP.write();
        let total_words = bm.word_len();
        let total_frames = bm.frame_capacity();
        if total_words == 0 || frame_count > total_frames {
            return None;
        }

        let start_word = NEXT_CONTIG_WORD_BASE.load(Ordering::Relaxed) % total_words;
        for step in 0..total_words {
            let word_idx = (start_word + step) % total_words;
            let mut bit_idx = 0usize;

            loop {
                let free = !bm.as_slice()[word_idx] & (!0u64 << bit_idx);
                if free == 0 {
                    break;
                }

                let bit = free.trailing_zeros() as usize;
                let raw_idx = word_idx * WORD_BITS + bit;
                if raw_idx >= total_frames {
                    break;
                }

                let min_idx = core::cmp::max(raw_idx, low_frames);
                let start_idx = align_frame_index(min_idx, align_frames)?;
                if start_idx >= total_frames {
                    break;
                }

                let Some(end_idx) = start_idx.checked_add(frame_count) else {
                    return None;
                };
                if end_idx > total_frames {
                    break;
                }

                match first_set_bit_in_range(bm.as_slice(), start_idx, end_idx) {
                    None => {
                        set_range(bm.as_mut_slice(), start_idx, frame_count);
                        let next_word = (end_idx / WORD_BITS) % total_words;
                        NEXT_CONTIG_WORD_BASE.store(next_word, Ordering::Relaxed);
                        USED_MEMORY_BYTES.fetch_add(
                            frame_count.saturating_mul(frame_size as usize),
                            Ordering::Relaxed,
                        );
                        return Some(AbiPhysAddr::new((start_idx as u64) * frame_size));
                    }
                    Some(conflict_idx) => {
                        let next_scan_idx = conflict_idx.saturating_add(1);
                        if next_scan_idx >= total_frames {
                            break;
                        }

                        if next_scan_idx / WORD_BITS != word_idx {
                            break;
                        }

                        bit_idx = next_scan_idx & (WORD_BITS - 1);
                    }
                }
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

        if base_idx < cached_low_reserved_frames() {
            return;
        }

        let mut bm = MEMORY_BITMAP.write();
        if !range_fits_bitmap(&bm, base_idx, len) {
            return;
        }

        clear_range(bm.as_mut_slice(), base_idx, len);
        USED_MEMORY_BYTES.fetch_sub(
            len.saturating_mul(cached_frame_size() as usize),
            Ordering::Relaxed,
        );
    }

    pub fn release_reserved_mapping_frame(base: AbiPhysAddr, size: MappingSize) {
        let Some(len) = base_frame_count_for_mapping(size) else {
            return;
        };
        let Some(base_idx) = frame_index(base.as_u64()) else {
            return;
        };

        if base_idx < cached_low_reserved_frames() {
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
                    newly_reclaimed.saturating_mul(cached_frame_size() as usize),
                    Ordering::Relaxed,
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
                bytes: cached_frame_size(),
            },
        );
    }
}

pub fn init_from_memory_regions(memory_regions: &[MemoryRegion]) {
    let frame_size = base_page_size();
    let frame_size_usize = usize::try_from(frame_size).unwrap_or(usize::MAX);
    let low_frames = low_reserved_frames();

    FRAME_SIZE_BYTES.store(frame_size_usize, Ordering::Relaxed);
    LOW_RESERVED_FRAME_COUNT.store(low_frames, Ordering::Relaxed);

    let mut bm = MEMORY_BITMAP.write();
    bm.reset_to_boot_storage();
    bm.as_mut_slice().fill(u64::MAX);

    let max_frames = bm.frame_capacity();
    for region in memory_regions
        .iter()
        .filter(|r| r.kind == MemoryRegionKind::Usable)
    {
        let Some(start_frame) = div_ceil_u64(region.start, frame_size) else {
            continue;
        };
        let end_frame = region.end / frame_size;

        let start_frame = usize::try_from(start_frame)
            .map(|v| core::cmp::min(v, max_frames))
            .unwrap_or(max_frames);
        let end_frame = usize::try_from(end_frame)
            .map(|v| core::cmp::min(v, max_frames))
            .unwrap_or(max_frames);

        if end_frame > start_frame {
            clear_range(bm.as_mut_slice(), start_frame, end_frame - start_frame);
        }
    }

    if low_frames != 0 {
        set_range(bm.as_mut_slice(), 0, core::cmp::min(low_frames, max_frames));
    }

    mark_unused_tail_bits_allocated(bm.as_mut_slice(), max_frames);

    NEXT_WORD_BASE.store(0, Ordering::Relaxed);
    NEXT_CONTIG_WORD_BASE.store(0, Ordering::Relaxed);
    USED_MEMORY_BYTES.store(0, Ordering::Relaxed);
    RECLAIMED_MEMORY_BYTES.store(0, Ordering::Relaxed);

    let covered_phys = physical_bytes_for_frames(max_frames, frame_size);
    refresh_boot_usable_stats(memory_regions, covered_phys);

    let mut reclaimed = RECLAIMED_MEMORY_BITMAP.write();
    reclaimed.reset_to_boot_storage();
    reclaimed.as_mut_slice().fill(0);
    let cap = reclaimed.frame_capacity();
    clear_unused_tail_bits(reclaimed.as_mut_slice(), cap);
}

pub fn total_usable_bytes() -> u64 {
    BOOT_USABLE_BYTES_COVERED.load(Ordering::Relaxed) as u64
        + RECLAIMED_MEMORY_BYTES.load(Ordering::Relaxed) as u64
}

pub fn boot_usable_bytes() -> u64 {
    let cached = BOOT_USABLE_BYTES_TOTAL.load(Ordering::Relaxed);
    if cached != 0 {
        return cached as u64;
    }

    boot_info()
        .memory_regions
        .iter()
        .filter(|r| r.kind == MemoryRegionKind::Usable)
        .map(|r| r.end.saturating_sub(r.start))
        .sum()
}

pub fn used_bytes() -> u64 {
    USED_MEMORY_BYTES.load(Ordering::Relaxed) as u64
}

pub fn resize_bitmap_for_ram(total_ram_bytes: u64) -> Result<(), BitmapResizeError> {
    let memory_regions = &boot_info().memory_regions;
    let physical_coverage_bytes = physical_coverage_for_ram(memory_regions, total_ram_bytes)?;
    let (new_frames, new_words) = bitmap_layout_for_physical_coverage(physical_coverage_bytes)?;

    {
        let bm = MEMORY_BITMAP.read();
        if bm.frame_capacity() == new_frames && bm.word_len() == new_words {
            refresh_boot_usable_stats(memory_regions, physical_coverage_bytes);
            return Ok(());
        }
    }

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

        let common_frames = core::cmp::min(bm.frame_capacity(), new_frames);
        preserve_set_bits_limited(new_bitmap.as_mut_slice(), bm.as_slice(), common_frames);
        preserve_reclaimed_free_bits_limited(
            new_bitmap.as_mut_slice(),
            bm.as_slice(),
            reclaimed.as_slice(),
            common_frames,
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

        NEXT_WORD_BASE.store(0, Ordering::Relaxed);
        NEXT_CONTIG_WORD_BASE.store(0, Ordering::Relaxed);
        RECLAIMED_MEMORY_BYTES.store(
            reclaimed_frames.saturating_mul(cached_frame_size() as usize),
            Ordering::Relaxed,
        );
        refresh_boot_usable_stats(memory_regions, physical_coverage_bytes);
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

    let low_frames = cached_low_reserved_frames();
    if start_frame < low_frames {
        return true;
    }

    for frame_idx in start_frame..memory.frame_capacity() {
        if !bit_is_set(memory.as_slice(), frame_idx) {
            continue;
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

fn frame_range_is_boot_info_usable(base_idx: usize, len: usize) -> bool {
    let Some(end_idx) = base_idx.checked_add(len) else {
        return false;
    };
    let frame_size = cached_frame_size();
    let Some(base) = checked_frame_phys(base_idx, frame_size) else {
        return false;
    };
    let Some(end_excl) = checked_frame_phys(end_idx, frame_size) else {
        return false;
    };

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
    let frame_size = cached_frame_size();
    if size.bytes == 0 || size.bytes % frame_size != 0 {
        return None;
    }
    usize::try_from(size.bytes / frame_size).ok()
}

fn frame_index(phys: u64) -> Option<usize> {
    let frame_size = cached_frame_size();
    if phys % frame_size != 0 {
        return None;
    }
    usize::try_from(phys / frame_size).ok()
}

fn cached_frame_size() -> u64 {
    let cached = FRAME_SIZE_BYTES.load(Ordering::Relaxed);
    if cached != 0 {
        cached as u64
    } else {
        base_page_size()
    }
}

fn cached_low_reserved_frames() -> usize {
    let cached = LOW_RESERVED_FRAME_COUNT.load(Ordering::Relaxed);
    if cached != 0 {
        cached
    } else {
        low_reserved_frames()
    }
}

fn align_frame_index(index: usize, align: usize) -> Option<usize> {
    if align <= 1 {
        return Some(index);
    }

    let rem = index % align;
    if rem == 0 {
        Some(index)
    } else {
        index.checked_add(align - rem)
    }
}

fn checked_frame_phys(frame_idx: usize, frame_size: u64) -> Option<u64> {
    (frame_idx as u64).checked_mul(frame_size)
}

fn physical_bytes_for_frames(frames: usize, frame_size: u64) -> u64 {
    (frames as u64).saturating_mul(frame_size)
}

fn refresh_boot_usable_stats(memory_regions: &[MemoryRegion], covered_phys: u64) {
    let covered = memory_regions
        .iter()
        .filter(|r| r.kind == MemoryRegionKind::Usable)
        .map(|r| usable_region_bytes_below(r, covered_phys))
        .sum::<u64>();

    let total = memory_regions
        .iter()
        .filter(|r| r.kind == MemoryRegionKind::Usable)
        .map(|r| r.end.saturating_sub(r.start))
        .sum::<u64>();

    BOOT_USABLE_BYTES_COVERED.store(saturating_usize_from_u64(covered), Ordering::Relaxed);
    BOOT_USABLE_BYTES_TOTAL.store(saturating_usize_from_u64(total), Ordering::Relaxed);
}

fn saturating_usize_from_u64(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

fn div_ceil_u64(value: u64, divisor: u64) -> Option<u64> {
    if divisor == 0 {
        return None;
    }

    let add = divisor - 1;
    value.checked_add(add).map(|v| v / divisor)
}
