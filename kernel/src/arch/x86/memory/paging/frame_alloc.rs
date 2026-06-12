use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::{
    memory::paging::{
        constants::{
            BOOT_MEMORY_SIZE, FRAMES_PER_1G, FRAMES_PER_2M, LOW_FRAMES, WORDS_PER_1G, WORDS_PER_2M,
        },
        paging::num_frames_4k,
    },
    util::boot_info,
};
use kernel_abi::{MemoryRegion, MemoryRegionKind};
use kernel_types::irq::IrqSafeRwLock;
use spin::RwLock;
use x86_64::{
    PhysAddr,
    structures::paging::{FrameAllocator, PageSize, PhysFrame, Size1GiB, Size2MiB, Size4KiB},
};

const FRAME_SIZE: usize = 0x1000;
const BOOT_BITMAP_FRAMES: usize = num_frames_4k(BOOT_MEMORY_SIZE);
const BOOT_BITMAP_WORDS: usize = (BOOT_BITMAP_FRAMES + 63) / 64;

pub struct FrameBitmap {
    boot: [u64; BOOT_BITMAP_WORDS],
    heap: Option<Vec<u64>>,
    frames: usize,
    words: usize,
}

impl FrameBitmap {
    pub const fn new() -> Self {
        Self {
            boot: [0; BOOT_BITMAP_WORDS],
            heap: None,
            frames: BOOT_BITMAP_FRAMES,
            words: BOOT_BITMAP_WORDS,
        }
    }

    fn reset_to_boot_storage(&mut self) {
        self.heap = None;
        self.frames = BOOT_BITMAP_FRAMES;
        self.words = BOOT_BITMAP_WORDS;
    }

    fn replace_with_heap_storage(&mut self, storage: Vec<u64>, frames: usize) -> Option<Vec<u64>> {
        let old = self.heap.take();

        self.words = storage.len();
        self.frames = frames;
        self.heap = Some(storage);

        old
    }

    fn as_slice(&self) -> &[u64] {
        match self.heap.as_ref() {
            Some(heap) => heap.as_slice(),
            None => &self.boot[..self.words],
        }
    }

    fn as_mut_slice(&mut self) -> &mut [u64] {
        match self.heap.as_mut() {
            Some(heap) => heap.as_mut_slice(),
            None => &mut self.boot[..self.words],
        }
    }

    fn frame_capacity(&self) -> usize {
        self.frames
    }

    fn word_len(&self) -> usize {
        self.words
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitmapResizeError {
    ZeroRam,
    RamTooLarge,
    RamBelowLowFrames,
    AllocatedFramesWouldBeTruncated,
    AllocationFailed,
}

pub static MEMORY_BITMAP: IrqSafeRwLock<FrameBitmap> = IrqSafeRwLock::new(FrameBitmap::new());
static RECLAIMED_MEMORY_BITMAP: IrqSafeRwLock<FrameBitmap> = IrqSafeRwLock::new(FrameBitmap::new());

pub static USED_MEMORY: AtomicUsize = AtomicUsize::new(0);
static RECLAIMED_MEMORY_BYTES: AtomicUsize = AtomicUsize::new(0);

static NEXT_WORD_4K: AtomicUsize = AtomicUsize::new(0);
static NEXT_WORD_2M: AtomicUsize = AtomicUsize::new(0);
static NEXT_WORD_1G: AtomicUsize = AtomicUsize::new(0);

pub fn total_usable_bytes() -> u64 {
    let max_phys = {
        let bm = MEMORY_BITMAP.read();
        (bm.frame_capacity() as u64).saturating_mul(FRAME_SIZE as u64)
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

pub fn resize_bitmap_for_ram(total_ram_bytes: u64) -> Result<(), BitmapResizeError> {
    let physical_coverage_bytes = bitmap_physical_coverage_for_ram(total_ram_bytes)?;
    let (new_frames, new_words) = bitmap_layout_for_physical_coverage(physical_coverage_bytes)?;

    let mut new_bitmap = build_memory_bitmap(new_frames, new_words)?;
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

        NEXT_WORD_4K.store(0, Ordering::Release);
        NEXT_WORD_2M.store(0, Ordering::Release);
        NEXT_WORD_1G.store(0, Ordering::Release);
        RECLAIMED_MEMORY_BYTES.store(
            reclaimed_frames.saturating_mul(FRAME_SIZE),
            Ordering::Release,
        );
    }

    drop(old_bitmap_heap);
    drop(old_reclaimed_heap);

    Ok(())
}

fn bitmap_physical_coverage_for_ram(total_ram_bytes: u64) -> Result<u64, BitmapResizeError> {
    if total_ram_bytes == 0 {
        return Err(BitmapResizeError::ZeroRam);
    }

    let requested =
        align_up_u64(total_ram_bytes, FRAME_SIZE as u64).ok_or(BitmapResizeError::RamTooLarge)?;

    let map_top = boot_info()
        .memory_regions
        .iter()
        .filter(|r| r.end > r.start)
        .map(|r| r.end)
        .max()
        .unwrap_or(0);

    let map_top = align_up_u64(map_top, FRAME_SIZE as u64).ok_or(BitmapResizeError::RamTooLarge)?;

    Ok(core::cmp::max(requested, map_top))
}

fn bitmap_layout_for_physical_coverage(
    physical_coverage_bytes: u64,
) -> Result<(usize, usize), BitmapResizeError> {
    if physical_coverage_bytes == 0 {
        return Err(BitmapResizeError::ZeroRam);
    }

    let frames_u64 = physical_coverage_bytes / FRAME_SIZE as u64;
    let frames = usize::try_from(frames_u64).map_err(|_| BitmapResizeError::RamTooLarge)?;

    if frames < LOW_FRAMES {
        return Err(BitmapResizeError::RamBelowLowFrames);
    }

    let words = bitmap_words_for_frames(frames).ok_or(BitmapResizeError::RamTooLarge)?;
    Ok((frames, words))
}

fn align_up_u64(value: u64, align: u64) -> Option<u64> {
    if align == 0 || !align.is_power_of_two() {
        return None;
    }

    let mask = align - 1;
    value.checked_add(mask).map(|v| v & !mask)
}
#[derive(Clone)]
pub struct BootInfoFrameAllocator {}

impl BootInfoFrameAllocator {
    pub fn init_start(_memory_regions: &'static [MemoryRegion]) {
        let mut bm = MEMORY_BITMAP.write();
        bm.reset_to_boot_storage();

        for w in bm.as_mut_slice().iter_mut() {
            *w = u64::MAX;
        }

        let max_frames = bm.frame_capacity();
        for region in boot_info()
            .memory_regions
            .iter()
            .filter(|r| r.kind == MemoryRegionKind::Usable)
        {
            let start_frame = core::cmp::min((region.start >> 12) as usize, max_frames);
            let end_frame = core::cmp::min((region.end >> 12) as usize, max_frames);
            if end_frame > start_frame {
                clear_range(bm.as_mut_slice(), start_frame, end_frame - start_frame);
            }
        }

        if LOW_FRAMES != 0 {
            set_range(bm.as_mut_slice(), 0, core::cmp::min(LOW_FRAMES, max_frames));
        }

        mark_unused_tail_bits_allocated(bm.as_mut_slice(), max_frames);

        NEXT_WORD_4K.store(0, Ordering::Release);
        NEXT_WORD_2M.store(0, Ordering::Release);
        NEXT_WORD_1G.store(0, Ordering::Release);
        RECLAIMED_MEMORY_BYTES.store(0, Ordering::Release);

        let mut reclaimed = RECLAIMED_MEMORY_BITMAP.write();
        reclaimed.reset_to_boot_storage();
        for w in reclaimed.as_mut_slice().iter_mut() {
            *w = 0;
        }
        let cap = reclaimed.frame_capacity();
        clear_unused_tail_bits(reclaimed.as_mut_slice(), cap);
    }

    pub fn init(_memory_regions: &'static [MemoryRegion]) -> Self {
        BootInfoFrameAllocator {}
    }

    pub fn allocate_contiguous_frames_aligned(
        num_frames: usize,
        align_frames: usize,
    ) -> Option<PhysAddr> {
        if num_frames == 0 || align_frames == 0 {
            return None;
        }

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

            while bit_idx < 64 {
                if (word & (1 << bit_idx)) == 0 {
                    let mut start_idx = word_idx * 64 + bit_idx;

                    let remainder = start_idx % align_frames;
                    if remainder != 0 {
                        start_idx += align_frames - remainder;
                    }

                    let end_idx = start_idx.checked_add(num_frames)?;

                    if end_idx > total_frames {
                        return None;
                    }

                    match first_set_bit_in_range(bm.as_slice(), start_idx, end_idx) {
                        None => {
                            set_range(bm.as_mut_slice(), start_idx, num_frames);
                            return Some(PhysAddr::new((start_idx * FRAME_SIZE) as u64));
                        }
                        Some(conflict_idx) => {
                            let next_scan_idx = conflict_idx + 1;
                            word_idx = next_scan_idx / 64;
                            bit_idx = next_scan_idx % 64;
                            break;
                        }
                    }
                }
                bit_idx += 1;
            }

            if bit_idx == 64 {
                word_idx += 1;
                bit_idx = 0;
            }
        }

        None
    }

    pub fn allocate_contiguous_frames(num_frames: usize) -> Option<PhysAddr> {
        Self::allocate_contiguous_frames_aligned(num_frames, 1)
    }

    pub fn allocate_contiguous_2mib_frames(num_frames: usize) -> Option<PhysAddr> {
        let frames_4k = num_frames.checked_mul(FRAMES_PER_2M)?;
        let phys = Self::allocate_contiguous_frames_aligned(frames_4k, FRAMES_PER_2M)?;
        USED_MEMORY.fetch_add(num_frames * Size2MiB::SIZE as usize, Ordering::SeqCst);
        Some(phys)
    }

    pub fn deallocate_frame<S: PageSize>(&self, frame: PhysFrame<S>) {
        let base_idx = (frame.start_address().as_u64() >> 12) as usize;
        let (len, bytes_u64) = match S::SIZE {
            Size4KiB::SIZE => (1usize, 0x1000u64),
            Size2MiB::SIZE => (FRAMES_PER_2M, 0x20_0000u64),
            Size1GiB::SIZE => (FRAMES_PER_1G, 0x4000_0000u64),
            _ => return,
        };

        let mut bm = MEMORY_BITMAP.write();
        if !range_fits_bitmap(&bm, base_idx, len) {
            return;
        }

        clear_range(bm.as_mut_slice(), base_idx, len);
        USED_MEMORY.fetch_sub(bytes_u64 as usize, Ordering::SeqCst);
    }

    pub fn release_reserved_frame<S: PageSize>(&self, frame: PhysFrame<S>) {
        let base_idx = (frame.start_address().as_u64() >> 12) as usize;
        let len = match S::SIZE {
            Size4KiB::SIZE => 1usize,
            Size2MiB::SIZE => FRAMES_PER_2M,
            Size1GiB::SIZE => FRAMES_PER_1G,
            _ => return,
        };

        if base_idx < LOW_FRAMES {
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
                RECLAIMED_MEMORY_BYTES.fetch_add(newly_reclaimed * FRAME_SIZE, Ordering::SeqCst);
            }
        }

        clear_range(bm.as_mut_slice(), base_idx, len);
    }
}

unsafe impl FrameAllocator<Size4KiB> for BootInfoFrameAllocator {
    #[inline]
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        let mut bm = MEMORY_BITMAP.write();
        let words = bm.word_len();
        let total_frames = bm.frame_capacity();
        if words == 0 {
            return None;
        }

        let start = NEXT_WORD_4K.load(Ordering::Relaxed) % words;
        for step in 0..words {
            let word_idx = (start + step) % words;
            let word = bm.as_slice()[word_idx];
            if word == u64::MAX {
                continue;
            }

            let free_bit = (!word).trailing_zeros() as usize;
            let frame_idx = word_idx * 64 + free_bit;
            if frame_idx >= total_frames {
                break;
            }

            if frame_idx < LOW_FRAMES {
                set_bit(bm.as_mut_slice(), frame_idx);
                continue;
            }

            if !frame_range_is_usable(frame_idx, 1) {
                set_bit(bm.as_mut_slice(), frame_idx);
                continue;
            }

            set_bit(bm.as_mut_slice(), frame_idx);
            NEXT_WORD_4K.store(word_idx, Ordering::Relaxed);

            USED_MEMORY.fetch_add(FRAME_SIZE, Ordering::SeqCst);
            let phys = (frame_idx as u64) << 12;
            return Some(PhysFrame::containing_address(PhysAddr::new(phys)));
        }

        None
    }
}

unsafe impl FrameAllocator<Size2MiB> for BootInfoFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size2MiB>> {
        let mut bm = MEMORY_BITMAP.write();
        let words = bm.word_len();
        let total_frames = bm.frame_capacity();
        if words == 0 {
            return None;
        }

        let start = NEXT_WORD_2M.load(Ordering::Relaxed) % words;
        for step in 0..words {
            let word_idx = (start + step) % words;
            let word = bm.as_slice()[word_idx];
            if word == u64::MAX {
                continue;
            }

            let bit = (!word).trailing_zeros() as usize;
            let idx = word_idx * 64 + bit;
            if idx >= total_frames {
                break;
            }

            let base = idx & !(FRAMES_PER_2M - 1);
            let end = match base.checked_add(FRAMES_PER_2M) {
                Some(v) => v,
                None => break,
            };
            if end > total_frames {
                break;
            }

            if base < LOW_FRAMES {
                set_bit(bm.as_mut_slice(), idx);
                continue;
            }

            if !frame_range_is_usable(base, FRAMES_PER_2M) {
                set_bit(bm.as_mut_slice(), idx);
                continue;
            }

            let start_w = base / 64;
            if start_w + WORDS_PER_2M > words {
                break;
            }

            let mut all_free = true;
            for w in &bm.as_slice()[start_w..start_w + WORDS_PER_2M] {
                if *w != 0 {
                    all_free = false;
                    break;
                }
            }
            if !all_free {
                continue;
            }

            for w in &mut bm.as_mut_slice()[start_w..start_w + WORDS_PER_2M] {
                *w = u64::MAX;
            }

            NEXT_WORD_2M.store(start_w + WORDS_PER_2M, Ordering::Relaxed);

            USED_MEMORY.fetch_add(0x20_0000, Ordering::SeqCst);
            let phys = (base as u64) << 12;
            return Some(PhysFrame::containing_address(PhysAddr::new(phys)));
        }
        None
    }
}

unsafe impl FrameAllocator<Size1GiB> for BootInfoFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size1GiB>> {
        let mut bm = MEMORY_BITMAP.write();
        let words = bm.word_len();
        let total_frames = bm.frame_capacity();
        if words == 0 {
            return None;
        }

        let start = NEXT_WORD_1G.load(Ordering::Relaxed) % words;
        for step in 0..words {
            let word_idx = (start + step) % words;
            let word = bm.as_slice()[word_idx];
            if word == u64::MAX {
                continue;
            }

            let bit = (!word).trailing_zeros() as usize;
            let idx = word_idx * 64 + bit;
            if idx >= total_frames {
                break;
            }

            let base = idx & !(FRAMES_PER_1G - 1);
            let end = match base.checked_add(FRAMES_PER_1G) {
                Some(v) => v,
                None => break,
            };
            if end > total_frames {
                break;
            }

            if base < LOW_FRAMES {
                set_bit(bm.as_mut_slice(), idx);
                continue;
            }

            if !frame_range_is_usable(base, FRAMES_PER_1G) {
                set_bit(bm.as_mut_slice(), idx);
                continue;
            }

            let start_w = base / 64;
            if start_w + WORDS_PER_1G > words {
                break;
            }

            let mut all_free = true;
            for w in &bm.as_slice()[start_w..start_w + WORDS_PER_1G] {
                if *w != 0 {
                    all_free = false;
                    break;
                }
            }
            if !all_free {
                continue;
            }

            for w in &mut bm.as_mut_slice()[start_w..start_w + WORDS_PER_1G] {
                *w = u64::MAX;
            }

            NEXT_WORD_1G.store(start_w + WORDS_PER_1G, Ordering::Relaxed);

            USED_MEMORY.fetch_add(0x4000_0000, Ordering::SeqCst);
            let phys = (base as u64) << 12;
            return Some(PhysFrame::containing_address(PhysAddr::new(phys)));
        }
        None
    }
}

fn bitmap_layout_for_ram(total_ram_bytes: u64) -> Result<(usize, usize), BitmapResizeError> {
    let frames_u64 = total_ram_bytes / FRAME_SIZE as u64;
    if frames_u64 == 0 {
        return Err(BitmapResizeError::ZeroRam);
    }

    let frames = usize::try_from(frames_u64).map_err(|_| BitmapResizeError::RamTooLarge)?;
    if frames < LOW_FRAMES {
        return Err(BitmapResizeError::RamBelowLowFrames);
    }

    let words = bitmap_words_for_frames(frames).ok_or(BitmapResizeError::RamTooLarge)?;
    Ok((frames, words))
}

fn bitmap_words_for_frames(frames: usize) -> Option<usize> {
    frames.checked_add(63).map(|v| v / 64)
}

fn heap_bitmap(words: usize, fill: u64) -> Result<Vec<u64>, BitmapResizeError> {
    let mut bitmap = Vec::new();

    bitmap
        .try_reserve_exact(words)
        .map_err(|_| BitmapResizeError::AllocationFailed)?;

    bitmap.resize(words, fill);
    Ok(bitmap)
}

fn build_memory_bitmap(frames: usize, words: usize) -> Result<Vec<u64>, BitmapResizeError> {
    let mut bitmap = heap_bitmap(words, u64::MAX)?;

    for region in boot_info()
        .memory_regions
        .iter()
        .filter(|r| r.kind == MemoryRegionKind::Usable)
    {
        let start_frame =
            div_ceil_u64(region.start, FRAME_SIZE as u64).ok_or(BitmapResizeError::RamTooLarge)?;

        let end_frame = region.end / FRAME_SIZE as u64;

        let start_frame = usize::try_from(start_frame)
            .map(|v| core::cmp::min(v, frames))
            .map_err(|_| BitmapResizeError::RamTooLarge)?;

        let end_frame = usize::try_from(end_frame)
            .map(|v| core::cmp::min(v, frames))
            .map_err(|_| BitmapResizeError::RamTooLarge)?;

        if end_frame > start_frame {
            clear_range(bitmap.as_mut_slice(), start_frame, end_frame - start_frame);
        }
    }

    if LOW_FRAMES != 0 {
        set_range(bitmap.as_mut_slice(), 0, core::cmp::min(LOW_FRAMES, frames));
    }

    mark_unused_tail_bits_allocated(bitmap.as_mut_slice(), frames);
    Ok(bitmap)
}

fn div_ceil_u64(value: u64, divisor: u64) -> Option<u64> {
    if divisor == 0 {
        return None;
    }

    let add = divisor - 1;
    value.checked_add(add).map(|v| v / divisor)
}
fn usable_region_bytes_below(region: &MemoryRegion, max_phys: u64) -> u64 {
    if region.start >= max_phys {
        return 0;
    }

    let end = core::cmp::min(region.end, max_phys);
    end.saturating_sub(region.start)
}

fn range_fits_bitmap(bitmap: &FrameBitmap, start: usize, len: usize) -> bool {
    let Some(end) = start.checked_add(len) else {
        return false;
    };
    end <= bitmap.frame_capacity()
}

fn preserve_set_bits_limited(dst: &mut [u64], src: &[u64], frames: usize) {
    let full_words = frames / 64;
    let common_full_words = core::cmp::min(full_words, core::cmp::min(dst.len(), src.len()));

    for idx in 0..common_full_words {
        dst[idx] |= src[idx];
    }

    let rem = frames & 63;
    if rem == 0 {
        return;
    }

    if full_words >= dst.len() || full_words >= src.len() {
        return;
    }

    dst[full_words] |= src[full_words] & low_bits_mask(rem);
}

fn count_set_bits_up_to(bitmap: &[u64], frames: usize) -> usize {
    if frames == 0 || bitmap.is_empty() {
        return 0;
    }

    let full_words = core::cmp::min(frames / 64, bitmap.len());
    let mut count = 0usize;

    for word in &bitmap[..full_words] {
        count += word.count_ones() as usize;
    }

    let rem = frames & 63;
    if rem != 0 && full_words < bitmap.len() {
        count += (bitmap[full_words] & low_bits_mask(rem)).count_ones() as usize;
    }

    count
}

fn allocated_usable_frame_exists_at_or_above(
    memory: &FrameBitmap,
    reclaimed: &FrameBitmap,
    start_frame: usize,
) -> bool {
    if start_frame >= memory.frame_capacity() {
        return false;
    }

    for frame_idx in start_frame..memory.frame_capacity() {
        if !bit_is_set(memory.as_slice(), frame_idx) {
            continue;
        }

        if frame_idx < LOW_FRAMES {
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
    let base = (base_idx as u64) << 12;
    let end_excl = (base_idx.saturating_add(len) as u64) << 12;

    boot_info().memory_regions.iter().any(|r| {
        if r.kind != MemoryRegionKind::Usable {
            return false;
        }
        let rs = r.start;
        let re = r.end;
        base >= rs && end_excl <= re
    })
}

fn frame_is_boot_info_usable(frame_idx: usize) -> bool {
    frame_range_is_boot_info_usable(frame_idx, 1)
}

fn set_bit(bitmap: &mut [u64], idx: usize) {
    let w = idx / 64;
    let b = idx & 63;
    if w >= bitmap.len() {
        return;
    }
    bitmap[w] |= 1u64 << b;
}

fn bit_is_set(bitmap: &[u64], idx: usize) -> bool {
    let w = idx / 64;
    let b = idx & 63;
    w < bitmap.len() && (bitmap[w] & (1u64 << b)) != 0
}

fn set_range(bitmap: &mut [u64], start: usize, len: usize) {
    if len == 0 {
        return;
    }

    let words = bitmap.len();
    if words == 0 {
        return;
    }

    if start / 64 >= words {
        return;
    }

    let end_incl = start + len - 1;
    let max_bit = words * 64 - 1;
    let end_incl = core::cmp::min(end_incl, max_bit);

    let first_word = start / 64;
    let last_word = end_incl / 64;

    if first_word == last_word {
        let mask = ((!0u64) << (start & 63)) & ((!0u64) >> (63 - (end_incl & 63)));
        bitmap[first_word] |= mask;
        return;
    }

    bitmap[first_word] |= !0u64 << (start & 63);

    for w in (first_word + 1)..last_word {
        bitmap[w] = !0u64;
    }

    bitmap[last_word] |= !0u64 >> (63 - (end_incl & 63));
}

fn clear_range(bitmap: &mut [u64], start: usize, len: usize) {
    if len == 0 {
        return;
    }

    let words = bitmap.len();
    if words == 0 {
        return;
    }

    if start / 64 >= words {
        return;
    }

    let end_incl = start + len - 1;
    let max_bit = words * 64 - 1;
    let end_incl = core::cmp::min(end_incl, max_bit);

    let first_word = start / 64;
    let last_word = end_incl / 64;

    if first_word == last_word {
        let mask = ((!0u64) << (start & 63)) & ((!0u64) >> (63 - (end_incl & 63)));
        bitmap[first_word] &= !mask;
        return;
    }

    bitmap[first_word] &= !(!0u64 << (start & 63));

    for w in (first_word + 1)..last_word {
        bitmap[w] = 0;
    }

    bitmap[last_word] &= !(!0u64 >> (63 - (end_incl & 63)));
}

fn set_range_count_new(
    bitmap: &mut [u64],
    frame_capacity: usize,
    start: usize,
    len: usize,
) -> usize {
    if len == 0 || start >= frame_capacity {
        return 0;
    }

    let end = start.saturating_add(len).min(frame_capacity);
    let mut new_bits = 0usize;

    for idx in start..end {
        let w = idx / 64;
        let b = idx & 63;
        if w >= bitmap.len() {
            break;
        }

        let mask = 1u64 << b;
        if bitmap[w] & mask == 0 {
            bitmap[w] |= mask;
            new_bits += 1;
        }
    }

    new_bits
}

fn range_all_set(bitmap: &[u64], frame_capacity: usize, start: usize, len: usize) -> bool {
    if len == 0 {
        return true;
    }

    let Some(end) = start.checked_add(len) else {
        return false;
    };
    if end > frame_capacity {
        return false;
    }

    for idx in start..end {
        let w = idx / 64;
        let b = idx & 63;
        if w >= bitmap.len() || bitmap[w] & (1u64 << b) == 0 {
            return false;
        }
    }

    true
}

fn first_set_bit_in_range(bitmap: &[u64], start: usize, end: usize) -> Option<usize> {
    if start >= end {
        return None;
    }
    let total_bits = bitmap.len() * 64;
    let end = end.min(total_bits);
    if start >= end {
        return None;
    }

    let first_word = start / 64;
    let last_word = (end - 1) / 64;
    let start_bit = start & 63;

    if first_word == last_word {
        let last_bit = (end - 1) & 63;
        let mask = (!0u64 << start_bit) & (!0u64 >> (63 - last_bit));
        let word = bitmap[first_word] & mask;
        return if word != 0 {
            Some(first_word * 64 + word.trailing_zeros() as usize)
        } else {
            None
        };
    }

    let word = bitmap[first_word] & (!0u64 << start_bit);
    if word != 0 {
        return Some(first_word * 64 + word.trailing_zeros() as usize);
    }

    for w in (first_word + 1)..last_word {
        let word = bitmap[w];
        if word != 0 {
            return Some(w * 64 + word.trailing_zeros() as usize);
        }
    }

    let last_bit = (end - 1) & 63;
    let word = bitmap[last_word] & (!0u64 >> (63 - last_bit));
    if word != 0 {
        Some(last_word * 64 + word.trailing_zeros() as usize)
    } else {
        None
    }
}

fn low_bits_mask(bits: usize) -> u64 {
    if bits == 0 {
        0
    } else if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

fn mark_unused_tail_bits_allocated(bitmap: &mut [u64], frames: usize) {
    if bitmap.is_empty() {
        return;
    }

    let rem = frames & 63;
    if rem == 0 {
        return;
    }

    let last_word = frames / 64;
    if last_word < bitmap.len() {
        bitmap[last_word] |= !low_bits_mask(rem);
    }
}

fn clear_unused_tail_bits(bitmap: &mut [u64], frames: usize) {
    if bitmap.is_empty() {
        return;
    }

    let rem = frames & 63;
    if rem == 0 {
        return;
    }

    let last_word = frames / 64;
    if last_word < bitmap.len() {
        bitmap[last_word] &= low_bits_mask(rem);
    }
}
