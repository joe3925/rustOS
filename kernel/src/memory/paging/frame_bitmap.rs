use alloc::vec::Vec;

use kernel_abi::{MemoryRegion, MemoryRegionKind};

use super::layout::{align_up, base_page_size, low_physical_reserve_bytes};

const EARLY_BOOT_BITMAP_STORAGE_BYTES: usize = 128 * 1024;
const EARLY_BOOT_FRAME_BITMAP_WORDS: usize =
    EARLY_BOOT_BITMAP_STORAGE_BYTES / core::mem::size_of::<u64>();
const WORD_BITS: usize = u64::BITS as usize;

const fn early_boot_frame_capacity() -> usize {
    EARLY_BOOT_FRAME_BITMAP_WORDS * WORD_BITS
}

pub struct FrameBitmap {
    boot: [u64; EARLY_BOOT_FRAME_BITMAP_WORDS],
    heap: Option<Vec<u64>>,
    frames: usize,
    words: usize,
}

impl FrameBitmap {
    pub const fn new() -> Self {
        Self {
            boot: [0; EARLY_BOOT_FRAME_BITMAP_WORDS],
            heap: None,
            frames: early_boot_frame_capacity(),
            words: EARLY_BOOT_FRAME_BITMAP_WORDS,
        }
    }

    pub fn reset_to_boot_storage(&mut self) {
        self.heap = None;
        self.frames = early_boot_frame_capacity();
        self.words = EARLY_BOOT_FRAME_BITMAP_WORDS;
    }

    pub fn replace_with_heap_storage(
        &mut self,
        storage: Vec<u64>,
        frames: usize,
    ) -> Option<Vec<u64>> {
        let old = self.heap.take();

        self.words = storage.len();
        self.frames = frames;
        self.heap = Some(storage);

        old
    }

    pub fn as_slice(&self) -> &[u64] {
        match self.heap.as_ref() {
            Some(heap) => heap.as_slice(),
            None => &self.boot[..self.words],
        }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u64] {
        match self.heap.as_mut() {
            Some(heap) => heap.as_mut_slice(),
            None => &mut self.boot[..self.words],
        }
    }

    pub fn frame_capacity(&self) -> usize {
        self.frames
    }

    pub fn word_len(&self) -> usize {
        self.words
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitmapResizeError {
    ZeroRam,
    RamTooLarge,
    RamBelowLowReserve,
    AllocatedFramesWouldBeTruncated,
    AllocationFailed,
}

pub fn physical_coverage_for_ram(
    memory_regions: &[MemoryRegion],
    total_ram_bytes: u64,
) -> Result<u64, BitmapResizeError> {
    if total_ram_bytes == 0 {
        return Err(BitmapResizeError::ZeroRam);
    }

    let frame_size = base_page_size();
    let requested = align_up(total_ram_bytes, frame_size).ok_or(BitmapResizeError::RamTooLarge)?;

    let map_top = memory_regions
        .iter()
        .filter(|r| r.end > r.start)
        .map(|r| r.end)
        .max()
        .unwrap_or(0);

    let map_top = align_up(map_top, frame_size).ok_or(BitmapResizeError::RamTooLarge)?;

    Ok(core::cmp::max(requested, map_top))
}

pub fn bitmap_layout_for_physical_coverage(
    physical_coverage_bytes: u64,
) -> Result<(usize, usize), BitmapResizeError> {
    if physical_coverage_bytes == 0 {
        return Err(BitmapResizeError::ZeroRam);
    }

    let frame_size = base_page_size();
    let frames_u64 = physical_coverage_bytes / frame_size;
    let frames = usize::try_from(frames_u64).map_err(|_| BitmapResizeError::RamTooLarge)?;

    let low_frames = low_reserved_frames();
    if frames < low_frames {
        return Err(BitmapResizeError::RamBelowLowReserve);
    }

    let words = bitmap_words_for_frames(frames).ok_or(BitmapResizeError::RamTooLarge)?;
    Ok((frames, words))
}

fn bitmap_words_for_frames(frames: usize) -> Option<usize> {
    frames.checked_add(WORD_BITS - 1).map(|v| v / WORD_BITS)
}

pub fn heap_bitmap(words: usize, fill: u64) -> Result<Vec<u64>, BitmapResizeError> {
    let mut bitmap = Vec::new();

    bitmap
        .try_reserve_exact(words)
        .map_err(|_| BitmapResizeError::AllocationFailed)?;

    bitmap.resize(words, fill);
    Ok(bitmap)
}

pub fn build_memory_bitmap(
    memory_regions: &[MemoryRegion],
    frames: usize,
    words: usize,
) -> Result<Vec<u64>, BitmapResizeError> {
    let mut bitmap = heap_bitmap(words, u64::MAX)?;
    let frame_size = base_page_size();

    for region in memory_regions
        .iter()
        .filter(|r| r.kind == MemoryRegionKind::Usable)
    {
        let start_frame =
            div_ceil_u64(region.start, frame_size).ok_or(BitmapResizeError::RamTooLarge)?;
        let end_frame = region.end / frame_size;

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

    let low_frames = low_reserved_frames();
    if low_frames != 0 {
        set_range(bitmap.as_mut_slice(), 0, core::cmp::min(low_frames, frames));
    }

    mark_unused_tail_bits_allocated(bitmap.as_mut_slice(), frames);
    Ok(bitmap)
}

pub fn usable_region_bytes_below(region: &MemoryRegion, max_phys: u64) -> u64 {
    if region.start >= max_phys {
        return 0;
    }

    let end = core::cmp::min(region.end, max_phys);
    end.saturating_sub(region.start)
}

pub fn range_fits_bitmap(bitmap: &FrameBitmap, start: usize, len: usize) -> bool {
    let Some(end) = start.checked_add(len) else {
        return false;
    };
    end <= bitmap.frame_capacity()
}

pub fn preserve_set_bits_limited(dst: &mut [u64], src: &[u64], frames: usize) {
    if frames == 0 {
        return;
    }

    let full_words = frames / WORD_BITS;
    let common_full_words = core::cmp::min(full_words, core::cmp::min(dst.len(), src.len()));

    for idx in 0..common_full_words {
        dst[idx] |= src[idx];
    }

    let rem = frames & (WORD_BITS - 1);
    if rem == 0 {
        return;
    }

    if full_words >= dst.len() || full_words >= src.len() {
        return;
    }

    dst[full_words] |= src[full_words] & low_bits_mask(rem);
}

pub fn preserve_reclaimed_free_bits_limited(
    dst_memory: &mut [u64],
    old_memory: &[u64],
    old_reclaimed: &[u64],
    frames: usize,
) {
    if frames == 0 {
        return;
    }

    let full_words = frames / WORD_BITS;
    let common_full_words = core::cmp::min(
        full_words,
        core::cmp::min(
            dst_memory.len(),
            core::cmp::min(old_memory.len(), old_reclaimed.len()),
        ),
    );

    for idx in 0..common_full_words {
        let reclaimed_free = old_reclaimed[idx] & !old_memory[idx];
        dst_memory[idx] &= !reclaimed_free;
    }

    let rem = frames & (WORD_BITS - 1);
    if rem == 0 {
        return;
    }

    if full_words >= dst_memory.len()
        || full_words >= old_memory.len()
        || full_words >= old_reclaimed.len()
    {
        return;
    }

    let mask = low_bits_mask(rem);
    let reclaimed_free = old_reclaimed[full_words] & !old_memory[full_words] & mask;
    dst_memory[full_words] &= !reclaimed_free;
}

pub fn count_set_bits_up_to(bitmap: &[u64], frames: usize) -> usize {
    if frames == 0 || bitmap.is_empty() {
        return 0;
    }

    let full_words = core::cmp::min(frames / WORD_BITS, bitmap.len());
    let mut count = 0usize;

    for word in &bitmap[..full_words] {
        count += word.count_ones() as usize;
    }

    let rem = frames & (WORD_BITS - 1);
    if rem != 0 && full_words < bitmap.len() {
        count += (bitmap[full_words] & low_bits_mask(rem)).count_ones() as usize;
    }

    count
}

pub fn set_bit(bitmap: &mut [u64], idx: usize) {
    let w = idx / WORD_BITS;
    let b = idx & (WORD_BITS - 1);
    if w >= bitmap.len() {
        return;
    }
    bitmap[w] |= 1u64 << b;
}

pub fn bit_is_set(bitmap: &[u64], idx: usize) -> bool {
    let w = idx / WORD_BITS;
    let b = idx & (WORD_BITS - 1);
    w < bitmap.len() && (bitmap[w] & (1u64 << b)) != 0
}

pub fn set_range(bitmap: &mut [u64], start: usize, len: usize) {
    let Some(end) = start.checked_add(len) else {
        return;
    };
    if len == 0 || bitmap.is_empty() {
        return;
    }

    let total_bits = bitmap.len().saturating_mul(WORD_BITS);
    if start >= total_bits {
        return;
    }

    let end = core::cmp::min(end, total_bits);
    if start >= end {
        return;
    }

    let first_word = start / WORD_BITS;
    let last_word = (end - 1) / WORD_BITS;
    let first_bit = start & (WORD_BITS - 1);
    let last_bit = (end - 1) & (WORD_BITS - 1);

    if first_word == last_word {
        bitmap[first_word] |= bit_range_mask(first_bit, last_bit);
        return;
    }

    bitmap[first_word] |= !0u64 << first_bit;

    if first_word + 1 < last_word {
        bitmap[first_word + 1..last_word].fill(u64::MAX);
    }

    bitmap[last_word] |= low_bits_mask(last_bit + 1);
}

pub fn clear_range(bitmap: &mut [u64], start: usize, len: usize) {
    let Some(end) = start.checked_add(len) else {
        return;
    };
    if len == 0 || bitmap.is_empty() {
        return;
    }

    let total_bits = bitmap.len().saturating_mul(WORD_BITS);
    if start >= total_bits {
        return;
    }

    let end = core::cmp::min(end, total_bits);
    if start >= end {
        return;
    }

    let first_word = start / WORD_BITS;
    let last_word = (end - 1) / WORD_BITS;
    let first_bit = start & (WORD_BITS - 1);
    let last_bit = (end - 1) & (WORD_BITS - 1);

    if first_word == last_word {
        bitmap[first_word] &= !bit_range_mask(first_bit, last_bit);
        return;
    }

    bitmap[first_word] &= low_bits_mask(first_bit);

    if first_word + 1 < last_word {
        bitmap[first_word + 1..last_word].fill(0);
    }

    bitmap[last_word] &= !low_bits_mask(last_bit + 1);
}

pub fn set_range_count_new(
    bitmap: &mut [u64],
    frame_capacity: usize,
    start: usize,
    len: usize,
) -> usize {
    let Some(end) = start.checked_add(len) else {
        return 0;
    };
    if len == 0 || start >= frame_capacity || bitmap.is_empty() {
        return 0;
    }

    let end = core::cmp::min(end, frame_capacity);
    let total_bits = bitmap.len().saturating_mul(WORD_BITS);
    let end = core::cmp::min(end, total_bits);
    if start >= end {
        return 0;
    }

    let first_word = start / WORD_BITS;
    let last_word = (end - 1) / WORD_BITS;
    let first_bit = start & (WORD_BITS - 1);
    let last_bit = (end - 1) & (WORD_BITS - 1);
    let mut new_bits = 0usize;

    if first_word == last_word {
        return set_word_bits_count_new(
            &mut bitmap[first_word],
            bit_range_mask(first_bit, last_bit),
        );
    }

    new_bits += set_word_bits_count_new(&mut bitmap[first_word], !0u64 << first_bit);

    for word in &mut bitmap[first_word + 1..last_word] {
        let old = *word;
        new_bits += (!old).count_ones() as usize;
        *word = u64::MAX;
    }

    new_bits += set_word_bits_count_new(&mut bitmap[last_word], low_bits_mask(last_bit + 1));
    new_bits
}

pub fn range_all_set(bitmap: &[u64], frame_capacity: usize, start: usize, len: usize) -> bool {
    let Some(end) = start.checked_add(len) else {
        return false;
    };
    if len == 0 {
        return true;
    }
    if end > frame_capacity || bitmap.is_empty() {
        return false;
    }

    let total_bits = bitmap.len().saturating_mul(WORD_BITS);
    if end > total_bits {
        return false;
    }

    let first_word = start / WORD_BITS;
    let last_word = (end - 1) / WORD_BITS;
    let first_bit = start & (WORD_BITS - 1);
    let last_bit = (end - 1) & (WORD_BITS - 1);

    if first_word == last_word {
        let mask = bit_range_mask(first_bit, last_bit);
        return bitmap[first_word] & mask == mask;
    }

    let first_mask = !0u64 << first_bit;
    if bitmap[first_word] & first_mask != first_mask {
        return false;
    }

    for word in &bitmap[first_word + 1..last_word] {
        if *word != u64::MAX {
            return false;
        }
    }

    let last_mask = low_bits_mask(last_bit + 1);
    bitmap[last_word] & last_mask == last_mask
}

pub fn first_set_bit_in_range(bitmap: &[u64], start: usize, end: usize) -> Option<usize> {
    if start >= end || bitmap.is_empty() {
        return None;
    }

    let total_bits = bitmap.len().saturating_mul(WORD_BITS);
    let end = end.min(total_bits);
    if start >= end {
        return None;
    }

    let first_word = start / WORD_BITS;
    let last_word = (end - 1) / WORD_BITS;
    let start_bit = start & (WORD_BITS - 1);

    if first_word == last_word {
        let last_bit = (end - 1) & (WORD_BITS - 1);
        let mask = bit_range_mask(start_bit, last_bit);
        let word = bitmap[first_word] & mask;
        return if word != 0 {
            Some(first_word * WORD_BITS + word.trailing_zeros() as usize)
        } else {
            None
        };
    }

    let word = bitmap[first_word] & (!0u64 << start_bit);
    if word != 0 {
        return Some(first_word * WORD_BITS + word.trailing_zeros() as usize);
    }

    for (w, word) in bitmap[first_word + 1..last_word].iter().enumerate() {
        if *word != 0 {
            return Some((first_word + 1 + w) * WORD_BITS + word.trailing_zeros() as usize);
        }
    }

    let last_bit = (end - 1) & (WORD_BITS - 1);
    let word = bitmap[last_word] & low_bits_mask(last_bit + 1);
    if word != 0 {
        Some(last_word * WORD_BITS + word.trailing_zeros() as usize)
    } else {
        None
    }
}

pub fn mark_unused_tail_bits_allocated(bitmap: &mut [u64], frames: usize) {
    if bitmap.is_empty() {
        return;
    }

    let rem = frames & (WORD_BITS - 1);
    if rem == 0 {
        return;
    }

    let last_word = frames / WORD_BITS;
    if last_word < bitmap.len() {
        bitmap[last_word] |= !low_bits_mask(rem);
    }
}

pub fn clear_unused_tail_bits(bitmap: &mut [u64], frames: usize) {
    if bitmap.is_empty() {
        return;
    }

    let rem = frames & (WORD_BITS - 1);
    if rem == 0 {
        return;
    }

    let last_word = frames / WORD_BITS;
    if last_word < bitmap.len() {
        bitmap[last_word] &= low_bits_mask(rem);
    }
}

pub fn low_reserved_frames() -> usize {
    let reserve = low_physical_reserve_bytes();
    if reserve == 0 {
        return 0;
    }

    let frame_size = base_page_size();
    usize::try_from(align_up(reserve, frame_size).unwrap_or(reserve) / frame_size)
        .unwrap_or(usize::MAX)
}

fn set_word_bits_count_new(word: &mut u64, mask: u64) -> usize {
    let old = *word;
    let new = old | mask;
    *word = new;
    (new ^ old).count_ones() as usize
}

fn bit_range_mask(first_bit: usize, last_bit: usize) -> u64 {
    let lower = !0u64 << first_bit;
    let upper = low_bits_mask(last_bit + 1);
    lower & upper
}

fn low_bits_mask(bits: usize) -> u64 {
    if bits == 0 {
        0
    } else if bits >= WORD_BITS {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

fn div_ceil_u64(value: u64, divisor: u64) -> Option<u64> {
    if divisor == 0 {
        return None;
    }

    let add = divisor - 1;
    value.checked_add(add).map(|v| v / divisor)
}
