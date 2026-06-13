use alloc::vec::Vec;

use kernel_abi::{MemoryRegion, MemoryRegionKind};

use super::layout::{align_up, base_page_size, low_physical_reserve_bytes};

const EARLY_BOOT_BITMAP_STORAGE_BYTES: usize = 128 * 1024;
const EARLY_BOOT_FRAME_BITMAP_WORDS: usize =
    EARLY_BOOT_BITMAP_STORAGE_BYTES / core::mem::size_of::<u64>();

const fn early_boot_frame_capacity() -> usize {
    EARLY_BOOT_FRAME_BITMAP_WORDS * u64::BITS as usize
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
    let word_bits = u64::BITS as usize;
    frames.checked_add(word_bits - 1).map(|v| v / word_bits)
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
    let full_words = frames / u64::BITS as usize;
    let common_full_words = core::cmp::min(full_words, core::cmp::min(dst.len(), src.len()));

    for idx in 0..common_full_words {
        dst[idx] |= src[idx];
    }

    let rem = frames & (u64::BITS as usize - 1);
    if rem == 0 {
        return;
    }

    if full_words >= dst.len() || full_words >= src.len() {
        return;
    }

    dst[full_words] |= src[full_words] & low_bits_mask(rem);
}

pub fn count_set_bits_up_to(bitmap: &[u64], frames: usize) -> usize {
    if frames == 0 || bitmap.is_empty() {
        return 0;
    }

    let full_words = core::cmp::min(frames / u64::BITS as usize, bitmap.len());
    let mut count = 0usize;

    for word in &bitmap[..full_words] {
        count += word.count_ones() as usize;
    }

    let rem = frames & (u64::BITS as usize - 1);
    if rem != 0 && full_words < bitmap.len() {
        count += (bitmap[full_words] & low_bits_mask(rem)).count_ones() as usize;
    }

    count
}

pub fn set_bit(bitmap: &mut [u64], idx: usize) {
    let w = idx / u64::BITS as usize;
    let b = idx & (u64::BITS as usize - 1);
    if w >= bitmap.len() {
        return;
    }
    bitmap[w] |= 1u64 << b;
}

pub fn bit_is_set(bitmap: &[u64], idx: usize) -> bool {
    let w = idx / u64::BITS as usize;
    let b = idx & (u64::BITS as usize - 1);
    w < bitmap.len() && (bitmap[w] & (1u64 << b)) != 0
}

pub fn set_range(bitmap: &mut [u64], start: usize, len: usize) {
    if len == 0 {
        return;
    }

    let words = bitmap.len();
    if words == 0 {
        return;
    }

    let word_bits = u64::BITS as usize;
    if start / word_bits >= words {
        return;
    }

    let end_incl = start + len - 1;
    let max_bit = words * word_bits - 1;
    let end_incl = core::cmp::min(end_incl, max_bit);

    let first_word = start / word_bits;
    let last_word = end_incl / word_bits;

    if first_word == last_word {
        let mask = ((!0u64) << (start & (word_bits - 1)))
            & ((!0u64) >> ((word_bits - 1) - (end_incl & (word_bits - 1))));
        bitmap[first_word] |= mask;
        return;
    }

    bitmap[first_word] |= !0u64 << (start & (word_bits - 1));

    for word in bitmap.iter_mut().take(last_word).skip(first_word + 1) {
        *word = !0u64;
    }

    bitmap[last_word] |= !0u64 >> ((word_bits - 1) - (end_incl & (word_bits - 1)));
}

pub fn clear_range(bitmap: &mut [u64], start: usize, len: usize) {
    if len == 0 {
        return;
    }

    let words = bitmap.len();
    if words == 0 {
        return;
    }

    let word_bits = u64::BITS as usize;
    if start / word_bits >= words {
        return;
    }

    let end_incl = start + len - 1;
    let max_bit = words * word_bits - 1;
    let end_incl = core::cmp::min(end_incl, max_bit);

    let first_word = start / word_bits;
    let last_word = end_incl / word_bits;

    if first_word == last_word {
        let mask = ((!0u64) << (start & (word_bits - 1)))
            & ((!0u64) >> ((word_bits - 1) - (end_incl & (word_bits - 1))));
        bitmap[first_word] &= !mask;
        return;
    }

    bitmap[first_word] &= !(!0u64 << (start & (word_bits - 1)));

    for word in bitmap.iter_mut().take(last_word).skip(first_word + 1) {
        *word = 0;
    }

    bitmap[last_word] &= !(!0u64 >> ((word_bits - 1) - (end_incl & (word_bits - 1))));
}

pub fn set_range_count_new(
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
    let word_bits = u64::BITS as usize;

    for idx in start..end {
        let w = idx / word_bits;
        let b = idx & (word_bits - 1);
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

pub fn range_all_set(bitmap: &[u64], frame_capacity: usize, start: usize, len: usize) -> bool {
    if len == 0 {
        return true;
    }

    let Some(end) = start.checked_add(len) else {
        return false;
    };
    if end > frame_capacity {
        return false;
    }

    let word_bits = u64::BITS as usize;
    for idx in start..end {
        let w = idx / word_bits;
        let b = idx & (word_bits - 1);
        if w >= bitmap.len() || bitmap[w] & (1u64 << b) == 0 {
            return false;
        }
    }

    true
}

pub fn first_set_bit_in_range(bitmap: &[u64], start: usize, end: usize) -> Option<usize> {
    if start >= end {
        return None;
    }
    let word_bits = u64::BITS as usize;
    let total_bits = bitmap.len() * word_bits;
    let end = end.min(total_bits);
    if start >= end {
        return None;
    }

    let first_word = start / word_bits;
    let last_word = (end - 1) / word_bits;
    let start_bit = start & (word_bits - 1);

    if first_word == last_word {
        let last_bit = (end - 1) & (word_bits - 1);
        let mask = (!0u64 << start_bit) & (!0u64 >> ((word_bits - 1) - last_bit));
        let word = bitmap[first_word] & mask;
        return if word != 0 {
            Some(first_word * word_bits + word.trailing_zeros() as usize)
        } else {
            None
        };
    }

    let word = bitmap[first_word] & (!0u64 << start_bit);
    if word != 0 {
        return Some(first_word * word_bits + word.trailing_zeros() as usize);
    }

    for (w, word) in bitmap
        .iter()
        .enumerate()
        .take(last_word)
        .skip(first_word + 1)
    {
        if *word != 0 {
            return Some(w * word_bits + word.trailing_zeros() as usize);
        }
    }

    let last_bit = (end - 1) & (word_bits - 1);
    let word = bitmap[last_word] & (!0u64 >> ((word_bits - 1) - last_bit));
    if word != 0 {
        Some(last_word * word_bits + word.trailing_zeros() as usize)
    } else {
        None
    }
}

pub fn mark_unused_tail_bits_allocated(bitmap: &mut [u64], frames: usize) {
    if bitmap.is_empty() {
        return;
    }

    let word_bits = u64::BITS as usize;
    let rem = frames & (word_bits - 1);
    if rem == 0 {
        return;
    }

    let last_word = frames / word_bits;
    if last_word < bitmap.len() {
        bitmap[last_word] |= !low_bits_mask(rem);
    }
}

pub fn clear_unused_tail_bits(bitmap: &mut [u64], frames: usize) {
    if bitmap.is_empty() {
        return;
    }

    let word_bits = u64::BITS as usize;
    let rem = frames & (word_bits - 1);
    if rem == 0 {
        return;
    }

    let last_word = frames / word_bits;
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

fn low_bits_mask(bits: usize) -> u64 {
    if bits == 0 {
        0
    } else if bits >= u64::BITS as usize {
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
