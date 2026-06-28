use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use kernel_abi::{MemoryRegion, MemoryRegionKind};

use super::layout::{align_up, base_page_size, low_physical_reserve_bytes};

const EARLY_BOOT_BITMAP_STORAGE_BYTES: usize = 128 * 1024;
const EARLY_BOOT_FRAME_BITMAP_WORDS: usize =
    EARLY_BOOT_BITMAP_STORAGE_BYTES / core::mem::size_of::<u64>();
const WORD_BITS: usize = u64::BITS as usize;
const CONTIGUOUS_ALLOC_RETRIES: usize = 4;
const ZERO_WORD_FAST_MIN_FRAMES: usize = 16;

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
    /// Creates a boot-time mutable bitmap using fixed early storage.
    pub const fn new() -> Self {
        Self {
            boot: [0; EARLY_BOOT_FRAME_BITMAP_WORDS],
            heap: None,
            frames: early_boot_frame_capacity(),
            words: EARLY_BOOT_FRAME_BITMAP_WORDS,
        }
    }

    /// Returns the bitmap to its fixed early storage and drops heap storage.
    pub fn reset_to_boot_storage(&mut self) {
        self.heap = None;
        self.frames = early_boot_frame_capacity();
        self.words = EARLY_BOOT_FRAME_BITMAP_WORDS;
    }

    /// Replaces the mutable boot/build bitmap with heap storage.
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

    /// Returns the mutable-builder bitmap as immutable words.
    pub fn as_slice(&self) -> &[u64] {
        match self.heap.as_ref() {
            Some(heap) => heap.as_slice(),
            None => &self.boot[..self.words],
        }
    }

    /// Returns the mutable-builder bitmap as mutable words.
    pub fn as_mut_slice(&mut self) -> &mut [u64] {
        match self.heap.as_mut() {
            Some(heap) => heap.as_mut_slice(),
            None => &mut self.boot[..self.words],
        }
    }

    /// Returns the number of physical frames representable by this bitmap.
    pub fn frame_capacity(&self) -> usize {
        self.frames
    }

    /// Returns the number of bitmap words currently in use.
    pub fn word_len(&self) -> usize {
        self.words
    }
}

pub struct RuntimeFrameBitmap {
    words: Vec<AtomicU64>,
    frames: usize,
    next_word: AtomicUsize,
}

impl RuntimeFrameBitmap {
    /// Allocates backing storage for the runtime atomic bitmap.
    pub fn reserved_atomic_storage(words: usize) -> Result<Vec<AtomicU64>, BitmapResizeError> {
        let mut storage = Vec::new();

        storage
            .try_reserve_exact(words)
            .map_err(|_| BitmapResizeError::AllocationFailed)?;

        Ok(storage)
    }

    /// Builds the live atomic frame bitmap from plain bitmap words.
    pub fn from_words(storage: Vec<u64>, frames: usize) -> Result<Self, BitmapResizeError> {
        let needed_words = bitmap_words_for_frames(frames).ok_or(BitmapResizeError::RamTooLarge)?;
        let atomic_storage = Self::reserved_atomic_storage(needed_words)?;

        Self::from_words_preallocated(storage, frames, atomic_storage)
    }

    /// Builds the live atomic frame bitmap using already-reserved atomic storage.
    pub fn from_words_preallocated(
        mut storage: Vec<u64>,
        frames: usize,
        mut atomic_storage: Vec<AtomicU64>,
    ) -> Result<Self, BitmapResizeError> {
        let needed_words = bitmap_words_for_frames(frames).ok_or(BitmapResizeError::RamTooLarge)?;

        if storage.len() < needed_words {
            return Err(BitmapResizeError::AllocatedFramesWouldBeTruncated);
        }

        if atomic_storage.capacity() < needed_words {
            return Err(BitmapResizeError::AllocationFailed);
        }

        storage.truncate(needed_words);
        mark_unused_tail_bits_allocated(storage.as_mut_slice(), frames);

        atomic_storage.clear();

        for word in storage {
            atomic_storage.push(AtomicU64::new(word));
        }

        Ok(Self {
            words: atomic_storage,
            frames,
            next_word: AtomicUsize::new(0),
        })
    }

    /// Copies a mutable boot/build bitmap into the live atomic frame bitmap.
    pub fn from_frame_bitmap(bitmap: &FrameBitmap) -> Result<Self, BitmapResizeError> {
        let mut storage = Vec::new();

        storage
            .try_reserve_exact(bitmap.word_len())
            .map_err(|_| BitmapResizeError::AllocationFailed)?;

        for word in bitmap.as_slice() {
            storage.push(*word);
        }

        Self::from_words(storage, bitmap.frame_capacity())
    }

    /// Returns the number of physical frames represented by this allocator.
    pub fn frame_capacity(&self) -> usize {
        self.frames
    }

    /// Returns the number of atomic bitmap words used by this allocator.
    pub fn word_len(&self) -> usize {
        self.words.len()
    }

    /// Returns a diagnostic snapshot of the runtime bitmap words.
    pub fn snapshot_words(&self) -> Result<Vec<u64>, BitmapResizeError> {
        let mut out = Vec::new();

        out.try_reserve_exact(self.words.len())
            .map_err(|_| BitmapResizeError::AllocationFailed)?;

        for word in &self.words {
            out.push(word.load(Ordering::Acquire));
        }

        Ok(out)
    }

    /// Allocates one physical frame using only atomic bitmap operations.
    pub fn alloc_frame(&self) -> Option<usize> {
        let word_count = self.words.len();
        if word_count == 0 {
            return None;
        }

        let start = self.next_word.fetch_add(1, Ordering::Relaxed) % word_count;

        for offset in 0..word_count {
            let word_index = (start + offset) % word_count;
            let word = &self.words[word_index];
            let mut old = word.load(Ordering::Relaxed);

            loop {
                let free = !old;
                if free == 0 {
                    break;
                }

                let bit = free.trailing_zeros() as usize;
                let frame = word_index * WORD_BITS + bit;

                if frame >= self.frames {
                    break;
                }

                let mask = 1u64 << bit;
                let new = old | mask;

                match word.compare_exchange_weak(old, new, Ordering::AcqRel, Ordering::Relaxed) {
                    Ok(_) => {
                        self.next_word
                            .store((word_index + 1) % word_count, Ordering::Relaxed);
                        return Some(frame);
                    }
                    Err(actual) => old = actual,
                }
            }
        }

        None
    }

    /// Frees one physical frame using only atomic bitmap operations.
    ///
    /// # Safety
    /// `frame` must be allocated, unused, and freed exactly once.
    pub unsafe fn free_frame(&self, frame: usize) {
        debug_assert!(frame < self.frames);

        if frame >= self.frames {
            return;
        }

        let word_index = frame / WORD_BITS;
        let bit = frame & (WORD_BITS - 1);
        let mask = 1u64 << bit;

        let old = self.words[word_index].fetch_and(!mask, Ordering::AcqRel);
        debug_assert!(old & mask != 0);
    }

    /// Allocates `count` non-contiguous physical frames into `out`.
    pub fn alloc_frames<'a>(&self, count: usize, out: &'a mut [usize]) -> Option<&'a mut [usize]> {
        if count > out.len() {
            return None;
        }

        let mut allocated = 0usize;

        while allocated < count {
            match self.alloc_frame() {
                Some(frame) => {
                    out[allocated] = frame;
                    allocated += 1;
                }
                None => {
                    for frame in &out[..allocated] {
                        unsafe { self.free_frame(*frame) };
                    }

                    return None;
                }
            }
        }

        Some(&mut out[..count])
    }

    /// Frees a list of non-contiguous physical frames.
    ///
    /// # Safety
    /// Every frame must be allocated, unused, unique in `frames`, and freed
    /// exactly once.
    pub unsafe fn free_frames(&self, frames: &[usize]) {
        for frame in frames {
            unsafe { self.free_frame(*frame) };
        }
    }

    /// Allocates a physically contiguous range of frames.
    pub fn alloc_contiguous_frames(&self, count: usize) -> Option<usize> {
        if count == 0 {
            return Some(0);
        }

        if count > self.frames {
            return None;
        }

        if count == 1 {
            return self.alloc_frame();
        }

        let mut attempt = 0usize;

        while attempt < CONTIGUOUS_ALLOC_RETRIES {
            if count >= ZERO_WORD_FAST_MIN_FRAMES {
                if let Some(start) = self.alloc_contiguous_zero_word_fast(count) {
                    return Some(start);
                }
            }

            if let Some(start) = self.alloc_contiguous_general(count) {
                return Some(start);
            }

            backoff(attempt);
            attempt += 1;
        }

        None
    }

    /// Allocates a physically contiguous range whose first frame satisfies `align_frames`.
    /// wait free if count = 1
    pub fn alloc_contiguous_frames_aligned(
        &self,
        count: usize,
        align_frames: usize,
    ) -> Option<usize> {
        if count == 0 {
            return Some(0);
        }

        if align_frames == 0 || count > self.frames {
            return None;
        }

        if align_frames <= 1 {
            return self.alloc_contiguous_frames(count);
        }

        let mut attempt = 0usize;

        while attempt < CONTIGUOUS_ALLOC_RETRIES {
            if count >= ZERO_WORD_FAST_MIN_FRAMES {
                if let Some(start) =
                    self.alloc_contiguous_zero_word_fast_aligned(count, align_frames)
                {
                    return Some(start);
                }
            }

            if let Some(start) = self.alloc_contiguous_aligned_general(count, align_frames) {
                return Some(start);
            }

            backoff(attempt);
            attempt += 1;
        }

        None
    }

    /// Frees a physically contiguous range of frames.
    /// # Safety
    /// The complete range must be allocated contiguously, unused, and freed
    /// exactly once.
    pub unsafe fn free_contiguous_frames(&self, start: usize, count: usize) {
        let Some(end) = start.checked_add(count) else {
            return;
        };

        debug_assert!(end <= self.frames);

        if count == 0 || end > self.frames {
            return;
        }

        let first_word = start / WORD_BITS;
        let last_word = (end - 1) / WORD_BITS;
        let mut word_index = first_word;

        while word_index <= last_word {
            let mask = range_word_mask(start, count, word_index);
            let old = self.words[word_index].fetch_and(!mask, Ordering::AcqRel);
            let missing = mask & !old;

            if missing != 0 {
                // panic!(
                //     "frame double-free or bad free range: start={} count={} end={} word_index={} old={:#018x} mask={:#018x} missing={:#018x} first_missing_frame={}",
                //     start,
                //     count,
                //     end,
                //     word_index,
                //     old,
                //     mask,
                //     missing,
                //     word_index * WORD_BITS + missing.trailing_zeros() as usize,
                // );
            }

            word_index += 1;
        }
    }

    fn alloc_contiguous_zero_word_fast(&self, count: usize) -> Option<usize> {
        let needed_words = count.div_ceil(WORD_BITS);

        if needed_words == 0 || needed_words > self.words.len() {
            return None;
        }

        let mut run_start = 0usize;
        let mut run_len = 0usize;
        let mut word_index = 0usize;

        while word_index < self.words.len() {
            let word = self.words[word_index].load(Ordering::Relaxed);

            if word == 0 {
                if run_len == 0 {
                    run_start = word_index;
                }

                run_len += 1;

                while run_len >= needed_words {
                    let start = run_start * WORD_BITS;

                    if start + count <= self.frames && self.try_claim_contiguous_at(start, count) {
                        return Some(start);
                    }

                    run_start += 1;
                    run_len -= 1;
                    backoff(0);
                }
            } else {
                run_len = 0;
            }

            word_index += 1;
        }

        None
    }

    fn alloc_contiguous_zero_word_fast_aligned(
        &self,
        count: usize,
        align_frames: usize,
    ) -> Option<usize> {
        let needed_words = count.div_ceil(WORD_BITS);

        if needed_words == 0 || needed_words > self.words.len() {
            return None;
        }

        let mut run_start = 0usize;
        let mut run_len = 0usize;
        let mut word_index = 0usize;

        while word_index < self.words.len() {
            let word = self.words[word_index].load(Ordering::Relaxed);

            if word == 0 {
                if run_len == 0 {
                    run_start = word_index;
                }

                run_len += 1;

                if run_len >= needed_words {
                    let run_frame_start = run_start * WORD_BITS;
                    let run_frame_end =
                        core::cmp::min((run_start + run_len) * WORD_BITS, self.frames);
                    let Some(mut candidate) = align_frame_index(run_frame_start, align_frames)
                    else {
                        return None;
                    };

                    loop {
                        let Some(candidate_end) = candidate.checked_add(count) else {
                            break;
                        };

                        if candidate_end > run_frame_end {
                            break;
                        }

                        if self.try_claim_contiguous_at(candidate, count) {
                            return Some(candidate);
                        }

                        let Some(next) = candidate
                            .checked_add(1)
                            .and_then(|frame| align_frame_index(frame, align_frames))
                        else {
                            break;
                        };

                        candidate = next;
                        backoff(0);
                    }
                }
            } else {
                run_len = 0;
            }

            word_index += 1;
        }

        None
    }

    fn alloc_contiguous_general(&self, count: usize) -> Option<usize> {
        let max_start = self.frames - count;
        let mut start = 0usize;

        while start <= max_start {
            let candidate = if count <= WORD_BITS {
                match self.find_subword_free_run_candidate(start, count) {
                    Some(candidate) => Some(candidate),
                    None => self.find_free_run_candidate(start, count),
                }
            } else {
                self.find_free_run_candidate(start, count)
            };

            let Some(candidate) = candidate else {
                return None;
            };

            if candidate > max_start {
                return None;
            }

            if self.try_claim_contiguous_at(candidate, count) {
                return Some(candidate);
            }

            start = candidate + 1;
            backoff(0);
        }

        None
    }

    fn alloc_contiguous_aligned_general(&self, count: usize, align_frames: usize) -> Option<usize> {
        let max_start = self.frames - count;
        let mut start = align_frame_index(0, align_frames)?;

        while start <= max_start {
            let candidate = self.find_aligned_free_run_candidate(start, count, align_frames)?;

            if candidate > max_start {
                return None;
            }

            if self.try_claim_contiguous_at(candidate, count) {
                return Some(candidate);
            }

            start = candidate
                .checked_add(1)
                .and_then(|frame| align_frame_index(frame, align_frames))?;

            backoff(0);
        }

        None
    }

    fn try_claim_contiguous_at(&self, start: usize, count: usize) -> bool {
        if count == 0 {
            return true;
        }

        let Some(end) = start.checked_add(count) else {
            return false;
        };

        if end > self.frames {
            return false;
        }

        let first_word = start / WORD_BITS;
        let last_word = (end - 1) / WORD_BITS;
        let mut word_index = first_word;

        while word_index <= last_word {
            let mask = range_word_mask(start, count, word_index);

            if try_claim_word_mask(&self.words[word_index], mask) {
                word_index += 1;
                continue;
            }

            self.rollback_contiguous_claim(start, count, first_word, word_index);
            return false;
        }

        true
    }

    fn rollback_contiguous_claim(
        &self,
        start: usize,
        count: usize,
        first_word: usize,
        failed_word: usize,
    ) {
        let mut word_index = first_word;

        while word_index < failed_word {
            let mask = range_word_mask(start, count, word_index);
            self.words[word_index].fetch_and(!mask, Ordering::AcqRel);
            word_index += 1;
        }
    }

    fn find_subword_free_run_candidate(&self, start: usize, count: usize) -> Option<usize> {
        if count == 0 || count > WORD_BITS || start >= self.frames {
            return None;
        }

        let mut word_index = start / WORD_BITS;
        let mut first_allowed_bit = start & (WORD_BITS - 1);

        while word_index < self.words.len() {
            let word_start = word_index * WORD_BITS;

            if word_start >= self.frames {
                return None;
            }

            let valid_bits = self.frames.saturating_sub(word_start).min(WORD_BITS);
            let valid_mask = low_bits_mask(valid_bits);
            let mut free = !self.words[word_index].load(Ordering::Relaxed) & valid_mask;

            free &= !0u64 << first_allowed_bit;

            let starts = subword_run_starts(free, count);
            if starts != 0 {
                let bit = starts.trailing_zeros() as usize;
                let frame = word_start + bit;

                if frame + count <= self.frames {
                    return Some(frame);
                }
            }

            word_index += 1;
            first_allowed_bit = 0;
        }

        None
    }

    fn find_free_run_candidate(&self, start: usize, count: usize) -> Option<usize> {
        if count == 0 {
            return Some(start);
        }

        if start >= self.frames {
            return None;
        }

        let mut word_index = start / WORD_BITS;
        let mut first_allowed_bit = start & (WORD_BITS - 1);
        let mut run_start = 0usize;
        let mut run_len = 0usize;

        while word_index < self.words.len() {
            let word_start = word_index * WORD_BITS;

            if word_start >= self.frames {
                return None;
            }

            let valid_bits = self.frames.saturating_sub(word_start).min(WORD_BITS);
            let valid_mask = low_bits_mask(valid_bits);
            let mut free = !self.words[word_index].load(Ordering::Relaxed) & valid_mask;

            free &= !0u64 << first_allowed_bit;

            let mut scan = free;
            let mut run_reaches_word_end = false;

            while scan != 0 {
                let first = scan.trailing_zeros() as usize;
                let len = (scan >> first).trailing_ones() as usize;
                let len = len.min(valid_bits - first);
                let frame = word_start + first;

                if run_len != 0 && run_start + run_len == frame {
                    run_len += len;
                } else {
                    run_start = frame;
                    run_len = len;
                }

                if run_len >= count {
                    return Some(run_start);
                }

                run_reaches_word_end = first + len == valid_bits;
                scan &= !bit_range_mask_from_len(first, len);
            }

            if !run_reaches_word_end {
                run_len = 0;
            }

            word_index += 1;
            first_allowed_bit = 0;
        }

        None
    }

    fn find_aligned_free_run_candidate(
        &self,
        start: usize,
        count: usize,
        align_frames: usize,
    ) -> Option<usize> {
        if count == 0 {
            return Some(start);
        }

        if start >= self.frames || align_frames == 0 {
            return None;
        }

        let mut word_index = start / WORD_BITS;
        let mut first_allowed_bit = start & (WORD_BITS - 1);
        let mut run_start = 0usize;
        let mut run_len = 0usize;

        while word_index < self.words.len() {
            let word_start = word_index * WORD_BITS;

            if word_start >= self.frames {
                return None;
            }

            let valid_bits = self.frames.saturating_sub(word_start).min(WORD_BITS);
            let valid_mask = low_bits_mask(valid_bits);
            let mut free = !self.words[word_index].load(Ordering::Relaxed) & valid_mask;

            free &= !0u64 << first_allowed_bit;

            let mut scan = free;
            let mut run_reaches_word_end = false;

            while scan != 0 {
                let first = scan.trailing_zeros() as usize;
                let len = (scan >> first).trailing_ones() as usize;
                let len = len.min(valid_bits - first);
                let frame = word_start + first;

                if run_len != 0 && run_start + run_len == frame {
                    run_len += len;
                } else {
                    run_start = frame;
                    run_len = len;
                }

                let min_candidate = core::cmp::max(run_start, start);
                if let Some(candidate) = align_frame_index(min_candidate, align_frames) {
                    if let Some(candidate_end) = candidate.checked_add(count) {
                        if candidate_end <= run_start + run_len && candidate_end <= self.frames {
                            return Some(candidate);
                        }
                    }
                }

                run_reaches_word_end = first + len == valid_bits;
                scan &= !bit_range_mask_from_len(first, len);
            }

            if !run_reaches_word_end {
                run_len = 0;
            }

            word_index += 1;
            first_allowed_bit = 0;
        }

        None
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitmapResizeError {
    ZeroRam,
    RamTooLarge,
    RamBelowLowReserve,
    AllocatedFramesWouldBeTruncated,
    AllocationFailed,
    RuntimeAllocatorAlreadyInitialized,
}

/// Returns the physical address coverage required by RAM size and the memory map.
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

/// Computes frame and word counts for a physical coverage size.
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

/// Allocates a mutable boot/build-time bitmap filled with `fill`.
pub fn heap_bitmap(words: usize, fill: u64) -> Result<Vec<u64>, BitmapResizeError> {
    let mut bitmap = Vec::new();

    bitmap
        .try_reserve_exact(words)
        .map_err(|_| BitmapResizeError::AllocationFailed)?;

    bitmap.resize(words, fill);
    Ok(bitmap)
}

/// Builds a mutable boot/build-time bitmap from the firmware memory map.
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

/// Returns usable bytes in `region` below `max_phys`.
pub fn usable_region_bytes_below(region: &MemoryRegion, max_phys: u64) -> u64 {
    if region.start >= max_phys {
        return 0;
    }

    let end = core::cmp::min(region.end, max_phys);
    end.saturating_sub(region.start)
}

/// Returns whether a frame range fits inside the mutable boot/build bitmap.
pub fn range_fits_bitmap(bitmap: &FrameBitmap, start: usize, len: usize) -> bool {
    let Some(end) = start.checked_add(len) else {
        return false;
    };

    end <= bitmap.frame_capacity()
}

/// Preserves allocated bits from `src` into `dst` up to `frames`.
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

/// Preserves reclaimed-free state from an old mutable bitmap into a new bitmap.
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

/// Counts allocated bits in a mutable bitmap up to `frames`.
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

/// Sets one bit in a mutable boot/build bitmap.
pub fn set_bit(bitmap: &mut [u64], idx: usize) {
    let w = idx / WORD_BITS;
    let b = idx & (WORD_BITS - 1);

    if w >= bitmap.len() {
        return;
    }

    bitmap[w] |= 1u64 << b;
}

/// Tests whether one bit is set in a mutable boot/build bitmap.
pub fn bit_is_set(bitmap: &[u64], idx: usize) -> bool {
    let w = idx / WORD_BITS;
    let b = idx & (WORD_BITS - 1);

    w < bitmap.len() && (bitmap[w] & (1u64 << b)) != 0
}

/// Sets a range of bits in a mutable boot/build bitmap.
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

/// Clears a range of bits in a mutable boot/build bitmap.
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

/// Sets a range and returns the number of newly-set bits.
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

/// Returns whether a range is fully set in a mutable boot/build bitmap.
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

/// Returns the first set bit in a mutable bitmap range.
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

/// Marks invalid tail bits allocated in a mutable bitmap.
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

/// Clears invalid tail bits in a mutable bitmap.
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

/// Returns the number of frames reserved at low physical memory.
pub fn low_reserved_frames() -> usize {
    let reserve = low_physical_reserve_bytes();

    if reserve == 0 {
        return 0;
    }

    let frame_size = base_page_size();

    usize::try_from(align_up(reserve, frame_size).unwrap_or(reserve) / frame_size)
        .unwrap_or(usize::MAX)
}

fn bitmap_words_for_frames(frames: usize) -> Option<usize> {
    frames.checked_add(WORD_BITS - 1).map(|v| v / WORD_BITS)
}

fn try_claim_word_mask(word: &AtomicU64, mask: u64) -> bool {
    if mask == 0 {
        return true;
    }

    if mask == u64::MAX {
        return word
            .compare_exchange(0, u64::MAX, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok();
    }

    let mut old = word.load(Ordering::Relaxed);

    loop {
        if old & mask != 0 {
            return false;
        }

        let new = old | mask;

        match word.compare_exchange_weak(old, new, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) => return true,
            Err(actual) => old = actual,
        }
    }
}

fn range_word_mask(start: usize, count: usize, word_index: usize) -> u64 {
    let end = start + count;
    let word_start = word_index * WORD_BITS;
    let word_end = word_start + WORD_BITS;
    let masked_start = start.max(word_start);
    let masked_end = end.min(word_end);

    if masked_start >= masked_end {
        return 0;
    }

    let first_bit = masked_start - word_start;
    let len = masked_end - masked_start;

    bit_range_mask_from_len(first_bit, len)
}

fn subword_run_starts(mut free: u64, len: usize) -> u64 {
    debug_assert!(len > 0);
    debug_assert!(len <= WORD_BITS);

    let mut covered = 1usize;

    while covered < len {
        let shift = core::cmp::min(covered, len - covered);
        free &= free >> shift;
        covered += shift;
    }

    free
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

fn bit_range_mask_from_len(first_bit: usize, len: usize) -> u64 {
    if len == 0 {
        return 0;
    }

    low_bits_mask(len) << first_bit
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

fn backoff(attempt: usize) {
    let spins = 1usize << attempt.min(6);
    let mut i = 0usize;

    while i < spins {
        core::hint::spin_loop();
        i += 1;
    }
}
