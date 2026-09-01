use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use kernel_abi::{MemoryRegion, MemoryRegionKind};

use super::layout::{align_up, base_page_size, low_physical_reserve_bytes};

const EARLY_BOOT_BITMAP_STORAGE_BYTES: usize = 128 * 1024;
const EARLY_BOOT_FRAME_BITMAP_WORDS: usize =
    EARLY_BOOT_BITMAP_STORAGE_BYTES / core::mem::size_of::<BitmapWord>();
type BitmapWord = u64;
type AtomicBitmapWord = AtomicU64;

const WORD_BITS: usize = BitmapWord::BITS as usize;
const WORD_MAX: BitmapWord = BitmapWord::MAX;
const CONTIGUOUS_ALLOC_RETRIES: usize = 4;
const ZERO_WORD_FAST_MIN_FRAMES: usize = 16;

const fn early_boot_frame_capacity() -> usize {
    EARLY_BOOT_FRAME_BITMAP_WORDS * WORD_BITS
}

pub struct FrameBitmap {
    boot: [BitmapWord; EARLY_BOOT_FRAME_BITMAP_WORDS],
    heap: Option<Vec<BitmapWord>>,
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
        storage: Vec<BitmapWord>,
        frames: usize,
    ) -> Option<Vec<BitmapWord>> {
        let old = self.heap.take();

        self.words = storage.len();
        self.frames = frames;
        self.heap = Some(storage);

        old
    }

    /// Returns the mutable-builder bitmap as immutable words.
    pub fn as_slice(&self) -> &[BitmapWord] {
        match self.heap.as_ref() {
            Some(heap) => heap.as_slice(),
            None => &self.boot[..self.words],
        }
    }

    /// Returns the mutable-builder bitmap as mutable words.
    pub fn as_mut_slice(&mut self) -> &mut [BitmapWord] {
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
    words: Vec<AtomicBitmapWord>,
    frames: usize,
    next_word: AtomicUsize,
    hierarchy: HierarchyLayout,
    dirty_free: HierarchicalFrameIndex,
    zeroed_free: HierarchicalFrameIndex,
}

pub struct RuntimeFrameBitmapBuilder {
    frames: usize,
    words: Vec<AtomicBitmapWord>,
    hierarchy: HierarchyLayout,
    dirty_free: HierarchicalFrameIndex,
    zeroed_free: HierarchicalFrameIndex,
}

impl RuntimeFrameBitmapBuilder {
    /// Populates preallocated storage without performing any heap allocation.
    pub fn build(
        mut self,
        storage: &[BitmapWord],
    ) -> Result<RuntimeFrameBitmap, BitmapResizeError> {
        let needed_words =
            bitmap_words_for_frames(self.frames).ok_or(BitmapResizeError::RamTooLarge)?;
        if storage.len() < needed_words {
            return Err(BitmapResizeError::AllocatedFramesWouldBeTruncated);
        }
        if self.words.capacity() < needed_words {
            return Err(BitmapResizeError::AllocationFailed);
        }

        for &word in &storage[..needed_words] {
            self.words.push(AtomicBitmapWord::new(word));
        }

        for (word_index, word) in self.words.iter().enumerate() {
            let mut free = !word.load(Ordering::Relaxed);

            while free != 0 {
                let bit = free.trailing_zeros() as usize;
                let frame = word_index * WORD_BITS + bit;

                if frame < self.frames {
                    self.dirty_free.insert(&self.hierarchy, frame);
                }

                free &= free - 1;
            }
        }

        Ok(RuntimeFrameBitmap {
            words: self.words,
            frames: self.frames,
            next_word: AtomicUsize::new(0),
            hierarchy: self.hierarchy,
            dirty_free: self.dirty_free,
            zeroed_free: self.zeroed_free,
        })
    }
}

#[derive(Clone, Copy)]
struct BitmapLevel {
    word_offset: usize,
    word_count: usize,
    bit_count: usize,
}

struct HierarchyLayout {
    levels: Vec<BitmapLevel>,
    total_words: usize,
}

impl HierarchyLayout {
    fn for_frames(frames: usize) -> Result<Self, BitmapResizeError> {
        let mut levels = Vec::new();
        let mut bit_count = frames;
        let mut word_offset = 0usize;

        loop {
            let word_count =
                bitmap_words_for_frames(bit_count).ok_or(BitmapResizeError::RamTooLarge)?;
            levels
                .try_reserve_exact(1)
                .map_err(|_| BitmapResizeError::AllocationFailed)?;
            levels.push(BitmapLevel {
                word_offset,
                word_count,
                bit_count,
            });
            word_offset = word_offset
                .checked_add(word_count)
                .ok_or(BitmapResizeError::RamTooLarge)?;

            if word_count <= 1 {
                break;
            }

            bit_count = word_count;
        }

        Ok(Self {
            levels,
            total_words: word_offset,
        })
    }
}

struct HierarchicalFrameIndex {
    storage: Vec<AtomicBitmapWord>,
    indexed_count: AtomicUsize,
    next_frame: AtomicUsize,
}

impl HierarchicalFrameIndex {
    fn empty(layout: &HierarchyLayout) -> Result<Self, BitmapResizeError> {
        let mut storage = Vec::new();
        storage
            .try_reserve_exact(layout.total_words)
            .map_err(|_| BitmapResizeError::AllocationFailed)?;
        storage.resize_with(layout.total_words, || AtomicBitmapWord::new(0));
        Ok(Self {
            storage,
            indexed_count: AtomicUsize::new(0),
            next_frame: AtomicUsize::new(0),
        })
    }

    fn insert(&self, layout: &HierarchyLayout, frame: usize) -> bool {
        if frame >= layout.levels[0].bit_count {
            return false;
        }

        let mut child_index = frame;

        for (level_index, level) in layout.levels.iter().enumerate() {
            let word_index = child_index / WORD_BITS;
            let bit = child_index & (WORD_BITS - 1);
            let mask = BitmapWord::from(1u8) << bit;
            let word = &self.storage[level.word_offset + word_index];
            let old = word.fetch_or(mask, Ordering::AcqRel);

            if old & mask != 0 {
                if level_index == 0 {
                    return false;
                }
                break;
            }

            if old != 0 {
                break;
            }

            child_index = word_index;
        }

        self.indexed_count.fetch_add(1, Ordering::Relaxed);
        true
    }

    fn remove(&self, layout: &HierarchyLayout, frame: usize) -> bool {
        if frame >= layout.levels[0].bit_count {
            return false;
        }

        let leaf = layout.levels[0];
        let leaf_word_index = frame / WORD_BITS;
        let leaf_mask = BitmapWord::from(1u8) << (frame & (WORD_BITS - 1));
        let leaf_word = &self.storage[leaf.word_offset + leaf_word_index];
        let old = leaf_word.fetch_and(!leaf_mask, Ordering::AcqRel);

        if old & leaf_mask == 0 {
            return false;
        }

        self.indexed_count.fetch_sub(1, Ordering::Relaxed);

        if old & !leaf_mask != 0 {
            return true;
        }

        let mut child_index = leaf_word_index;

        for level_index in 1..layout.levels.len() {
            let level = layout.levels[level_index];
            let word_index = child_index / WORD_BITS;
            let mask = BitmapWord::from(1u8) << (child_index & (WORD_BITS - 1));
            let word = &self.storage[level.word_offset + word_index];
            let old = word.fetch_and(!mask, Ordering::AcqRel);

            if self
                .level_word(layout, level_index - 1, child_index)
                .load(Ordering::Acquire)
                != 0
            {
                word.fetch_or(mask, Ordering::Release);
                break;
            }

            if old & !mask != 0 {
                break;
            }

            child_index = word_index;
        }

        true
    }

    fn find_candidate(&self, layout: &HierarchyLayout) -> Option<usize> {
        if self.indexed_count.load(Ordering::Acquire) == 0 {
            return None;
        }

        let frames = layout.levels[0].bit_count;
        let start = self.next_frame.fetch_add(1, Ordering::Relaxed) % frames;
        let candidate = self
            .find_set_bit_at_or_after(layout, 0, start)
            .or_else(|| self.find_set_bit_at_or_after(layout, 0, 0))?;

        if candidate < frames {
            self.next_frame
                .store(candidate.wrapping_add(1) % frames, Ordering::Relaxed);
            Some(candidate)
        } else {
            None
        }
    }

    fn find_set_bit_at_or_after(
        &self,
        layout: &HierarchyLayout,
        level_index: usize,
        start_bit: usize,
    ) -> Option<usize> {
        let level = layout.levels[level_index];
        if start_bit >= level.bit_count {
            return None;
        }

        let word_index = start_bit / WORD_BITS;
        let first_bit = start_bit & (WORD_BITS - 1);
        let first_word = self.storage[level.word_offset + word_index].load(Ordering::Acquire)
            & (WORD_MAX << first_bit);

        if first_word != 0 {
            return Some(word_index * WORD_BITS + first_word.trailing_zeros() as usize);
        }

        let parent_level = level_index.checked_add(1)?;
        if parent_level >= layout.levels.len() {
            return None;
        }

        let child_word = self.find_set_bit_at_or_after(layout, parent_level, word_index + 1)?;
        if child_word >= level.word_count {
            return None;
        }

        let word = self.storage[level.word_offset + child_word].load(Ordering::Acquire);
        if word == 0 {
            return None;
        }

        Some(child_word * WORD_BITS + word.trailing_zeros() as usize)
    }

    fn remove_range(&self, layout: &HierarchyLayout, start: usize, count: usize) {
        let Some(end) = start.checked_add(count) else {
            return;
        };
        let end = end.min(layout.levels[0].bit_count);
        if start >= end {
            return;
        }

        let leaf = layout.levels[0];
        let first_word = start / WORD_BITS;
        let last_word = (end - 1) / WORD_BITS;
        let mut word_index = first_word;
        let mut removed = 0usize;

        while word_index <= last_word {
            let mask = range_word_mask(start, end - start, word_index);
            let word = &self.storage[leaf.word_offset + word_index];
            let old = word.fetch_and(!mask, Ordering::AcqRel);
            removed = removed.saturating_add((old & mask).count_ones() as usize);

            if old != 0 && old & !mask == 0 {
                self.prune_empty_word(layout, word_index);
            }

            word_index += 1;
        }

        if removed != 0 {
            self.indexed_count.fetch_sub(removed, Ordering::Relaxed);
        }
    }

    fn prune_empty_word(&self, layout: &HierarchyLayout, mut child_index: usize) {
        for level_index in 1..layout.levels.len() {
            let level = layout.levels[level_index];
            let word_index = child_index / WORD_BITS;
            let mask = BitmapWord::from(1u8) << (child_index & (WORD_BITS - 1));
            let word = &self.storage[level.word_offset + word_index];
            let old = word.fetch_and(!mask, Ordering::AcqRel);

            if self
                .level_word(layout, level_index - 1, child_index)
                .load(Ordering::Acquire)
                != 0
            {
                word.fetch_or(mask, Ordering::Release);
                break;
            }

            if old & !mask != 0 {
                break;
            }

            child_index = word_index;
        }
    }

    fn level_word(
        &self,
        layout: &HierarchyLayout,
        level_index: usize,
        word_index: usize,
    ) -> &AtomicBitmapWord {
        &self.storage[layout.levels[level_index].word_offset + word_index]
    }
}

impl RuntimeFrameBitmap {
    fn claim_from(&self, index: &HierarchicalFrameIndex) -> Option<usize> {
        let frame = index.find_candidate(&self.hierarchy)?;
        let word_index = frame / WORD_BITS;
        let mask = BitmapWord::from(1u8) << (frame & (WORD_BITS - 1));
        let word = &self.words[word_index];
        let mut old = word.load(Ordering::Acquire);

        loop {
            if old & mask != 0 {
                return None;
            }

            match word.compare_exchange_weak(old, old | mask, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => {
                    self.dirty_free.remove(&self.hierarchy, frame);
                    self.zeroed_free.remove(&self.hierarchy, frame);
                    return Some(frame);
                }
                Err(actual) => old = actual,
            }
        }
    }

    fn finish_contiguous_claim(&self, start: usize, count: usize) -> usize {
        self.dirty_free.remove_range(&self.hierarchy, start, count);
        self.zeroed_free.remove_range(&self.hierarchy, start, count);
        start
    }

    /// Allocates every component needed to build a runtime bitmap.
    pub fn prepare(frames: usize) -> Result<RuntimeFrameBitmapBuilder, BitmapResizeError> {
        let needed_words = bitmap_words_for_frames(frames).ok_or(BitmapResizeError::RamTooLarge)?;
        let mut words = Vec::new();
        words
            .try_reserve_exact(needed_words)
            .map_err(|_| BitmapResizeError::AllocationFailed)?;

        let hierarchy = HierarchyLayout::for_frames(frames)?;
        let dirty_free = HierarchicalFrameIndex::empty(&hierarchy)?;
        let zeroed_free = HierarchicalFrameIndex::empty(&hierarchy)?;

        Ok(RuntimeFrameBitmapBuilder {
            frames,
            words,
            hierarchy,
            dirty_free,
            zeroed_free,
        })
    }

    /// Builds the live atomic frame bitmap from plain bitmap words.
    pub fn from_words(storage: Vec<BitmapWord>, frames: usize) -> Result<Self, BitmapResizeError> {
        Self::prepare(frames)?.build(storage.as_slice())
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
    pub fn snapshot_words(&self) -> Result<Vec<BitmapWord>, BitmapResizeError> {
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
        self.claim_from(&self.dirty_free)
            .or_else(|| self.claim_from(&self.zeroed_free))
    }

    pub fn alloc_zeroed_frame(&self) -> Option<usize> {
        self.claim_from(&self.zeroed_free)
    }

    pub fn alloc_dirty_frame(&self) -> Option<usize> {
        self.claim_from(&self.dirty_free)
    }

    pub unsafe fn publish_zeroed_frame(&self, frame: usize) {
        if frame >= self.frames {
            return;
        }

        let word_index = frame / WORD_BITS;
        let mask = BitmapWord::from(1u8) << (frame & (WORD_BITS - 1));
        self.dirty_free.remove(&self.hierarchy, frame);
        self.zeroed_free.insert(&self.hierarchy, frame);
        let old = self.words[word_index].fetch_and(!mask, Ordering::Release);
        debug_assert!(old & mask != 0);
    }

    pub fn has_dirty_frames(&self) -> bool {
        self.dirty_free.indexed_count.load(Ordering::Acquire) != 0
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
        let mask = BitmapWord::from(1u8) << bit;

        self.zeroed_free.remove(&self.hierarchy, frame);
        self.dirty_free.insert(&self.hierarchy, frame);
        let old = self.words[word_index].fetch_and(!mask, Ordering::Release);
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
                    return Some(self.finish_contiguous_claim(start, count));
                }
            }

            if let Some(start) = self.alloc_contiguous_general(count) {
                return Some(self.finish_contiguous_claim(start, count));
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
                    return Some(self.finish_contiguous_claim(start, count));
                }
            }

            if let Some(start) = self.alloc_contiguous_aligned_general(count, align_frames) {
                return Some(self.finish_contiguous_claim(start, count));
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

        self.zeroed_free.remove_range(&self.hierarchy, start, count);
        let mut publish_frame = start;
        while publish_frame < end {
            self.dirty_free.insert(&self.hierarchy, publish_frame);
            publish_frame += 1;
        }

        let first_word = start / WORD_BITS;
        let last_word = (end - 1) / WORD_BITS;
        let mut word_index = first_word;

        while word_index <= last_word {
            let mask = range_word_mask(start, count, word_index);
            let old = self.words[word_index].fetch_and(!mask, Ordering::Release);
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

            free &= WORD_MAX << first_allowed_bit;

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

            free &= WORD_MAX << first_allowed_bit;

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

            free &= WORD_MAX << first_allowed_bit;

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
        .filter(|r| r.kind == MemoryRegionKind::Usable && r.end > r.start)
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
pub fn heap_bitmap(words: usize, fill: BitmapWord) -> Result<Vec<BitmapWord>, BitmapResizeError> {
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
) -> Result<Vec<BitmapWord>, BitmapResizeError> {
    let mut bitmap = heap_bitmap(words, WORD_MAX)?;
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
pub fn preserve_set_bits_limited(dst: &mut [BitmapWord], src: &[BitmapWord], frames: usize) {
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
    dst_memory: &mut [BitmapWord],
    old_memory: &[BitmapWord],
    old_reclaimed: &[BitmapWord],
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
pub fn count_set_bits_up_to(bitmap: &[BitmapWord], frames: usize) -> usize {
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
pub fn set_bit(bitmap: &mut [BitmapWord], idx: usize) {
    let w = idx / WORD_BITS;
    let b = idx & (WORD_BITS - 1);

    if w >= bitmap.len() {
        return;
    }

    bitmap[w] |= BitmapWord::from(1u8) << b;
}

/// Tests whether one bit is set in a mutable boot/build bitmap.
pub fn bit_is_set(bitmap: &[BitmapWord], idx: usize) -> bool {
    let w = idx / WORD_BITS;
    let b = idx & (WORD_BITS - 1);

    w < bitmap.len() && (bitmap[w] & (BitmapWord::from(1u8) << b)) != 0
}

/// Sets a range of bits in a mutable boot/build bitmap.
pub fn set_range(bitmap: &mut [BitmapWord], start: usize, len: usize) {
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

    bitmap[first_word] |= WORD_MAX << first_bit;

    if first_word + 1 < last_word {
        bitmap[first_word + 1..last_word].fill(WORD_MAX);
    }

    bitmap[last_word] |= low_bits_mask(last_bit + 1);
}

/// Clears a range of bits in a mutable boot/build bitmap.
pub fn clear_range(bitmap: &mut [BitmapWord], start: usize, len: usize) {
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
    bitmap: &mut [BitmapWord],
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

    new_bits += set_word_bits_count_new(&mut bitmap[first_word], WORD_MAX << first_bit);

    for word in &mut bitmap[first_word + 1..last_word] {
        let old = *word;
        new_bits += (!old).count_ones() as usize;
        *word = WORD_MAX;
    }

    new_bits += set_word_bits_count_new(&mut bitmap[last_word], low_bits_mask(last_bit + 1));
    new_bits
}

/// Returns whether a range is fully set in a mutable boot/build bitmap.
pub fn range_all_set(
    bitmap: &[BitmapWord],
    frame_capacity: usize,
    start: usize,
    len: usize,
) -> bool {
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

    let first_mask = WORD_MAX << first_bit;
    if bitmap[first_word] & first_mask != first_mask {
        return false;
    }

    for word in &bitmap[first_word + 1..last_word] {
        if *word != WORD_MAX {
            return false;
        }
    }

    let last_mask = low_bits_mask(last_bit + 1);
    bitmap[last_word] & last_mask == last_mask
}

/// Returns the first set bit in a mutable bitmap range.
pub fn first_set_bit_in_range(bitmap: &[BitmapWord], start: usize, end: usize) -> Option<usize> {
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

    let word = bitmap[first_word] & (WORD_MAX << start_bit);
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
pub fn mark_unused_tail_bits_allocated(bitmap: &mut [BitmapWord], frames: usize) {
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
pub fn clear_unused_tail_bits(bitmap: &mut [BitmapWord], frames: usize) {
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

fn try_claim_word_mask(word: &AtomicBitmapWord, mask: BitmapWord) -> bool {
    if mask == 0 {
        return true;
    }

    if mask == WORD_MAX {
        return word
            .compare_exchange(0, WORD_MAX, Ordering::AcqRel, Ordering::Relaxed)
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

fn range_word_mask(start: usize, count: usize, word_index: usize) -> BitmapWord {
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

fn subword_run_starts(mut free: BitmapWord, len: usize) -> BitmapWord {
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

fn set_word_bits_count_new(word: &mut BitmapWord, mask: BitmapWord) -> usize {
    let old = *word;
    let new = old | mask;

    *word = new;
    (new ^ old).count_ones() as usize
}

fn bit_range_mask(first_bit: usize, last_bit: usize) -> BitmapWord {
    let lower = WORD_MAX << first_bit;
    let upper = low_bits_mask(last_bit + 1);

    lower & upper
}

fn bit_range_mask_from_len(first_bit: usize, len: usize) -> BitmapWord {
    if len == 0 {
        return 0;
    }

    low_bits_mask(len) << first_bit
}

fn low_bits_mask(bits: usize) -> BitmapWord {
    if bits == 0 {
        0
    } else if bits >= WORD_BITS {
        WORD_MAX
    } else {
        (BitmapWord::from(1u8) << bits) - 1
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
