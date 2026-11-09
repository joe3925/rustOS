use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

const RADIX_BITS: u32 = 3;
const RADIX: usize = 1 << RADIX_BITS;
const CHUNKS_PER_LEAF: usize = u64::BITS as usize;
const LEAF_BITS: u32 = CHUNKS_PER_LEAF.ilog2();
const WHOLE_CLAIM: u64 = u64::MAX;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RadixMapError {
    InvalidGranularity,
    InvalidRange,
    LengthOverflow,
    AllocationFailed,
    Conflict,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RadixMapStorageRequirements {
    pub levels: usize,
    pub terminal_entries: usize,
    pub internal_entries: usize,
    pub total_words: usize,
    pub total_bytes: usize,
}

#[derive(Clone, Copy)]
struct RadixNode {
    level: usize,
    word: usize,
    start: usize,
    end: usize,
}

struct RadixLevel {
    word_offset: usize,
    shift: u32,
}

pub struct RadixMap {
    byte_len: usize,
    granularity: usize,
    chunks: usize,
    words: Box<[AtomicU64]>,
    levels: Box<[RadixLevel]>,
}

pub fn required_storage(
    byte_len: usize,
    granularity: usize,
) -> Result<RadixMapStorageRequirements, RadixMapError> {
    if !granularity.is_power_of_two() {
        return Err(RadixMapError::InvalidGranularity);
    }
    let terminal_entries = byte_len
        .checked_add(granularity - 1)
        .ok_or(RadixMapError::LengthOverflow)?
        / granularity;
    let terminal_words = terminal_entries
        .checked_add(CHUNKS_PER_LEAF - 1)
        .ok_or(RadixMapError::LengthOverflow)?
        / CHUNKS_PER_LEAF;
    let mut entries = terminal_words;
    let mut internal_entries = 0;
    let mut levels = 0;
    while entries > 1 {
        entries = entries.div_ceil(RADIX);
        internal_entries += entries;
        levels += 1;
    }
    let total_words = terminal_words + internal_entries;
    let total_bytes = total_words * core::mem::size_of::<AtomicU64>();
    Ok(RadixMapStorageRequirements {
        levels,
        terminal_entries,
        internal_entries,
        total_words,
        total_bytes,
    })
}

impl RadixMap {
    pub fn try_new(byte_len: usize, granularity: usize) -> Result<Self, RadixMapError> {
        let storage = required_storage(byte_len, granularity)?;
        let mut words = Vec::new();
        words
            .try_reserve_exact(storage.total_words)
            .map_err(|_| RadixMapError::AllocationFailed)?;
        words.resize_with(storage.total_words, || AtomicU64::new(0));

        let mut levels = Vec::new();
        levels
            .try_reserve_exact(storage.levels + usize::from(storage.terminal_entries != 0))
            .map_err(|_| RadixMapError::AllocationFailed)?;
        let mut entries = storage.terminal_entries.div_ceil(CHUNKS_PER_LEAF);
        let mut word_offset = 0;
        let mut shift = LEAF_BITS;
        while entries > 0 {
            levels.push(RadixLevel { word_offset, shift });
            if entries == 1 {
                break;
            }
            word_offset += entries;
            shift += RADIX_BITS;
            entries = entries.div_ceil(RADIX);
        }
        Ok(Self {
            byte_len,
            granularity,
            chunks: storage.terminal_entries,
            words: words.into_boxed_slice(),
            levels: levels.into_boxed_slice(),
        })
    }

    pub const fn len(&self) -> usize {
        self.byte_len
    }

    pub const fn granularity(&self) -> usize {
        self.granularity
    }

    pub const fn level_count(&self) -> usize {
        self.levels.len().saturating_sub(1)
    }

    pub fn try_claim_range(&self, start: usize, len: usize) -> Result<(), RadixMapError> {
        let (first, end) = self.rounded_range(start, len)?;
        self.try_claim_chunks(first, end - first)
    }

    pub fn try_claim_chunks(&self, first: usize, count: usize) -> Result<(), RadixMapError> {
        let end = first
            .checked_add(count)
            .ok_or(RadixMapError::LengthOverflow)?;
        if end > self.chunks {
            return Err(RadixMapError::InvalidRange);
        }
        if count != 0 {
            self.claim(self.root(), first, end)?;
        }
        Ok(())
    }

    /// Releases a previously claimed rounded range.
    ///
    /// # Safety
    /// The exact rounded range must have been successfully claimed by the
    /// caller's logical owner, remain owned, and be released exactly once.
    pub unsafe fn release_range(&self, start: usize, len: usize) {
        let Ok((first, end)) = self.rounded_range(start, len) else {
            debug_assert!(false);
            return;
        };
        unsafe { self.release_chunks(first, end - first) };
    }

    /// Releases a previously claimed chunk range.
    ///
    /// # Safety
    /// The exact chunk range must have been successfully claimed by the
    /// caller's logical owner, remain owned, and be released exactly once.
    pub unsafe fn release_chunks(&self, first: usize, count: usize) {
        let Some(end) = first.checked_add(count).filter(|&end| end <= self.chunks) else {
            debug_assert!(false);
            return;
        };
        if count != 0 {
            self.release(self.root(), first, end);
        }
    }

    /// Materializes a claimed range so both sides of a chunk boundary can be
    /// released independently without changing the occupied union.
    ///
    /// # Safety
    /// The complete chunk range must be exclusively owned by the caller.
    pub unsafe fn split_claim(
        &self,
        first: usize,
        count: usize,
        left_count: usize,
    ) -> Result<(), RadixMapError> {
        let end = first
            .checked_add(count)
            .ok_or(RadixMapError::LengthOverflow)?;
        let boundary = first
            .checked_add(left_count)
            .ok_or(RadixMapError::LengthOverflow)?;
        if count == 0 || boundary > end || end > self.chunks {
            return Err(RadixMapError::InvalidRange);
        }
        if boundary == first || boundary == end {
            return Ok(());
        }
        let mut node = self.root();
        while node.level != 0 {
            let word = &self.words[node.word];
            if word.load(Ordering::Relaxed) == WHOLE_CLAIM {
                for child in self.children(node, node.start, node.end) {
                    let state = if child.level == 0 {
                        leaf_mask(child.start, child.end)
                    } else {
                        WHOLE_CLAIM
                    };
                    self.words[child.word].store(state, Ordering::Relaxed);
                }
                word.store((node.end - node.start) as u64, Ordering::Release);
            }
            node = self
                .children(node, boundary, boundary + 1)
                .next()
                .expect("interior split boundary has a child");
            if boundary == node.start {
                break;
            }
        }
        Ok(())
    }

    fn root(&self) -> RadixNode {
        RadixNode {
            level: self.levels.len() - 1,
            word: self.words.len() - 1,
            start: 0,
            end: self.chunks,
        }
    }

    fn children(
        &self,
        node: RadixNode,
        first: usize,
        end: usize,
    ) -> impl Iterator<Item = RadixNode> {
        let level = node.level - 1;
        let RadixLevel { word_offset, shift } = self.levels[level];
        let span = 1usize << shift;
        (first >> shift..=(end - 1) >> shift).map(move |index| {
            let start = index << shift;
            RadixNode {
                level,
                word: word_offset + index,
                start,
                end: node.end.min(start.saturating_add(span)),
            }
        })
    }

    fn claim(&self, node: RadixNode, first: usize, end: usize) -> Result<(), RadixMapError> {
        let word = &self.words[node.word];
        if node.level == 0 {
            let mask = leaf_mask(first, end);
            return word
                .try_update(Ordering::AcqRel, Ordering::Relaxed, |bits| {
                    (bits & mask == 0).then_some(bits | mask)
                })
                .map(|_| ())
                .map_err(|_| RadixMapError::Conflict);
        }
        if first == node.start && end == node.end {
            return word
                .compare_exchange(0, WHOLE_CLAIM, Ordering::AcqRel, Ordering::Relaxed)
                .map(|_| ())
                .map_err(|_| RadixMapError::Conflict);
        }

        let count = (end - first) as u64;
        word.try_update(Ordering::AcqRel, Ordering::Relaxed, |reserved| {
            reserved
                .checked_add(count)
                .filter(|&next| next != WHOLE_CLAIM)
        })
        .map_err(|_| RadixMapError::Conflict)?;

        for child in self.children(node, first, end) {
            if let Err(error) = self.claim(child, first.max(child.start), end.min(child.end)) {
                if child.start > first {
                    for prior in self.children(node, first, child.start) {
                        self.release(prior, first.max(prior.start), prior.end);
                    }
                }
                word.fetch_sub(count, Ordering::Release);
                return Err(error);
            }
        }
        Ok(())
    }

    fn release(&self, node: RadixNode, first: usize, end: usize) {
        let word = &self.words[node.word];
        if node.level == 0 {
            let mask = leaf_mask(first, end);
            let previous = word.fetch_and(!mask, Ordering::Release);
            debug_assert_eq!(previous & mask, mask);
        } else if first == node.start
            && end == node.end
            && word.load(Ordering::Relaxed) == WHOLE_CLAIM
        {
            word.store(0, Ordering::Release);
        } else {
            for child in self.children(node, first, end) {
                self.release(child, first.max(child.start), end.min(child.end));
            }
            let count = (end - first) as u64;
            let previous = word.fetch_sub(count, Ordering::Release);
            debug_assert!(previous != WHOLE_CLAIM && previous >= count);
        }
    }

    fn rounded_range(&self, start: usize, len: usize) -> Result<(usize, usize), RadixMapError> {
        if len == 0 || start >= self.byte_len {
            return Err(RadixMapError::InvalidRange);
        }
        let end = start
            .checked_add(len)
            .ok_or(RadixMapError::LengthOverflow)?;
        if end > self.byte_len {
            return Err(RadixMapError::InvalidRange);
        }
        Ok((start / self.granularity, end.div_ceil(self.granularity)))
    }
}

fn leaf_mask(first: usize, end: usize) -> u64 {
    (u64::MAX >> (CHUNKS_PER_LEAF - (end - first))) << (first % CHUNKS_PER_LEAF)
}
