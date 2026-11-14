use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

const RADIX_BITS: u32 = 3;
const CHUNKS_PER_LEAF: usize = u64::BITS as usize;
const LEAF_BITS: u32 = CHUNKS_PER_LEAF.ilog2();
const WHOLE_CLAIM: u64 = u64::MAX;
// This retry delay improved contended throughput on the tested EPYC host,
// at the cost of higher tail latency. It is not an operation-latency bound.
const CAS_RETRY_PAUSES: usize = 256;

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
        entries = entries.div_ceil(1 << RADIX_BITS);
        internal_entries += entries;
        levels += 1;
    }
    let total_words = terminal_words + internal_entries;
    let total_bytes = total_words
        .checked_mul(core::mem::size_of::<AtomicU64>())
        .ok_or(RadixMapError::LengthOverflow)?;
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
            entries = entries.div_ceil(1 << RADIX_BITS);
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

    #[inline(always)]
    pub fn try_claim_chunks(&self, first: usize, count: usize) -> Result<(), RadixMapError> {
        let end = first
            .checked_add(count)
            .ok_or(RadixMapError::LengthOverflow)?;
        if end > self.chunks {
            return Err(RadixMapError::InvalidRange);
        }
        if count != 0 {
            if count == self.chunks && self.levels.len() > 1 {
                return self.words[self.levels.last().unwrap().word_offset]
                    .compare_exchange(0, WHOLE_CLAIM, Ordering::AcqRel, Ordering::Relaxed)
                    .map(|_| ())
                    .map_err(|_| RadixMapError::Conflict);
            }
            if self.is_partial_branch_run(first, end) {
                self.claim_branch_run(first, end)?;
            } else if first >> LEAF_BITS == (end - 1) >> LEAF_BITS {
                self.claim_single_leaf(first, end)?;
            } else if self.is_partial_leaf_run(first, end) {
                self.claim_leaf_run(first, end)?;
            } else {
                self.claim(self.root(), first, end)?;
            }
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
    #[inline(always)]
    pub unsafe fn release_chunks(&self, first: usize, count: usize) {
        let Some(end) = first.checked_add(count).filter(|&end| end <= self.chunks) else {
            debug_assert!(false);
            return;
        };
        if count != 0 {
            if count == self.chunks && self.levels.len() > 1 {
                let word = &self.words[self.levels.last().unwrap().word_offset];
                if word.load(Ordering::Relaxed) == WHOLE_CLAIM {
                    word.store(0, Ordering::Release);
                    return;
                }
            }
            if self.is_partial_branch_run(first, end) {
                self.release_branch_run(first, end);
            } else if first >> LEAF_BITS == (end - 1) >> LEAF_BITS {
                self.release_single_leaf(first, end);
            } else if self.is_partial_leaf_run(first, end) {
                self.release_leaf_run(first, end);
            } else {
                self.release(self.root(), first, end);
            }
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

    #[inline(always)]
    fn reserve_ancestor(word: &AtomicU64, count: u64) -> Result<(), RadixMapError> {
        let mut reserved = word.load(Ordering::Relaxed);
        loop {
            let Some(next) = reserved.checked_add(count).filter(|&next| next != WHOLE_CLAIM) else {
                return Err(RadixMapError::Conflict);
            };
            match word.compare_exchange_weak(reserved, next, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => return Ok(()),
                Err(current) => {
                    if current.checked_add(count).filter(|&next| next != WHOLE_CLAIM).is_none() {
                        return Err(RadixMapError::Conflict);
                    }
                    for _ in 0..CAS_RETRY_PAUSES {
                        core::hint::spin_loop();
                    }
                    // A failed CAS snapshot can become stale during backoff.
                    // Reload after pausing, including the zero-pause control.
                    reserved = word.load(Ordering::Relaxed);
                }
            }
        }
    }

    #[inline(always)]
    fn ancestor_word(&self, level: usize, first: usize) -> &AtomicU64 {
        let info = &self.levels[level];
        // A final root level can span more than usize::MAX chunks.
        let index = first.checked_shr(info.shift).unwrap_or(0);
        &self.words[info.word_offset + index]
    }

    #[inline(always)]
    fn single_leaf_node(&self, first: usize) -> RadixNode {
        let start = first & !(CHUNKS_PER_LEAF - 1);
        RadixNode {
            level: 0,
            word: first >> LEAF_BITS,
            start,
            end: self.chunks.min(start.saturating_add(CHUNKS_PER_LEAF)),
        }
    }

    #[inline(always)]
    fn is_partial_branch_run(&self, first: usize, end: usize) -> bool {
        const BRANCH_BITS: u32 = LEAF_BITS + RADIX_BITS;
        const BRANCH_SPAN: usize = 1usize << BRANCH_BITS;
        const PARENT_BITS: u32 = BRANCH_BITS + RADIX_BITS;
        const PARENT_SPAN: usize = 1usize << PARENT_BITS;
        if (first | end) & (BRANCH_SPAN - 1) != 0 || self.levels.len() < 3 {
            return false;
        }
        let start = first & !(PARENT_SPAN - 1);
        let parent_end = self.chunks.min(start.saturating_add(PARENT_SPAN));
        first >> PARENT_BITS == (end - 1) >> PARENT_BITS
            && (first != start || end != parent_end)
    }

    fn claim_branch_run(&self, first: usize, end: usize) -> Result<(), RadixMapError> {
        const BRANCH_BITS: u32 = LEAF_BITS + RADIX_BITS;
        let count = (end - first) as u64;
        // Every complete L1 branch shares the same L2-and-up ancestor chain.
        for level in (2..self.levels.len()).rev() {
            let result = Self::reserve_ancestor(self.ancestor_word(level, first), count);
            if result.is_err() {
                for acquired in level + 1..self.levels.len() {
                    self.ancestor_word(acquired, first)
                        .fetch_sub(count, Ordering::Release);
                }
                return Err(RadixMapError::Conflict);
            }
        }
        let first_branch = first >> BRANCH_BITS;
        let end_branch = end >> BRANCH_BITS;
        let word_offset = self.levels[1].word_offset;
        for index in first_branch..end_branch {
            if self.words[word_offset + index]
                .compare_exchange(0, WHOLE_CLAIM, Ordering::AcqRel, Ordering::Relaxed)
                .is_err()
            {
                // These earlier branches are still exclusively ours and
                // have not been published to a caller that could split them.
                for prior in first_branch..index {
                    self.words[word_offset + prior].store(0, Ordering::Release);
                }
                for level in 2..self.levels.len() {
                    self.ancestor_word(level, first)
                        .fetch_sub(count, Ordering::Release);
                }
                return Err(RadixMapError::Conflict);
            }
        }
        Ok(())
    }

    fn release_branch_run(&self, first: usize, end: usize) {
        const BRANCH_BITS: u32 = LEAF_BITS + RADIX_BITS;
        const BRANCH_SPAN: usize = 1usize << BRANCH_BITS;
        // Check retained truncated ancestor sentinels before any mutation.
        if end == self.chunks {
            for level in (2..self.levels.len()).rev() {
                if self.ancestor_word(level, first).load(Ordering::Relaxed) == WHOLE_CLAIM {
                    self.release(self.root(), first, end);
                    return;
                }
            }
        }
        let word_offset = self.levels[1].word_offset;
        for index in first >> BRANCH_BITS..end >> BRANCH_BITS {
            let word_index = word_offset + index;
            let word = &self.words[word_index];
            if word.load(Ordering::Relaxed) == WHOLE_CLAIM {
                word.store(0, Ordering::Release);
            } else {
                // A prior split may have materialized this owned branch.
                let start = index << BRANCH_BITS;
                let node = RadixNode {
                    level: 1,
                    word: word_index,
                    start,
                    end: start + BRANCH_SPAN,
                };
                self.release(node, node.start, node.end);
            }
        }
        let count = (end - first) as u64;
        for level in 2..self.levels.len() {
            let previous = self.ancestor_word(level, first)
                .fetch_sub(count, Ordering::Release);
            debug_assert!(previous != WHOLE_CLAIM && previous >= count);
        }
    }

    #[inline(always)]
    fn is_partial_leaf_run(&self, first: usize, end: usize) -> bool {
        const BRANCH_BITS: u32 = LEAF_BITS + RADIX_BITS;
        const BRANCH_SPAN: usize = 1usize << BRANCH_BITS;
        let start = first & !(BRANCH_SPAN - 1);
        let branch_end = self.chunks.min(start.saturating_add(BRANCH_SPAN));
        first >> BRANCH_BITS == (end - 1) >> BRANCH_BITS
            && (first != start || end != branch_end)
    }

    fn claim_leaf_run(&self, first: usize, end: usize) -> Result<(), RadixMapError> {
        let count = (end - first) as u64;
        // Every leaf in this partial branch has the same ancestor chain.
        // Keep the recursive algorithm's root-to-leaf reservation order.
        for level in (1..self.levels.len()).rev() {
            let result = Self::reserve_ancestor(self.ancestor_word(level, first), count);
            if result.is_err() {
                for acquired in level + 1..self.levels.len() {
                    self.ancestor_word(acquired, first)
                        .fetch_sub(count, Ordering::Release);
                }
                return Err(RadixMapError::Conflict);
            }
        }
        let first_leaf = first >> LEAF_BITS;
        let last_leaf = (end - 1) >> LEAF_BITS;
        for index in first_leaf..=last_leaf {
            let node = self.single_leaf_node(index << LEAF_BITS);
            let result = self.claim_leaf(node, first.max(node.start), end.min(node.end));
            if let Err(error) = result {
                for prior_index in first_leaf..index {
                    let prior = self.single_leaf_node(prior_index << LEAF_BITS);
                    self.release_leaf(prior, first.max(prior.start), end.min(prior.end));
                }
                for level in 1..self.levels.len() {
                    self.ancestor_word(level, first)
                        .fetch_sub(count, Ordering::Release);
                }
                return Err(error);
            }
        }
        Ok(())
    }

    fn release_leaf_run(&self, first: usize, end: usize) {
        // Splitting a partial branch materializes its descendants. Preserve
        // the generic fallback for any retained truncated-tail sentinel,
        // checking every ancestor before changing any bitmap or counter.
        if end == self.chunks {
            for level in (1..self.levels.len()).rev() {
                if self.ancestor_word(level, first).load(Ordering::Relaxed) == WHOLE_CLAIM {
                    self.release(self.root(), first, end);
                    return;
                }
            }
        }
        for index in first >> LEAF_BITS..=(end - 1) >> LEAF_BITS {
            let node = self.single_leaf_node(index << LEAF_BITS);
            self.release_leaf(node, first.max(node.start), end.min(node.end));
        }
        let count = (end - first) as u64;
        for level in 1..self.levels.len() {
            let previous = self.ancestor_word(level, first)
                .fetch_sub(count, Ordering::Release);
            debug_assert!(previous != WHOLE_CLAIM && previous >= count);
        }
    }

    fn claim_single_leaf(&self, first: usize, end: usize) -> Result<(), RadixMapError> {
        let count = (end - first) as u64;
        if self.levels.len() == 4 {
            // Resolve all immutable metadata and addresses before the first RMW.
            let root = self.ancestor_word(3, first);
            let parent = self.ancestor_word(2, first);
            let branch = self.ancestor_word(1, first);
            let node = self.single_leaf_node(first);
            let leaf = &self.words[node.word];
            let mask = leaf_mask(first, end);
            let whole_leaf = first == node.start && end == node.end;
            let reserve = |word: &AtomicU64| Self::reserve_ancestor(word, count);
            reserve(root)?;
            if reserve(parent).is_err() {
                root.fetch_sub(count, Ordering::Release);
                return Err(RadixMapError::Conflict);
            }
            if reserve(branch).is_err() {
                parent.fetch_sub(count, Ordering::Release);
                root.fetch_sub(count, Ordering::Release);
                return Err(RadixMapError::Conflict);
            }
            let result = if whole_leaf {
                leaf.compare_exchange(0, mask, Ordering::AcqRel, Ordering::Relaxed)
            } else {
                leaf.try_update(Ordering::AcqRel, Ordering::Relaxed, |bits| {
                    (bits & mask == 0).then_some(bits | mask)
                })
            }.map(|_| ()).map_err(|_| RadixMapError::Conflict);
            if result.is_err() {
                branch.fetch_sub(count, Ordering::Release);
                parent.fetch_sub(count, Ordering::Release);
                root.fetch_sub(count, Ordering::Release);
            }
            return result;
        }
        // Reserve ancestors before touching the leaf, exactly as recursion does.
        for level in (1..self.levels.len()).rev() {
            let result = Self::reserve_ancestor(self.ancestor_word(level, first), count);
            if result.is_err() {
                for acquired in level + 1..self.levels.len() {
                    self.ancestor_word(acquired, first)
                        .fetch_sub(count, Ordering::Release);
                }
                return Err(RadixMapError::Conflict);
            }
        }
        let result = self.claim_leaf(self.single_leaf_node(first), first, end);
        if result.is_err() {
            for level in 1..self.levels.len() {
                self.ancestor_word(level, first)
                    .fetch_sub(count, Ordering::Release);
            }
        }
        result
    }

    fn release_single_leaf(&self, first: usize, end: usize) {
        if self.levels.len() == 4 {
            // Resolve every address before clearing the bitmap or counters.
            let root = self.ancestor_word(3, first);
            let parent = self.ancestor_word(2, first);
            let branch = self.ancestor_word(1, first);
            let node = self.single_leaf_node(first);
            let leaf = &self.words[node.word];
            let mask = leaf_mask(first, end);
            let whole_leaf = first == node.start && end == node.end;
            let count = (end - first) as u64;
            if end == self.chunks
                && (root.load(Ordering::Relaxed) == WHOLE_CLAIM
                    || parent.load(Ordering::Relaxed) == WHOLE_CLAIM
                    || branch.load(Ordering::Relaxed) == WHOLE_CLAIM)
            {
                self.release(self.root(), first, end);
                return;
            }
            if whole_leaf {
                debug_assert_eq!(leaf.load(Ordering::Relaxed), mask);
                leaf.store(0, Ordering::Release);
            } else {
                let previous = leaf.fetch_and(!mask, Ordering::Release);
                debug_assert_eq!(previous & mask, mask);
            }
            let previous = branch.fetch_sub(count, Ordering::Release);
            debug_assert!(previous != WHOLE_CLAIM && previous >= count);
            let previous = parent.fetch_sub(count, Ordering::Release);
            debug_assert!(previous != WHOLE_CLAIM && previous >= count);
            let previous = root.fetch_sub(count, Ordering::Release);
            debug_assert!(previous != WHOLE_CLAIM && previous >= count);
            return;
        }
        // An internal whole claim fits one leaf only when its node is
        // truncated at the backing end. Other subranges require split
        // materialization before release, so their ancestors cannot be WHOLE.
        if end == self.chunks {
            for level in (1..self.levels.len()).rev() {
                if self.ancestor_word(level, first).load(Ordering::Relaxed) == WHOLE_CLAIM {
                    self.release(self.root(), first, end);
                    return;
                }
            }
        }
        self.release_leaf(self.single_leaf_node(first), first, end);
        let count = (end - first) as u64;
        for level in 1..self.levels.len() {
            let previous = self.ancestor_word(level, first)
                .fetch_sub(count, Ordering::Release);
            debug_assert!(previous != WHOLE_CLAIM && previous >= count);
        }
    }

    #[inline(always)]
    fn claim_leaf(&self, node: RadixNode, first: usize, end: usize) -> Result<(), RadixMapError> {
        let word = &self.words[node.word];
        let mask = leaf_mask(first, end);
        if first == node.start && end == node.end {
            return word
                .compare_exchange(0, mask, Ordering::AcqRel, Ordering::Relaxed)
                .map(|_| ())
                .map_err(|_| RadixMapError::Conflict);
        }
        word.try_update(Ordering::AcqRel, Ordering::Relaxed, |bits| {
            (bits & mask == 0).then_some(bits | mask)
        })
        .map(|_| ())
        .map_err(|_| RadixMapError::Conflict)
    }

    #[inline(always)]
    fn claim_partial_branch(
        &self, node: RadixNode, first: usize, end: usize,
    ) -> Result<(), RadixMapError> {
        debug_assert_eq!(node.level, 1);
        debug_assert!(first != node.start || end != node.end);
        let word = &self.words[node.word];
        let count = (end - first) as u64;
        Self::reserve_ancestor(word, count)?;
        let first_leaf = first >> LEAF_BITS;
        let last_leaf = (end - 1) >> LEAF_BITS;
        for index in first_leaf..=last_leaf {
            let leaf = self.single_leaf_node(index << LEAF_BITS);
            if let Err(error) = self.claim_leaf(leaf, first.max(leaf.start), end.min(leaf.end)) {
                for prior_index in first_leaf..index {
                    let prior = self.single_leaf_node(prior_index << LEAF_BITS);
                    self.release_leaf(prior, first.max(prior.start), end.min(prior.end));
                }
                word.fetch_sub(count, Ordering::Release);
                return Err(error);
            }
        }
        Ok(())
    }

    #[inline(always)]
    fn release_materialized_branch(&self, node: RadixNode, first: usize, end: usize) {
        debug_assert_eq!(node.level, 1);
        // A complete WHOLE child was handled by the caller. Other releases
        // have materialized descendants from their claim or a required split.
        for index in first >> LEAF_BITS..=(end - 1) >> LEAF_BITS {
            let leaf = self.single_leaf_node(index << LEAF_BITS);
            self.release_leaf(leaf, first.max(leaf.start), end.min(leaf.end));
        }
        let count = (end - first) as u64;
        let previous = self.words[node.word].fetch_sub(count, Ordering::Release);
        debug_assert!(previous != WHOLE_CLAIM && previous >= count);
    }

    fn claim(&self, node: RadixNode, first: usize, end: usize) -> Result<(), RadixMapError> {
        let word = &self.words[node.word];
        if node.level == 0 {
            return self.claim_leaf(node, first, end);
        }
        if first == node.start && end == node.end {
            return word
                .compare_exchange(0, WHOLE_CLAIM, Ordering::AcqRel, Ordering::Relaxed)
                .map(|_| ())
                .map_err(|_| RadixMapError::Conflict);
        }

        let count = (end - first) as u64;
        Self::reserve_ancestor(word, count)?;

        for child in self.children(node, first, end) {
            let result = if child.level == 0 {
                self.claim_leaf(child, first.max(child.start), end.min(child.end))
            } else if first <= child.start && end >= child.end {
                self.words[child.word]
                    .compare_exchange(0, WHOLE_CLAIM, Ordering::AcqRel, Ordering::Relaxed)
                    .map(|_| ())
                    .map_err(|_| RadixMapError::Conflict)
            } else if child.level == 1 {
                self.claim_partial_branch(child, first.max(child.start), end.min(child.end))
            } else {
                self.claim(child, first.max(child.start), end.min(child.end))
            };
            if let Err(error) = result {
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

    #[inline(always)]
    fn release_leaf(&self, node: RadixNode, first: usize, end: usize) {
        let word = &self.words[node.word];
        let mask = leaf_mask(first, end);
        if first == node.start && end == node.end {
            // Exclusive ownership covers every valid bit in this leaf.
            debug_assert_eq!(word.load(Ordering::Relaxed), mask);
            word.store(0, Ordering::Release);
        } else {
            let previous = word.fetch_and(!mask, Ordering::Release);
            debug_assert_eq!(previous & mask, mask);
        }
    }

    fn release(&self, node: RadixNode, first: usize, end: usize) {
        let word = &self.words[node.word];
        if node.level == 0 {
            self.release_leaf(node, first, end);
        } else if first == node.start
            && end == node.end
            && word.load(Ordering::Relaxed) == WHOLE_CLAIM
        {
            word.store(0, Ordering::Release);
        } else {
            for child in self.children(node, first, end) {
                if child.level == 0 {
                    self.release_leaf(child, first.max(child.start), end.min(child.end));
                } else if first <= child.start
                    && end >= child.end
                    && self.words[child.word].load(Ordering::Relaxed) == WHOLE_CLAIM
                {
                    self.words[child.word].store(0, Ordering::Release);
                } else if child.level == 1 {
                    self.release_materialized_branch(child, first.max(child.start), end.min(child.end));
                } else {
                    self.release(child, first.max(child.start), end.min(child.end));
                }
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
