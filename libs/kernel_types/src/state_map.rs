use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AtomicStateMapError {
    InvalidBits,
    LengthOverflow,
    AllocationFailed,
}

pub struct AtomicStateMap<const BITS: usize> {
    words: Box<[AtomicU64]>,
    len: usize,
}

impl<const BITS: usize> AtomicStateMap<BITS> {
    pub fn try_new(len: usize) -> Result<Self, AtomicStateMapError> {
        let word_len = Self::required_words(len).ok_or_else(|| {
            if BITS == 0 || BITS > 64 || 64 % BITS != 0 {
                AtomicStateMapError::InvalidBits
            } else {
                AtomicStateMapError::LengthOverflow
            }
        })?;
        let mut words = Vec::new();
        words
            .try_reserve_exact(word_len)
            .map_err(|_| AtomicStateMapError::AllocationFailed)?;
        words.resize_with(word_len, || AtomicU64::new(0));
        Ok(Self {
            words: words.into_boxed_slice(),
            len,
        })
    }

    pub const fn required_words(entries: usize) -> Option<usize> {
        if BITS == 0 || BITS > 64 || 64 % BITS != 0 {
            return None;
        }
        let entries_per_word = 64 / BITS;
        match entries.checked_add(entries_per_word - 1) {
            Some(rounded) => Some(rounded / entries_per_word),
            None => None,
        }
    }

    pub const fn required_bytes(entries: usize) -> Option<usize> {
        match Self::required_words(entries) {
            Some(words) => words.checked_mul(core::mem::size_of::<AtomicU64>()),
            None => None,
        }
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn load(&self, index: usize, ordering: Ordering) -> usize {
        assert!(index < self.len);
        let entries_per_word = 64 / BITS;
        let shift = (index % entries_per_word) * BITS;
        ((self.words[index / entries_per_word].load(ordering) >> shift) & Self::value_mask())
            as usize
    }

    pub fn compare_exchange(
        &self,
        index: usize,
        current: usize,
        new: usize,
        success: Ordering,
        failure: Ordering,
    ) -> Result<usize, usize> {
        self.compare_exchange_entry(index, current, new, success, failure, false)
    }

    pub fn compare_exchange_weak(
        &self,
        index: usize,
        current: usize,
        new: usize,
        success: Ordering,
        failure: Ordering,
    ) -> Result<usize, usize> {
        self.compare_exchange_entry(index, current, new, success, failure, true)
    }

    fn compare_exchange_entry(
        &self,
        index: usize,
        current: usize,
        new: usize,
        success: Ordering,
        failure: Ordering,
        weak: bool,
    ) -> Result<usize, usize> {
        assert!(index < self.len);
        let entries_per_word = 64 / BITS;
        let shift = (index % entries_per_word) * BITS;
        let value_mask = Self::value_mask();
        let field_mask = value_mask << shift;
        let expected_value = (current as u64) & value_mask;
        let new_value = (new as u64) & value_mask;
        let word = &self.words[index / entries_per_word];
        let mut observed = word.load(failure);

        loop {
            let actual = (observed >> shift) & value_mask;
            if actual != expected_value {
                return Err(actual as usize);
            }
            let replacement = (observed & !field_mask) | (new_value << shift);
            let result = if weak {
                word.compare_exchange_weak(observed, replacement, success, failure)
            } else {
                word.compare_exchange(observed, replacement, success, failure)
            };
            match result {
                Ok(_) => return Ok(actual as usize),
                Err(next) => observed = next,
            }
        }
    }

    pub const fn word_len(&self) -> usize {
        self.words.len()
    }

    pub fn load_word(&self, index: usize, ordering: Ordering) -> u64 {
        self.words[index].load(ordering)
    }

    pub fn any_nonzero(&self, first: usize, count: usize, ordering: Ordering) -> bool {
        let end = first.checked_add(count).expect("state range overflow");
        assert!(end <= self.len);
        let entries_per_word = 64 / BITS;
        let mut cursor = first;
        while cursor < end {
            let word_index = cursor / entries_per_word;
            let entry_offset = cursor % entries_per_word;
            let entries = (end - cursor).min(entries_per_word - entry_offset);
            let shift = entry_offset * BITS;
            let bits = entries * BITS;
            let mask = if bits == 64 {
                u64::MAX
            } else {
                ((1u64 << bits) - 1) << shift
            };
            if self.words[word_index].load(ordering) & mask != 0 {
                return true;
            }
            cursor += entries;
        }
        false
    }

    pub fn fetch_or_word(&self, index: usize, value: u64, ordering: Ordering) -> u64 {
        self.words[index].fetch_or(value, ordering)
    }

    pub fn fetch_and_word(&self, index: usize, value: u64, ordering: Ordering) -> u64 {
        self.words[index].fetch_and(value, ordering)
    }

    pub fn compare_exchange_word(
        &self,
        index: usize,
        current: u64,
        new: u64,
        success: Ordering,
        failure: Ordering,
    ) -> Result<u64, u64> {
        self.words[index].compare_exchange(current, new, success, failure)
    }

    pub fn compare_exchange_weak_word(
        &self,
        index: usize,
        current: u64,
        new: u64,
        success: Ordering,
        failure: Ordering,
    ) -> Result<u64, u64> {
        self.words[index].compare_exchange_weak(current, new, success, failure)
    }

    const fn value_mask() -> u64 {
        if BITS == 64 {
            u64::MAX
        } else {
            (1u64 << BITS) - 1
        }
    }
}
