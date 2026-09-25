use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use crate::state_map::{AtomicStateMap, AtomicStateMapError};

const RADIX_BITS: usize = 4;
const RADIX: usize = 1 << RADIX_BITS;

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

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RadixState {
    Empty = 0b00,
    Partial = 0b01,
    Full = 0b10,
    Updating = 0b11,
}

struct RadixLevel {
    entry_offset: usize,
    entry_count: usize,
    shift: u32,
}

pub struct RadixMap {
    byte_len: usize,
    granularity: usize,
    terminal: AtomicStateMap<1>,
    internal: AtomicStateMap<2>,
    levels: Box<[RadixLevel]>,
}

pub fn required_storage(
    byte_len: usize,
    granularity: usize,
) -> Result<RadixMapStorageRequirements, RadixMapError> {
    if granularity == 0 || !granularity.is_power_of_two() {
        return Err(RadixMapError::InvalidGranularity);
    }
    let terminal_entries = if byte_len == 0 {
        0
    } else {
        byte_len
            .checked_add(granularity - 1)
            .ok_or(RadixMapError::LengthOverflow)?
            / granularity
    };
    let terminal_words = AtomicStateMap::<1>::required_words(terminal_entries)
        .ok_or(RadixMapError::LengthOverflow)?;
    let mut levels = 0usize;
    let mut internal_entries = 0usize;
    let mut entries = terminal_entries;
    while entries > 1 {
        entries = entries
            .checked_add(RADIX - 1)
            .ok_or(RadixMapError::LengthOverflow)?
            / RADIX;
        levels = levels.checked_add(1).ok_or(RadixMapError::LengthOverflow)?;
        internal_entries = internal_entries
            .checked_add(entries)
            .ok_or(RadixMapError::LengthOverflow)?;
    }
    let internal_words = AtomicStateMap::<2>::required_words(internal_entries)
        .ok_or(RadixMapError::LengthOverflow)?;
    let total_words = terminal_words
        .checked_add(internal_words)
        .ok_or(RadixMapError::LengthOverflow)?;
    let total_bytes = total_words
        .checked_mul(core::mem::size_of::<u64>())
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
        let requirements = required_storage(byte_len, granularity)?;
        let terminal = AtomicStateMap::try_new(requirements.terminal_entries).map_err(map_alloc)?;
        let mut descriptions = Vec::new();
        descriptions
            .try_reserve_exact(requirements.levels)
            .map_err(|_| RadixMapError::AllocationFailed)?;
        let mut child_entries = requirements.terminal_entries;
        let mut shift = 0u32;
        while child_entries > 1 {
            let entries = child_entries
                .checked_add(RADIX - 1)
                .ok_or(RadixMapError::LengthOverflow)?
                / RADIX;
            shift = shift
                .checked_add(RADIX_BITS as u32)
                .ok_or(RadixMapError::LengthOverflow)?;
            descriptions.push((entries, shift));
            child_entries = entries;
        }
        descriptions.reverse();
        let internal = AtomicStateMap::try_new(requirements.internal_entries).map_err(map_alloc)?;
        let mut levels = Vec::new();
        levels
            .try_reserve_exact(descriptions.len())
            .map_err(|_| RadixMapError::AllocationFailed)?;
        let mut entry_offset = 0usize;
        for (entries, shift) in descriptions {
            levels.push(RadixLevel {
                entry_offset,
                entry_count: entries,
                shift,
            });
            entry_offset = entry_offset
                .checked_add(entries)
                .ok_or(RadixMapError::LengthOverflow)?;
        }
        Ok(Self {
            byte_len,
            granularity,
            terminal,
            internal,
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
        self.levels.len()
    }

    pub fn try_claim_range(&self, start: usize, len: usize) -> Result<(), RadixMapError> {
        let (first, end) = self.rounded_range(start, len)?;
        self.try_claim_chunks(first, end - first)
    }

    pub fn try_claim_chunks(&self, first: usize, count: usize) -> Result<(), RadixMapError> {
        let end = first
            .checked_add(count)
            .ok_or(RadixMapError::LengthOverflow)?;
        if end > self.terminal.len() {
            return Err(RadixMapError::InvalidRange);
        }
        if count == 0 {
            return Ok(());
        }
        let mut cursor = first;
        while cursor < end {
            let (target, units) = self.chunk(cursor, end);
            let units = if target.is_none() {
                units.max((end - cursor).min(RADIX - cursor % RADIX))
            } else {
                units
            };
            let result = match target {
                Some(_) => self.claim_chunk(cursor, target),
                None => self.claim_terminal_range(cursor, units),
            };
            if result.is_err() {
                if cursor != first {
                    unsafe { self.release_chunks(first, cursor - first) };
                }
                return Err(RadixMapError::Conflict);
            }
            cursor += units;
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
        let Some(end) = first.checked_add(count) else {
            debug_assert!(false);
            return;
        };
        if end > self.terminal.len() {
            debug_assert!(false);
            return;
        }
        if count == 0 {
            return;
        }
        let mut cursor = first;
        while cursor < end {
            let (target, units) = self.chunk(cursor, end);
            let units = if target.is_none() {
                units.max((end - cursor).min(RADIX - cursor % RADIX))
            } else {
                units
            };
            match target {
                Some(_) => unsafe { self.release_target(cursor, target) },
                None => unsafe { self.release_terminal_range(cursor, units) },
            }
            cursor += units;
        }
        for level_index in (0..self.levels.len()).rev() {
            let mut previous = usize::MAX;
            let mut cursor = first;
            while cursor < end {
                let (target, units) = self.chunk(cursor, end);
                let units = if target.is_none() {
                    units.max((end - cursor).min(RADIX - cursor % RADIX))
                } else {
                    units
                };
                let ancestor_end = target.unwrap_or(self.levels.len());
                if level_index < ancestor_end {
                    let index = cursor >> self.levels[level_index].shift;
                    if index != previous {
                        self.repair_entry(level_index, index);
                        previous = index;
                    }
                }
                cursor += units;
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
        if count == 0 || left_count > count || end > self.terminal.len() {
            return Err(RadixMapError::InvalidRange);
        }
        if boundary == first || boundary == end {
            return Ok(());
        }
        let mut cursor = first;
        while cursor < end {
            let (target, units) = self.chunk(cursor, end);
            let chunk_end = cursor + units;
            if boundary == cursor || boundary == chunk_end {
                return Ok(());
            }
            if boundary > cursor && boundary < chunk_end {
                let Some(mut level_index) = target else {
                    return Err(RadixMapError::InvalidRange);
                };
                let mut entry_index = cursor >> self.levels[level_index].shift;
                loop {
                    self.expand_full(level_index, entry_index)?;
                    let child_shift = self.levels[level_index].shift - RADIX_BITS as u32;
                    let child_span = 1usize << child_shift;
                    if boundary % child_span == 0 {
                        return Ok(());
                    }
                    level_index += 1;
                    if level_index >= self.levels.len() {
                        return Err(RadixMapError::InvalidRange);
                    }
                    entry_index = boundary >> self.levels[level_index].shift;
                }
            }
            cursor = chunk_end;
        }
        Err(RadixMapError::InvalidRange)
    }

    fn rounded_range(&self, start: usize, len: usize) -> Result<(usize, usize), RadixMapError> {
        if len == 0 || start >= self.byte_len {
            return Err(RadixMapError::InvalidRange);
        }
        let byte_end = start
            .checked_add(len)
            .ok_or(RadixMapError::LengthOverflow)?;
        if byte_end > self.byte_len {
            return Err(RadixMapError::InvalidRange);
        }
        let end = byte_end
            .checked_add(self.granularity - 1)
            .ok_or(RadixMapError::LengthOverflow)?
            / self.granularity;
        Ok((start / self.granularity, end))
    }

    fn chunk(&self, cursor: usize, end: usize) -> (Option<usize>, usize) {
        let Some(root) = self.levels.first() else {
            return (None, 1);
        };
        if cursor == 0 && end == self.terminal.len() {
            return (Some(0), end);
        }
        let remaining = end - cursor;
        let length_shift = usize::BITS - 1 - remaining.leading_zeros();
        let alignment_shift = if cursor == 0 {
            usize::BITS - 1
        } else {
            cursor.trailing_zeros()
        };
        let shift = length_shift.min(alignment_shift).min(root.shift);
        let shift = shift - shift % RADIX_BITS as u32;
        if shift >= RADIX_BITS as u32 {
            let level_index = ((root.shift - shift) / RADIX_BITS as u32) as usize;
            let span = 1usize << shift;
            if level_index < self.levels.len() && span <= remaining {
                return (Some(level_index), span);
            }
        }
        (None, 1)
    }

    fn claim_chunk(&self, terminal_index: usize, target: Option<usize>) -> Result<(), ()> {
        let ancestor_end = target.unwrap_or(self.levels.len());
        if ancestor_end != 0 {
            let level_index = 0;
            let index = terminal_index >> self.levels[level_index].shift;
            let state_index = self.levels[level_index].entry_offset + index;
            loop {
                match self.internal.load(state_index, Ordering::Acquire) {
                    state if state == RadixState::Full as usize => return Err(()),
                    state if state == RadixState::Updating as usize => {
                        self.help_update(level_index, index)
                    }
                    _ => break,
                }
            }
        }
        let claimed = match target {
            Some(level_index) => {
                let index = terminal_index >> self.levels[level_index].shift;
                self.internal.compare_exchange(
                    self.levels[level_index].entry_offset + index,
                    RadixState::Empty as usize,
                    RadixState::Full as usize,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
            }
            None => self.terminal.compare_exchange(
                terminal_index,
                0,
                1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ),
        };
        if claimed.is_err() {
            return Err(());
        }
        for level_index in (0..ancestor_end).rev() {
            let index = terminal_index >> self.levels[level_index].shift;
            let state_index = self.levels[level_index].entry_offset + index;
            loop {
                let state = self.internal.load(state_index, Ordering::Acquire);
                if state == RadixState::Partial as usize {
                    break;
                }
                if state == RadixState::Full as usize {
                    unsafe { self.release_target(terminal_index, target) };
                    self.repair_ancestors(terminal_index, ancestor_end);
                    return Err(());
                }
                if state == RadixState::Updating as usize {
                    self.help_update(level_index, index);
                    continue;
                }
                if self
                    .internal
                    .compare_exchange(
                        state_index,
                        RadixState::Empty as usize,
                        RadixState::Partial as usize,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
                {
                    break;
                }
            }
        }
        Ok(())
    }

    fn claim_terminal_range(&self, first: usize, count: usize) -> Result<(), ()> {
        if !self.levels.is_empty() {
            let index = first >> self.levels[0].shift;
            let state_index = self.levels[0].entry_offset + index;
            loop {
                match self.internal.load(state_index, Ordering::Acquire) {
                    state if state == RadixState::Full as usize => return Err(()),
                    state if state == RadixState::Updating as usize => self.help_update(0, index),
                    _ => break,
                }
            }
        }
        let word_index = first / 64;
        let shift = first % 64;
        let mask = ((1u64 << count) - 1) << shift;
        let mut observed = self.terminal.load_word(word_index, Ordering::Acquire);
        loop {
            if observed & mask != 0 {
                return Err(());
            }
            match self.terminal.compare_exchange_weak_word(
                word_index,
                observed,
                observed | mask,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(next) => observed = next,
            }
        }
        for level_index in (0..self.levels.len()).rev() {
            let index = first >> self.levels[level_index].shift;
            let state_index = self.levels[level_index].entry_offset + index;
            loop {
                let state = self.internal.load(state_index, Ordering::Acquire);
                if state == RadixState::Partial as usize {
                    break;
                }
                if state == RadixState::Full as usize {
                    self.terminal
                        .fetch_and_word(word_index, !mask, Ordering::AcqRel);
                    self.repair_ancestors(first, self.levels.len());
                    return Err(());
                }
                if state == RadixState::Updating as usize {
                    self.help_update(level_index, index);
                    continue;
                }
                if self
                    .internal
                    .compare_exchange(
                        state_index,
                        RadixState::Empty as usize,
                        RadixState::Partial as usize,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
                {
                    break;
                }
            }
        }
        Ok(())
    }

    unsafe fn release_terminal_range(&self, first: usize, count: usize) {
        let word_index = first / 64;
        let shift = first % 64;
        let mask = ((1u64 << count) - 1) << shift;
        let previous = self
            .terminal
            .fetch_and_word(word_index, !mask, Ordering::AcqRel);
        debug_assert_eq!(previous & mask, mask);
    }

    unsafe fn release_target(&self, terminal_index: usize, target: Option<usize>) {
        let result = match target {
            Some(level_index) => {
                let index = terminal_index >> self.levels[level_index].shift;
                self.internal.compare_exchange(
                    self.levels[level_index].entry_offset + index,
                    RadixState::Full as usize,
                    RadixState::Empty as usize,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
            }
            None => self.terminal.compare_exchange(
                terminal_index,
                1,
                0,
                Ordering::AcqRel,
                Ordering::Acquire,
            ),
        };
        debug_assert!(result.is_ok());
    }

    fn repair_ancestors(&self, terminal_index: usize, ancestor_end: usize) {
        for level_index in (0..ancestor_end).rev() {
            let index = terminal_index >> self.levels[level_index].shift;
            self.repair_entry(level_index, index);
        }
    }

    fn repair_entry(&self, level_index: usize, index: usize) {
        if self
            .internal
            .compare_exchange(
                self.levels[level_index].entry_offset + index,
                RadixState::Partial as usize,
                RadixState::Updating as usize,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            self.help_update(level_index, index);
        }
    }

    fn help_update(&self, level_index: usize, index: usize) {
        if self.internal.load(
            self.levels[level_index].entry_offset + index,
            Ordering::Acquire,
        ) != RadixState::Updating as usize
        {
            return;
        }
        let first_child = index * RADIX;
        let occupied = if level_index + 1 < self.levels.len() {
            let children = &self.levels[level_index + 1];
            let end = first_child.saturating_add(RADIX).min(children.entry_count);
            self.internal.any_nonzero(
                children.entry_offset + first_child,
                end - first_child,
                Ordering::Acquire,
            )
        } else {
            let end = first_child.saturating_add(RADIX).min(self.terminal.len());
            self.terminal
                .any_nonzero(first_child, end - first_child, Ordering::Acquire)
        };
        let next = if occupied {
            RadixState::Partial
        } else {
            RadixState::Empty
        };
        let _ = self.internal.compare_exchange(
            self.levels[level_index].entry_offset + index,
            RadixState::Updating as usize,
            next as usize,
            Ordering::Release,
            Ordering::Relaxed,
        );
    }

    fn expand_full(&self, level_index: usize, index: usize) -> Result<(), RadixMapError> {
        if self.internal.load(
            self.levels[level_index].entry_offset + index,
            Ordering::Acquire,
        ) != RadixState::Full as usize
        {
            return Err(RadixMapError::Conflict);
        }
        let first_child = index
            .checked_mul(RADIX)
            .ok_or(RadixMapError::LengthOverflow)?;
        if level_index + 1 < self.levels.len() {
            let children = &self.levels[level_index + 1];
            let end = first_child.saturating_add(RADIX).min(children.entry_count);
            for child in first_child..end {
                self.internal
                    .compare_exchange(
                        children.entry_offset + child,
                        RadixState::Empty as usize,
                        RadixState::Full as usize,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .map_err(|_| RadixMapError::Conflict)?;
            }
        } else {
            let end = first_child.saturating_add(RADIX).min(self.terminal.len());
            for child in first_child..end {
                self.terminal
                    .compare_exchange(child, 0, 1, Ordering::AcqRel, Ordering::Acquire)
                    .map_err(|_| RadixMapError::Conflict)?;
            }
        }
        self.internal
            .compare_exchange(
                self.levels[level_index].entry_offset + index,
                RadixState::Full as usize,
                RadixState::Partial as usize,
                Ordering::Release,
                Ordering::Acquire,
            )
            .map_err(|_| RadixMapError::Conflict)?;
        Ok(())
    }
}

fn map_alloc(error: AtomicStateMapError) -> RadixMapError {
    match error {
        AtomicStateMapError::AllocationFailed => RadixMapError::AllocationFailed,
        AtomicStateMapError::InvalidBits | AtomicStateMapError::LengthOverflow => {
            RadixMapError::LengthOverflow
        }
    }
}
