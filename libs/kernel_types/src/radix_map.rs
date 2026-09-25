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
    states: AtomicStateMap<2>,
    span_units: usize,
}

pub struct RadixMap {
    byte_len: usize,
    granularity: usize,
    terminal: AtomicStateMap<1>,
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
    let mut internal_words = 0usize;
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
        internal_words = internal_words
            .checked_add(
                AtomicStateMap::<2>::required_words(entries)
                    .ok_or(RadixMapError::LengthOverflow)?,
            )
            .ok_or(RadixMapError::LengthOverflow)?;
    }
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
        let mut span_units = 1usize;
        while child_entries > 1 {
            let entries = child_entries
                .checked_add(RADIX - 1)
                .ok_or(RadixMapError::LengthOverflow)?
                / RADIX;
            span_units = span_units
                .checked_mul(RADIX)
                .ok_or(RadixMapError::LengthOverflow)?;
            descriptions.push((entries, span_units));
            child_entries = entries;
        }
        descriptions.reverse();
        let mut levels = Vec::new();
        levels
            .try_reserve_exact(descriptions.len())
            .map_err(|_| RadixMapError::AllocationFailed)?;
        for (entries, span_units) in descriptions {
            levels.push(RadixLevel {
                states: AtomicStateMap::try_new(entries).map_err(map_alloc)?,
                span_units,
            });
        }
        Ok(Self {
            byte_len,
            granularity,
            terminal,
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
        let mut claimed = 0usize;
        while cursor < end {
            let (target, units) = self.chunk(cursor, end);
            if self.claim_chunk(cursor, target).is_err() {
                let mut rollback_cursor = first;
                let mut rollback_count = 0usize;
                while rollback_count < claimed {
                    let (rollback_target, rollback_units) = self.chunk(rollback_cursor, end);
                    unsafe { self.release_chunk(rollback_cursor, rollback_target) };
                    rollback_cursor += rollback_units;
                    rollback_count += 1;
                }
                return Err(RadixMapError::Conflict);
            }
            cursor += units;
            claimed += 1;
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
        let mut cursor = first;
        while cursor < end {
            let (target, units) = self.chunk(cursor, end);
            unsafe { self.release_chunk(cursor, target) };
            cursor += units;
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
                let mut entry_index = cursor / self.levels[level_index].span_units;
                loop {
                    self.expand_full(level_index, entry_index)?;
                    let child_span = self.levels[level_index].span_units / RADIX;
                    if boundary % child_span == 0 {
                        return Ok(());
                    }
                    level_index += 1;
                    if level_index >= self.levels.len() {
                        return Err(RadixMapError::InvalidRange);
                    }
                    entry_index = boundary / self.levels[level_index].span_units;
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
        for (level_index, level) in self.levels.iter().enumerate() {
            if cursor % level.span_units == 0 && level.span_units <= end - cursor {
                return (Some(level_index), level.span_units);
            }
        }
        (None, 1)
    }

    fn claim_chunk(&self, terminal_index: usize, target: Option<usize>) -> Result<(), ()> {
        let ancestor_end = target.unwrap_or(self.levels.len());
        for level_index in 0..ancestor_end {
            let index = terminal_index / self.levels[level_index].span_units;
            loop {
                match self.levels[level_index]
                    .states
                    .load(index, Ordering::Acquire)
                {
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
                let index = terminal_index / self.levels[level_index].span_units;
                self.levels[level_index].states.compare_exchange(
                    index,
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
            let index = terminal_index / self.levels[level_index].span_units;
            loop {
                let state = self.levels[level_index]
                    .states
                    .load(index, Ordering::Acquire);
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
                if self.levels[level_index]
                    .states
                    .compare_exchange(
                        index,
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

    unsafe fn release_chunk(&self, terminal_index: usize, target: Option<usize>) {
        let ancestor_end = target.unwrap_or(self.levels.len());
        unsafe { self.release_target(terminal_index, target) };
        self.repair_ancestors(terminal_index, ancestor_end);
    }

    unsafe fn release_target(&self, terminal_index: usize, target: Option<usize>) {
        let result = match target {
            Some(level_index) => {
                let index = terminal_index / self.levels[level_index].span_units;
                self.levels[level_index].states.compare_exchange(
                    index,
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
            let index = terminal_index / self.levels[level_index].span_units;
            if self.levels[level_index]
                .states
                .compare_exchange(
                    index,
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
    }

    fn help_update(&self, level_index: usize, index: usize) {
        if self.levels[level_index]
            .states
            .load(index, Ordering::Acquire)
            != RadixState::Updating as usize
        {
            return;
        }
        let first_child = index * RADIX;
        let occupied = if level_index + 1 < self.levels.len() {
            let children = &self.levels[level_index + 1].states;
            let end = first_child.saturating_add(RADIX).min(children.len());
            (first_child..end)
                .any(|child| children.load(child, Ordering::Acquire) != RadixState::Empty as usize)
        } else {
            let end = first_child.saturating_add(RADIX).min(self.terminal.len());
            (first_child..end).any(|child| self.terminal.load(child, Ordering::Acquire) != 0)
        };
        let next = if occupied {
            RadixState::Partial
        } else {
            RadixState::Empty
        };
        let _ = self.levels[level_index].states.compare_exchange(
            index,
            RadixState::Updating as usize,
            next as usize,
            Ordering::Release,
            Ordering::Relaxed,
        );
    }

    fn expand_full(&self, level_index: usize, index: usize) -> Result<(), RadixMapError> {
        if self.levels[level_index]
            .states
            .load(index, Ordering::Acquire)
            != RadixState::Full as usize
        {
            return Err(RadixMapError::Conflict);
        }
        let first_child = index
            .checked_mul(RADIX)
            .ok_or(RadixMapError::LengthOverflow)?;
        if level_index + 1 < self.levels.len() {
            let children = &self.levels[level_index + 1].states;
            let end = first_child
                .checked_add(RADIX)
                .ok_or(RadixMapError::LengthOverflow)?;
            if end > children.len() {
                return Err(RadixMapError::InvalidRange);
            }
            for child in first_child..end {
                children
                    .compare_exchange(
                        child,
                        RadixState::Empty as usize,
                        RadixState::Full as usize,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .map_err(|_| RadixMapError::Conflict)?;
            }
        } else {
            let end = first_child
                .checked_add(RADIX)
                .ok_or(RadixMapError::LengthOverflow)?;
            if end > self.terminal.len() {
                return Err(RadixMapError::InvalidRange);
            }
            for child in first_child..end {
                self.terminal
                    .compare_exchange(child, 0, 1, Ordering::AcqRel, Ordering::Acquire)
                    .map_err(|_| RadixMapError::Conflict)?;
            }
        }
        self.levels[level_index]
            .states
            .compare_exchange(
                index,
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
