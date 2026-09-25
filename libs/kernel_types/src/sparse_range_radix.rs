use alloc::alloc::{Layout, alloc, dealloc};
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use portable_atomic::AtomicU128;

use crate::state_map::AtomicStateMap;

#[cfg(not(target_pointer_width = "64"))]
compile_error!("SparseRangeRadix requires 64-bit pointers");

const RADIX_BITS: usize = 4;
const RADIX: usize = 1 << RADIX_BITS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SparseRangeRadixError {
    Conflict,
    OutOfRange,
    AllocationFailed,
}

#[derive(Clone, Copy, Debug, Default)]
struct RangeSummary {
    prefix_free: u64,
    suffix_free: u64,
    max_free: u64,
}

struct AtomicRangeSummary {
    prefix_free: AtomicU64,
    suffix_free: AtomicU64,
    max_free: AtomicU64,
    dirty: AtomicBool,
}

impl AtomicRangeSummary {
    fn new() -> Self {
        Self {
            prefix_free: AtomicU64::new(0),
            suffix_free: AtomicU64::new(0),
            max_free: AtomicU64::new(0),
            dirty: AtomicBool::new(true),
        }
    }

    fn load(&self) -> RangeSummary {
        RangeSummary {
            prefix_free: self.prefix_free.load(Ordering::Acquire),
            suffix_free: self.suffix_free.load(Ordering::Acquire),
            max_free: self.max_free.load(Ordering::Acquire),
        }
    }

    fn store(&self, summary: RangeSummary) {
        self.prefix_free
            .store(summary.prefix_free, Ordering::Release);
        self.suffix_free
            .store(summary.suffix_free, Ordering::Release);
        self.max_free.store(summary.max_free, Ordering::Release);
        self.dirty.store(false, Ordering::Release);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RangeEntry {
    Empty,
    Full,
    Node { ptr: *mut (), occupancy: u16 },
}

#[repr(transparent)]
struct AtomicRangeEntry {
    raw: AtomicU128,
}

impl AtomicRangeEntry {
    fn new(entry: RangeEntry) -> Self {
        Self {
            raw: AtomicU128::new(Self::pack(entry)),
        }
    }

    fn pack(entry: RangeEntry) -> u128 {
        match entry {
            RangeEntry::Empty => 0,
            RangeEntry::Full => 1u128 << 80,
            RangeEntry::Node { ptr, occupancy } => {
                (ptr as usize as u128) | ((occupancy as u128) << 64) | (2u128 << 80)
            }
        }
    }

    fn unpack(raw: u128) -> RangeEntry {
        match (raw >> 80) & 3 {
            0 => RangeEntry::Empty,
            1 => RangeEntry::Full,
            2 => RangeEntry::Node {
                ptr: raw as u64 as usize as *mut (),
                occupancy: ((raw >> 64) & 0xffff) as u16,
            },
            _ => unreachable!(),
        }
    }

    fn load(&self) -> RangeEntry {
        Self::unpack(self.raw.load(Ordering::Acquire))
    }

    fn compare_exchange(&self, old: RangeEntry, new: RangeEntry) -> Result<(), RangeEntry> {
        self.raw
            .compare_exchange(
                Self::pack(old),
                Self::pack(new),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map(|_| ())
            .map_err(Self::unpack)
    }

    fn try_acquire_node(&self) -> Result<(*mut (), u16), RangeEntry> {
        loop {
            let old = self.load();
            let RangeEntry::Node { ptr, occupancy } = old else {
                return Err(old);
            };
            let Some(next) = occupancy.checked_add(1) else {
                return Err(old);
            };
            if self
                .compare_exchange(
                    old,
                    RangeEntry::Node {
                        ptr,
                        occupancy: next,
                    },
                )
                .is_ok()
            {
                return Ok((ptr, next));
            }
        }
    }

    fn release_acquired_node(&self, ptr: *mut (), delta: i32) -> u16 {
        loop {
            let old = self.load();
            let RangeEntry::Node {
                ptr: current,
                occupancy,
            } = old
            else {
                unreachable!()
            };
            assert_eq!(current, ptr);
            let adjusted = i32::from(occupancy) + delta;
            assert!(adjusted >= 0);
            if adjusted > u16::MAX as i32 {
                core::hint::spin_loop();
                continue;
            }
            let next = adjusted as u16;
            if self
                .compare_exchange(
                    old,
                    RangeEntry::Node {
                        ptr,
                        occupancy: next,
                    },
                )
                .is_ok()
            {
                return next;
            }
        }
    }

    fn try_publish_node(&self, old: RangeEntry, ptr: *mut (), occupancy: u16) -> bool {
        self.compare_exchange(old, RangeEntry::Node { ptr, occupancy })
            .is_ok()
    }

    fn try_detach_empty_node(&self, ptr: *mut ()) -> bool {
        self.compare_exchange(RangeEntry::Node { ptr, occupancy: 0 }, RangeEntry::Empty)
            .is_ok()
    }
}

struct RangeRadixNode {
    entries: [AtomicRangeEntry; RADIX],
    summary: AtomicRangeSummary,
}

impl RangeRadixNode {
    fn new(full: bool) -> Self {
        Self {
            entries: core::array::from_fn(|_| {
                AtomicRangeEntry::new(if full {
                    RangeEntry::Full
                } else {
                    RangeEntry::Empty
                })
            }),
            summary: AtomicRangeSummary::new(),
        }
    }
}

struct RangeTerminalNode {
    allocations: AtomicStateMap<1>,
    summary: AtomicRangeSummary,
}

impl RangeTerminalNode {
    fn try_new(full: bool) -> Result<Self, SparseRangeRadixError> {
        let allocations = AtomicStateMap::<1>::try_new(RADIX)
            .map_err(|_| SparseRangeRadixError::AllocationFailed)?;
        if full {
            allocations.fetch_or_word(0, (1u64 << RADIX) - 1, Ordering::Release);
        }
        Ok(Self {
            allocations,
            summary: AtomicRangeSummary::new(),
        })
    }
}

pub struct SparseRangeRadix {
    root: RangeRadixNode,
    units: u64,
    levels: u8,
    root_occupancy: AtomicU64,
    needs_prune: AtomicBool,
}

impl core::fmt::Debug for SparseRangeRadix {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SparseRangeRadix")
            .field("units", &self.units)
            .field("levels", &self.levels)
            .finish()
    }
}

unsafe impl Send for SparseRangeRadix {}
unsafe impl Sync for SparseRangeRadix {}

impl SparseRangeRadix {
    pub fn try_new(units: u64) -> Result<Self, SparseRangeRadixError> {
        if units == 0 {
            return Err(SparseRangeRadixError::OutOfRange);
        }
        if !AtomicU128::is_lock_free() {
            return Err(SparseRangeRadixError::AllocationFailed);
        }
        let mut child_span = RADIX as u128;
        let mut levels = 0;
        while child_span * (RADIX as u128) < units as u128 {
            child_span *= RADIX as u128;
            levels += 1;
        }
        Ok(Self {
            root: RangeRadixNode::new(false),
            units,
            levels,
            root_occupancy: AtomicU64::new(0),
            needs_prune: AtomicBool::new(false),
        })
    }

    fn root_child_span(&self) -> u128 {
        (RADIX as u128) << (self.levels as usize * RADIX_BITS)
    }

    fn validate(&self, first: u64, count: u64) -> Result<(), SparseRangeRadixError> {
        if count == 0 || first.checked_add(count).is_none_or(|end| end > self.units) {
            Err(SparseRangeRadixError::OutOfRange)
        } else {
            Ok(())
        }
    }

    fn next_chunk(first: u64, remaining: u64, maximum: u128) -> u64 {
        let mut span = 1u128;
        while span * RADIX as u128 <= maximum
            && span * RADIX as u128 <= remaining as u128
            && (first as u128) % (span * RADIX as u128) == 0
        {
            span *= RADIX as u128;
        }
        span as u64
    }

    pub fn try_claim(&self, first: u64, count: u64) -> Result<(), SparseRangeRadixError> {
        self.validate(first, count)?;
        let mut cursor = first;
        let end = first + count;
        while cursor < end {
            let chunk = Self::next_chunk(cursor, end - cursor, self.root_child_span());
            self.root_occupancy.fetch_add(1, Ordering::AcqRel);
            match self.claim_node(
                &self.root,
                self.root_child_span(),
                cursor as u128,
                chunk as u128,
            ) {
                Ok(delta) => {
                    self.root_occupancy
                        .fetch_sub(1 - delta as u64, Ordering::AcqRel);
                }
                Err(error) => {
                    self.root_occupancy.fetch_sub(1, Ordering::AcqRel);
                    if cursor > first {
                        unsafe { self.release(first, cursor - first) };
                    }
                    self.prune_if_needed();
                    return Err(error);
                }
            }
            cursor += chunk;
        }
        self.prune_if_needed();
        Ok(())
    }

    fn claim_node(
        &self,
        node: &RangeRadixNode,
        child_span: u128,
        first: u128,
        count: u128,
    ) -> Result<i32, SparseRangeRadixError> {
        node.summary.dirty.store(true, Ordering::Release);
        let index = ((first / child_span) % RADIX as u128) as usize;
        let entry = &node.entries[index];
        let whole = first % child_span == 0 && count == child_span;
        loop {
            match entry.load() {
                RangeEntry::Full => return Err(SparseRangeRadixError::Conflict),
                RangeEntry::Empty if whole => {
                    if entry
                        .compare_exchange(RangeEntry::Empty, RangeEntry::Full)
                        .is_ok()
                    {
                        return Ok(1);
                    }
                }
                RangeEntry::Empty => {
                    let terminal = child_span == RADIX as u128;
                    let ptr = if terminal {
                        let child = RangeTerminalNode::try_new(false)?;
                        unsafe { allocate(child)? as *mut () }
                    } else {
                        unsafe { allocate(RangeRadixNode::new(false))? as *mut () }
                    };
                    let occupancy = match self.claim_child(ptr, child_span, first, count) {
                        Ok(delta) => delta as u16,
                        Err(error) => {
                            unsafe { free_tree(ptr, child_span) };
                            return Err(error);
                        }
                    };
                    if entry.try_publish_node(RangeEntry::Empty, ptr, occupancy) {
                        return Ok(1);
                    }
                    unsafe { free_tree(ptr, child_span) };
                }
                RangeEntry::Node { .. } => {
                    let Ok((ptr, _)) = entry.try_acquire_node() else {
                        if matches!(
                            entry.load(),
                            RangeEntry::Node {
                                occupancy: u16::MAX,
                                ..
                            }
                        ) {
                            return Err(SparseRangeRadixError::AllocationFailed);
                        }
                        continue;
                    };
                    let result = self.claim_child(ptr, child_span, first, count);
                    let delta = result.as_ref().copied().unwrap_or(0);
                    if entry.release_acquired_node(ptr, delta - 1) == 0 {
                        self.needs_prune.store(true, Ordering::Release);
                    }
                    return result.map(|_| 0);
                }
            }
        }
    }

    fn claim_child(
        &self,
        ptr: *mut (),
        span: u128,
        first: u128,
        count: u128,
    ) -> Result<i32, SparseRangeRadixError> {
        if span == RADIX as u128 {
            let terminal = unsafe { &*(ptr as *mut RangeTerminalNode) };
            terminal.summary.dirty.store(true, Ordering::Release);
            let start = (first % span) as usize;
            let mut claimed = 0;
            for index in start..start + count as usize {
                if terminal
                    .allocations
                    .compare_exchange(index, 0, 1, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
                {
                    for rollback in start..start + claimed {
                        terminal
                            .allocations
                            .compare_exchange(rollback, 1, 0, Ordering::AcqRel, Ordering::Acquire)
                            .expect("claim rollback lost ownership");
                    }
                    return Err(SparseRangeRadixError::Conflict);
                }
                claimed += 1;
            }
            Ok(claimed as i32)
        } else {
            let child = unsafe { &*(ptr as *mut RangeRadixNode) };
            self.claim_node(child, span / RADIX as u128, first, count)
        }
    }

    pub unsafe fn release(&self, first: u64, count: u64) {
        if self.validate(first, count).is_err() {
            return;
        }
        let mut cursor = first;
        let end = first + count;
        while cursor < end {
            let chunk = Self::next_chunk(cursor, end - cursor, self.root_child_span());
            self.root_occupancy.fetch_add(1, Ordering::AcqRel);
            let delta = self.release_node(
                &self.root,
                self.root_child_span(),
                cursor as u128,
                chunk as u128,
            );
            self.root_occupancy
                .fetch_sub(1 + delta as u64, Ordering::AcqRel);
            cursor += chunk;
        }
        self.prune_if_needed();
    }

    fn release_node(
        &self,
        node: &RangeRadixNode,
        child_span: u128,
        first: u128,
        count: u128,
    ) -> i32 {
        node.summary.dirty.store(true, Ordering::Release);
        let index = ((first / child_span) % RADIX as u128) as usize;
        let entry = &node.entries[index];
        let whole = first % child_span == 0 && count == child_span;
        loop {
            match entry.load() {
                RangeEntry::Empty => return 0,
                RangeEntry::Full if whole => {
                    if entry
                        .compare_exchange(RangeEntry::Full, RangeEntry::Empty)
                        .is_ok()
                    {
                        return 1;
                    }
                }
                RangeEntry::Full => {
                    let terminal = child_span == RADIX as u128;
                    let ptr = if terminal {
                        let Ok(child) = RangeTerminalNode::try_new(true) else {
                            panic!("range release metadata allocation failed")
                        };
                        unsafe {
                            allocate(child).expect("range release metadata allocation failed")
                                as *mut ()
                        }
                    } else {
                        unsafe {
                            allocate(RangeRadixNode::new(true))
                                .expect("range release metadata allocation failed")
                                as *mut ()
                        }
                    };
                    let removed = self.release_child(ptr, child_span, first, count);
                    if entry.try_publish_node(RangeEntry::Full, ptr, RADIX as u16 - removed as u16)
                    {
                        return 0;
                    }
                    unsafe { free_tree(ptr, child_span) };
                }
                RangeEntry::Node { .. } => {
                    let Ok((ptr, _)) = entry.try_acquire_node() else {
                        continue;
                    };
                    let removed = self.release_child(ptr, child_span, first, count);
                    let remaining = entry.release_acquired_node(ptr, -removed - 1);
                    if remaining == 0 && entry.try_detach_empty_node(ptr) {
                        unsafe { free_child(ptr, child_span == RADIX as u128) };
                        return 1;
                    }
                    return 0;
                }
            }
        }
    }

    fn release_child(&self, ptr: *mut (), span: u128, first: u128, count: u128) -> i32 {
        if span == RADIX as u128 {
            let terminal = unsafe { &*(ptr as *mut RangeTerminalNode) };
            terminal.summary.dirty.store(true, Ordering::Release);
            let start = (first % span) as usize;
            let mut removed = 0;
            for index in start..start + count as usize {
                if terminal
                    .allocations
                    .compare_exchange(index, 1, 0, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    removed += 1;
                }
            }
            removed
        } else {
            let child = unsafe { &*(ptr as *mut RangeRadixNode) };
            self.release_node(child, span / RADIX as u128, first, count)
        }
    }

    fn terminal_summary(terminal: &RangeTerminalNode, valid: usize) -> RangeSummary {
        let bits = terminal.allocations.load_word(0, Ordering::Acquire);
        let mut prefix = 0;
        let mut suffix = 0;
        let mut maximum = 0;
        let mut run = 0;
        for index in 0..valid {
            if bits & (1 << index) == 0 {
                run += 1;
                maximum = maximum.max(run);
                if run as usize == index + 1 {
                    prefix = run;
                }
            } else {
                run = 0;
            }
        }
        for index in (0..valid).rev() {
            if bits & (1 << index) != 0 {
                break;
            }
            suffix += 1;
        }
        RangeSummary {
            prefix_free: prefix,
            suffix_free: suffix,
            max_free: maximum,
        }
    }

    fn repair_node(&self, node: &RangeRadixNode, base: u128, child_span: u128) -> RangeSummary {
        let mut prefix = 0u64;
        let mut suffix = 0u64;
        let mut maximum = 0u64;
        let mut run = 0u64;
        let mut all_prefix = true;
        for index in 0..RADIX {
            let child_base = base + index as u128 * child_span;
            let valid = (self.units as u128)
                .saturating_sub(child_base)
                .min(child_span) as u64;
            if valid == 0 {
                break;
            }
            let entry = &node.entries[index];
            let summary = loop {
                match entry.load() {
                    RangeEntry::Empty => {
                        break RangeSummary {
                            prefix_free: valid,
                            suffix_free: valid,
                            max_free: valid,
                        };
                    }
                    RangeEntry::Full => break RangeSummary::default(),
                    RangeEntry::Node { .. } => {
                        let Ok((ptr, _)) = entry.try_acquire_node() else {
                            continue;
                        };
                        let result = if child_span == RADIX as u128 {
                            let child = unsafe { &*(ptr as *mut RangeTerminalNode) };
                            let result = Self::terminal_summary(child, valid as usize);
                            child.summary.store(result);
                            result
                        } else {
                            let child = unsafe { &*(ptr as *mut RangeRadixNode) };
                            self.repair_node(child, child_base, child_span / RADIX as u128)
                        };
                        if entry.release_acquired_node(ptr, -1) == 0 {
                            self.needs_prune.store(true, Ordering::Release);
                        }
                        break result;
                    }
                }
            };
            maximum = maximum
                .max(summary.max_free)
                .max(run.saturating_add(summary.prefix_free));
            if all_prefix {
                prefix = prefix.saturating_add(summary.prefix_free);
                all_prefix = summary.prefix_free == valid;
            }
            run = if summary.suffix_free == valid {
                run.saturating_add(valid)
            } else {
                summary.suffix_free
            };
            suffix = run;
        }
        let result = RangeSummary {
            prefix_free: prefix,
            suffix_free: suffix,
            max_free: maximum,
        };
        node.summary.store(result);
        result
    }

    fn find_free(
        &self,
        node: &RangeRadixNode,
        base: u128,
        child_span: u128,
        start: u128,
        summarized: bool,
        needed: u64,
    ) -> Option<u64> {
        if start >= self.units as u128 {
            return None;
        }
        for index in 0..RADIX {
            let child_base = base + index as u128 * child_span;
            if child_base >= self.units as u128 {
                return None;
            }
            let child_end = child_base + child_span;
            if child_end <= start {
                continue;
            }
            let entry = &node.entries[index];
            loop {
                match entry.load() {
                    RangeEntry::Empty => return Some(start.max(child_base) as u64),
                    RangeEntry::Full => break,
                    RangeEntry::Node { .. } => {
                        let Ok((ptr, _)) = entry.try_acquire_node() else {
                            continue;
                        };
                        let result = if child_span == RADIX as u128 {
                            let terminal = unsafe { &*(ptr as *mut RangeTerminalNode) };
                            ((start.max(child_base) - child_base) as usize
                                ..(self.units as u128 - child_base).min(child_span) as usize)
                                .find(|&bit| terminal.allocations.load(bit, Ordering::Acquire) == 0)
                                .map(|bit| (child_base + bit as u128) as u64)
                        } else {
                            let child = unsafe { &*(ptr as *mut RangeRadixNode) };
                            let summary = child.summary.load();
                            if summarized
                                && !child.summary.dirty.load(Ordering::Acquire)
                                && summary.max_free < needed
                                && summary.prefix_free == 0
                                && summary.suffix_free == 0
                            {
                                None
                            } else {
                                self.find_free(
                                    child,
                                    child_base,
                                    child_span / RADIX as u128,
                                    start,
                                    summarized,
                                    needed,
                                )
                            }
                        };
                        if entry.release_acquired_node(ptr, -1) == 0 {
                            self.needs_prune.store(true, Ordering::Release);
                        }
                        if result.is_some_and(|unit| unit < self.units) {
                            return result;
                        }
                        break;
                    }
                }
            }
        }
        None
    }

    fn find_allocated(
        &self,
        node: &RangeRadixNode,
        base: u128,
        child_span: u128,
        start: u128,
    ) -> Option<u64> {
        if start >= self.units as u128 {
            return None;
        }
        for index in 0..RADIX {
            let child_base = base + index as u128 * child_span;
            if child_base >= self.units as u128 {
                return None;
            }
            if child_base + child_span <= start {
                continue;
            }
            let entry = &node.entries[index];
            loop {
                match entry.load() {
                    RangeEntry::Empty => break,
                    RangeEntry::Full => return Some(start.max(child_base) as u64),
                    RangeEntry::Node { .. } => {
                        let Ok((ptr, _)) = entry.try_acquire_node() else {
                            continue;
                        };
                        let result = if child_span == RADIX as u128 {
                            let terminal = unsafe { &*(ptr as *mut RangeTerminalNode) };
                            ((start.max(child_base) - child_base) as usize
                                ..(self.units as u128 - child_base).min(child_span) as usize)
                                .find(|&bit| terminal.allocations.load(bit, Ordering::Acquire) != 0)
                                .map(|bit| (child_base + bit as u128) as u64)
                        } else {
                            let child = unsafe { &*(ptr as *mut RangeRadixNode) };
                            self.find_allocated(
                                child,
                                child_base,
                                child_span / RADIX as u128,
                                start,
                            )
                        };
                        if entry.release_acquired_node(ptr, -1) == 0 {
                            self.needs_prune.store(true, Ordering::Release);
                        }
                        if result.is_some() {
                            return result;
                        }
                        break;
                    }
                }
            }
        }
        None
    }

    fn prune_node(&self, node: &RangeRadixNode, child_span: u128) -> u64 {
        let mut removed = 0;
        for entry in &node.entries {
            loop {
                match entry.load() {
                    RangeEntry::Empty | RangeEntry::Full => break,
                    RangeEntry::Node { ptr, occupancy: 0 } => {
                        if entry.try_detach_empty_node(ptr) {
                            node.summary.dirty.store(true, Ordering::Release);
                            unsafe { free_child(ptr, child_span == RADIX as u128) };
                            removed += 1;
                            break;
                        }
                    }
                    RangeEntry::Node { .. } => {
                        let Ok((ptr, _)) = entry.try_acquire_node() else {
                            continue;
                        };
                        let child_removed = if child_span == RADIX as u128 {
                            0
                        } else {
                            let child = unsafe { &*(ptr as *mut RangeRadixNode) };
                            self.prune_node(child, child_span / RADIX as u128)
                        };
                        let remaining =
                            entry.release_acquired_node(ptr, -(child_removed as i32) - 1);
                        if remaining == 0 && entry.try_detach_empty_node(ptr) {
                            node.summary.dirty.store(true, Ordering::Release);
                            unsafe { free_child(ptr, child_span == RADIX as u128) };
                            removed += 1;
                        }
                        break;
                    }
                }
            }
        }
        removed
    }

    fn prune_if_needed(&self) {
        if self.needs_prune.swap(false, Ordering::AcqRel) {
            self.root_occupancy.fetch_add(1, Ordering::AcqRel);
            let removed = self.prune_node(&self.root, self.root_child_span());
            self.root_occupancy.fetch_sub(removed + 1, Ordering::AcqRel);
        }
    }

    fn find_free_root(&self, start: u128, summarized: bool, needed: u64) -> Option<u64> {
        let result = self.find_free(
            &self.root,
            0,
            self.root_child_span(),
            start,
            summarized,
            needed,
        );
        self.prune_if_needed();
        result
    }

    fn find_allocated_root(&self, start: u128) -> Option<u64> {
        let result = self.find_allocated(&self.root, 0, self.root_child_span(), start);
        self.prune_if_needed();
        result
    }

    pub fn try_claim_auto(&self, count: u64, alignment: u64) -> Result<u64, SparseRangeRadixError> {
        if count == 0 || count > self.units || alignment == 0 || !alignment.is_power_of_two() {
            return Err(SparseRangeRadixError::OutOfRange);
        }
        self.repair_node(&self.root, 0, self.root_child_span());
        self.prune_if_needed();
        let mut summarized = true;
        let mut cursor = 0u128;
        loop {
            if cursor >= self.units as u128 {
                if summarized {
                    summarized = false;
                    cursor = 0;
                    continue;
                }
                return Err(SparseRangeRadixError::OutOfRange);
            }
            let free = match self.find_free_root(cursor, summarized, count) {
                Some(free) => free as u128,
                None if summarized => {
                    summarized = false;
                    cursor = 0;
                    continue;
                }
                None => return Err(SparseRangeRadixError::OutOfRange),
            };
            let exact = self
                .find_free_root(cursor, false, count)
                .unwrap_or(self.units);
            let free = free.min(exact as u128);
            let aligned = (free + alignment as u128 - 1) & !(alignment as u128 - 1);
            if aligned + count as u128 > self.units as u128 {
                if summarized {
                    summarized = false;
                    cursor = 0;
                    continue;
                }
                return Err(SparseRangeRadixError::OutOfRange);
            }
            if let Some(occupied) = self.find_allocated_root(aligned) {
                if occupied as u128 >= aligned + count as u128 {
                    match self.try_claim(aligned as u64, count) {
                        Ok(()) => return Ok(aligned as u64),
                        Err(SparseRangeRadixError::Conflict) => {}
                        Err(error) => return Err(error),
                    }
                    cursor = aligned + alignment as u128;
                } else {
                    cursor = occupied as u128 + 1;
                }
            } else {
                match self.try_claim(aligned as u64, count) {
                    Ok(()) => return Ok(aligned as u64),
                    Err(SparseRangeRadixError::Conflict) => {}
                    Err(error) => return Err(error),
                }
                cursor = aligned + alignment as u128;
            }
        }
    }

    pub fn next_allocation(&self, start: u64) -> Option<(u64, u64)> {
        let mut cursor = start;
        loop {
            let first = self.find_allocated_root(cursor as u128)?;
            let end = self
                .find_free_root(first as u128, false, 1)
                .unwrap_or(self.units);
            if end > first {
                return Some((first, end - first));
            }
            cursor = first.checked_add(1)?;
        }
    }
}

impl Drop for SparseRangeRadix {
    fn drop(&mut self) {
        unsafe {
            free_descendants(&self.root, self.root_child_span());
        }
    }
}

unsafe fn free_descendants(node: &RangeRadixNode, child_span: u128) {
    for entry in &node.entries {
        if let Ok((ptr, _)) = entry.try_acquire_node() {
            if child_span != RADIX as u128 {
                unsafe {
                    free_descendants(&*(ptr as *mut RangeRadixNode), child_span / RADIX as u128);
                }
            }
            entry.release_acquired_node(ptr, -1);
            unsafe {
                free_child(ptr, child_span == RADIX as u128);
            }
        }
    }
}

unsafe fn free_tree(ptr: *mut (), span: u128) {
    if span != RADIX as u128 {
        unsafe {
            free_descendants(&*(ptr as *mut RangeRadixNode), span / RADIX as u128);
        }
    }
    unsafe {
        free_child(ptr, span == RADIX as u128);
    }
}

unsafe fn allocate<T>(value: T) -> Result<*mut T, SparseRangeRadixError> {
    let ptr = unsafe { alloc(Layout::new::<T>()) as *mut T };
    if ptr.is_null() {
        return Err(SparseRangeRadixError::AllocationFailed);
    }
    unsafe { ptr.write(value) };
    Ok(ptr)
}

unsafe fn free_child(ptr: *mut (), terminal: bool) {
    if terminal {
        let ptr = ptr as *mut RangeTerminalNode;
        unsafe {
            ptr::drop_in_place(ptr);
            dealloc(ptr.cast(), Layout::new::<RangeTerminalNode>());
        }
    } else {
        let ptr = ptr as *mut RangeRadixNode;
        unsafe {
            ptr::drop_in_place(ptr);
            dealloc(ptr.cast(), Layout::new::<RangeRadixNode>());
        }
    }
}
