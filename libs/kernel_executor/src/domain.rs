use crate::future_arena::{FutureArena, FutureArenaConfig};
use crate::global_async::CacheAligned;
use crate::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};
use crate::sync::Arc;
use alloc::boxed::Box;
use core::ptr;
use core::sync::atomic::AtomicPtr;

const BUILTIN_GENERATION: u32 = 1;
const KERNEL_HIGH_SLOT: u32 = 0;
const DRIVER_SLOT: u32 = 1;
const KERNEL_NORMAL_SLOT: u32 = 2;
const KERNEL_BACKGROUND_SLOT: u32 = 3;

const DOMAIN_SLOT_EMPTY: usize = 0;
const DOMAIN_SLOT_RESERVED: usize = 1;
const DOMAIN_SLOT_ACTIVE: usize = 2;
const DOMAIN_SLOT_BUILTIN: usize = 3;

const DOMAIN_CHUNK_BITS: usize = 6;
const DOMAIN_CHUNK_SIZE: usize = 1 << DOMAIN_CHUNK_BITS;
const DOMAIN_CHUNK_MASK: usize = DOMAIN_CHUNK_SIZE - 1;
const MAX_DOMAIN_CHUNKS: usize = 64;
const MAX_DOMAIN_SLOTS: usize = DOMAIN_CHUNK_SIZE * MAX_DOMAIN_CHUNKS;
const TASK_ID_BITS: u32 = 35;
const TASK_ID_MASK: u64 = (1u64 << TASK_ID_BITS) - 1;
const READY_TAG_MASK: u64 = (1u64 << (64 - TASK_ID_BITS)) - 1;
pub const MAX_READY_SHARDS: usize = 64;

#[repr(align(64))]
struct ReadyHead(AtomicU64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct ExecutorDomainId(u64);

impl ExecutorDomainId {
    pub const fn from_parts(slot: u32, generation: u32) -> Self {
        Self(((generation as u64) << 32) | slot as u64)
    }

    pub const fn raw(self) -> u64 {
        self.0
    }

    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    pub const fn slot(self) -> u32 {
        self.0 as u32
    }

    pub const fn generation(self) -> u32 {
        (self.0 >> 32) as u32
    }

    pub const fn is_valid(self) -> bool {
        self.generation() != 0
    }
}

pub const KERNEL_HIGH_EXECUTOR_DOMAIN: ExecutorDomainId =
    ExecutorDomainId::from_parts(KERNEL_HIGH_SLOT, BUILTIN_GENERATION);
pub const DRIVER_EXECUTOR_DOMAIN: ExecutorDomainId =
    ExecutorDomainId::from_parts(DRIVER_SLOT, BUILTIN_GENERATION);
pub const KERNEL_NORMAL_EXECUTOR_DOMAIN: ExecutorDomainId =
    ExecutorDomainId::from_parts(KERNEL_NORMAL_SLOT, BUILTIN_GENERATION);
pub const KERNEL_BACKGROUND_EXECUTOR_DOMAIN: ExecutorDomainId =
    ExecutorDomainId::from_parts(KERNEL_BACKGROUND_SLOT, BUILTIN_GENERATION);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ExecutorDomainClass {
    KernelHigh = 0,
    Driver = 1,
    KernelNormal = 2,
    ProcessIo = 3,
    KernelBackground = 4,
}

impl ExecutorDomainClass {
    pub const fn default_weight(self) -> usize {
        match self {
            ExecutorDomainClass::KernelHigh => 8,
            ExecutorDomainClass::Driver => 6,
            ExecutorDomainClass::KernelNormal => 4,
            ExecutorDomainClass::ProcessIo => 3,
            ExecutorDomainClass::KernelBackground => 1,
        }
    }

    pub const fn default_quantum(self) -> usize {
        match self {
            ExecutorDomainClass::KernelHigh => 8,
            ExecutorDomainClass::Driver => 6,
            ExecutorDomainClass::KernelNormal => 4,
            ExecutorDomainClass::ProcessIo => 4,
            ExecutorDomainClass::KernelBackground => 1,
        }
    }

    pub fn default_max_active(self, cpu_count: usize) -> usize {
        let cpu_count = cpu_count.max(1);

        match self {
            ExecutorDomainClass::KernelHigh => cpu_count,
            ExecutorDomainClass::Driver => (cpu_count / 2).max(1),
            ExecutorDomainClass::KernelNormal => cpu_count,
            ExecutorDomainClass::ProcessIo => (cpu_count / 4).max(1),
            ExecutorDomainClass::KernelBackground => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ExecutorDomainState {
    Active = 0,
    Draining = 1,
    Dead = 2,
}

impl ExecutorDomainState {
    const fn from_u8(value: u8) -> Self {
        match value {
            0 => ExecutorDomainState::Active,
            1 => ExecutorDomainState::Draining,
            _ => ExecutorDomainState::Dead,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ExecutorDomainConfig {
    pub class: ExecutorDomainClass,
    pub max_active: usize,
    pub quantum: usize,
    pub weight: usize,
    pub future_arena: FutureArenaConfig,
    pub ready_shards: usize,
}

impl ExecutorDomainConfig {
    pub fn for_class(class: ExecutorDomainClass, cpu_count: usize) -> Self {
        Self {
            class,
            max_active: class.default_max_active(cpu_count),
            quantum: class.default_quantum(),
            weight: class.default_weight(),
            future_arena: FutureArenaConfig::default(),
            ready_shards: cpu_count.clamp(1, MAX_READY_SHARDS),
        }
    }

    pub fn kernel_normal(cpu_count: usize) -> Self {
        Self::for_class(ExecutorDomainClass::KernelNormal, cpu_count)
    }

    fn normalized(mut self) -> Self {
        self.max_active = self.max_active.max(1);
        self.quantum = self.quantum.max(1);
        self.weight = self.weight.max(1);
        self.ready_shards = self.ready_shards.clamp(1, MAX_READY_SHARDS);
        self
    }
}

impl Default for ExecutorDomainConfig {
    fn default() -> Self {
        Self::kernel_normal(1)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DestroyExecutorDomainError {
    InvalidDomain,
    StaleDomain,
    BuiltinDomain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DestroyExecutorDomainResult {
    Destroyed,
    Draining,
}

#[derive(Clone, Copy, Debug)]
pub struct ExecutorDomainStats {
    pub domain_id: ExecutorDomainId,
    pub generation: u32,
    pub class: ExecutorDomainClass,
    pub state: ExecutorDomainState,
    pub queued_count: usize,
    pub active_count: usize,
    pub live_task_count: usize,
    pub live_future_count: usize,
    pub live_future_bytes: usize,
    pub max_active: usize,
    pub quantum: usize,
    pub weight: usize,
    pub ready_shards: usize,
    pub deficit: usize,
    pub scheduled: bool,
    pub submitted: usize,
    pub completed: usize,
    pub total_runs: usize,
    pub scheduler_selections: usize,
    pub last_run_tick: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct GlobalExecutorStats {
    pub active_pumps: usize,
    pub max_pumps: usize,
    pub runnable_executor_domain_count: usize,
    pub domain_count: usize,
    pub total_submissions: usize,
    pub total_pump_runs: usize,
}

pub struct ExecutorDomain {
    id: ExecutorDomainId,
    generation: u32,
    class: ExecutorDomainClass,
    ready_heads: Box<[ReadyHead]>,
    ready_cursor: CacheAligned,
    future_arena: FutureArena,
    live_task_count: CacheAligned,

    state: AtomicU8,
    scheduled_count: CacheAligned,

    queued_count: CacheAligned,
    active_count: CacheAligned,
    max_active: CacheAligned,

    quantum: CacheAligned,
    weight: CacheAligned,
    deficit: CacheAligned,

    submitted: CacheAligned,
    completed: CacheAligned,
    total_runs: CacheAligned,
    scheduler_selections: CacheAligned,
    last_run_tick: CacheAligned,
}

impl ExecutorDomain {
    fn new(id: ExecutorDomainId, config: ExecutorDomainConfig) -> Self {
        let config = config.normalized();

        Self {
            id,
            generation: id.generation(),
            class: config.class,
            ready_heads: (0..config.ready_shards)
                .map(|_| ReadyHead(AtomicU64::new(0)))
                .collect::<alloc::vec::Vec<_>>()
                .into_boxed_slice(),
            ready_cursor: CacheAligned(AtomicUsize::new(0)),
            future_arena: FutureArena::new(id, config.future_arena),
            live_task_count: CacheAligned(AtomicUsize::new(0)),

            state: AtomicU8::new(ExecutorDomainState::Active as u8),
            scheduled_count: CacheAligned(AtomicUsize::new(0)),

            queued_count: CacheAligned(AtomicUsize::new(0)),
            active_count: CacheAligned(AtomicUsize::new(0)),
            max_active: CacheAligned(AtomicUsize::new(config.max_active)),

            quantum: CacheAligned(AtomicUsize::new(config.quantum)),
            weight: CacheAligned(AtomicUsize::new(config.weight)),
            deficit: CacheAligned(AtomicUsize::new(0)),

            submitted: CacheAligned(AtomicUsize::new(0)),
            completed: CacheAligned(AtomicUsize::new(0)),
            total_runs: CacheAligned(AtomicUsize::new(0)),
            scheduler_selections: CacheAligned(AtomicUsize::new(0)),
            last_run_tick: CacheAligned(AtomicUsize::new(0)),
        }
    }

    #[inline]
    pub fn is_scheduled(&self) -> bool {
        self.scheduled_count.0.load(Ordering::Acquire) != 0
    }

    #[inline]
    pub fn is_schedulable_for_policy(&self) -> bool {
        self.is_runnable_for_policy() && !self.is_at_active_limit()
    }

    pub(crate) fn clear_runnable(&self) {
        self.scheduled_count.0.store(0, Ordering::Release);
    }

    pub fn id(&self) -> ExecutorDomainId {
        self.id
    }

    pub fn class(&self) -> ExecutorDomainClass {
        self.class
    }

    pub fn state(&self) -> ExecutorDomainState {
        ExecutorDomainState::from_u8(self.state.load(Ordering::Acquire))
    }

    pub fn quantum(&self) -> usize {
        self.quantum.0.load(Ordering::Acquire).max(1)
    }

    pub fn weight(&self) -> usize {
        self.weight.0.load(Ordering::Acquire).max(1)
    }

    pub fn max_active(&self) -> usize {
        self.max_active.0.load(Ordering::Acquire).max(1)
    }

    pub fn set_max_active(&self, max_active: usize) {
        self.max_active
            .0
            .store(max_active.max(1), Ordering::Release);
    }

    pub fn queued_count(&self) -> usize {
        self.queued_count.0.load(Ordering::Acquire)
    }

    pub fn active_count(&self) -> usize {
        self.active_count.0.load(Ordering::Acquire)
    }

    pub fn future_arena(&self) -> &FutureArena {
        &self.future_arena
    }

    pub fn live_task_count(&self) -> usize {
        self.live_task_count.0.load(Ordering::Acquire)
    }

    pub(crate) fn retain_task(&self) {
        self.live_task_count.0.fetch_add(1, Ordering::AcqRel);
    }

    pub(crate) fn release_task(&self) {
        self.live_task_count.0.fetch_sub(1, Ordering::AcqRel);
        self.maybe_finish_draining();
    }

    pub fn has_queued_work(&self) -> bool {
        self.ready_heads
            .iter()
            .any(|head| head.0.load(Ordering::Acquire) & TASK_ID_MASK != 0)
    }

    pub fn ready_shard_count(&self) -> usize {
        self.ready_heads.len()
    }

    #[inline]
    fn pack_ready(task_id: usize, tag: u64) -> u64 {
        ((tag & READY_TAG_MASK) << TASK_ID_BITS) | (task_id as u64 & TASK_ID_MASK)
    }

    pub(crate) fn enqueue_task(&self, task_id: usize) -> bool {
        if self.state() == ExecutorDomainState::Dead || task_id == 0 {
            return false;
        }
        let Some((shard, local, generation)) = crate::runtime::slab::decode_slab_task_ptr(task_id)
        else {
            return false;
        };
        let slab = crate::runtime::slab::get_task_table();
        let Some(slot) = slab.get_slot(shard, local, generation) else {
            return false;
        };
        self.queued_count.0.fetch_add(1, Ordering::AcqRel);
        let ready_head = &self.ready_heads[task_id % self.ready_heads.len()];
        let mut head = ready_head.0.load(Ordering::Acquire);
        loop {
            let head_id = head & TASK_ID_MASK;
            slot.ready_next.store(head_id as usize, Ordering::Relaxed);
            let tag = ((head >> TASK_ID_BITS).wrapping_add(1)) & READY_TAG_MASK;
            let next = Self::pack_ready(task_id, tag);
            // A failed strong CAS proves that another CPU changed this head.
            match ready_head
                .0
                .compare_exchange(head, next, Ordering::Release, Ordering::Acquire)
            {
                Ok(_) => {
                    break;
                }
                Err(actual) => head = actual,
            }
        }
        self.submitted.0.fetch_add(1, Ordering::Relaxed);
        true
    }

    pub(crate) fn pop_task(&self) -> Option<usize> {
        let shard_count = self.ready_heads.len();
        let start = self.ready_cursor.0.fetch_add(1, Ordering::Relaxed) % shard_count;

        for offset in 0..shard_count {
            if let Some(task_id) = self.pop_task_from_head((start + offset) % shard_count) {
                return Some(task_id);
            }
        }
        None
    }

    fn pop_task_from_head(&self, ready_shard: usize) -> Option<usize> {
        let slab = crate::runtime::slab::get_task_table();
        let ready_head = &self.ready_heads[ready_shard];
        let mut head = ready_head.0.load(Ordering::Acquire);
        loop {
            let task_id = (head & TASK_ID_MASK) as usize;
            if task_id == 0 {
                return None;
            }
            let (shard, local, generation) = crate::runtime::slab::decode_slab_task_ptr(task_id)?;
            let slot = slab.get_slot(shard, local, generation)?;
            let next_id = slot.ready_next.load(Ordering::Acquire);
            let tag = ((head >> TASK_ID_BITS).wrapping_add(1)) & READY_TAG_MASK;
            let next = Self::pack_ready(next_id, tag);
            // As on push, every retry is evidence of concurrent progress.
            match ready_head
                .0
                .compare_exchange(head, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    slot.ready_next.store(0, Ordering::Relaxed);
                    self.queued_count.0.fetch_sub(1, Ordering::AcqRel);
                    return Some(task_id);
                }
                Err(actual) => head = actual,
            }
        }
    }

    pub fn is_runnable_for_policy(&self) -> bool {
        self.state() != ExecutorDomainState::Dead && self.has_queued_work()
    }

    pub fn is_at_active_limit(&self) -> bool {
        self.active_count() >= self.max_active()
    }

    #[inline]
    pub(crate) fn try_reserve_schedule_token(&self) -> bool {
        let max_active = self.max_active();
        let mut scheduled = self.scheduled_count.0.load(Ordering::Acquire);

        loop {
            let active = self.active_count();
            if active >= max_active {
                return false;
            }

            let queued = self.queued_count();
            if scheduled >= queued || active.saturating_add(scheduled) >= max_active {
                return false;
            }

            match self.scheduled_count.0.compare_exchange(
                scheduled,
                scheduled + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(next) => scheduled = next,
            }
        }
    }

    #[inline]
    pub(crate) fn release_schedule_token(&self) {
        let previous = self.scheduled_count.0.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous != 0, "executor domain schedule token underflow");
    }

    pub(crate) fn try_reserve_active(&self) -> bool {
        self.active_count
            .0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < self.max_active()).then_some(active + 1)
            })
            .is_ok()
    }

    pub(crate) fn release_active(&self) {
        self.active_count.0.fetch_sub(1, Ordering::AcqRel);
    }

    pub(crate) fn add_deficit(&self, amount: usize) -> usize {
        self.deficit
            .0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                Some(current.saturating_add(amount))
            })
            .map(|old| old.saturating_add(amount))
            .unwrap_or(amount)
    }

    pub(crate) fn spend_deficit(&self, amount: usize) {
        let _ = self
            .deficit
            .0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                Some(current.saturating_sub(amount))
            });
    }

    pub(crate) fn record_scheduler_selection(&self) {
        self.scheduler_selections.0.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_run_started(&self, tick: usize) {
        self.total_runs.0.fetch_add(1, Ordering::Relaxed);
        self.last_run_tick.0.store(tick, Ordering::Release);
    }

    pub(crate) fn record_completed(&self) {
        self.completed.0.fetch_add(1, Ordering::Relaxed);
    }

    fn move_to_draining(&self) {
        let _ = self.state.compare_exchange(
            ExecutorDomainState::Active as u8,
            ExecutorDomainState::Draining as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    fn move_to_dead(&self) {
        self.state
            .store(ExecutorDomainState::Dead as u8, Ordering::Release);
        self.clear_runnable();
    }

    pub(crate) fn maybe_finish_draining(&self) {
        if self.state() == ExecutorDomainState::Draining
            && self.queued_count() == 0
            && self.active_count() == 0
            && self.live_task_count() == 0
            && self.future_arena.live_futures() == 0
        {
            self.move_to_dead();
        }
    }

    pub fn stats(&self) -> ExecutorDomainStats {
        ExecutorDomainStats {
            domain_id: self.id,
            generation: self.generation,
            class: self.class,
            state: self.state(),
            queued_count: self.queued_count(),
            active_count: self.active_count(),
            live_task_count: self.live_task_count(),
            live_future_count: self.future_arena.live_futures(),
            live_future_bytes: self.future_arena.live_bytes(),
            max_active: self.max_active(),
            quantum: self.quantum(),
            weight: self.weight(),
            ready_shards: self.ready_shard_count(),
            deficit: self.deficit.0.load(Ordering::Acquire),
            scheduled: self.is_scheduled(),
            submitted: self.submitted.0.load(Ordering::Acquire),
            completed: self.completed.0.load(Ordering::Acquire),
            total_runs: self.total_runs.0.load(Ordering::Acquire),
            scheduler_selections: self.scheduler_selections.0.load(Ordering::Acquire),
            last_run_tick: self.last_run_tick.0.load(Ordering::Acquire),
        }
    }
}

struct DomainSlot {
    state: AtomicUsize,
    generation: AtomicUsize,
    domain: AtomicPtr<ExecutorDomain>,
}

impl DomainSlot {
    fn new() -> Self {
        Self {
            state: AtomicUsize::new(DOMAIN_SLOT_EMPTY),
            generation: AtomicUsize::new(BUILTIN_GENERATION as usize),
            domain: AtomicPtr::new(ptr::null_mut()),
        }
    }

    #[inline]
    fn generation(&self) -> u32 {
        self.generation.load(Ordering::Acquire) as u32
    }

    #[inline]
    fn load_domain_ptr(&self) -> *mut ExecutorDomain {
        self.domain.load(Ordering::Acquire)
    }

    #[inline]
    unsafe fn clone_domain_from_ptr(ptr: *mut ExecutorDomain) -> Arc<ExecutorDomain> {
        Arc::increment_strong_count(ptr);
        Arc::from_raw(ptr)
    }
}

struct DomainChunk {
    slots: [DomainSlot; DOMAIN_CHUNK_SIZE],
}

impl DomainChunk {
    fn new() -> Self {
        Self {
            slots: core::array::from_fn(|_| DomainSlot::new()),
        }
    }
}

pub struct ExecutorDomainTable {
    next_slot: AtomicUsize,
    chunks: [AtomicPtr<DomainChunk>; MAX_DOMAIN_CHUNKS],
}

impl ExecutorDomainTable {
    pub(crate) fn new(cpu_count: usize) -> Self {
        let table = Self {
            next_slot: AtomicUsize::new(0),
            chunks: core::array::from_fn(|_| AtomicPtr::new(ptr::null_mut())),
        };

        table.install_builtin(
            KERNEL_HIGH_SLOT,
            ExecutorDomainConfig::for_class(ExecutorDomainClass::KernelHigh, cpu_count),
        );
        table.install_builtin(
            DRIVER_SLOT,
            ExecutorDomainConfig::for_class(ExecutorDomainClass::Driver, cpu_count),
        );
        table.install_builtin(
            KERNEL_NORMAL_SLOT,
            ExecutorDomainConfig::for_class(ExecutorDomainClass::KernelNormal, cpu_count),
        );
        table.install_builtin(
            KERNEL_BACKGROUND_SLOT,
            ExecutorDomainConfig::for_class(ExecutorDomainClass::KernelBackground, cpu_count),
        );

        table
    }

    fn chunk_index(slot_idx: usize) -> usize {
        slot_idx >> DOMAIN_CHUNK_BITS
    }

    fn chunk_slot_index(slot_idx: usize) -> usize {
        slot_idx & DOMAIN_CHUNK_MASK
    }

    fn publish_slot_count(&self, required: usize) {
        let mut current = self.next_slot.load(Ordering::Acquire);

        while current < required {
            match self.next_slot.compare_exchange_weak(
                current,
                required,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(next) => current = next,
            }
        }
    }

    fn get_or_create_chunk(&self, chunk_idx: usize) -> *mut DomainChunk {
        assert!(
            chunk_idx < MAX_DOMAIN_CHUNKS,
            "executor domain table exhausted"
        );

        let existing = self.chunks[chunk_idx].load(Ordering::Acquire);
        if !existing.is_null() {
            return existing;
        }

        let new_chunk = Box::into_raw(Box::new(DomainChunk::new()));

        match self.chunks[chunk_idx].compare_exchange(
            ptr::null_mut(),
            new_chunk,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => new_chunk,
            Err(existing) => {
                unsafe {
                    drop(Box::from_raw(new_chunk));
                }

                existing
            }
        }
    }

    fn get_existing_chunk(&self, chunk_idx: usize) -> Option<*mut DomainChunk> {
        if chunk_idx >= MAX_DOMAIN_CHUNKS {
            return None;
        }

        let chunk = self.chunks[chunk_idx].load(Ordering::Acquire);
        (!chunk.is_null()).then_some(chunk)
    }

    fn get_or_create_slot(&self, slot_idx: usize) -> &DomainSlot {
        let chunk = self.get_or_create_chunk(Self::chunk_index(slot_idx));
        let idx = Self::chunk_slot_index(slot_idx);

        unsafe { &(*chunk).slots[idx] }
    }

    fn get_existing_slot(&self, slot_idx: usize) -> Option<&DomainSlot> {
        let chunk = self.get_existing_chunk(Self::chunk_index(slot_idx))?;
        let idx = Self::chunk_slot_index(slot_idx);

        Some(unsafe { &(*chunk).slots[idx] })
    }

    fn install_builtin(&self, slot_idx: u32, config: ExecutorDomainConfig) {
        let slot_idx = slot_idx as usize;
        let id = ExecutorDomainId::from_parts(slot_idx as u32, BUILTIN_GENERATION);
        let slot = self.get_or_create_slot(slot_idx);

        slot.state.store(DOMAIN_SLOT_RESERVED, Ordering::Release);
        slot.generation
            .store(BUILTIN_GENERATION as usize, Ordering::Release);

        let domain = Arc::new(ExecutorDomain::new(id, config));
        let raw = Arc::into_raw(domain) as *mut ExecutorDomain;

        slot.domain.store(raw, Ordering::Release);
        slot.state.store(DOMAIN_SLOT_BUILTIN, Ordering::Release);

        self.publish_slot_count(slot_idx + 1);
    }

    pub fn create_executor_domain(&self, config: ExecutorDomainConfig) -> ExecutorDomainId {
        let config = config.normalized();

        if let Some((idx, slot)) = self.reserve_reusable_slot() {
            return self.install_user_domain(idx, slot, config);
        }

        loop {
            let idx = self
                .next_slot
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |next| {
                    (next < MAX_DOMAIN_SLOTS).then_some(next + 1)
                })
                .expect("executor domain table exhausted");

            let slot = self.get_or_create_slot(idx);

            if slot
                .state
                .compare_exchange(
                    DOMAIN_SLOT_EMPTY,
                    DOMAIN_SLOT_RESERVED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                return self.install_user_domain(idx, slot, config);
            }
        }
    }

    fn reserve_reusable_slot(&self) -> Option<(usize, &DomainSlot)> {
        let limit = self.next_slot.load(Ordering::Acquire);
        let mut idx = 0usize;

        while idx < limit {
            let Some(slot) = self.get_existing_slot(idx) else {
                idx += 1;
                continue;
            };

            if slot
                .state
                .compare_exchange(
                    DOMAIN_SLOT_EMPTY,
                    DOMAIN_SLOT_RESERVED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                return Some((idx, slot));
            }

            idx += 1;
        }

        None
    }

    fn install_user_domain(
        &self,
        idx: usize,
        slot: &DomainSlot,
        config: ExecutorDomainConfig,
    ) -> ExecutorDomainId {
        let generation = slot.generation.load(Ordering::Acquire).max(1) as u32;
        let id = ExecutorDomainId::from_parts(idx as u32, generation);

        let domain = Arc::new(ExecutorDomain::new(id, config));
        let raw = Arc::into_raw(domain) as *mut ExecutorDomain;

        slot.domain.store(raw, Ordering::Release);
        slot.state.store(DOMAIN_SLOT_ACTIVE, Ordering::Release);

        id
    }

    pub fn destroy_executor_domain(
        &self,
        domain_id: ExecutorDomainId,
    ) -> Result<DestroyExecutorDomainResult, DestroyExecutorDomainError> {
        let slot = self
            .get_existing_slot(domain_id.slot() as usize)
            .ok_or(DestroyExecutorDomainError::InvalidDomain)?;

        let slot_state = slot.state.load(Ordering::Acquire);

        if slot_state == DOMAIN_SLOT_BUILTIN {
            return Err(DestroyExecutorDomainError::BuiltinDomain);
        }

        if slot_state != DOMAIN_SLOT_ACTIVE {
            return Err(DestroyExecutorDomainError::InvalidDomain);
        }

        if slot.generation() != domain_id.generation() {
            return Err(DestroyExecutorDomainError::StaleDomain);
        }

        let Some(domain) = self.get_executor_domain(domain_id) else {
            return Err(DestroyExecutorDomainError::InvalidDomain);
        };

        if domain.queued_count() == 0
            && domain.active_count() == 0
            && domain.live_task_count() == 0
            && domain.future_arena().live_futures() == 0
        {
            domain.move_to_dead();

            if slot
                .state
                .compare_exchange(
                    DOMAIN_SLOT_ACTIVE,
                    DOMAIN_SLOT_RESERVED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                return Err(DestroyExecutorDomainError::InvalidDomain);
            }

            slot.domain.store(ptr::null_mut(), Ordering::Release);

            let next_generation = domain_id.generation().wrapping_add(1).max(1);
            slot.generation
                .store(next_generation as usize, Ordering::Release);
            slot.state.store(DOMAIN_SLOT_EMPTY, Ordering::Release);

            return Ok(DestroyExecutorDomainResult::Destroyed);
        }

        domain.move_to_draining();
        Ok(DestroyExecutorDomainResult::Draining)
    }

    pub fn get_executor_domain(&self, domain_id: ExecutorDomainId) -> Option<Arc<ExecutorDomain>> {
        if !domain_id.is_valid() {
            return None;
        }

        let slot = self.get_existing_slot(domain_id.slot() as usize)?;

        let state = slot.state.load(Ordering::Acquire);
        if state != DOMAIN_SLOT_ACTIVE && state != DOMAIN_SLOT_BUILTIN {
            return None;
        }

        let generation = slot.generation.load(Ordering::Acquire) as u32;
        if generation != domain_id.generation() {
            return None;
        }

        let ptr = slot.load_domain_ptr();
        if ptr.is_null() {
            return None;
        }

        let domain = unsafe { DomainSlot::clone_domain_from_ptr(ptr) };

        let state_after = slot.state.load(Ordering::Acquire);
        let generation_after = slot.generation.load(Ordering::Acquire) as u32;
        let ptr_after = slot.load_domain_ptr();

        if ptr_after != ptr
            || generation_after != domain_id.generation()
            || (state_after != DOMAIN_SLOT_ACTIVE && state_after != DOMAIN_SLOT_BUILTIN)
        {
            drop(domain);
            return None;
        }

        Some(domain)
    }

    pub fn domain_count(&self) -> usize {
        let limit = self.next_slot.load(Ordering::Acquire);
        let mut count = 0usize;
        let mut idx = 0usize;

        while idx < limit {
            if let Some(slot) = self.get_existing_slot(idx) {
                let state = slot.state.load(Ordering::Acquire);

                if state == DOMAIN_SLOT_ACTIVE || state == DOMAIN_SLOT_BUILTIN {
                    count += 1;
                }
            }

            idx += 1;
        }

        count
    }
}
