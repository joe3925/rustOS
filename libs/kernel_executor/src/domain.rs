use crate::global_async::CacheAligned;
use crate::sync::Arc;
use crate::sync::atomic::{AtomicBool, AtomicU8, AtomicU128, AtomicUsize, Ordering};
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
const DOMAIN_SLOT_RETIRED: usize = 4;
const DOMAIN_SLOT_REAPING: usize = 5;
const DOMAIN_READER_CLOSED: usize = 1usize << (usize::BITS - 1);
const DOMAIN_READER_CHECKING: usize = 1usize << (usize::BITS - 2);
const DOMAIN_READER_TOUCHED: usize = 1usize << (usize::BITS - 3);
const DOMAIN_READER_COUNT: usize =
    !(DOMAIN_READER_CLOSED | DOMAIN_READER_CHECKING | DOMAIN_READER_TOUCHED);

const DOMAIN_CHUNK_BITS: usize = 6;
const DOMAIN_CHUNK_SIZE: usize = 1 << DOMAIN_CHUNK_BITS;
const DOMAIN_CHUNK_MASK: usize = DOMAIN_CHUNK_SIZE - 1;
const MAX_DOMAIN_CHUNKS: usize = 64;
const MAX_DOMAIN_SLOTS: usize = DOMAIN_CHUNK_SIZE * MAX_DOMAIN_CHUNKS;
const TASK_ID_MASK: u128 = u64::MAX as u128;
const READY_TAG_SHIFT: u32 = 64;
pub const MAX_READY_SHARDS: usize = 64;

#[repr(align(64))]
struct ReadyHead(AtomicU128);

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
    pub max_active: usize,
    pub quantum: usize,
    pub weight: usize,
    pub ready_shards: usize,
}

impl ExecutorDomainConfig {
    pub fn for_class(class: ExecutorDomainClass, cpu_count: usize) -> Self {
        Self {
            max_active: class.default_max_active(cpu_count),
            quantum: class.default_quantum(),
            weight: class.default_weight(),
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
    pub state: ExecutorDomainState,
    pub queued_count: usize,
    pub active_count: usize,
    pub live_task_count: usize,
    pub max_active: usize,
    pub ready_shards: usize,
}

pub struct ExecutorDomain {
    id: ExecutorDomainId,
    ready_heads: Box<[ReadyHead]>,
    ready_cursor: CacheAligned,
    reclamation: Arc<DomainReclamation>,
    live_task_count: CacheAligned,

    state: AtomicU8,
    scheduled_count: CacheAligned,

    queued_count: CacheAligned,
    active_count: CacheAligned,
    max_active: CacheAligned,

    quantum: CacheAligned,
    weight: CacheAligned,
    deficit: CacheAligned,
}

impl ExecutorDomain {
    fn new(
        id: ExecutorDomainId,
        config: ExecutorDomainConfig,
        reclamation: Arc<DomainReclamation>,
    ) -> Self {
        let config = config.normalized();

        Self {
            id,
            ready_heads: (0..config.ready_shards)
                .map(|_| ReadyHead(AtomicU128::new(0)))
                .collect::<alloc::vec::Vec<_>>()
                .into_boxed_slice(),
            ready_cursor: CacheAligned(AtomicUsize::new(0)),
            reclamation,
            live_task_count: CacheAligned(AtomicUsize::new(0)),

            state: AtomicU8::new(ExecutorDomainState::Active as u8),
            scheduled_count: CacheAligned(AtomicUsize::new(0)),

            queued_count: CacheAligned(AtomicUsize::new(0)),
            active_count: CacheAligned(AtomicUsize::new(0)),
            max_active: CacheAligned(AtomicUsize::new(config.max_active)),

            quantum: CacheAligned(AtomicUsize::new(config.quantum)),
            weight: CacheAligned(AtomicUsize::new(config.weight)),
            deficit: CacheAligned(AtomicUsize::new(0)),
        }
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

    #[inline]
    fn pack_ready(task_id: usize, tag: u64) -> u128 {
        ((tag as u128) << READY_TAG_SHIFT) | (task_id as u128 & TASK_ID_MASK)
    }

    pub(crate) fn enqueue_task(&self, task_id: usize) -> bool {
        if self.state() == ExecutorDomainState::Dead || task_id == 0 {
            return false;
        }
        let Some((shard, local, generation)) =
            crate::runtime::slab::ptr::decode_slab_task_ptr(task_id)
        else {
            return false;
        };
        let slab = crate::runtime::slab::task_slab::get_task_table();
        let Some(slot) = slab.get_slot(shard, local, generation) else {
            return false;
        };
        self.queued_count.0.fetch_add(1, Ordering::AcqRel);
        let ready_head = &self.ready_heads[task_id % self.ready_heads.len()];
        let mut head = ready_head.0.load(Ordering::Acquire);
        loop {
            let head_id = (head & TASK_ID_MASK) as usize;
            slot.ready_next.store(head_id, Ordering::Relaxed);
            let tag = ((head >> READY_TAG_SHIFT) as u64).wrapping_add(1);
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
        true
    }

    pub(crate) fn pop_task(&self) -> Option<usize> {
        let shard_count = self.ready_heads.len();
        let start = if crate::platform::in_interrupt_context() {
            self.ready_cursor.0.fetch_add(1, Ordering::Relaxed) % shard_count
        } else {
            crate::platform::with_executor_local(|tls| {
                let cursor = tls.ready_cursor.get();
                tls.ready_cursor.set(cursor.wrapping_add(1));
                cursor % shard_count
            })
        };

        for offset in 0..shard_count {
            if let Some(task_id) = self.pop_task_from_head((start + offset) % shard_count) {
                return Some(task_id);
            }
        }
        None
    }

    fn pop_task_from_head(&self, ready_shard: usize) -> Option<usize> {
        let slab = crate::runtime::slab::task_slab::get_task_table();
        let ready_head = &self.ready_heads[ready_shard];
        let mut head = ready_head.0.load(Ordering::Acquire);
        loop {
            let task_id = (head & TASK_ID_MASK) as usize;
            if task_id == 0 {
                return None;
            }
            let (shard, local, generation) =
                crate::runtime::slab::ptr::decode_slab_task_ptr(task_id)?;
            let slot = slab.get_slot(shard, local, generation)?;
            let next_id = slot.ready_next.load(Ordering::Acquire);
            let tag = ((head >> READY_TAG_SHIFT) as u64).wrapping_add(1);
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
        {
            self.reclamation.request(self.id.slot() as usize);
        }
    }

    pub fn stats(&self) -> ExecutorDomainStats {
        ExecutorDomainStats {
            state: self.state(),
            queued_count: self.queued_count(),
            active_count: self.active_count(),
            live_task_count: self.live_task_count(),
            max_active: self.max_active(),
            ready_shards: self.ready_heads.len(),
        }
    }
}

struct DomainReclamation {
    pending: AtomicBool,
    candidates: [AtomicUsize; MAX_DOMAIN_SLOTS.div_ceil(usize::BITS as usize)],
}

impl DomainReclamation {
    fn request(&self, index: usize) {
        self.candidates[index / usize::BITS as usize]
            .fetch_or(1usize << (index % usize::BITS as usize), Ordering::Release);
        self.pending.store(true, Ordering::Release);
        crate::global_async::GlobalAsyncExecutor::global().try_schedule::<true>();
    }
}

pub(crate) struct DomainBorrow<'a> {
    domain: *const ExecutorDomain,
    slot: &'a DomainSlot,
    reclamation: &'a DomainReclamation,
    pinned: bool,
    notify: bool,
}

impl core::ops::Deref for DomainBorrow<'_> {
    type Target = ExecutorDomain;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.domain }
    }
}

impl Drop for DomainBorrow<'_> {
    fn drop(&mut self) {
        if self.pinned {
            let index = self.id.slot() as usize;
            let draining = self.notify && self.state() != ExecutorDomainState::Active;
            if self.slot.readers.fetch_sub(1, Ordering::SeqCst) & DOMAIN_READER_COUNT == 1
                && (draining
                    || matches!(
                        self.slot.state.load(Ordering::SeqCst),
                        DOMAIN_SLOT_RETIRED | DOMAIN_SLOT_REAPING
                    ))
            {
                self.reclamation.request(index);
            }
        }
    }
}

struct DomainSlot {
    state: AtomicUsize,
    readers: AtomicUsize,
    generation: AtomicUsize,
    domain: AtomicPtr<ExecutorDomain>,
}

impl DomainSlot {
    fn new() -> Self {
        Self {
            state: AtomicUsize::new(DOMAIN_SLOT_EMPTY),
            readers: AtomicUsize::new(0),
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
        unsafe {
            Arc::increment_strong_count(ptr);
            Arc::from_raw(ptr)
        }
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
    reclamation: Arc<DomainReclamation>,
    next_slot: AtomicUsize,
    chunks: [AtomicPtr<DomainChunk>; MAX_DOMAIN_CHUNKS],
}

impl ExecutorDomainTable {
    pub(crate) fn new(cpu_count: usize) -> Self {
        let table = Self {
            reclamation: Arc::new(DomainReclamation {
                pending: AtomicBool::new(false),
                candidates: core::array::from_fn(|_| AtomicUsize::new(0)),
            }),
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

        let domain = Arc::new(ExecutorDomain::new(id, config, self.reclamation.clone()));
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

        let domain = Arc::new(ExecutorDomain::new(id, config, self.reclamation.clone()));
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
        if slot.state.load(Ordering::SeqCst) == DOMAIN_SLOT_BUILTIN {
            return Err(DestroyExecutorDomainError::BuiltinDomain);
        }
        if slot.generation() != domain_id.generation() {
            return Err(DestroyExecutorDomainError::StaleDomain);
        }
        let domain = self
            .borrow_executor_domain(domain_id)
            .ok_or(DestroyExecutorDomainError::InvalidDomain)?;
        domain.move_to_draining();
        self.reclamation.request(domain_id.slot() as usize);
        drop(domain);
        if !crate::platform::in_interrupt_context() {
            self.drain_retired();
        }
        if slot.generation() != domain_id.generation()
            || matches!(
                slot.state.load(Ordering::SeqCst),
                DOMAIN_SLOT_RETIRED | DOMAIN_SLOT_REAPING | DOMAIN_SLOT_EMPTY
            )
        {
            Ok(DestroyExecutorDomainResult::Destroyed)
        } else {
            Ok(DestroyExecutorDomainResult::Draining)
        }
    }

    pub(crate) fn borrow_executor_domain(
        &self,
        domain_id: ExecutorDomainId,
    ) -> Option<DomainBorrow<'_>> {
        if !domain_id.is_valid() {
            return None;
        }
        let slot = self.get_existing_slot(domain_id.slot() as usize)?;
        let state = slot.state.load(Ordering::SeqCst);
        if state != DOMAIN_SLOT_ACTIVE && state != DOMAIN_SLOT_BUILTIN {
            return None;
        }
        let pinned = state != DOMAIN_SLOT_BUILTIN;
        if pinned {
            let previous = slot.readers.fetch_add(1, Ordering::SeqCst);
            assert!(previous & DOMAIN_READER_COUNT < DOMAIN_READER_COUNT);
            if previous & DOMAIN_READER_CLOSED != 0 {
                if slot.readers.fetch_sub(1, Ordering::SeqCst) & DOMAIN_READER_COUNT == 1 {
                    self.reclamation.request(domain_id.slot() as usize);
                }
                return None;
            }
            if previous & DOMAIN_READER_CHECKING != 0 {
                let mut readers = slot.readers.load(Ordering::SeqCst);
                while readers & DOMAIN_READER_CHECKING != 0 && readers & DOMAIN_READER_TOUCHED == 0
                {
                    match slot.readers.compare_exchange_weak(
                        readers,
                        readers | DOMAIN_READER_TOUCHED,
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                    ) {
                        Ok(_) => break,
                        Err(actual) => readers = actual,
                    }
                }
            }
        }
        if slot.state.load(Ordering::SeqCst) != state || slot.generation() != domain_id.generation()
        {
            if pinned && slot.readers.fetch_sub(1, Ordering::SeqCst) & DOMAIN_READER_COUNT == 1 {
                self.reclamation.request(domain_id.slot() as usize);
            }
            return None;
        }
        let raw = slot.load_domain_ptr();
        assert!(!raw.is_null());
        Some(DomainBorrow {
            domain: raw,
            slot,
            reclamation: &self.reclamation,
            pinned,
            notify: true,
        })
    }

    pub fn get_executor_domain(&self, domain_id: ExecutorDomainId) -> Option<Arc<ExecutorDomain>> {
        let domain = self.borrow_executor_domain(domain_id)?;
        Some(unsafe { DomainSlot::clone_domain_from_ptr(ptr::from_ref(&*domain).cast_mut()) })
    }

    pub(crate) fn has_retired(&self) -> bool {
        self.reclamation.pending.load(Ordering::Acquire)
    }

    pub(crate) fn drain_retired(&self) {
        if !self.reclamation.pending.load(Ordering::Acquire)
            || !self.reclamation.pending.swap(false, Ordering::AcqRel)
        {
            return;
        }
        for (word_index, word) in self.reclamation.candidates.iter().enumerate() {
            let mut candidates = word.swap(0, Ordering::AcqRel);
            while candidates != 0 {
                let bit = candidates.trailing_zeros() as usize;
                candidates &= candidates - 1;
                let index = word_index * usize::BITS as usize + bit;
                let Some(slot) = self.get_existing_slot(index) else {
                    continue;
                };
                if slot.state.load(Ordering::SeqCst) == DOMAIN_SLOT_ACTIVE {
                    let id = ExecutorDomainId::from_parts(index as u32, slot.generation());
                    if let Some(mut domain) = self.borrow_executor_domain(id) {
                        domain.notify = false;
                        if domain.state() == ExecutorDomainState::Draining
                            && slot
                                .readers
                                .compare_exchange(
                                    1,
                                    DOMAIN_READER_CHECKING | 1,
                                    Ordering::SeqCst,
                                    Ordering::SeqCst,
                                )
                                .is_ok()
                        {
                            let empty = domain.queued_count() == 0
                                && domain.active_count() == 0
                                && domain.live_task_count() == 0;
                            if empty
                                && slot
                                    .readers
                                    .compare_exchange(
                                        DOMAIN_READER_CHECKING | 1,
                                        DOMAIN_READER_CLOSED | 1,
                                        Ordering::SeqCst,
                                        Ordering::SeqCst,
                                    )
                                    .is_ok()
                            {
                                domain.move_to_dead();
                                slot.state.store(DOMAIN_SLOT_RETIRED, Ordering::SeqCst);
                            } else {
                                let previous = slot
                                    .readers
                                    .fetch_and(DOMAIN_READER_COUNT, Ordering::SeqCst);
                                if empty && previous & DOMAIN_READER_TOUCHED != 0 {
                                    self.reclamation.request(index);
                                }
                            }
                        }
                    }
                }
                if slot
                    .state
                    .compare_exchange(
                        DOMAIN_SLOT_RETIRED,
                        DOMAIN_SLOT_REAPING,
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                    )
                    .is_err()
                {
                    continue;
                }
                if slot.readers.load(Ordering::SeqCst) & DOMAIN_READER_COUNT != 0 {
                    slot.state.store(DOMAIN_SLOT_RETIRED, Ordering::SeqCst);
                    if slot.readers.load(Ordering::SeqCst) & DOMAIN_READER_COUNT == 0 {
                        self.reclamation.request(index);
                    }
                    continue;
                }
                let raw = slot.domain.swap(ptr::null_mut(), Ordering::AcqRel);
                let generation = slot.generation().wrapping_add(1).max(1);
                slot.generation
                    .store(generation as usize, Ordering::Release);
                unsafe { drop(Arc::from_raw(raw)) };
                slot.readers.store(0, Ordering::SeqCst);
                slot.state.store(DOMAIN_SLOT_EMPTY, Ordering::SeqCst);
            }
        }
    }
}
