use crate::global_async::CacheAligned;
use crate::platform::ExecutorPlatform;
use crate::sync::Arc;
use crate::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use alloc::boxed::Box;
use core::cell::UnsafeCell;
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
const DOMAIN_SLOT_CLEANUP: usize = 6;
const DOMAIN_SLOT_CLEANING: usize = 7;
const DOMAIN_READER_CLOSED: usize = 1usize << (usize::BITS - 1);
const DOMAIN_READER_COUNT: usize = !DOMAIN_READER_CLOSED;

const DOMAIN_CHUNK_BITS: usize = 6;
const DOMAIN_CHUNK_SIZE: usize = 1 << DOMAIN_CHUNK_BITS;
const DOMAIN_CHUNK_MASK: usize = DOMAIN_CHUNK_SIZE - 1;
const MAX_DOMAIN_CHUNKS: usize = 64;
const MAX_DOMAIN_SLOTS: usize = DOMAIN_CHUNK_SIZE * MAX_DOMAIN_CHUNKS;
pub const MAX_READY_SHARDS: usize = 64;
pub(crate) const BATCH_EMPTY: u8 = 0;
pub(crate) const BATCH_READY: u8 = 1;
pub(crate) const BATCH_OWNED: u8 = 2;
pub(crate) const RUN_PENDING: usize = 1;
pub(crate) const ACTIVE_UNIT: usize = 2;

#[repr(align(64))]
struct ReadyHead(AtomicUsize);

#[repr(align(64))]
pub(crate) struct ReadyBatch {
    pub current: usize,
    pub local_task: usize,
    pub local_slot: Option<&'static crate::runtime::slab::slot::TaskSlot>,
    pub local_runs: u8,
    pub shard_cursor: usize,
}

#[repr(align(64))]
pub(crate) struct BatchSlot {
    pub state: AtomicU8,
    pub index: usize,
    pub batch: UnsafeCell<ReadyBatch>,
    pub spawned: crate::steal_queue::StealQueue<256>,
}

unsafe impl Sync for BatchSlot {}

struct DomainCleanup {
    queue_index: usize,
    queue_head: usize,
    task_cursor: [usize; 3],
    blocking_cursor: [usize; 2],
    tasks_done: bool,
}

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
            ExecutorDomainClass::KernelHigh => 64,
            ExecutorDomainClass::Driver => 48,
            ExecutorDomainClass::KernelNormal => 32,
            ExecutorDomainClass::ProcessIo => 24,
            ExecutorDomainClass::KernelBackground => 8,
        }
    }

    pub const fn default_quantum(self) -> usize {
        match self {
            ExecutorDomainClass::KernelHigh => 64,
            ExecutorDomainClass::Driver => 48,
            ExecutorDomainClass::KernelNormal => 32,
            ExecutorDomainClass::ProcessIo => 32,
            ExecutorDomainClass::KernelBackground => 8,
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
pub struct ExecutorDomainInfo {
    pub state: ExecutorDomainState,
    pub max_active: usize,
    pub ready_shards: usize,
}

pub struct ExecutorDomain<E: ExecutorPlatform> {
    id: ExecutorDomainId,
    ready_heads: Box<[ReadyHead]>,
    pub(crate) ready_batches: CacheAligned,
    pub(crate) batches: Box<[BatchSlot]>,
    pub(crate) help_requested: CacheAligned,
    reclamation: Arc<DomainReclamation<E>>,
    cleanup: UnsafeCell<DomainCleanup>,

    state: AtomicU8,
    pub(crate) schedule_state: CacheAligned,
    pub(crate) run_overflow: AtomicBool,

    max_active: CacheAligned,

    quantum: usize,
    weight: usize,
    deficit: CacheAligned,
}

unsafe impl<E: ExecutorPlatform> Sync for ExecutorDomain<E> {}

impl<E: ExecutorPlatform> ExecutorDomain<E> {
    fn new(
        id: ExecutorDomainId,
        config: ExecutorDomainConfig,
        reclamation: Arc<DomainReclamation<E>>,
        workers: usize,
    ) -> Self {
        let config = config.normalized();

        Self {
            id,
            ready_heads: (0..config.ready_shards)
                .map(|_| ReadyHead(AtomicUsize::new(0)))
                .collect::<alloc::vec::Vec<_>>()
                .into_boxed_slice(),
            ready_batches: CacheAligned(AtomicUsize::new(0)),
            batches: (0..workers.max(1))
                .map(|index| BatchSlot {
                    state: AtomicU8::new(BATCH_EMPTY),
                    index,
                    batch: UnsafeCell::new(ReadyBatch {
                        current: 0,
                        local_task: 0,
                        local_slot: None,
                        local_runs: 0,
                        shard_cursor: index % config.ready_shards,
                    }),
                    spawned: crate::steal_queue::StealQueue::new(),
                })
                .collect(),
            help_requested: CacheAligned(AtomicUsize::new(0)),
            reclamation,
            cleanup: UnsafeCell::new(DomainCleanup {
                queue_index: 0,
                queue_head: 0,
                task_cursor: [0; 3],
                blocking_cursor: [0, usize::MAX],
                tasks_done: false,
            }),

            state: AtomicU8::new(ExecutorDomainState::Active as u8),
            schedule_state: CacheAligned(AtomicUsize::new(0)),
            run_overflow: AtomicBool::new(false),
            max_active: CacheAligned(AtomicUsize::new(config.max_active)),

            quantum: config.quantum,
            weight: config.weight,
            deficit: CacheAligned(AtomicUsize::new(0)),
        }
    }

    #[inline]
    pub fn is_schedulable_for_policy(&self) -> bool {
        self.is_runnable_for_policy() && !self.is_at_active_limit()
    }

    pub fn id(&self) -> ExecutorDomainId {
        self.id
    }

    pub fn state(&self) -> ExecutorDomainState {
        ExecutorDomainState::from_u8(self.state.load(Ordering::Acquire))
    }

    pub fn quantum(&self) -> usize {
        self.quantum
    }

    pub fn weight(&self) -> usize {
        self.weight
    }

    pub fn max_active(&self) -> usize {
        self.max_active.0.load(Ordering::Acquire).max(1)
    }

    pub fn set_max_active(&self, max_active: usize) {
        self.max_active
            .0
            .store(max_active.max(1), Ordering::Release);
    }

    pub(crate) fn active_count(&self) -> usize {
        self.schedule_state.0.load(Ordering::Acquire) / ACTIVE_UNIT
    }

    pub fn has_queued_work(&self) -> bool {
        self.ready_batches.0.load(Ordering::Acquire) != 0
            || self
                .ready_heads
                .iter()
                .any(|head| head.0.load(Ordering::Acquire) != 0)
            || self.batches.iter().any(|batch| batch.spawned.has_work())
    }

    #[inline]
    pub(crate) fn enqueue_tasks(
        &self,
        task_id: usize,
        tail: &crate::runtime::slab::slot::TaskSlot,
        shard_hint: Option<&mut usize>,
    ) -> Option<bool> {
        if self.state() != ExecutorDomainState::Active || task_id == 0 {
            return None;
        }
        let Some((shard, local, _)) =
            crate::runtime::slab::ptr::decode_slab_task_ptr(task_id)
        else {
            return None;
        };
        let shard_index = match &shard_hint {
            Some(cursor) => **cursor,
            None => (shard ^ local) % self.ready_heads.len(),
        };
        let ready_head = &self.ready_heads[shard_index];
        let mut head = ready_head.0.load(Ordering::Relaxed);
        loop {
            tail.ready_next.store(head, Ordering::Relaxed);
            match ready_head
                .0
                .compare_exchange(head, task_id, Ordering::Release, Ordering::Relaxed)
            {
                Ok(_) => {
                    if let Some(cursor) = shard_hint {
                        *cursor = if shard_index + 1 == self.ready_heads.len() {
                            0
                        } else {
                            shard_index + 1
                        };
                    }
                    return Some(head == 0);
                }
                Err(actual) => head = actual,
            }
        }
    }

    pub(crate) fn refill_batch(&self, batch: &mut ReadyBatch) -> bool {
        let shard_count = self.ready_heads.len();
        let mut index = batch.shard_cursor;
        for _ in 0..shard_count {
            let head = &self.ready_heads[index].0;
            index += 1;
            if index == shard_count {
                index = 0;
            }
            if head.load(Ordering::Relaxed) == 0 {
                continue;
            }
            batch.current = head.swap(0, Ordering::Acquire);
            if batch.current != 0 {
                batch.shard_cursor = index;
                return true;
            }
        }
        false
    }

    pub fn is_runnable_for_policy(&self) -> bool {
        self.state() == ExecutorDomainState::Active && self.has_queued_work()
    }

    pub fn is_at_active_limit(&self) -> bool {
        self.active_count() >= self.max_active()
    }

    pub(crate) fn try_reserve_active<const IDLE_ONLY: bool>(&self) -> bool {
        if IDLE_ONLY {
            return self
                .schedule_state
                .0
                .compare_exchange(0, ACTIVE_UNIT, Ordering::AcqRel, Ordering::Acquire)
                .is_ok();
        }
        let mut reserved = false;
        let _ = self
            .schedule_state
            .0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                reserved = state / ACTIVE_UNIT < self.max_active();
                Some((state & !RUN_PENDING) + if reserved { ACTIVE_UNIT } else { 0 })
            });
        reserved
    }

    pub(crate) fn release_active(&self) {
        self.schedule_state
            .0
            .fetch_sub(ACTIVE_UNIT, Ordering::AcqRel);
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
        self.schedule_state.0.store(0, Ordering::Release);
    }

    pub(crate) fn maybe_finish_draining(&self) {
        if self.state() == ExecutorDomainState::Draining && self.active_count() == 0 {
            self.reclamation.request(self.id.slot() as usize);
        }
    }

    pub fn info(&self) -> ExecutorDomainInfo {
        ExecutorDomainInfo {
            state: self.state(),
            max_active: self.max_active(),
            ready_shards: self.ready_heads.len(),
        }
    }
}

struct DomainReclamation<E: ExecutorPlatform> {
    _platform: core::marker::PhantomData<fn() -> E>,
    pending: AtomicBool,
    candidates: [AtomicUsize; MAX_DOMAIN_SLOTS.div_ceil(usize::BITS as usize)],
}

impl<E: ExecutorPlatform> DomainReclamation<E> {
    fn request(&self, index: usize) {
        self.candidates[index / usize::BITS as usize]
            .fetch_or(1usize << (index % usize::BITS as usize), Ordering::Release);
        self.pending.store(true, Ordering::Release);
        crate::global_async::GlobalAsyncExecutor::<E>::global().try_schedule::<true>();
    }
}

pub(crate) struct DomainBorrow<'a, E: ExecutorPlatform> {
    domain: *const ExecutorDomain<E>,
    slot: &'a DomainSlot<E>,
    reclamation: &'a DomainReclamation<E>,
    pinned: bool,
    notify: bool,
}

impl<E: ExecutorPlatform> core::ops::Deref for DomainBorrow<'_, E> {
    type Target = ExecutorDomain<E>;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.domain }
    }
}

impl<E: ExecutorPlatform> Drop for DomainBorrow<'_, E> {
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

struct DomainSlot<E: ExecutorPlatform> {
    state: AtomicUsize,
    readers: AtomicUsize,
    generation: AtomicUsize,
    domain: AtomicPtr<ExecutorDomain<E>>,
}

impl<E: ExecutorPlatform> DomainSlot<E> {
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
    fn load_domain_ptr(&self) -> *mut ExecutorDomain<E> {
        self.domain.load(Ordering::Acquire)
    }

    #[inline]
    unsafe fn clone_domain_from_ptr(ptr: *mut ExecutorDomain<E>) -> Arc<ExecutorDomain<E>> {
        unsafe {
            Arc::increment_strong_count(ptr);
            Arc::from_raw(ptr)
        }
    }
}

struct DomainChunk<E: ExecutorPlatform> {
    slots: [DomainSlot<E>; DOMAIN_CHUNK_SIZE],
}

impl<E: ExecutorPlatform> DomainChunk<E> {
    fn new() -> Self {
        Self {
            slots: core::array::from_fn(|_| DomainSlot::<E>::new()),
        }
    }
}

pub struct ExecutorDomainTable<E: ExecutorPlatform> {
    reclamation: Arc<DomainReclamation<E>>,
    next_slot: AtomicUsize,
    chunks: [AtomicPtr<DomainChunk<E>>; MAX_DOMAIN_CHUNKS],
    workers: usize,
}

impl<E: ExecutorPlatform> ExecutorDomainTable<E> {
    pub(crate) fn new(cpu_count: usize) -> Self {
        let table = Self {
            reclamation: Arc::new(DomainReclamation::<E> {
                _platform: core::marker::PhantomData,
                pending: AtomicBool::new(false),
                candidates: core::array::from_fn(|_| AtomicUsize::new(0)),
            }),
            next_slot: AtomicUsize::new(0),
            chunks: core::array::from_fn(|_| AtomicPtr::new(ptr::null_mut())),
            workers: cpu_count.max(1),
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

    fn get_or_create_chunk(&self, chunk_idx: usize) -> *mut DomainChunk<E> {
        assert!(
            chunk_idx < MAX_DOMAIN_CHUNKS,
            "executor domain table exhausted"
        );

        let existing = self.chunks[chunk_idx].load(Ordering::Acquire);
        if !existing.is_null() {
            return existing;
        }

        let new_chunk = Box::into_raw(Box::new(DomainChunk::<E>::new()));

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

    fn get_existing_chunk(&self, chunk_idx: usize) -> Option<*mut DomainChunk<E>> {
        if chunk_idx >= MAX_DOMAIN_CHUNKS {
            return None;
        }

        let chunk = self.chunks[chunk_idx].load(Ordering::Acquire);
        (!chunk.is_null()).then_some(chunk)
    }

    fn get_or_create_slot(&self, slot_idx: usize) -> &DomainSlot<E> {
        let chunk = self.get_or_create_chunk(Self::chunk_index(slot_idx));
        let idx = Self::chunk_slot_index(slot_idx);

        unsafe { &(*chunk).slots[idx] }
    }

    fn get_existing_slot(&self, slot_idx: usize) -> Option<&DomainSlot<E>> {
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

        let domain = Arc::new(ExecutorDomain::<E>::new(
            id,
            config,
            self.reclamation.clone(),
            self.workers,
        ));
        let raw = Arc::into_raw(domain) as *mut ExecutorDomain<E>;

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

    fn reserve_reusable_slot(&self) -> Option<(usize, &DomainSlot<E>)> {
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
        slot: &DomainSlot<E>,
        config: ExecutorDomainConfig,
    ) -> ExecutorDomainId {
        let generation = slot.generation.load(Ordering::Acquire).max(1) as u32;
        let id = ExecutorDomainId::from_parts(idx as u32, generation);

        let domain = Arc::new(ExecutorDomain::<E>::new(
            id,
            config,
            self.reclamation.clone(),
            self.workers,
        ));
        let raw = Arc::into_raw(domain) as *mut ExecutorDomain<E>;

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
        if matches!(
            slot.state.load(Ordering::SeqCst),
            DOMAIN_SLOT_CLEANUP | DOMAIN_SLOT_CLEANING
        ) {
            return Ok(DestroyExecutorDomainResult::Draining);
        }
        let domain = self
            .borrow_executor_domain(domain_id)
            .ok_or(DestroyExecutorDomainError::InvalidDomain)?;
        domain.move_to_draining();
        self.reclamation.request(domain_id.slot() as usize);
        drop(domain);
        if !E::in_interrupt_context() {
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
    ) -> Option<DomainBorrow<'_, E>> {
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

    pub fn get_executor_domain(
        &self,
        domain_id: ExecutorDomainId,
    ) -> Option<Arc<ExecutorDomain<E>>> {
        let domain = self.borrow_executor_domain(domain_id)?;
        Some(unsafe { DomainSlot::<E>::clone_domain_from_ptr(ptr::from_ref(&*domain).cast_mut()) })
    }

    pub(crate) fn has_retired(&self) -> bool {
        self.reclamation.pending.load(Ordering::Acquire)
    }

    pub(crate) fn recover_runs(&self, mut push: impl FnMut(ExecutorDomainId) -> bool) -> bool {
        let mut remaining = false;
        for index in 0..self.next_slot.load(Ordering::Acquire) {
            let Some(slot) = self.get_existing_slot(index) else {
                continue;
            };
            let id = ExecutorDomainId::from_parts(index as u32, slot.generation());
            let Some(domain) = self.borrow_executor_domain(id) else {
                continue;
            };
            if domain.state() == ExecutorDomainState::Active
                && domain.run_overflow.swap(false, Ordering::AcqRel)
                && !push(id)
            {
                domain.run_overflow.store(true, Ordering::Release);
                remaining = true;
            }
        }
        remaining
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
                        if domain.state() == ExecutorDomainState::Draining
                            && slot
                                .readers
                                .compare_exchange(
                                    1,
                                    DOMAIN_READER_CLOSED | 1,
                                    Ordering::SeqCst,
                                    Ordering::SeqCst,
                                )
                                .is_ok()
                        {
                            domain.notify = false;
                            slot.state.store(DOMAIN_SLOT_CLEANUP, Ordering::SeqCst);
                        }
                    }
                }
                if slot
                    .state
                    .compare_exchange(
                        DOMAIN_SLOT_CLEANUP,
                        DOMAIN_SLOT_CLEANING,
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                    )
                    .is_ok()
                {
                    let domain = unsafe { &*slot.load_domain_ptr() };
                    let cleanup = unsafe { &mut *domain.cleanup.get() };
                    let table = crate::runtime::slab::task_slab::get_task_table::<E>();
                    let mut remaining = 256usize;
                    let queues = domain.ready_heads.len() + domain.batches.len() * 3;
                    while remaining != 0
                        && (cleanup.queue_head != 0 || cleanup.queue_index < queues)
                    {
                        if cleanup.queue_head == 0 {
                            let queue = cleanup.queue_index;
                            cleanup.queue_index += 1;
                            if queue < domain.ready_heads.len() {
                                cleanup.queue_head =
                                    domain.ready_heads[queue].0.swap(0, Ordering::Acquire);
                            } else {
                                let queue = queue - domain.ready_heads.len();
                                let owned = &domain.batches[queue / 3];
                                let batch = unsafe { &mut *owned.batch.get() };
                                cleanup.queue_head = match queue % 3 {
                                    0 => core::mem::take(&mut batch.current),
                                    1 => core::mem::take(&mut batch.local_task),
                                    _ => {
                                        // All readers and owners have left the domain.
                                        let task = unsafe { owned.spawned.pop() }.unwrap_or(0);
                                        if task != 0 {
                                            cleanup.queue_index -= 1;
                                        }
                                        task
                                    }
                                };
                            }
                            continue;
                        }
                        let (shard, local, generation) =
                            crate::runtime::slab::ptr::decode_slab_task_ptr(cleanup.queue_head)
                                .expect("invalid cleanup task");
                        let task = table
                            .get_slot(shard, local, generation)
                            .expect("cleanup task missing");
                        cleanup.queue_head = task.ready_next.load(Ordering::Relaxed);
                        task.ready_next.store(0, Ordering::Relaxed);
                        table.decrement_ref::<true>(shard, local, generation);
                        remaining -= 1;
                    }
                    if cleanup.queue_head == 0
                        && cleanup.queue_index == queues
                        && !cleanup.tasks_done
                    {
                        cleanup.tasks_done = table.slab.scan_slots(
                            &mut cleanup.task_cursor,
                            &mut remaining,
                            |handle, task| {
                                let shard = handle.shard as usize;
                                let local = handle.local_index as usize;
                                let generation = handle.generation;
                                if task.executor_domain_id() != Some(domain.id())
                                    || !table.increment_ref(shard, local, generation)
                                {
                                    return;
                                }
                                if task.executor_domain_id() == Some(domain.id()) {
                                    use crate::runtime::task::{
                                        STATE_COMPLETED, STATE_IDLE, STATE_POLLING, STATE_QUEUED,
                                    };
                                    let mut state = task.state.load(Ordering::Acquire);
                                    loop {
                                        if state == STATE_COMPLETED {
                                            break;
                                        }
                                        assert!(matches!(state, STATE_IDLE | STATE_QUEUED));
                                        match task.state.compare_exchange(
                                            state,
                                            STATE_POLLING,
                                            Ordering::AcqRel,
                                            Ordering::Acquire,
                                        ) {
                                            Ok(_) => {
                                                let token =
                                                    crate::runtime::slab::ptr::encode_slab_task_ptr(
                                                        handle.shard,
                                                        handle.local_index,
                                                        generation,
                                                    );
                                                unsafe {
                                                    task.cancel_owned::<E>(token);
                                                }
                                                table.decrement_ref::<true>(
                                                    shard, local, generation,
                                                );
                                                break;
                                            }
                                            Err(actual) => state = actual,
                                        }
                                    }
                                    task.domain_id.store(0, Ordering::Release);
                                }
                                table.decrement_ref::<true>(shard, local, generation);
                            },
                        );
                    }
                    let finished = cleanup.tasks_done
                        && crate::runtime::blocking::cancel_domain_jobs::<E>(
                            domain.id(),
                            &mut cleanup.blocking_cursor,
                            remaining,
                        );
                    if finished {
                        domain.move_to_dead();
                        slot.state.store(DOMAIN_SLOT_RETIRED, Ordering::SeqCst);
                    } else {
                        slot.state.store(DOMAIN_SLOT_CLEANUP, Ordering::SeqCst);
                        self.reclamation.request(index);
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
