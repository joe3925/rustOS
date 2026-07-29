use crate::future_arena::{FutureArena, FutureArenaConfig};
use crate::global_async::{CacheAligned, WorkItem};
use crate::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use crate::sync::{Arc, RwLock};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ptr;
use core::sync::atomic::AtomicPtr;
use kernel_types::capacity::{
    Growable, OccupancyHint, PolicyOutcome, ResizeContext, ResizeError, ResizeEvent, ResizePolicy,
    ResizePolicyKind,
};
use kernel_types::io::BoundedTreiberStack;

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
const IRQ_FALLBACK_ITEMS_PER_SHARD: usize = 4;

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
    pub initial_queue_capacity: usize,
    /// Preallocated interrupt-only queue capacity. `None` disables the fallback.
    pub interrupt_fallback_capacity: Option<usize>,
    pub quantum: usize,
    pub weight: usize,
    pub resize_policy: ResizePolicyKind,
    pub future_arena: FutureArenaConfig,
}

impl ExecutorDomainConfig {
    pub fn for_class(
        class: ExecutorDomainClass,
        cpu_count: usize,
        initial_queue_capacity: usize,
    ) -> Self {
        Self {
            class,
            max_active: class.default_max_active(cpu_count),
            initial_queue_capacity,
            interrupt_fallback_capacity: Some(
                cpu_count
                    .max(1)
                    .saturating_mul(IRQ_FALLBACK_ITEMS_PER_SHARD),
            ),
            quantum: class.default_quantum(),
            weight: class.default_weight(),
            resize_policy: ResizePolicyKind::default(),
            future_arena: FutureArenaConfig::default(),
        }
    }

    pub fn kernel_normal(cpu_count: usize, initial_queue_capacity: usize) -> Self {
        Self::for_class(
            ExecutorDomainClass::KernelNormal,
            cpu_count,
            initial_queue_capacity,
        )
    }

    fn normalized(mut self) -> Self {
        self.max_active = self.max_active.max(1);
        self.initial_queue_capacity = self.initial_queue_capacity.max(1);
        if self.resize_policy.validate().is_err() {
            self.resize_policy = ResizePolicyKind::Fixed;
        }
        self.quantum = self.quantum.max(1);
        self.weight = self.weight.max(1);
        self
    }
}

impl Default for ExecutorDomainConfig {
    fn default() -> Self {
        Self::kernel_normal(1, 1024)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutorSubmitErrorKind {
    ExecutorUninitialized,
    InvalidDomain,
    StaleDomain,
    DomainDraining,
    DomainDead,
    DomainFull,
    RetryLater,
    OutOfMemory,
    DomainCannotContinue,
}

#[derive(Clone, Copy, Debug)]
pub struct ExecutorSubmitError {
    pub kind: ExecutorSubmitErrorKind,
    pub domain_id: ExecutorDomainId,
    pub work_item: WorkItem,
}

impl ExecutorSubmitError {
    pub(crate) fn new(
        kind: ExecutorSubmitErrorKind,
        domain_id: ExecutorDomainId,
        work_item: WorkItem,
    ) -> Self {
        Self {
            kind,
            domain_id,
            work_item,
        }
    }

    pub fn into_work_item(self) -> WorkItem {
        self.work_item
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
    pub initial_queue_capacity: usize,
    pub interrupt_fallback_capacity: Option<usize>,
    pub queue_minimum_capacity: usize,
    pub queue_capacity: usize,
    pub queue_maximum_capacity: Option<usize>,
    pub resize_policy: ResizePolicyKind,
    pub quantum: usize,
    pub weight: usize,
    pub deficit: usize,
    pub scheduled: bool,
    pub submitted: usize,
    pub completed: usize,
    pub rejected: usize,
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
    pub total_rejections: usize,
    pub total_pump_runs: usize,
}

struct ShardedQueues {
    queues: RwLock<Vec<BoundedTreiberStack<WorkItem>>>,
    interrupt_fallback: Option<BoundedTreiberStack<WorkItem>>,
    prefer_interrupt_fallback: AtomicBool,
    minimum_capacity: usize,
    maximum_capacity: Option<usize>,
    published_capacity: CacheAligned,
    pump_hint: CacheAligned,
    work_count: CacheAligned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplaceResizePolicyResult {
    Changed,
    Rejected,
    RetryLater,
}

impl ShardedQueues {
    fn new(
        initial_capacity: usize,
        shards: usize,
        interrupt_fallback_capacity: Option<usize>,
    ) -> Self {
        let initial_capacity = initial_capacity.max(1);
        let shard_count = shards.clamp(1, initial_capacity);
        let base = initial_capacity / shard_count;
        let remainder = initial_capacity % shard_count;
        let mut queues = Vec::with_capacity(shard_count);
        for index in 0..shard_count {
            queues.push(BoundedTreiberStack::new(
                base + usize::from(index < remainder),
            ));
        }
        Self {
            queues: RwLock::new(queues),
            interrupt_fallback: interrupt_fallback_capacity
                .filter(|capacity| *capacity != 0)
                .map(BoundedTreiberStack::new),
            prefer_interrupt_fallback: AtomicBool::new(true),
            minimum_capacity: 1,
            maximum_capacity: None,
            published_capacity: CacheAligned(AtomicUsize::new(initial_capacity)),
            pump_hint: CacheAligned(AtomicUsize::new(0)),
            work_count: CacheAligned(AtomicUsize::new(0)),
        }
    }

    fn shard_count(&self) -> usize {
        self.queues.read().len()
    }

    fn try_push<F>(
        &self,
        item: WorkItem,
        in_interrupt: bool,
        may_insert: F,
    ) -> Result<(), QueuePushError>
    where
        F: FnOnce() -> bool,
    {
        if !may_insert() {
            return Err(QueuePushError::Unavailable);
        }
        let queues = if in_interrupt {
            let Some(queues) = self.queues.try_read() else {
                return self
                    .interrupt_fallback
                    .as_ref()
                    .ok_or(QueuePushError::Contended)?
                    .try_push(item)
                    .map(|()| {
                        self.work_count.0.fetch_add(1, Ordering::Release);
                    })
                    .map_err(|_| QueuePushError::Contended);
            };
            queues
        } else {
            self.queues.read()
        };
        let shard_count = queues.len();
        let start = self.pump_hint.0.fetch_add(1, Ordering::Relaxed) % shard_count;
        let mut item = item;
        for offset in 0..shard_count {
            match queues[(start + offset) % shard_count].try_push(item) {
                Ok(()) => {
                    self.work_count.0.fetch_add(1, Ordering::Release);
                    return Ok(());
                }
                Err(returned) => item = returned,
            }
        }
        Err(QueuePushError::Full)
    }

    fn pop_round_robin(&self, start_idx: usize, in_interrupt: bool) -> Option<(WorkItem, usize)> {
        let prefer_interrupt = self
            .prefer_interrupt_fallback
            .fetch_xor(true, Ordering::Relaxed);
        if prefer_interrupt {
            if let Some(item) = self.pop_interrupt_fallback() {
                return Some((item, start_idx));
            }
        }
        if let Some(item) = self.pop_primary_round_robin(start_idx, in_interrupt) {
            return Some(item);
        }
        if !prefer_interrupt {
            return self.pop_interrupt_fallback().map(|item| (item, start_idx));
        }
        None
    }

    fn pop_interrupt_fallback(&self) -> Option<WorkItem> {
        let item = self.interrupt_fallback.as_ref()?.pop()?;
        self.work_count.0.fetch_sub(1, Ordering::AcqRel);
        Some(item)
    }

    fn pop_primary_round_robin(
        &self,
        start_idx: usize,
        in_interrupt: bool,
    ) -> Option<(WorkItem, usize)> {
        let queues = if in_interrupt {
            self.queues.try_read()?
        } else {
            self.queues.read()
        };
        let shard_count = queues.len();
        for offset in 0..shard_count {
            let index = (start_idx + offset) % shard_count;
            if let Some(item) = queues[index].pop() {
                self.work_count.0.fetch_sub(1, Ordering::AcqRel);
                return Some((item, index));
            }
        }
        None
    }

    fn has_pending_work(&self) -> bool {
        self.work_count.0.load(Ordering::Acquire) != 0
    }

    fn next_pump_hint(&self) -> usize {
        let shards = self.shard_count();
        self.pump_hint.0.fetch_add(1, Ordering::Relaxed) % shards
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QueuePushError {
    Full,
    Contended,
    Unavailable,
}

impl Growable for ShardedQueues {
    fn occupancy_hint(&self) -> OccupancyHint {
        OccupancyHint::new(
            self.work_count.0.load(Ordering::Acquire),
            self.published_capacity.0.load(Ordering::Acquire),
        )
    }

    fn minimum_capacity(&self) -> usize {
        self.minimum_capacity
    }

    fn maximum_capacity(&self) -> Option<usize> {
        self.maximum_capacity
    }

    fn allocation_granularity(&self) -> usize {
        1
    }

    fn try_grow(&self, minimum_capacity: usize) -> Result<usize, ResizeError> {
        let mut queues = self.queues.try_write().ok_or(ResizeError::Contended)?;
        let current: usize = queues.iter().map(BoundedTreiberStack::capacity).sum();
        if minimum_capacity <= current {
            return Ok(current);
        }
        if self
            .maximum_capacity
            .is_some_and(|max| minimum_capacity > max)
        {
            return Err(ResizeError::MaximumCapacityReached);
        }
        queues
            .try_reserve_exact(1)
            .map_err(|_| ResizeError::OutOfMemory)?;
        let additional = minimum_capacity - current;
        let queue =
            BoundedTreiberStack::try_new(additional).map_err(|_| ResizeError::OutOfMemory)?;
        queues.push(queue);
        self.published_capacity
            .0
            .store(minimum_capacity, Ordering::Release);
        Ok(minimum_capacity)
    }

    fn try_shrink(&self, requested_capacity: usize) -> Result<usize, ResizeError> {
        let published = self.published_capacity.0.load(Ordering::Acquire);
        let requested_capacity = requested_capacity.max(self.minimum_capacity);
        if requested_capacity >= published {
            return Ok(0);
        }
        let mut queues = self.queues.try_write().ok_or(ResizeError::Contended)?;
        let old: usize = queues.iter().map(BoundedTreiberStack::capacity).sum();
        let used: usize = queues.iter().map(BoundedTreiberStack::len).sum();
        let target = requested_capacity.max(self.minimum_capacity).max(used);
        if target >= old {
            return Ok(0);
        }
        let mut capacity = old;
        let mut index = queues.len();
        while index != 0 && capacity > target {
            index -= 1;
            let chunk_capacity = queues[index].capacity();
            if queues[index].is_empty()
                && capacity.saturating_sub(chunk_capacity) >= target
                && capacity.saturating_sub(chunk_capacity) >= self.minimum_capacity
            {
                queues.remove(index);
                capacity -= chunk_capacity;
            }
        }
        self.published_capacity.0.store(capacity, Ordering::Release);
        Ok(old - capacity)
    }
}

pub struct ExecutorDomain {
    id: ExecutorDomainId,
    generation: u32,
    class: ExecutorDomainClass,
    resize_policy: RwLock<ResizePolicyKind>,
    queues: ShardedQueues,
    future_arena: FutureArena,
    live_task_count: CacheAligned,

    state: AtomicU8,
    initial_queue_capacity: usize,

    scheduled_count: CacheAligned,

    queued_count: CacheAligned,
    active_count: CacheAligned,
    max_active: CacheAligned,

    quantum: CacheAligned,
    weight: CacheAligned,
    deficit: CacheAligned,

    submitted: CacheAligned,
    completed: CacheAligned,
    rejected: CacheAligned,
    total_runs: CacheAligned,
    scheduler_selections: CacheAligned,
    last_run_tick: CacheAligned,
}

impl ExecutorDomain {
    fn new(id: ExecutorDomainId, config: ExecutorDomainConfig, shards: usize) -> Self {
        let config = config.normalized();

        Self {
            id,
            generation: id.generation(),
            class: config.class,
            resize_policy: RwLock::new(config.resize_policy),
            queues: ShardedQueues::new(
                config.initial_queue_capacity,
                shards,
                config.interrupt_fallback_capacity,
            ),
            future_arena: FutureArena::new(id, config.future_arena),
            live_task_count: CacheAligned(AtomicUsize::new(0)),

            state: AtomicU8::new(ExecutorDomainState::Active as u8),
            initial_queue_capacity: config.initial_queue_capacity,

            scheduled_count: CacheAligned(AtomicUsize::new(0)),

            queued_count: CacheAligned(AtomicUsize::new(0)),
            active_count: CacheAligned(AtomicUsize::new(0)),
            max_active: CacheAligned(AtomicUsize::new(config.max_active)),

            quantum: CacheAligned(AtomicUsize::new(config.quantum)),
            weight: CacheAligned(AtomicUsize::new(config.weight)),
            deficit: CacheAligned(AtomicUsize::new(0)),

            submitted: CacheAligned(AtomicUsize::new(0)),
            completed: CacheAligned(AtomicUsize::new(0)),
            rejected: CacheAligned(AtomicUsize::new(0)),
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
        self.queues.has_pending_work()
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

            match self.scheduled_count.0.compare_exchange_weak(
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

    fn try_submit_work(
        &self,
        domain_id: ExecutorDomainId,
        work_item: WorkItem,
    ) -> Result<bool, ExecutorSubmitError> {
        match self.state() {
            ExecutorDomainState::Active => {}
            ExecutorDomainState::Draining => {
                return Err(self.reject_submit(
                    ExecutorSubmitErrorKind::DomainDraining,
                    domain_id,
                    work_item,
                ));
            }
            ExecutorDomainState::Dead => {
                return Err(self.reject_submit(
                    ExecutorSubmitErrorKind::DomainDead,
                    domain_id,
                    work_item,
                ));
            }
        }

        let in_interrupt = crate::platform::in_interrupt_context();
        let policy = if in_interrupt {
            let Some(policy) = self.resize_policy.try_read() else {
                return Err(self.reject_submit(
                    ExecutorSubmitErrorKind::RetryLater,
                    domain_id,
                    work_item,
                ));
            };
            policy
        } else {
            self.resize_policy.read()
        };
        let previous_queued = self.queued_count();
        match self.queues.try_push(work_item, in_interrupt, || {
            self.state() == ExecutorDomainState::Active
        }) {
            Ok(()) => {}
            Err(QueuePushError::Unavailable) => {
                return Err(self.reject_submit(
                    match self.state() {
                        ExecutorDomainState::Active => ExecutorSubmitErrorKind::RetryLater,
                        ExecutorDomainState::Draining => ExecutorSubmitErrorKind::DomainDraining,
                        ExecutorDomainState::Dead => ExecutorSubmitErrorKind::DomainDead,
                    },
                    domain_id,
                    work_item,
                ));
            }
            Err(QueuePushError::Contended) => {
                return Err(self.reject_submit(
                    ExecutorSubmitErrorKind::RetryLater,
                    domain_id,
                    work_item,
                ));
            }
            Err(QueuePushError::Full) => {
                let context = ResizeContext {
                    occupancy: self.queues.occupancy_hint(),
                    in_interrupt_context: in_interrupt,
                    event: ResizeEvent::CapacityReached,
                };
                let outcome = policy.on_capacity_reached(&self.queues, context);
                let failure = match outcome {
                    PolicyOutcome::Resized => {
                        match self.queues.try_push(work_item, in_interrupt, || {
                            self.state() == ExecutorDomainState::Active
                        }) {
                            Ok(()) => None,
                            Err(QueuePushError::Contended) => {
                                Some(ExecutorSubmitErrorKind::RetryLater)
                            }
                            Err(QueuePushError::Full) => Some(ExecutorSubmitErrorKind::DomainFull),
                            Err(QueuePushError::Unavailable) => {
                                Some(ExecutorSubmitErrorKind::DomainDraining)
                            }
                        }
                    }
                    PolicyOutcome::RetryLater => Some(ExecutorSubmitErrorKind::RetryLater),
                    PolicyOutcome::OutOfMemory => Some(ExecutorSubmitErrorKind::OutOfMemory),
                    PolicyOutcome::OwnerCannotContinue => {
                        self.move_to_draining();
                        Some(ExecutorSubmitErrorKind::DomainCannotContinue)
                    }
                    PolicyOutcome::NoChange | PolicyOutcome::Reject => {
                        Some(ExecutorSubmitErrorKind::DomainFull)
                    }
                };
                if let Some(kind) = failure {
                    return Err(self.reject_submit(kind, domain_id, work_item));
                }
            }
        }

        self.queued_count.0.fetch_add(1, Ordering::AcqRel);
        let _ = policy.on_insert(
            &self.queues,
            ResizeContext {
                occupancy: self.queues.occupancy_hint(),
                in_interrupt_context: in_interrupt,
                event: ResizeEvent::Inserted,
            },
        );
        self.submitted.0.fetch_add(1, Ordering::Relaxed);
        Ok(previous_queued == 0)
    }

    pub(crate) fn pop_work(&self, cursor: usize) -> Option<(WorkItem, usize)> {
        let in_interrupt = crate::platform::in_interrupt_context();
        let policy = if in_interrupt {
            self.resize_policy.try_read()?
        } else {
            self.resize_policy.read()
        };
        let item = self.queues.pop_round_robin(cursor, in_interrupt)?;
        self.queued_count.0.fetch_sub(1, Ordering::AcqRel);
        let _ = policy.on_remove(
            &self.queues,
            ResizeContext {
                occupancy: self.queues.occupancy_hint(),
                in_interrupt_context: in_interrupt,
                event: ResizeEvent::Removed,
            },
        );
        Some(item)
    }

    pub(crate) fn next_pump_hint(&self) -> usize {
        self.queues.next_pump_hint()
    }

    pub fn resize_policy(&self) -> ResizePolicyKind {
        *self.resize_policy.read()
    }

    pub fn replace_resize_policy(
        &self,
        replacement: ResizePolicyKind,
    ) -> ReplaceResizePolicyResult {
        let Some(mut current) = self.resize_policy.try_write() else {
            return ReplaceResizePolicyResult::RetryLater;
        };
        let context = ResizeContext {
            occupancy: self.queues.occupancy_hint(),
            in_interrupt_context: crate::platform::in_interrupt_context(),
            event: ResizeEvent::PolicyReplacement,
        };
        match current.on_policy_change(&self.queues, context, &replacement) {
            PolicyOutcome::NoChange | PolicyOutcome::Resized => {
                *current = replacement;
                ReplaceResizePolicyResult::Changed
            }
            PolicyOutcome::RetryLater => ReplaceResizePolicyResult::RetryLater,
            PolicyOutcome::Reject
            | PolicyOutcome::OutOfMemory
            | PolicyOutcome::OwnerCannotContinue => ReplaceResizePolicyResult::Rejected,
        }
    }

    pub(crate) fn shard_count(&self) -> usize {
        self.queues.shard_count()
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

    fn record_rejection(&self) {
        self.rejected.0.fetch_add(1, Ordering::Relaxed);
    }

    #[cold]
    fn reject_submit(
        &self,
        kind: ExecutorSubmitErrorKind,
        domain_id: ExecutorDomainId,
        work_item: WorkItem,
    ) -> ExecutorSubmitError {
        self.record_rejection();
        ExecutorSubmitError::new(kind, domain_id, work_item)
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
        let occupancy = self.queues.occupancy_hint();
        let resize_policy = *self.resize_policy.read();
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
            initial_queue_capacity: self.initial_queue_capacity,
            interrupt_fallback_capacity: self
                .queues
                .interrupt_fallback
                .as_ref()
                .map(BoundedTreiberStack::capacity),
            queue_minimum_capacity: resize_policy.minimum_capacity(),
            queue_capacity: occupancy.capacity,
            queue_maximum_capacity: resize_policy.maximum_capacity(),
            resize_policy,
            quantum: self.quantum(),
            weight: self.weight(),
            deficit: self.deficit.0.load(Ordering::Acquire),
            scheduled: self.is_scheduled(),
            submitted: self.submitted.0.load(Ordering::Acquire),
            completed: self.completed.0.load(Ordering::Acquire),
            rejected: self.rejected.0.load(Ordering::Acquire),
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
    shards: usize,
    next_slot: AtomicUsize,
    chunks: [AtomicPtr<DomainChunk>; MAX_DOMAIN_CHUNKS],
}

impl ExecutorDomainTable {
    pub(crate) fn new(shards: usize, max_work_items: usize) -> Self {
        let table = Self {
            shards: shards.max(1),
            next_slot: AtomicUsize::new(0),
            chunks: core::array::from_fn(|_| AtomicPtr::new(ptr::null_mut())),
        };

        table.install_builtin(
            KERNEL_HIGH_SLOT,
            ExecutorDomainConfig::for_class(
                ExecutorDomainClass::KernelHigh,
                shards,
                max_work_items,
            ),
        );
        table.install_builtin(
            DRIVER_SLOT,
            ExecutorDomainConfig::for_class(ExecutorDomainClass::Driver, shards, max_work_items),
        );
        table.install_builtin(
            KERNEL_NORMAL_SLOT,
            ExecutorDomainConfig::for_class(
                ExecutorDomainClass::KernelNormal,
                shards,
                max_work_items,
            ),
        );
        table.install_builtin(
            KERNEL_BACKGROUND_SLOT,
            ExecutorDomainConfig::for_class(
                ExecutorDomainClass::KernelBackground,
                shards,
                max_work_items,
            ),
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

        let domain = Arc::new(ExecutorDomain::new(id, config, self.shards));
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

        let domain = Arc::new(ExecutorDomain::new(id, config, self.shards));
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

    fn resolve_submit_domain(
        &self,
        domain_id: ExecutorDomainId,
        work_item: WorkItem,
    ) -> Result<Arc<ExecutorDomain>, ExecutorSubmitError> {
        if !domain_id.is_valid() {
            return Err(Self::invalid_submit(
                ExecutorSubmitErrorKind::InvalidDomain,
                domain_id,
                work_item,
            ));
        }

        let Some(slot) = self.get_existing_slot(domain_id.slot() as usize) else {
            return Err(Self::invalid_submit(
                ExecutorSubmitErrorKind::InvalidDomain,
                domain_id,
                work_item,
            ));
        };

        let slot_state = slot.state.load(Ordering::Acquire);

        if slot.generation() != domain_id.generation() {
            return Err(Self::invalid_submit(
                ExecutorSubmitErrorKind::StaleDomain,
                domain_id,
                work_item,
            ));
        }

        if slot_state != DOMAIN_SLOT_ACTIVE && slot_state != DOMAIN_SLOT_BUILTIN {
            return Err(Self::invalid_submit(
                ExecutorSubmitErrorKind::InvalidDomain,
                domain_id,
                work_item,
            ));
        }

        let Some(domain) = self.get_executor_domain(domain_id) else {
            return Err(Self::invalid_submit(
                ExecutorSubmitErrorKind::InvalidDomain,
                domain_id,
                work_item,
            ));
        };

        Ok(domain)
    }

    #[cold]
    fn invalid_submit(
        kind: ExecutorSubmitErrorKind,
        domain_id: ExecutorDomainId,
        work_item: WorkItem,
    ) -> ExecutorSubmitError {
        ExecutorSubmitError::new(kind, domain_id, work_item)
    }

    pub(crate) fn submit_to_executor_domain(
        &self,
        domain_id: ExecutorDomainId,
        work_item: WorkItem,
    ) -> Result<DomainSubmitOutcome, ExecutorSubmitError> {
        let domain = self.resolve_submit_domain(domain_id, work_item)?;
        let became_runnable = domain.try_submit_work(domain_id, work_item)?;

        Ok(DomainSubmitOutcome {
            domain_id,
            became_runnable,
        })
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

#[derive(Debug)]
pub(crate) struct DomainSubmitOutcome {
    pub(crate) domain_id: ExecutorDomainId,
    pub(crate) became_runnable: bool,
}

#[cfg(all(test, not(any(loom, feature = "loom"))))]
mod resize_queue_tests {
    use super::{Ordering, QueuePushError, ShardedQueues};
    use crate::global_async::WorkItem;

    extern "C" fn noop(_: usize) {}

    #[test]
    fn interrupt_push_uses_fallback_only_while_chunk_list_is_write_locked() {
        let queues = ShardedQueues::new(4, 2, Some(8));
        let _write = queues.queues.write();
        let item = WorkItem {
            trampoline: noop,
            ctx: 42,
        };

        assert_eq!(queues.try_push(item, true, || true), Ok(()));
        let (popped, _) = queues
            .pop_round_robin(0, true)
            .expect("fallback item was not visible");
        assert_eq!(popped.ctx, 42);

        let rejected = queues.try_push(item, true, || false);
        assert_eq!(rejected, Err(QueuePushError::Unavailable));
    }

    #[test]
    fn disabled_interrupt_fallback_reports_contention() {
        let queues = ShardedQueues::new(4, 2, None);
        let _write = queues.queues.write();
        let item = WorkItem {
            trampoline: noop,
            ctx: 42,
        };

        assert_eq!(
            queues.try_push(item, true, || true),
            Err(QueuePushError::Contended)
        );
    }

    #[test]
    fn pop_alternates_interrupt_fallback_and_primary_queue() {
        let queues = ShardedQueues::new(4, 1, Some(4));

        assert_eq!(
            queues.try_push(
                WorkItem {
                    trampoline: noop,
                    ctx: 1,
                },
                false,
                || true,
            ),
            Ok(())
        );
        assert_eq!(
            queues.try_push(
                WorkItem {
                    trampoline: noop,
                    ctx: 2,
                },
                false,
                || true,
            ),
            Ok(())
        );

        let fallback = queues.interrupt_fallback.as_ref().unwrap();
        fallback
            .try_push(WorkItem {
                trampoline: noop,
                ctx: 101,
            })
            .unwrap();
        fallback
            .try_push(WorkItem {
                trampoline: noop,
                ctx: 102,
            })
            .unwrap();
        queues.work_count.0.fetch_add(2, Ordering::Release);

        let popped = [
            queues.pop_round_robin(0, false).unwrap().0.ctx,
            queues.pop_round_robin(0, false).unwrap().0.ctx,
            queues.pop_round_robin(0, false).unwrap().0.ctx,
            queues.pop_round_robin(0, false).unwrap().0.ctx,
        ];
        assert!(popped[0] >= 100);
        assert!(popped[1] < 100);
        assert!(popped[2] >= 100);
        assert!(popped[3] < 100);
    }
}
