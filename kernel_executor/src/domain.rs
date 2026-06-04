use crate::global_async::{CacheAligned, WorkItem};
use crate::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use crate::sync::{Arc, Mutex};
use alloc::vec::Vec;
use kernel_types::io::BoundedTreiberStack;

const BUILTIN_GENERATION: u32 = 1;
const KERNEL_HIGH_SLOT: u32 = 0;
const DRIVER_SLOT: u32 = 1;
const KERNEL_NORMAL_SLOT: u32 = 2;
const KERNEL_BACKGROUND_SLOT: u32 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct DomainId(u64);

impl DomainId {
    pub const fn from_parts(slot: u32, generation: u32) -> Self {
        Self(((generation as u64) << 32) | slot as u64)
    }

    pub const fn raw(self) -> u64 {
        self.0
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

pub const KERNEL_HIGH_DOMAIN: DomainId =
    DomainId::from_parts(KERNEL_HIGH_SLOT, BUILTIN_GENERATION);
pub const DRIVER_DOMAIN: DomainId = DomainId::from_parts(DRIVER_SLOT, BUILTIN_GENERATION);
pub const KERNEL_NORMAL_DOMAIN: DomainId =
    DomainId::from_parts(KERNEL_NORMAL_SLOT, BUILTIN_GENERATION);
pub const KERNEL_BACKGROUND_DOMAIN: DomainId =
    DomainId::from_parts(KERNEL_BACKGROUND_SLOT, BUILTIN_GENERATION);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DomainClass {
    KernelHigh = 0,
    Driver = 1,
    KernelNormal = 2,
    ProcessIo = 3,
    KernelBackground = 4,
}

impl DomainClass {
    pub const fn default_weight(self) -> usize {
        match self {
            DomainClass::KernelHigh => 8,
            DomainClass::Driver => 6,
            DomainClass::KernelNormal => 4,
            DomainClass::ProcessIo => 3,
            DomainClass::KernelBackground => 1,
        }
    }

    pub const fn default_quantum(self) -> usize {
        match self {
            DomainClass::KernelHigh => 8,
            DomainClass::Driver => 6,
            DomainClass::KernelNormal => 4,
            DomainClass::ProcessIo => 4,
            DomainClass::KernelBackground => 1,
        }
    }

    pub fn default_max_active(self, cpu_count: usize) -> usize {
        let cpu_count = cpu_count.max(1);
        match self {
            DomainClass::KernelHigh => cpu_count,
            DomainClass::Driver => (cpu_count / 2).max(1),
            DomainClass::KernelNormal => cpu_count,
            DomainClass::ProcessIo => (cpu_count / 4).max(1),
            DomainClass::KernelBackground => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DomainState {
    Active = 0,
    Draining = 1,
    Dead = 2,
}

impl DomainState {
    const fn from_u8(value: u8) -> Self {
        match value {
            0 => DomainState::Active,
            1 => DomainState::Draining,
            _ => DomainState::Dead,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AdmissionPolicy {
    RejectWhenFull = 0,
}

#[derive(Clone, Copy, Debug)]
pub struct DomainConfig {
    pub class: DomainClass,
    pub max_active: usize,
    pub max_queued: usize,
    pub quantum: usize,
    pub weight: usize,
    pub admission_policy: AdmissionPolicy,
}

impl DomainConfig {
    pub fn for_class(class: DomainClass, cpu_count: usize, max_queued: usize) -> Self {
        Self {
            class,
            max_active: class.default_max_active(cpu_count),
            max_queued,
            quantum: class.default_quantum(),
            weight: class.default_weight(),
            admission_policy: AdmissionPolicy::RejectWhenFull,
        }
    }

    pub fn kernel_normal(cpu_count: usize, max_queued: usize) -> Self {
        Self::for_class(DomainClass::KernelNormal, cpu_count, max_queued)
    }

    fn normalized(mut self) -> Self {
        self.max_active = self.max_active.max(1);
        self.max_queued = self.max_queued.max(1);
        self.quantum = self.quantum.max(1);
        self.weight = self.weight.max(1);
        self
    }
}

impl Default for DomainConfig {
    fn default() -> Self {
        Self::kernel_normal(1, 1024)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmitErrorKind {
    ExecutorUninitialized,
    InvalidDomain,
    StaleDomain,
    DomainDraining,
    DomainDead,
    DomainFull,
}

#[derive(Clone, Copy, Debug)]
pub struct SubmitError {
    pub kind: SubmitErrorKind,
    pub domain_id: DomainId,
    pub work_item: WorkItem,
}

impl SubmitError {
    pub(crate) fn new(kind: SubmitErrorKind, domain_id: DomainId, work_item: WorkItem) -> Self {
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
pub enum DestroyDomainError {
    InvalidDomain,
    StaleDomain,
    BuiltinDomain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DestroyDomainResult {
    Destroyed,
    Draining,
}

#[derive(Clone, Copy, Debug)]
pub struct DomainStats {
    pub domain_id: DomainId,
    pub generation: u32,
    pub class: DomainClass,
    pub state: DomainState,
    pub queued_count: usize,
    pub active_count: usize,
    pub max_active: usize,
    pub max_queued: usize,
    pub admission_policy: AdmissionPolicy,
    pub quantum: usize,
    pub weight: usize,
    pub deficit: usize,
    pub ready_enqueued: bool,
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
    pub runnable_domain_count: usize,
    pub domain_count: usize,
    pub total_submissions: usize,
    pub total_rejections: usize,
    pub total_pump_runs: usize,
}

struct ShardedQueues {
    queues: Vec<BoundedTreiberStack<WorkItem>>,
    enqueue_hint: CacheAligned,
    pump_hint: CacheAligned,
    work_count: CacheAligned,
}

impl ShardedQueues {
    fn new(shards: usize, max_work_items: usize) -> Self {
        let shards = shards.max(1);
        let base = max_work_items / shards;
        let rem = max_work_items % shards;

        let mut queues = Vec::with_capacity(shards);

        let mut i = 0usize;
        while i < shards {
            let cap = base + usize::from(i < rem);
            queues.push(BoundedTreiberStack::new(cap));
            i += 1;
        }

        Self {
            queues,
            enqueue_hint: CacheAligned(AtomicUsize::new(0)),
            pump_hint: CacheAligned(AtomicUsize::new(0)),
            work_count: CacheAligned(AtomicUsize::new(0)),
        }
    }

    fn shard_count(&self) -> usize {
        self.queues.len()
    }

    fn try_push(&self, mut item: WorkItem) -> Result<(), WorkItem> {
        let shards = self.shard_count();
        let start = self.enqueue_hint.0.fetch_add(1, Ordering::Relaxed) % shards;

        let mut offset = 0usize;
        while offset < shards {
            let idx = (start + offset) % shards;

            match self.queues[idx].try_push(item) {
                Ok(()) => {
                    self.work_count.0.fetch_add(1, Ordering::Release);
                    return Ok(());
                }
                Err(returned) => {
                    item = returned;
                }
            }

            offset += 1;
        }

        Err(item)
    }

    fn pop_round_robin(&self, start_idx: usize) -> Option<(WorkItem, usize)> {
        let shards = self.shard_count();

        let mut offset = 0usize;
        while offset < shards {
            let idx = (start_idx + offset) % shards;

            if let Some(item) = self.queues[idx].pop() {
                self.work_count.0.fetch_sub(1, Ordering::AcqRel);
                return Some((item, idx));
            }

            offset += 1;
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

pub struct ExecutorDomain {
    id: DomainId,
    generation: u32,
    class: DomainClass,
    admission_policy: AdmissionPolicy,
    queues: ShardedQueues,
    state: AtomicU8,
    queued_count: CacheAligned,
    active_count: CacheAligned,
    max_active: CacheAligned,
    max_queued: usize,
    quantum: CacheAligned,
    weight: CacheAligned,
    deficit: CacheAligned,
    ready_enqueued: AtomicBool,
    submitted: CacheAligned,
    completed: CacheAligned,
    rejected: CacheAligned,
    total_runs: CacheAligned,
    scheduler_selections: CacheAligned,
    last_run_tick: CacheAligned,
}

impl ExecutorDomain {
    fn new(id: DomainId, config: DomainConfig, shards: usize) -> Self {
        let config = config.normalized();

        Self {
            id,
            generation: id.generation(),
            class: config.class,
            admission_policy: config.admission_policy,
            queues: ShardedQueues::new(shards, config.max_queued),
            state: AtomicU8::new(DomainState::Active as u8),
            queued_count: CacheAligned(AtomicUsize::new(0)),
            active_count: CacheAligned(AtomicUsize::new(0)),
            max_active: CacheAligned(AtomicUsize::new(config.max_active)),
            max_queued: config.max_queued,
            quantum: CacheAligned(AtomicUsize::new(config.quantum)),
            weight: CacheAligned(AtomicUsize::new(config.weight)),
            deficit: CacheAligned(AtomicUsize::new(0)),
            ready_enqueued: AtomicBool::new(false),
            submitted: CacheAligned(AtomicUsize::new(0)),
            completed: CacheAligned(AtomicUsize::new(0)),
            rejected: CacheAligned(AtomicUsize::new(0)),
            total_runs: CacheAligned(AtomicUsize::new(0)),
            scheduler_selections: CacheAligned(AtomicUsize::new(0)),
            last_run_tick: CacheAligned(AtomicUsize::new(0)),
        }
    }

    pub fn id(&self) -> DomainId {
        self.id
    }

    pub fn class(&self) -> DomainClass {
        self.class
    }

    pub fn state(&self) -> DomainState {
        DomainState::from_u8(self.state.load(Ordering::Acquire))
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

    pub fn queued_count(&self) -> usize {
        self.queued_count.0.load(Ordering::Acquire)
    }

    pub fn active_count(&self) -> usize {
        self.active_count.0.load(Ordering::Acquire)
    }

    pub fn has_queued_work(&self) -> bool {
        self.queued_count() != 0 || self.queues.has_pending_work()
    }

    pub fn is_runnable_for_policy(&self) -> bool {
        self.state() != DomainState::Dead && self.has_queued_work()
    }

    pub fn is_at_active_limit(&self) -> bool {
        self.active_count() >= self.max_active()
    }

    fn try_submit_work(
        &self,
        domain_id: DomainId,
        work_item: WorkItem,
    ) -> Result<bool, SubmitError> {
        match self.state() {
            DomainState::Active => {}
            DomainState::Draining => {
                return Err(self.reject_submit(
                    SubmitErrorKind::DomainDraining,
                    domain_id,
                    work_item,
                ));
            }
            DomainState::Dead => {
                return Err(self.reject_submit(
                    SubmitErrorKind::DomainDead,
                    domain_id,
                    work_item,
                ));
            }
        }

        if self
            .queued_count
            .0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |queued| {
                (queued < self.max_queued).then_some(queued + 1)
            })
            .is_err()
        {
            return Err(self.reject_submit(
                SubmitErrorKind::DomainFull,
                domain_id,
                work_item,
            ));
        }

        if self.state() != DomainState::Active {
            self.queued_count.0.fetch_sub(1, Ordering::AcqRel);
            return Err(self.reject_submit(
                match self.state() {
                    DomainState::Active => SubmitErrorKind::DomainFull,
                    DomainState::Draining => SubmitErrorKind::DomainDraining,
                    DomainState::Dead => SubmitErrorKind::DomainDead,
                },
                domain_id,
                work_item,
            ));
        }

        if let Err(work_item) = self.queues.try_push(work_item) {
            self.queued_count.0.fetch_sub(1, Ordering::AcqRel);
            return Err(self.reject_submit(
                SubmitErrorKind::DomainFull,
                domain_id,
                work_item,
            ));
        }

        self.submitted.0.fetch_add(1, Ordering::AcqRel);
        Ok(self.mark_runnable())
    }

    pub(crate) fn mark_runnable(&self) -> bool {
        self.ready_enqueued
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    pub(crate) fn clear_runnable(&self) {
        self.ready_enqueued.store(false, Ordering::Release);
    }

    pub(crate) fn pop_work(&self, cursor: usize) -> Option<(WorkItem, usize)> {
        let item = self.queues.pop_round_robin(cursor)?;
        self.queued_count.0.fetch_sub(1, Ordering::AcqRel);
        Some(item)
    }

    pub(crate) fn next_pump_hint(&self) -> usize {
        self.queues.next_pump_hint()
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
        self.scheduler_selections.0.fetch_add(1, Ordering::AcqRel);
    }

    pub(crate) fn record_run_started(&self, tick: usize) {
        self.total_runs.0.fetch_add(1, Ordering::AcqRel);
        self.last_run_tick.0.store(tick, Ordering::Release);
    }

    pub(crate) fn record_completed(&self) {
        self.completed.0.fetch_add(1, Ordering::AcqRel);
    }

    fn record_rejection(&self) {
        self.rejected.0.fetch_add(1, Ordering::AcqRel);
    }

    #[cold]
    fn reject_submit(
        &self,
        kind: SubmitErrorKind,
        domain_id: DomainId,
        work_item: WorkItem,
    ) -> SubmitError {
        self.record_rejection();
        SubmitError::new(kind, domain_id, work_item)
    }

    fn move_to_draining(&self) {
        let _ = self.state.compare_exchange(
            DomainState::Active as u8,
            DomainState::Draining as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    fn move_to_dead(&self) {
        self.state
            .store(DomainState::Dead as u8, Ordering::Release);
        self.clear_runnable();
    }

    pub(crate) fn maybe_finish_draining(&self) {
        if self.state() == DomainState::Draining
            && self.queued_count() == 0
            && self.active_count() == 0
        {
            self.move_to_dead();
        }
    }

    pub fn stats(&self) -> DomainStats {
        DomainStats {
            domain_id: self.id,
            generation: self.generation,
            class: self.class,
            state: self.state(),
            queued_count: self.queued_count(),
            active_count: self.active_count(),
            max_active: self.max_active(),
            max_queued: self.max_queued,
            admission_policy: self.admission_policy,
            quantum: self.quantum(),
            weight: self.weight(),
            deficit: self.deficit.0.load(Ordering::Acquire),
            ready_enqueued: self.ready_enqueued.load(Ordering::Acquire),
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
    generation: u32,
    domain: Option<Arc<ExecutorDomain>>,
    builtin: bool,
}

pub struct DomainTable {
    shards: usize,
    slots: Mutex<Vec<DomainSlot>>,
}

impl DomainTable {
    pub(crate) fn new(shards: usize, max_work_items: usize) -> Self {
        let table = Self {
            shards: shards.max(1),
            slots: Mutex::new(Vec::new()),
        };

        table.install_builtin(
            KERNEL_HIGH_SLOT,
            DomainConfig::for_class(DomainClass::KernelHigh, shards, max_work_items),
        );
        table.install_builtin(
            DRIVER_SLOT,
            DomainConfig::for_class(DomainClass::Driver, shards, max_work_items),
        );
        table.install_builtin(
            KERNEL_NORMAL_SLOT,
            DomainConfig::for_class(DomainClass::KernelNormal, shards, max_work_items),
        );
        table.install_builtin(
            KERNEL_BACKGROUND_SLOT,
            DomainConfig::for_class(DomainClass::KernelBackground, shards, max_work_items),
        );

        table
    }

    fn install_builtin(&self, slot_idx: u32, config: DomainConfig) {
        let id = DomainId::from_parts(slot_idx, BUILTIN_GENERATION);
        let mut slots = self.slots.lock();
        while slots.len() <= slot_idx as usize {
            slots.push(DomainSlot {
                generation: BUILTIN_GENERATION,
                domain: None,
                builtin: false,
            });
        }

        slots[slot_idx as usize] = DomainSlot {
            generation: BUILTIN_GENERATION,
            domain: Some(Arc::new(ExecutorDomain::new(id, config, self.shards))),
            builtin: true,
        };
    }

    pub fn create_domain(&self, config: DomainConfig) -> DomainId {
        let mut slots = self.slots.lock();
        let config = config.normalized();

        let mut idx = 0usize;
        while idx < slots.len() {
            if slots[idx].domain.is_none() && !slots[idx].builtin {
                let generation = slots[idx].generation.max(1);
                let id = DomainId::from_parts(idx as u32, generation);
                slots[idx].domain = Some(Arc::new(ExecutorDomain::new(id, config, self.shards)));
                return id;
            }

            idx += 1;
        }

        let id = DomainId::from_parts(slots.len() as u32, BUILTIN_GENERATION);
        slots.push(DomainSlot {
            generation: BUILTIN_GENERATION,
            domain: Some(Arc::new(ExecutorDomain::new(id, config, self.shards))),
            builtin: false,
        });
        id
    }

    pub fn destroy_domain(
        &self,
        domain_id: DomainId,
    ) -> Result<DestroyDomainResult, DestroyDomainError> {
        let mut slots = self.slots.lock();
        let Some(slot) = slots.get_mut(domain_id.slot() as usize) else {
            return Err(DestroyDomainError::InvalidDomain);
        };

        if slot.generation != domain_id.generation() {
            return Err(DestroyDomainError::StaleDomain);
        }

        if slot.builtin {
            return Err(DestroyDomainError::BuiltinDomain);
        }

        let Some(domain) = slot.domain.as_ref() else {
            return Err(DestroyDomainError::InvalidDomain);
        };

        if domain.queued_count() == 0 && domain.active_count() == 0 {
            domain.move_to_dead();
            slot.domain = None;
            slot.generation = slot.generation.wrapping_add(1).max(1);
            return Ok(DestroyDomainResult::Destroyed);
        }

        domain.move_to_draining();
        Ok(DestroyDomainResult::Draining)
    }

    pub fn get_domain(&self, domain_id: DomainId) -> Option<Arc<ExecutorDomain>> {
        let slots = self.slots.lock();
        let slot = slots.get(domain_id.slot() as usize)?;
        if slot.generation != domain_id.generation() {
            return None;
        }
        slot.domain.clone()
    }

    fn resolve_submit_domain(
        &self,
        domain_id: DomainId,
        work_item: WorkItem,
    ) -> Result<Arc<ExecutorDomain>, SubmitError> {
        if !domain_id.is_valid() {
            return Err(Self::invalid_submit(
                SubmitErrorKind::InvalidDomain,
                domain_id,
                work_item,
            ));
        }

        let slots = self.slots.lock();
        let Some(slot) = slots.get(domain_id.slot() as usize) else {
            return Err(Self::invalid_submit(
                SubmitErrorKind::InvalidDomain,
                domain_id,
                work_item,
            ));
        };

        if slot.generation != domain_id.generation() {
            return Err(Self::invalid_submit(
                SubmitErrorKind::StaleDomain,
                domain_id,
                work_item,
            ));
        }

        let Some(domain) = slot.domain.as_ref() else {
            return Err(Self::invalid_submit(
                SubmitErrorKind::InvalidDomain,
                domain_id,
                work_item,
            ));
        };

        Ok(domain.clone())
    }

    #[cold]
    fn invalid_submit(
        kind: SubmitErrorKind,
        domain_id: DomainId,
        work_item: WorkItem,
    ) -> SubmitError {
        SubmitError::new(kind, domain_id, work_item)
    }

    pub(crate) fn submit_to_domain(
        &self,
        domain_id: DomainId,
        work_item: WorkItem,
    ) -> Result<DomainSubmitOutcome, SubmitError> {
        let domain = self.resolve_submit_domain(domain_id, work_item)?;
        let became_runnable = domain.try_submit_work(domain_id, work_item)?;

        Ok(DomainSubmitOutcome {
            domain_id,
            became_runnable,
        })
    }

    pub fn domain_count(&self) -> usize {
        let slots = self.slots.lock();
        slots.iter().filter(|slot| slot.domain.is_some()).count()
    }
}

#[derive(Debug)]
pub(crate) struct DomainSubmitOutcome {
    pub(crate) domain_id: DomainId,
    pub(crate) became_runnable: bool,
}
