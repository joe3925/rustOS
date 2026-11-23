use crate::platform::ExecutorPlatform;
use crate::sync::Arc;
use crate::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering, fence};
use alloc::boxed::Box;
use core::cell::UnsafeCell;
use core::ptr;
use core::sync::atomic::AtomicPtr;

const INITIAL_GENERATION: u32 = 1;

const DOMAIN_SLOT_EMPTY: usize = 0;
const DOMAIN_SLOT_RESERVED: usize = 1;
const DOMAIN_SLOT_ACTIVE: usize = 2;
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
pub(crate) const BATCH_EMPTY: u8 = 0;
pub(crate) const BATCH_OWNED: u8 = 2;

#[repr(align(64))]
pub(crate) struct ReadyBatch {
    pub local_task: usize,
    pub local_runs: u8,
    pub tick: u32,
    pub random: u64,
    pub global_interval: u32,
    #[cfg(any(test, loom, feature = "loom", feature = "hosted"))]
    pub poll_started: Option<std::time::Instant>,
    #[cfg(not(any(test, loom, feature = "loom", feature = "hosted")))]
    pub poll_started: Option<u64>,
    pub poll_count: usize,
    pub elapsed_ns: u64,
    #[cfg(any(test, loom, feature = "loom", feature = "hosted"))]
    pub poll_time_ns: f64,
    #[cfg(not(any(test, loom, feature = "loom", feature = "hosted")))]
    pub poll_time_ns: u64,
}

impl ReadyBatch {
    pub(crate) fn start_poll_sample<E: crate::platform::ExecutorPlatform>(&mut self) {
        #[cfg(any(test, loom, feature = "loom", feature = "hosted"))]
        { self.poll_started = Some(std::time::Instant::now()); }
        #[cfg(not(any(test, loom, feature = "loom", feature = "hosted")))]
        { self.poll_started = Some(E::scheduler_time_ns()); }
        self.poll_count = 0;
    }

    pub(crate) fn finish_poll_sample<E: crate::platform::ExecutorPlatform>(&mut self) {
        if let Some(started) = self.poll_started.take() && self.poll_count != 0 {
            #[cfg(any(test, loom, feature = "loom", feature = "hosted"))]
            {
                let count = self.poll_count as f64;
                let elapsed = started.elapsed().as_nanos() as u64;
                self.elapsed_ns = self.elapsed_ns.saturating_add(elapsed);
                let mean = elapsed as f64 / count;
                let alpha = 1.0 - 0.9_f64.powf(count);
                self.poll_time_ns = alpha * mean + (1.0 - alpha) * self.poll_time_ns;
            }
            #[cfg(not(any(test, loom, feature = "loom", feature = "hosted")))]
            {
                const DECAY: [u32; 128] = [0, 3865470566, 3478923510, 3131031159, 2817928043, 2536135239, 2282521715, 2054269543, 1848842589, 1663958330, 1497562497, 1347806247, 1213025623, 1091723060, 982550754, 884295679, 795866111, 716279500, 644651550, 580186395, 522167755, 469950980, 422955882, 380660294, 342594264, 308334838, 277501354, 249751219, 224776097, 202298487, 182068638, 163861775, 147475597, 132728037, 119455234, 107509710, 96758739, 87082865, 78374579, 70537121, 63483409, 57135068, 51421561, 46279405, 41651465, 37486318, 33737686, 30363918, 27327526, 24594773, 22135296, 19921766, 17929590, 16136631, 14522968, 13070671, 11763604, 10587243, 9528519, 8575667, 7718100, 6946290, 6251661, 5626495, 5063846, 4557461, 4101715, 3691544, 3322389, 2990150, 2691135, 2422022, 2179820, 1961838, 1765654, 1589088, 1430180, 1287162, 1158445, 1042601, 938341, 844507, 760056, 684050, 615645, 554081, 498673, 448806, 403925, 363532, 327179, 294461, 265015, 238514, 214662, 193196, 173876, 156489, 140840, 126756, 114080, 102672, 92405, 83165, 74848, 67363, 60627, 54564, 49108, 44197, 39777, 35800, 32220, 28998, 26098, 23488, 21139, 19025, 17123, 15411, 13870, 12483, 11234, 10111, 9100, 8190, 7371, 6634];
                let elapsed = E::scheduler_time_ns().saturating_sub(started);
                self.elapsed_ns = self.elapsed_ns.saturating_add(elapsed);
                let mean = elapsed / self.poll_count as u64;
                let weight = DECAY.get(self.poll_count).copied().unwrap_or(0) as u128;
                self.poll_time_ns = ((((1u128 << 32) - weight) * mean as u128
                    + weight * self.poll_time_ns as u128) >> 32) as u64;
            }
        }
        self.poll_count = 0;
    }
}

#[repr(align(64))]
pub(crate) struct BatchSlot {
    pub state: AtomicU8,
    pub batch: UnsafeCell<ReadyBatch>,
    pub spawned: crate::steal_queue::StealQueue<256>,
}

unsafe impl Sync for BatchSlot {}

pub(crate) struct Injection {
    pub head: usize,
    pub tail: Option<&'static crate::runtime::slab::slot::TaskSlot>,
    pub len: usize,
}

struct DomainCleanup {
    queue_index: usize,
    queue_head: usize,
    task_cursor: [usize; 3],
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
    pub weight: usize,
}

impl ExecutorDomainConfig {
    fn normalized(self) -> Self {
        Self { weight: self.weight.clamp(1, u16::MAX as usize) }
    }
}

impl Default for ExecutorDomainConfig {
    fn default() -> Self {
        Self { weight: 1 }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DestroyExecutorDomainError {
    InvalidDomain,
    StaleDomain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DestroyExecutorDomainResult {
    Destroyed,
    Draining,
}

#[derive(Clone, Copy, Debug)]
pub struct ExecutorDomainInfo {
    pub state: ExecutorDomainState,
    pub weight: usize,
}

#[repr(align(64))]
pub struct ExecutorDomain<E: ExecutorPlatform> {
    id: ExecutorDomainId,
    pub(crate) batches: Box<[BatchSlot]>,
    pub(crate) inject: crate::sync::SchedulerMutex<Injection>,
    pub(crate) inject_len: AtomicUsize,
    pub(crate) incoming: AtomicUsize,
    pub(crate) poll_time_ns: AtomicU64,
    pub(crate) service: AtomicU64,
    _platform: core::marker::PhantomData<fn() -> E>,
    cleanup: UnsafeCell<DomainCleanup>,
    state: AtomicU8,
    weight: AtomicUsize,
}

unsafe impl<E: ExecutorPlatform> Sync for ExecutorDomain<E> {}

impl<E: ExecutorPlatform> ExecutorDomain<E> {
    fn new(
        id: ExecutorDomainId,
        config: ExecutorDomainConfig,
        workers: usize,
    ) -> Self {
        let config = config.normalized();
        Self {
            id,
            batches: (0..workers.max(1)).map(|index| BatchSlot {
                state: AtomicU8::new(BATCH_EMPTY),
                batch: UnsafeCell::new(ReadyBatch {
                    local_task: 0,
                    local_runs: 0,
                    tick: 0,
                    random: (index as u64 + 1).wrapping_mul(0x9e3779b97f4a7c15),
                    global_interval: 61,
                    poll_started: None,
                    poll_count: 0,
                    elapsed_ns: 0,
                    #[cfg(any(test, loom, feature = "loom", feature = "hosted"))]
                    poll_time_ns: 200_000.0 / 61.0,
                    #[cfg(not(any(test, loom, feature = "loom", feature = "hosted")))]
                    poll_time_ns: 200_000 / 61,
                }),
                spawned: crate::steal_queue::StealQueue::new(),
            }).collect(),
            inject: crate::sync::SchedulerMutex::new(Injection { head: 0, tail: None, len: 0 }),
            inject_len: AtomicUsize::new(0),
            incoming: AtomicUsize::new(0),
            poll_time_ns: AtomicU64::new(200_000 / 61),
            service: AtomicU64::new(0),
            _platform: core::marker::PhantomData,
            cleanup: UnsafeCell::new(DomainCleanup {
                queue_index: 0,
                queue_head: 0,
                task_cursor: [0; 3],
                tasks_done: false,
            }),
            state: AtomicU8::new(ExecutorDomainState::Active as u8),
            weight: AtomicUsize::new(config.weight),
        }
    }

    pub fn id(&self) -> ExecutorDomainId { self.id }

    pub fn state(&self) -> ExecutorDomainState {
        ExecutorDomainState::from_u8(self.state.load(Ordering::Acquire))
    }

    pub fn weight(&self) -> usize { self.weight.load(Ordering::Relaxed) }

    pub fn set_weight(&self, weight: usize) {
        self.weight.store(weight.clamp(1, u16::MAX as usize), Ordering::Relaxed);
    }

    pub(crate) fn has_queued_work(&self) -> bool {
        self.incoming.load(Ordering::Acquire) != 0
            || self.inject_len.load(Ordering::Acquire) != 0
            || self.batches.iter().any(|batch| batch.spawned.has_work())
    }

    fn move_to_draining(&self) {
        let _ = self.state.compare_exchange(
            ExecutorDomainState::Active as u8,
            ExecutorDomainState::Draining as u8,
            Ordering::AcqRel, Ordering::Acquire,
        );
    }

    fn move_to_dead(&self) {
        self.state.store(ExecutorDomainState::Dead as u8, Ordering::Release);
    }

    pub fn info(&self) -> ExecutorDomainInfo {
        ExecutorDomainInfo { state: self.state(), weight: self.weight() }
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
            generation: AtomicUsize::new(INITIAL_GENERATION as usize),
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
    ready: [AtomicUsize; MAX_DOMAIN_SLOTS.div_ceil(usize::BITS as usize)],
    ready_groups: AtomicU64,
    selection: crate::sync::SchedulerMutex<u64>,
}

impl<E: ExecutorPlatform> ExecutorDomainTable<E> {
    pub(crate) fn new(cpu_count: usize) -> Self {
        Self {
            reclamation: Arc::new(DomainReclamation::<E> {
                _platform: core::marker::PhantomData,
                pending: AtomicBool::new(false),
                candidates: core::array::from_fn(|_| AtomicUsize::new(0)),
            }),
            next_slot: AtomicUsize::new(0),
            chunks: core::array::from_fn(|_| AtomicPtr::new(ptr::null_mut())),
            workers: cpu_count.max(1),
            ready: core::array::from_fn(|_| AtomicUsize::new(0)),
            ready_groups: AtomicU64::new(0),
            selection: crate::sync::SchedulerMutex::new(0),
        }
    }

    fn chunk_index(slot_idx: usize) -> usize {
        slot_idx >> DOMAIN_CHUNK_BITS
    }

    fn chunk_slot_index(slot_idx: usize) -> usize {
        slot_idx & DOMAIN_CHUNK_MASK
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

    pub fn create_executor_domain(&self, config: ExecutorDomainConfig) -> Arc<ExecutorDomain<E>> {
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
    ) -> Arc<ExecutorDomain<E>> {
        let generation = slot.generation.load(Ordering::Acquire).max(1) as u32;
        let id = ExecutorDomainId::from_parts(idx as u32, generation);

        let domain = Arc::new(ExecutorDomain::<E>::new(
            id,
            config,
            self.workers,
        ));
        let raw = Arc::into_raw(domain.clone()) as *mut ExecutorDomain<E>;

        slot.domain.store(raw, Ordering::Release);
        slot.state.store(DOMAIN_SLOT_ACTIVE, Ordering::Release);

        domain
    }

    pub fn destroy_executor_domain(
        &self,
        domain_id: ExecutorDomainId,
    ) -> Result<DestroyExecutorDomainResult, DestroyExecutorDomainError> {
        let slot = self
            .get_existing_slot(domain_id.slot() as usize)
            .ok_or(DestroyExecutorDomainError::InvalidDomain)?;
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
        if state != DOMAIN_SLOT_ACTIVE {
            return None;
        }
        let previous = slot.readers.fetch_add(1, Ordering::SeqCst);
        assert!(previous & DOMAIN_READER_COUNT < DOMAIN_READER_COUNT);
        if previous & DOMAIN_READER_CLOSED != 0 {
            if slot.readers.fetch_sub(1, Ordering::SeqCst) & DOMAIN_READER_COUNT == 1 {
                self.reclamation.request(domain_id.slot() as usize);
            }
            return None;
        }
        if slot.state.load(Ordering::SeqCst) != state || slot.generation() != domain_id.generation()
        {
            if slot.readers.fetch_sub(1, Ordering::SeqCst) & DOMAIN_READER_COUNT == 1 {
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

    pub(crate) fn mark_ready(&self, id: ExecutorDomainId) {
        let index = id.slot() as usize;
        let word = index / usize::BITS as usize;
        let bit = 1usize << (index % usize::BITS as usize);
        self.ready[word].fetch_or(bit, Ordering::Release);
        if self.ready_groups.load(Ordering::Acquire) & (1u64 << word) == 0 {
            self.ready_groups.fetch_or(1u64 << word, Ordering::Release);
        }
    }

    pub(crate) fn visit_ready<'a>(&'a self, mut visit: impl FnMut(DomainBorrow<'a, E>) -> bool) {
        let mut groups = self.ready_groups.load(Ordering::Acquire);
        while groups != 0 {
            let word_index = groups.trailing_zeros() as usize;
            groups &= groups - 1;
            let mut bits = self.ready[word_index].load(Ordering::Acquire);
            while bits != 0 {
                let bit = bits.trailing_zeros() as usize;
                bits &= bits - 1;
                let index = word_index * usize::BITS as usize + bit;
                let Some(slot) = self.get_existing_slot(index) else { continue; };
                let id = ExecutorDomainId::from_parts(index as u32, slot.generation());
                let Some(domain) = self.borrow_executor_domain(id) else { continue; };
                if domain.state() != ExecutorDomainState::Active { continue; }
                if !domain.has_queued_work() {
                    if domain.batches.iter().all(|batch| batch.state.load(Ordering::Acquire) == BATCH_EMPTY) {
                        self.ready[word_index].fetch_and(!(1usize << bit), Ordering::AcqRel);
                        fence(Ordering::SeqCst);
                        if domain.has_queued_work()
                            || domain.batches.iter().any(|batch| batch.state.load(Ordering::Acquire) != BATCH_EMPTY)
                        {
                            self.mark_ready(id);
                            if !domain.has_queued_work() { continue; }
                        } else {
                            continue;
                        }
                    } else {
                        continue;
                    }
                }
                if !visit(domain) { return; }
            }
        }
    }

    pub(crate) fn select_domain(
        &self,
        cached: Option<&ExecutorDomain<E>>,
    ) -> Option<(DomainBorrow<'_, E>, u64, u64)> {
        if let Some(domain) = cached
            && domain.state() == ExecutorDomainState::Active
            && !self.has_competition(domain.id())
        {
            let domain = self.borrow_executor_domain(domain.id())?;
            if domain.state() != ExecutorDomainState::Active { return None; }
            let weight = domain.weight() as u64;
            return Some((domain, 0, weight));
        }
        let mut sole = None;
        let mut found = false;
        self.visit_ready(|domain| {
            found = true;
            if !self.has_competition(domain.id()) { sole = Some(domain); }
            false
        });
        if !found { return None; }
        if let Some(domain) = sole {
            let weight = domain.weight() as u64;
            return Some((domain, 0, weight));
        }
        {
            let mut floor = self.selection.lock();
            let mut selected: Option<DomainBorrow<'_, E>> = None;
            let mut minimum = u64::MAX;
            self.visit_ready(|domain| {
                let service = domain.service.load(Ordering::Relaxed).max(*floor);
                if service < minimum {
                    minimum = service;
                    selected = Some(domain);
                }
                true
            });
            let domain = selected?;
            let weight = domain.weight() as u64;
            let reservation = domain.poll_time_ns.load(Ordering::Relaxed)
                .saturating_mul(61 * 1024) / weight;
            *floor = minimum;
            domain.service.fetch_max(minimum, Ordering::Relaxed);
            domain.service.fetch_add(reservation, Ordering::Relaxed);
            Some((domain, reservation, weight))
        }
    }

    pub(crate) fn has_competition(&self, id: ExecutorDomainId) -> bool {
        let index = id.slot() as usize;
        let mut groups = self.ready_groups.load(Ordering::Acquire);
        while groups != 0 {
            let word = groups.trailing_zeros() as usize;
            groups &= groups - 1;
            let own = if word == index / usize::BITS as usize {
                1usize << (index % usize::BITS as usize)
            } else { 0 };
            if self.ready[word].load(Ordering::Acquire) & !own != 0 { return true; }
        }
        false
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
                            && crate::global_async::GlobalAsyncExecutor::<E>::global().blocking_tasks.lock()
                                .iter().flatten().any(|task| task.domain_id == domain.id())
                        {
                            domain.notify = false;
                            continue;
                        }
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
                    let queues = 2 + domain.batches.len() * 2;
                    while remaining != 0 && (cleanup.queue_head != 0 || cleanup.queue_index < queues) {
                        if cleanup.queue_head == 0 {
                            let queue = cleanup.queue_index;
                            cleanup.queue_index += 1;
                            if queue == 0 {
                                let mut inject = domain.inject.lock();
                                cleanup.queue_head = core::mem::take(&mut inject.head);
                                inject.tail = None;
                                inject.len = 0;
                                domain.inject_len.store(0, Ordering::Release);
                            } else if queue == 1 {
                                cleanup.queue_head = domain.incoming.swap(0, Ordering::Acquire);
                            } else {
                                let queue = queue - 2;
                                let owned = &domain.batches[queue / 2];
                                cleanup.queue_head = if queue % 2 == 0 {
                                    unsafe { core::mem::take(&mut (*owned.batch.get()).local_task) }
                                } else {
                                    let task = unsafe { owned.spawned.pop() }.unwrap_or(0);
                                    if task != 0 { cleanup.queue_index -= 1; }
                                    task
                                };
                            }
                            continue;
                        }
                        let task = unsafe { &*(cleanup.queue_head as *const crate::runtime::slab::slot::TaskSlot) };
                        let (shard, local, generation) = crate::runtime::slab::ptr::decode_slab_task_ptr(
                            task.task_id.load(Ordering::Relaxed) as usize,
                        ).expect("invalid cleanup task");
                        cleanup.queue_head = task.ready_next.swap(0, Ordering::Relaxed);
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
                                                if task.cancellation_guards.load(Ordering::Acquire) != 0 {
                                                    let target = E::cancellation_domain();
                                                    let executor = crate::global_async::GlobalAsyncExecutor::<E>::global();
                                                    task.domain_id.store(target.id().raw(), Ordering::Release);
                                                    task.state.store(STATE_QUEUED, Ordering::Release);
                                                    let queued = table.get_slot(shard, local, generation)
                                                        .expect("protected task slot missing");
                                                    crate::platform::with_executor_local::<E, _>(|tls| {
                                                        executor.enqueue_task::<false, false, true>(
                                                            target, tls,
                                                            task.task_id.load(Ordering::Relaxed) as usize,
                                                            queued,
                                                        );
                                                    });
                                                    return;
                                                }
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
                                }
                                table.decrement_ref::<true>(shard, local, generation);
                            },
                        );
                    }
                    let finished = cleanup.tasks_done;
                    if finished {
                        self.ready[index / usize::BITS as usize].fetch_and(
                            !(1usize << (index % usize::BITS as usize)), Ordering::AcqRel,
                        );
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
