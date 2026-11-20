use crate::domain::{ACTIVE_UNIT, BATCH_EMPTY, BATCH_OWNED, BATCH_READY, RUN_PENDING};
use crate::platform::ExecutorPlatform;
use crate::platform::{ExecutorBatchGuard, ExecutorThreadLocal, Job, SlabCache, with_executor_local};
use crate::runtime::runtime::{drain_retired_block_on_states, has_retired_block_on_states};
use crate::sync::Arc;
use crate::sync::atomic::{AtomicBool, AtomicUsize, Ordering, fence};
use alloc::boxed::Box;
use crossbeam_queue::ArrayQueue;
use spin::Once;

pub use crate::domain::{
    DRIVER_EXECUTOR_DOMAIN, DestroyExecutorDomainError, DestroyExecutorDomainResult,
    ExecutorDomain, ExecutorDomainClass, ExecutorDomainConfig, ExecutorDomainId,
    ExecutorDomainInfo, ExecutorDomainState, ExecutorDomainTable,
    KERNEL_BACKGROUND_EXECUTOR_DOMAIN, KERNEL_HIGH_EXECUTOR_DOMAIN, KERNEL_NORMAL_EXECUTOR_DOMAIN,
};

#[repr(align(64))]
pub(crate) struct CacheAligned(pub(crate) AtomicUsize);

const MAX_SHARDS: usize = 32;

struct DomainRunQueue {
    queue: ArrayQueue<ExecutorDomainId>,
}

impl DomainRunQueue {
    fn new(capacity: usize) -> Self {
        Self {
            queue: ArrayQueue::new(capacity.max(1)),
        }
    }

    #[inline]
    fn push(&self, domain_id: ExecutorDomainId) -> bool {
        self.queue.push(domain_id).is_ok()
    }

    #[inline]
    fn pop(&self) -> Option<ExecutorDomainId> {
        self.queue.pop()
    }
}

#[repr(align(64))]
pub(crate) struct WorkerShared {
    claimed: AtomicBool,
}

struct WorkerGuard<'a, E: ExecutorPlatform> {
    worker: Option<&'a WorkerShared>,
    previous: *const WorkerShared,
    previous_caches: Option<[SlabCache; 1]>,
    _platform: core::marker::PhantomData<fn() -> E>,
}

impl<E: ExecutorPlatform> Drop for WorkerGuard<'_, E> {
    fn drop(&mut self) {
        GlobalAsyncExecutor::<E>::global().release_local_batch::<false>(true);
        with_executor_local::<E, _>(|tls| {
            let mut caches = tls.caches.borrow_mut();
            for cache in &mut *caches {
                if let Some(flush) = cache.flush.take() {
                    unsafe { flush(cache.owner, &mut cache.entries[..cache.len]) };
                    cache.len = 0;
                    cache.owner = core::ptr::null();
                }
            }
            if let Some(previous) = self.previous_caches.take() {
                *caches = previous;
            }
            tls.worker.set(self.previous);
        });
        if let Some(worker) = self.worker {
            worker.claimed.store(false, Ordering::Release);
        }
    }
}

struct ExecutorRuntime<E: ExecutorPlatform> {
    domains: ExecutorDomainTable<E>,
    workers: Box<[WorkerShared]>,
    run_queue: DomainRunQueue,
    run_overflow: AtomicBool,
}

impl<E: ExecutorPlatform> ExecutorRuntime<E> {
    fn new(cpu_count: usize) -> Self {
        Self {
            domains: ExecutorDomainTable::<E>::new(cpu_count),
            workers: (0..cpu_count)
                .map(|_| WorkerShared {
                    claimed: AtomicBool::new(false),
                })
                .collect(),
            run_queue: DomainRunQueue::new(crate::runtime::slab::constants::MAX_TASK_SLOTS),
            run_overflow: AtomicBool::new(false),
        }
    }
}

pub struct GlobalAsyncExecutor<E: ExecutorPlatform> {
    runtime: Once<ExecutorRuntime<E>>,
    pub(crate) task_table: Once<crate::runtime::slab::task_slab::TaskTable<E>>,
    pub(crate) retired_block_on_states: core::sync::atomic::AtomicUsize,
    pub(crate) blocking_tasks:
        crate::sync::Mutex<alloc::vec::Vec<Option<crate::runtime::blocking::BlockingEntry>>>,
    active_pumps: CacheAligned,
    max_pumps: CacheAligned,
}

impl<E: ExecutorPlatform> GlobalAsyncExecutor<E> {
    pub fn new() -> Self {
        Self {
            runtime: Once::new(),
            active_pumps: CacheAligned(AtomicUsize::new(0)),
            max_pumps: CacheAligned(AtomicUsize::new(0)),
            task_table: Once::new(),
            retired_block_on_states: core::sync::atomic::AtomicUsize::new(0),
            blocking_tasks: crate::sync::Mutex::new(alloc::vec::Vec::new()),
        }
    }

    pub fn global() -> &'static Self {
        E::global_executor()
    }

    pub fn init(&self, shards: usize, initial_task_capacity: usize) {
        let shards = shards.clamp(1, MAX_SHARDS);

        crate::runtime::slab::task_slab::init_task_table_with::<E, _>(|config| {
            config.capacity(initial_task_capacity)
        });

        self.runtime.call_once(|| ExecutorRuntime::<E>::new(shards));

        E::init_blocking(shards);
        E::init_runtime(shards, shards);

        self.max_pumps.0.store(shards, Ordering::Release);
        fence(Ordering::SeqCst);

        if self.has_runnable_domains() {
            self.try_schedule::<false>();
        } else if crate::runtime::slab::task_slab::get_task_table::<E>().has_retired()
            || has_retired_block_on_states::<E>()
            || self.runtime().domains.has_retired()
        {
            self.try_schedule::<true>();
        }
    }

    #[inline]
    fn runtime(&self) -> &ExecutorRuntime<E> {
        self.runtime
            .get()
            .expect("global async executor not initialized")
    }

    pub(crate) fn enqueue_task_to_executor_domain(
        &self,
        domain_id: ExecutorDomainId,
        task_id: usize,
    ) {
        let accepted = self
            .with_executor_domain(domain_id, |domain, tls| {
                if domain.state() != ExecutorDomainState::Active {
                    return false;
                }
                let local = !E::in_interrupt_context()
                    && with_executor_local::<E, _>(|tls| {
                        if tls.active_domain.get() != domain as *const ExecutorDomain<E> {
                            return false;
                        }
                        if tls.current.get().is_none_or(|context| context.task_id != task_id) {
                            return false;
                        }
                        let Some(slot) = (unsafe { tls.batch.get().as_ref() }) else {
                            return false;
                        };
                        let batch = unsafe { &mut *slot.batch.get() };
                        if batch.local_task != 0 {
                            return false;
                        }
                        batch.local_task = task_id;
                        batch.local_slot = None;
                        true
                    });
                if local {
                    return true;
                }
                let Some((shard, local, generation)) =
                    crate::runtime::slab::ptr::decode_slab_task_ptr(task_id)
                else {
                    return false;
                };
                let Some(slot) = crate::runtime::slab::task_slab::get_task_table::<E>()
                    .get_slot(shard, local, generation)
                else {
                    return false;
                };
                self.enqueue_task::<false, false>(domain, tls, task_id, slot);
                true
            })
            .unwrap_or(false);
        if !accepted {
            if let Some((shard, local, generation)) =
                crate::runtime::slab::ptr::decode_slab_task_ptr(task_id)
            {
                crate::runtime::slab::task_slab::get_task_table::<E>()
                    .decrement_ref::<false>(shard, local, generation);
            }
        }
    }

    #[inline(always)]
    pub(crate) fn enqueue_task<const SPAWN: bool, const POLL_INLINE: bool>(
        &self,
        domain: &ExecutorDomain<E>,
        tls: &ExecutorThreadLocal<E>,
        task_id: usize,
        slot: &'static crate::runtime::slab::slot::TaskSlot,
    ) {
        if SPAWN
            && POLL_INLINE
            && tls.current.get().is_none()
            && domain.state() == ExecutorDomainState::Active
            && domain.try_reserve_active::<true>()
        {
            crate::runtime::slab::ptr::poll_slab_task::<E>(
                crate::runtime::slab::task_slab::get_task_table::<E>(),
                task_id,
                Some(slot),
            );
            domain.release_active();
            fence(Ordering::SeqCst);
            if domain.is_runnable_for_policy() {
                self.schedule_domain_if_needed::<false>(self.runtime(), domain.id(), domain);
            }
            domain.maybe_finish_draining();
            return;
        }
        let local = if task_id != 0 && (SPAWN || !E::in_interrupt_context()) {
            (|| {
                if tls.active_domain.get() != domain as *const ExecutorDomain<E> {
                    return None;
                }
                let owned = unsafe { tls.batch.get().as_ref()? };
                let batch = unsafe { &mut *owned.batch.get() };
                if domain.state() != ExecutorDomainState::Active {
                    return None;
                }
                if SPAWN {
                    slot.ready_next.store(0, Ordering::Relaxed);
                    let sequence = owned.next_task.sequence.load(Ordering::Acquire);
                    if sequence & 1 == 0
                        && slot.result_ptr.load(Ordering::Relaxed)
                            != crate::runtime::slab::slot::RESULT_ABANDONED
                    {
                        owned.next_task.slot.store(core::ptr::from_ref(slot).cast_mut(), Ordering::Relaxed);
                        owned.next_task.task.store(task_id, Ordering::Relaxed);
                        owned.next_task.sequence.store(sequence.wrapping_add(1), Ordering::Release);
                        return Some(!domain.is_at_active_limit());
                    }
                    if unsafe { owned.spawned.push(task_id) } {
                        // RUN_PENDING coalesces requests. At the active limit,
                        // the already running pumps will check visible work.
                        return Some(!domain.is_at_active_limit());
                    }
                    return None; // Bounded queue overflow uses the shared heads.
                }
                if batch.local_task == 0 && batch.current == 0 {
                    batch.local_task = task_id;
                    batch.local_slot = Some(slot);
                    return Some(false);
                }
                None
            })()
        } else {
            None
        };
        if let Some(notify) = local {
            if notify {
                self.schedule_domain_if_needed::<false>(self.runtime(), domain.id(), domain);
            }
            return;
        }
        match domain.enqueue_tasks(task_id, slot, None) {
            Some(true) => {
                self.schedule_domain_if_needed::<false>(self.runtime(), domain.id(), domain);
            }
            Some(false) => {}
            None => {
                if let Some((shard, local, generation)) =
                    crate::runtime::slab::ptr::decode_slab_task_ptr(task_id)
                {
                    crate::runtime::slab::task_slab::get_task_table::<E>()
                        .decrement_ref::<false>(shard, local, generation);
                }
            }
        }
    }

    #[inline]
    pub(crate) fn with_executor_domain<R>(
        &self,
        domain_id: ExecutorDomainId,
        f: impl FnOnce(&ExecutorDomain<E>, &ExecutorThreadLocal<E>) -> R,
    ) -> Option<R> {
        with_executor_local::<E, _>(|tls| {
            if let Some(domain) = unsafe { tls.active_domain.get().as_ref() } {
                if domain.id() == domain_id {
                    return Some(f(domain, tls));
                }
            }
            let domain = self.runtime().domains.borrow_executor_domain(domain_id)?;
            Some(f(&domain, tls))
        })
    }

    pub(crate) fn release_local_batch<const CHECK_IRQ: bool>(&self, notify: bool) {
        if CHECK_IRQ && E::in_interrupt_context() {
            return;
        }
        let owned = with_executor_local::<E, _>(|tls| {
            let slot = tls.batch.replace(core::ptr::null());
            unsafe { Some((slot.as_ref()?, tls.active_domain.get().as_ref()?)) }
        });
        let Some((slot, domain)) = owned else {
            return;
        };
        let batch = unsafe { &mut *slot.batch.get() };
        if batch.current != 0
            && domain.state() == ExecutorDomainState::Active
            && domain.help_requested.0.load(Ordering::Acquire) != 0
            && domain.help_requested.0.swap(0, Ordering::AcqRel) != 0
        {
            if let Some(other) = domain.batches.iter().find(|other| {
                other
                    .state
                    .compare_exchange(
                        BATCH_EMPTY,
                        BATCH_OWNED,
                        Ordering::Acquire,
                        Ordering::Relaxed,
                    )
                    .is_ok()
            }) {
                let table = crate::runtime::slab::task_slab::get_task_table::<E>();
                let mut last = batch.current;
                for _ in 1..domain.quantum().min(32) {
                    let (shard, local, generation) =
                        crate::runtime::slab::ptr::decode_slab_task_ptr(last)
                            .expect("invalid batch task");
                    let task = table
                        .get_slot(shard, local, generation)
                        .expect("batch task missing");
                    let next = task.ready_next.load(Ordering::Relaxed);
                    if next == 0 {
                        break;
                    }
                    last = next;
                }
                let (shard, local, generation) =
                    crate::runtime::slab::ptr::decode_slab_task_ptr(last)
                        .expect("invalid batch split");
                let task = table
                    .get_slot(shard, local, generation)
                    .expect("batch split missing");
                let next = unsafe { &mut *other.batch.get() };
                next.current = task.ready_next.load(Ordering::Relaxed);
                task.ready_next.store(0, Ordering::Relaxed);
                next.local_task = 0;
                next.local_slot = None;
                next.local_runs = 0;
                next.shard_cursor = batch.shard_cursor;
                let ready = next.current != 0;
                other.state.store(
                    if ready { BATCH_READY } else { BATCH_EMPTY },
                    Ordering::Release,
                );
                if ready {
                    domain
                        .ready_batches
                        .0
                        .fetch_or(1 << other.index, Ordering::Release);
                }
            }
        }
        let ready = batch.current != 0
            || batch.local_task != 0
            || slot.next_task.sequence.load(Ordering::Acquire) & 1 != 0
            || slot.spawned.has_work();
        slot.state.store(
            if ready { BATCH_READY } else { BATCH_EMPTY },
            Ordering::Release,
        );
        if ready {
            domain
                .ready_batches
                .0
                .fetch_or(1 << slot.index, Ordering::Release);
        }
        if ready && notify {
            self.schedule_domain_if_needed::<false>(self.runtime(), domain.id(), domain);
        }
    }

    pub fn create_executor_domain(&self, config: ExecutorDomainConfig) -> ExecutorDomainId {
        self.runtime().domains.create_executor_domain(config)
    }

    pub fn worker_count(&self) -> usize {
        self.max_pumps.0.load(Ordering::Acquire)
    }

    pub fn destroy_executor_domain(
        &self,
        domain_id: ExecutorDomainId,
    ) -> Result<DestroyExecutorDomainResult, DestroyExecutorDomainError> {
        self.runtime().domains.destroy_executor_domain(domain_id)
    }

    pub fn get_executor_domain(
        &self,
        domain_id: ExecutorDomainId,
    ) -> Option<Arc<ExecutorDomain<E>>> {
        self.runtime().domains.get_executor_domain(domain_id)
    }

    fn has_runnable_domains(&self) -> bool {
        let Some(runtime) = self.runtime.get() else {
            return false;
        };

        !runtime.run_queue.queue.is_empty() || runtime.run_overflow.load(Ordering::Acquire)
    }

    #[inline]
    fn schedule_domain_if_needed<const RELEASE_ACTIVE: bool>(
        &self,
        runtime: &ExecutorRuntime<E>,
        domain_id: ExecutorDomainId,
        domain: &ExecutorDomain<E>,
    ) {
        if domain.state() != ExecutorDomainState::Active {
            if RELEASE_ACTIVE {
                domain.release_active();
                domain.maybe_finish_draining();
            }
            return;
        }

        if !RELEASE_ACTIVE
            && domain.schedule_state.0.load(Ordering::Acquire) & RUN_PENDING != 0
        {
            fence(Ordering::SeqCst);
            if domain.schedule_state.0.load(Ordering::Acquire) & RUN_PENDING != 0 {
                return;
            }
        }

        let previous = if RELEASE_ACTIVE {
            domain
                .schedule_state
                .0
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                    Some((state - ACTIVE_UNIT) | RUN_PENDING)
                })
                .unwrap()
        } else {
            domain
                .schedule_state
                .0
                .fetch_or(RUN_PENDING, Ordering::AcqRel)
        };
        if previous & RUN_PENDING == 0 {
            if !runtime.run_queue.push(domain_id) {
                domain.run_overflow.store(true, Ordering::Release);
                runtime.run_overflow.store(true, Ordering::Release);
            }
            if !RELEASE_ACTIVE {
                self.try_schedule::<false>();
            }
        }
        if RELEASE_ACTIVE {
            domain.maybe_finish_draining();
        }
    }

    pub(crate) fn try_schedule<const IDLE_ONLY: bool>(&self) {
        if IDLE_ONLY {
            fence(Ordering::SeqCst);
        }
        if E::PERSISTENT_RUNTIME_WORKERS
            && E::wake_runtime_worker::<IDLE_ONLY>(self.active_pumps.0.load(Ordering::Acquire))
        {
            return;
        }
        let mut max = self.max_pumps.0.load(Ordering::Acquire);
        if max == 0 {
            fence(Ordering::SeqCst);
            max = self.max_pumps.0.load(Ordering::Acquire);
        }

        let reserved = self
            .active_pumps
            .0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < max && (!IDLE_ONLY || active == 0)).then_some(active + 1)
            })
            .is_ok();

        if !reserved {
            return;
        }

        if !E::submit_runtime(Job {
            f: pump_trampoline::<E>,
            a: 0,
        }) {
            self.active_pumps.0.fetch_sub(1, Ordering::AcqRel);
            return;
        }
    }

    #[inline]
    fn exit_pump(&self) {
        self.active_pumps.0.fetch_sub(1, Ordering::AcqRel);
    }

    fn pump(&self) {
        self.release_local_batch::<false>(true);
        let task_table = crate::runtime::slab::task_slab::get_task_table::<E>();
        let worker = self
            .runtime()
            .workers
            .iter()
            .enumerate()
            .find(|(_, worker)| {
                worker
                    .claimed
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
            });
        let (previous, previous_caches) = with_executor_local::<E, _>(|tls| {
            if let Some((index, _)) = worker {
                tls.ready_cursor.set(index);
                tls.allocation_cursor.set(index);
            }
            let previous = tls
                .worker
                .replace(worker.map_or(core::ptr::null(), |(_, worker)| worker));
            let mut caches = tls.caches.borrow_mut();
            let previous_caches = caches
                .iter()
                .any(|cache| !cache.owner.is_null())
                .then(|| core::mem::replace(&mut *caches, [const { SlabCache::new() }; 1]));
            (previous, previous_caches)
        });
        let worker_guard = WorkerGuard::<E> {
            worker: worker.map(|(_, worker)| worker),
            previous,
            previous_caches,
            _platform: core::marker::PhantomData,
        };
        let mut cached_domain: Option<crate::domain::DomainBorrow<'_, E>> = None;

        loop {
            let runtime = self.runtime();
            if E::PERSISTENT_RUNTIME_WORKERS {
                E::runtime_search::<true>();
            }

            if runtime.run_overflow.load(Ordering::Acquire)
                && runtime.run_overflow.swap(false, Ordering::AcqRel)
                && runtime
                    .domains
                    .recover_runs(|id| runtime.run_queue.push(id))
            {
                runtime.run_overflow.store(true, Ordering::Release);
            }
            let Some(domain_id) = runtime.run_queue.pop() else {
                if E::PERSISTENT_RUNTIME_WORKERS {
                    E::runtime_search::<false>();
                    if self.has_runnable_domains() {
                        self.try_schedule::<false>();
                    }
                    drop(cached_domain.take());
                    task_table.drain_retired();
                    drain_retired_block_on_states::<E>();
                    runtime.domains.drain_retired();
                    if E::wait_for_runtime_work(|| {
                        self.has_runnable_domains()
                            || task_table.has_retired()
                            || has_retired_block_on_states::<E>()
                            || runtime.domains.has_retired()
                    }) {
                        continue;
                    }
                }
                break;
            };

            if cached_domain
                .as_ref()
                .is_none_or(|domain| domain.id() != domain_id)
            {
                cached_domain = runtime.domains.borrow_executor_domain(domain_id);
            }
            let Some(domain) = cached_domain.as_ref() else {
                continue;
            };

            if !domain.try_reserve_active::<false>() {
                cached_domain = None;
                continue;
            }

            if !domain.is_runnable_for_policy() {
                domain.release_active();
                domain.maybe_finish_draining();
                cached_domain = None;
                continue;
            }

            if E::PERSISTENT_RUNTIME_WORKERS {
                E::runtime_search::<false>();
            }
            loop {
                let budget = self.pick_domain_budget(domain);
                let ran = self.run_domain_batch(domain, budget);
                if E::PERSISTENT_RUNTIME_WORKERS && self.has_runnable_domains() {
                    self.try_schedule::<false>();
                }
                task_table.drain_retired();
                drain_retired_block_on_states::<E>();
                if ran != 0
                    && runtime.run_queue.queue.is_empty()
                    && !runtime.run_overflow.load(Ordering::Acquire)
                    && domain.state() == ExecutorDomainState::Active
                    && domain.active_count() <= domain.max_active()
                    && domain.ready_batches.0.load(Ordering::Acquire) != 0
                {
                    self.after_domain_batch::<false>(runtime, domain_id, domain, ran);
                    runtime.domains.drain_retired();
                } else {
                    self.after_domain_batch::<true>(runtime, domain_id, domain, ran);
                    break;
                }
            }
            if domain.state() != ExecutorDomainState::Active {
                cached_domain = None;
            }
            runtime.domains.drain_retired();
        }

        drop(cached_domain);
        task_table.drain_retired();
        drain_retired_block_on_states::<E>();
        drop(worker_guard);
        self.runtime().domains.drain_retired();
        self.exit_pump();
        fence(Ordering::SeqCst);

        if self.has_runnable_domains() {
            self.try_schedule::<false>();
        } else if task_table.has_retired()
            || has_retired_block_on_states::<E>()
            || self.runtime().domains.has_retired()
        {
            self.try_schedule::<true>();
        }
    }

    #[inline]
    fn pick_domain_budget(&self, domain: &ExecutorDomain<E>) -> usize {
        let quantum = domain.quantum();
        let weight = domain.weight();
        if weight >= quantum {
            quantum
        } else {
            domain.add_deficit(weight).min(quantum).max(1)
        }
    }

    fn run_domain_batch(&self, domain: &ExecutorDomain<E>, budget: usize) -> usize {
        let start = with_executor_local::<E, _>(|tls| {
            let cursor = tls.ready_cursor.get();
            tls.ready_cursor.set(cursor.wrapping_add(1));
            cursor % domain.batches.len()
        });
        let mut owned = None;
        let mut ready = domain.ready_batches.0.load(Ordering::Acquire);
        while ready != 0 {
            let offset = ready.rotate_right(start as u32).trailing_zeros() as usize;
            let index = (start + offset) % usize::BITS as usize;
            match domain.ready_batches.0.compare_exchange_weak(
                ready,
                ready & !(1 << index),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    let slot = &domain.batches[index];
                    slot.state.store(BATCH_OWNED, Ordering::Relaxed);
                    owned = Some(slot);
                    break;
                }
                Err(actual) => ready = actual,
            }
        }
        if owned.is_none() {
            for offset in 0..domain.batches.len() {
                let slot = &domain.batches[(start + offset) % domain.batches.len()];
                if slot.state.load(Ordering::Relaxed) == BATCH_EMPTY
                    && slot
                        .state
                        .compare_exchange(
                            BATCH_EMPTY,
                            BATCH_OWNED,
                            Ordering::Acquire,
                            Ordering::Relaxed,
                        )
                        .is_ok()
                {
                    owned = Some(slot);
                    break;
                }
            }
        }
        let Some(owned) = owned else {
            domain.help_requested.0.store(1, Ordering::Release);
            return 0;
        };
        if !E::PERSISTENT_RUNTIME_WORKERS
            && !domain.is_at_active_limit()
            && domain.has_queued_work()
        {
            self.schedule_domain_if_needed::<false>(self.runtime(), domain.id(), domain);
        }
        let (previous_domain, previous_batch) = with_executor_local::<E, _>(|tls| {
            (tls.active_domain.replace(domain), tls.batch.replace(owned))
        });
        let _batch = ExecutorBatchGuard::<E> {
            previous_domain,
            previous_batch,
        };
        let mut ran = 0usize;
        let mut empty_searches = 0usize;
        let budget = budget.max(1);
        let table = crate::runtime::slab::task_slab::get_task_table::<E>();

        while ran < budget {
            if domain.state() != ExecutorDomainState::Active
                || with_executor_local::<E, _>(|tls| tls.batch.get().is_null())
            {
                break;
            }
            let (task_id, slot) = {
                let batch = unsafe { &mut *owned.batch.get() };
                let spawned = if batch.local_runs < 3 {
                    owned.take_next().map(|(task, slot)| (task, Some(slot))).or_else(|| {
                        if batch.local_task == 0 && owned.spawned.has_work() {
                            unsafe { owned.spawned.pop() }.map(|task| (task, None))
                        } else {
                            None
                        }
                    })
                } else {
                    None
                };
                if let Some(task) = spawned {
                    batch.local_runs += 1;
                    task
                } else if batch.local_runs < 3 && batch.local_task != 0 {
                    batch.local_runs += 1;
                    (core::mem::take(&mut batch.local_task), batch.local_slot.take())
                } else {
                    if batch.current == 0 {
                        domain.refill_batch(batch);
                    }
                    if batch.current != 0 {
                        let task_id = batch.current;
                        let (shard, local, generation) =
                            crate::runtime::slab::ptr::decode_slab_task_ptr(task_id)
                                .expect("invalid ready task");
                        let task = table
                            .get_slot(shard, local, generation)
                            .expect("ready task missing");
                        batch.current = task.ready_next.load(Ordering::Relaxed);
                        task.ready_next.store(0, Ordering::Relaxed);
                        batch.local_runs = 0;
                        (task_id, Some(task))
                    } else {
                        // Keep the local LIFO preference bounded even when no
                        // helper is available. A self-wake must not bypass
                        // the oldest spawn after three local polls.
                        let oldest_first = batch.local_runs >= 3;
                        batch.local_runs = 1;
                        let task_id = if oldest_first {
                            owned.spawned.steal().map(|task| (task, None))
                                .or_else(|| owned.take_next().map(|(task, slot)| (task, Some(slot))))
                        } else {
                            owned.take_next().map(|(task, slot)| (task, Some(slot)))
                                .or_else(|| unsafe { owned.spawned.pop() }.map(|task| (task, None)))
                        };
                        if let Some(task) = task_id {
                            task
                        } else if batch.local_task != 0 {
                            (core::mem::take(&mut batch.local_task), batch.local_slot.take())
                        } else {
                            // Thieves read only atomic indices and slab IDs,
                            // never the owner's private intrusive chain.
                            let task_id = (1..domain.batches.len()).find_map(|offset| {
                                let victim = &domain.batches[(owned.index + offset) % domain.batches.len()];
                                victim.take_next().map(|(task, slot)| (task, Some(slot)))
                                    .or_else(|| victim.spawned.steal().map(|task| (task, None)))
                            });
                            task_id.unwrap_or((0, None))
                        }
                    }
                }
            };
            if task_id == 0 {
                if E::PERSISTENT_RUNTIME_WORKERS
                    && empty_searches < 32
                    && !self.has_runnable_domains()
                {
                    empty_searches += 1;
                    core::hint::spin_loop();
                    continue;
                }
                domain.help_requested.0.store(1, Ordering::Release);
                break;
            }
            empty_searches = 0;
            if E::PERSISTENT_RUNTIME_WORKERS && ran == 0 {
                if !domain.is_at_active_limit() && domain.has_queued_work() {
                    self.schedule_domain_if_needed::<false>(self.runtime(), domain.id(), domain);
                } else if self.has_runnable_domains() {
                    self.try_schedule::<false>();
                }
            }
            ran += with_executor_local::<E, _>(|tls| {
                let inline = (budget - ran - 1).min(3) as u8;
                let previous = tls.inline_budget.replace(inline);
                crate::runtime::slab::ptr::poll_slab_task::<E>(table, task_id, slot);
                1 + (inline - tls.inline_budget.replace(previous)) as usize
            });
        }

        ran
    }

    #[inline]
    fn after_domain_batch<const RELEASE_ACTIVE: bool>(
        &self,
        runtime: &ExecutorRuntime<E>,
        domain_id: ExecutorDomainId,
        domain: &ExecutorDomain<E>,
        ran_count: usize,
    ) {
        if domain.weight() < domain.quantum() && (ran_count != 0 || domain.is_runnable_for_policy())
        {
            domain.spend_deficit(ran_count.max(1));
        }

        if RELEASE_ACTIVE {
            self.schedule_domain_if_needed::<true>(runtime, domain_id, domain);
        }
    }
}

#[inline(never)]
pub extern "C" fn pump_trampoline<E: ExecutorPlatform>(_ctx: usize) {
    GlobalAsyncExecutor::<E>::global().pump();
}
