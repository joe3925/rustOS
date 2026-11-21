use crate::domain::{BATCH_EMPTY, BATCH_OWNED};
use crate::platform::ExecutorPlatform;
use crate::platform::{ExecutorBatchGuard, ExecutorThreadLocal, Job, SlabCache, with_executor_local};
use crate::runtime::runtime::{drain_retired_block_on_states, has_retired_block_on_states};
use crate::sync::Arc;
use crate::sync::atomic::{AtomicBool, AtomicUsize, Ordering, fence};
use alloc::boxed::Box;
use spin::Once;

pub use crate::domain::{
    DestroyExecutorDomainError, DestroyExecutorDomainResult, ExecutorDomain,
    ExecutorDomainConfig, ExecutorDomainId, ExecutorDomainInfo, ExecutorDomainState,
    ExecutorDomainTable,
};

#[repr(align(64))]
pub(crate) struct CacheAligned(pub(crate) AtomicUsize);

const MAX_SHARDS: usize = 32;

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
}

impl<E: ExecutorPlatform> ExecutorRuntime<E> {
    fn new(cpu_count: usize) -> Self {
        Self {
            domains: ExecutorDomainTable::<E>::new(cpu_count),
            workers: (0..cpu_count)
                .map(|_| WorkerShared { claimed: AtomicBool::new(false) })
                .collect(),
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

        if self.has_runnable_tasks(None) {
            self.try_schedule::<false>();
        } else if crate::runtime::slab::task_slab::get_task_table::<E>().has_retired()
            || has_retired_block_on_states::<E>()
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

    #[inline(never)]
    pub(crate) fn enqueue_task_to_executor_domain<const YIELD: bool>(
        &self,
        domain_id: ExecutorDomainId,
        task_id: usize,
        slot: &'static crate::runtime::slab::slot::TaskSlot,
    ) {
        let accepted = self
            .with_executor_domain(domain_id, #[inline(always)] |domain, tls| {
                self.enqueue_task::<false, false, YIELD>(domain, tls, task_id, slot);
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
    pub(crate) fn enqueue_task<const SPAWN: bool, const SHARED_SPAWN: bool, const YIELD: bool>(
        &self,
        domain: &ExecutorDomain<E>,
        tls: &ExecutorThreadLocal<E>,
        task_id: usize,
        slot: &'static crate::runtime::slab::slot::TaskSlot,
    ) {
        let mut task = core::ptr::from_ref(slot) as usize;
        let local = if task_id != 0 && (SPAWN || !E::in_interrupt_context())
            && core::ptr::eq(tls.active_domain.get(), domain)
            && let Some(owned) = unsafe { tls.batch.get().as_ref() }
        {
            let batch = unsafe { &mut *owned.batch.get() };
            if !YIELD && batch.local_runs < 3
                && (!SPAWN || !SHARED_SPAWN || domain.batches.len() == 1
                    || batch.global_interval >= 61)
            {
                let displaced = core::mem::replace(&mut batch.local_task, task);
                if displaced == 0 {
                    return;
                }
                task = displaced;
            }
            unsafe {
                owned.spawned.push_or_overflow(task, |tasks| self.inject_tasks(domain, tasks));
            }
            Some(self.worker_count() > 1)
        } else {
            None
        };
        if let Some(notify) = local {
            if notify {
                self.try_schedule::<false>();
            }
            return;
        }
        self.inject_tasks(domain, &mut core::iter::once(task));
        self.try_schedule::<false>();
    }

    #[inline]
    pub(crate) fn with_executor_domain<R>(
        &self,
        domain_id: ExecutorDomainId,
        f: impl FnOnce(&ExecutorDomain<E>, &ExecutorThreadLocal<E>) -> R,
    ) -> Option<R> {
        with_executor_local::<E, _>(|tls| {
            if !E::in_interrupt_context() {
                if let Some(domain) = unsafe { tls.active_domain.get().as_ref() }
                    && domain.id() == domain_id
                {
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
            let domain = tls.active_domain.get();
            let slot = tls.batch.replace(core::ptr::null());
            unsafe { slot.as_ref().zip(domain.as_ref()) }
        });
        let Some((owned, domain)) = owned else { return; };
        let batch = unsafe { &mut *owned.batch.get() };
        if batch.local_task != 0 {
            let task = core::mem::take(&mut batch.local_task);
            self.inject_tasks(domain, &mut core::iter::once(task));
        }
        batch.local_runs = 0;
        owned.state.store(BATCH_EMPTY, Ordering::Release);
        if notify && self.has_runnable_tasks(None) {
            self.try_schedule::<false>();
        }
    }

    fn inject_tasks<I: Iterator<Item = usize>>(&self, domain: &ExecutorDomain<E>, tasks: &mut I) {
        let Some(first) = tasks.next() else { return; };
        let mut tail = unsafe { &*(first as *const crate::runtime::slab::slot::TaskSlot) };
        let mut count = 1;
        for task in tasks {
            tail.ready_next.store(task, Ordering::Relaxed);
            tail = unsafe { &*(task as *const crate::runtime::slab::slot::TaskSlot) };
            count += 1;
        }
        tail.ready_next.store(0, Ordering::Relaxed);
        E::with_scheduler_critical(|| {
            let mut inject = domain.inject.lock();
            if let Some(previous_tail) = inject.tail {
                previous_tail.ready_next.store(first, Ordering::Relaxed);
            } else {
                inject.head = first;
            }
            inject.tail = Some(tail);
            inject.len += count;
            domain.inject_len.store(inject.len, Ordering::Release);
        });
        self.runtime().domains.mark_ready(domain.id());
    }

    fn take_injected(
        &self,
        domain: &ExecutorDomain<E>,
        local: &crate::steal_queue::StealQueue<256>,
        limit: usize,
    ) -> Option<(usize, &'static crate::runtime::slab::slot::TaskSlot)> {
        if domain.inject_len.load(Ordering::Acquire) == 0 {
            return None;
        }
        E::with_scheduler_critical(|| {
            let mut inject = domain.inject.lock();
            let count = limit.min(inject.len);
            let mut first = None;
            for index in 0..count {
                let task = inject.head;
                let slot = unsafe { &*(task as *const crate::runtime::slab::slot::TaskSlot) };
                inject.head = slot.ready_next.load(Ordering::Relaxed);
                slot.ready_next.store(0, Ordering::Relaxed);
                inject.len -= 1;
                if index == 0 {
                    first = Some((slot.task_id.load(Ordering::Relaxed) as usize, slot));
                } else {
                    assert!(unsafe { local.push(task) }, "injection batch exceeded local capacity");
                }
            }
            if inject.len == 0 {
                inject.tail = None;
            }
            domain.inject_len.store(inject.len, Ordering::Release);
            first
        })
    }

    pub fn create_executor_domain(&self, config: ExecutorDomainConfig) -> Arc<ExecutorDomain<E>> {
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

    fn has_runnable_tasks(&self, cached: Option<&ExecutorDomain<E>>) -> bool {
        self.runtime.get().is_some_and(|runtime| {
            if let Some(domain) = cached
                && domain.state() == ExecutorDomainState::Active
            {
                if domain.has_queued_work() { return true; }
                if !runtime.domains.has_competition(domain.id()) { return false; }
            }
            let mut ready = false;
            runtime.domains.visit_ready(|_| { ready = true; false });
            ready
        })
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
        let domains = &self.runtime().domains;
        let mut cached: Option<Arc<ExecutorDomain<E>>> = None;
        let mut selected = domains.select_domain(None);
        let mut searching = if E::PERSISTENT_RUNTIME_WORKERS {
            E::runtime_search::<true>()
        } else {
            false
        };
        loop {
            let mut ran = 0;
            if let Some((domain, reservation, weight)) = selected.take() {
                if cached.as_deref().is_none_or(|previous| previous.id() != domain.id()) {
                    cached = domains.get_executor_domain(domain.id());
                }
                let budget = if reservation == 0 { usize::MAX } else { 61 };
                let (polls, elapsed) = self.run_domain_batch(&domain, budget, &mut searching);
                ran = polls;
                if reservation != 0 {
                    let charged = elapsed.saturating_mul(1024) / weight;
                    let _ = domain.service.fetch_update(Ordering::Relaxed, Ordering::Relaxed,
                        |service| Some(service.saturating_sub(reservation).saturating_add(charged)));
                }
                drop(domain);
            }
            task_table.drain_retired();
            drain_retired_block_on_states::<E>();
            domains.drain_retired();
            if cached.as_deref().is_some_and(|domain| domain.state() != ExecutorDomainState::Active) {
                cached = None;
            }
            if ran != 0 && self.has_runnable_tasks(cached.as_deref()) {
                selected = domains.select_domain(cached.as_deref());
                if selected.is_some() { continue; }
            }
            if E::PERSISTENT_RUNTIME_WORKERS && E::wait_for_runtime_work(|| {
                self.has_runnable_tasks(cached.as_deref())
                    || task_table.has_retired()
                    || domains.has_retired()
                    || has_retired_block_on_states::<E>()
            }) {
                searching = E::runtime_search::<true>();
                selected = domains.select_domain(cached.as_deref());
                continue;
            }
            if searching { E::runtime_search::<false>(); }
            break;
        }
        task_table.drain_retired();
        drain_retired_block_on_states::<E>();
        drop(worker_guard);
        self.exit_pump();
        fence(Ordering::SeqCst);
        if self.has_runnable_tasks(cached.as_deref()) {
            self.try_schedule::<false>();
        } else if task_table.has_retired() || domains.has_retired() || has_retired_block_on_states::<E>() {
            self.try_schedule::<true>();
        }
    }

    fn run_domain_batch(
        &self,
        domain: &ExecutorDomain<E>,
        budget: usize,
        searching: &mut bool,
    ) -> (usize, u64) {
        if domain.state() != ExecutorDomainState::Active { return (0, 0); }
        let start = with_executor_local::<E, _>(|tls| tls.ready_cursor.get() % domain.batches.len());
        let owned = (0..domain.batches.len()).find_map(|offset| {
            let slot = &domain.batches[(start + offset) % domain.batches.len()];
            slot.state.compare_exchange(
                BATCH_EMPTY, BATCH_OWNED, Ordering::Acquire, Ordering::Relaxed,
            ).is_ok().then_some(slot)
        });
        let Some(owned) = owned else { return (0, 0); };
        let (previous_batch, previous_domain) = with_executor_local::<E, _>(|tls| {
            (tls.batch.replace(owned), tls.active_domain.replace(domain))
        });
        let _batch = ExecutorBatchGuard::<E> {
            previous_batch,
            previous_domain,
        };
        let table = crate::runtime::slab::task_slab::get_task_table::<E>();
        unsafe {
            let batch = &mut *owned.batch.get();
            batch.elapsed_ns = 0;
            batch.start_poll_sample::<E>();
        }
        let mut ran = 0;
        let mut empty_searches = 0;
        let mut lifo_chain = false;
        while ran < budget {
            let continued_lifo = unsafe {
                lifo_chain && (*owned.batch.get()).local_task != 0
            };
            if !continued_lifo {
                let batch = unsafe { &mut *owned.batch.get() };
                batch.local_runs = 0;
                batch.tick = batch.tick.wrapping_add(1);
                if batch.tick % 61 == 0 {
                    batch.finish_poll_sample::<E>();
                    batch.start_poll_sample::<E>();
                }
            }
            let batch = unsafe { &mut *owned.batch.get() };
            let mut selected = if continued_lifo {
                batch.local_runs += 1;
                Some(unsafe {
                    crate::runtime::slab::slot::TaskSlot::from_queued_pointer(
                        core::mem::take(&mut batch.local_task),
                    )
                })
            } else {
                let injected = if batch.tick % batch.global_interval == 0 {
                    #[cfg(any(test, loom, feature = "loom", feature = "hosted"))]
                    let next = ((200_000.0 / batch.poll_time_ns) as u32).clamp(2, 127);
                    #[cfg(not(any(test, loom, feature = "loom", feature = "hosted")))]
                    let next = ((200_000 / batch.poll_time_ns.max(1)) as u32).clamp(2, 127);
                    if u32::abs_diff(batch.global_interval, next) > 2 {
                        batch.global_interval = next;
                    }
                    self.take_injected(domain, &owned.spawned, 1).map(|(task, slot)| (task, Some(slot)))
                } else {
                    None
                };
                injected.or_else(|| {
                    if batch.local_task != 0 {
                        Some(unsafe {
                    crate::runtime::slab::slot::TaskSlot::from_queued_pointer(
                        core::mem::take(&mut batch.local_task),
                    )
                })
                    } else {
                        unsafe { owned.spawned.pop() }.map(|task| unsafe {
                            crate::runtime::slab::slot::TaskSlot::from_queued_pointer(task)
                        })
                    }
                })
            };
            if selected.is_none() {
                let cap = owned.spawned.remaining_slots().min(128);
                let count = (domain.inject_len.load(Ordering::Acquire) / domain.batches.len() + 1)
                    .min(cap).max(1);
                selected = self.take_injected(domain, &owned.spawned, count).map(|(task, slot)| (task, Some(slot)));
            }
            if selected.is_none() {
                batch.finish_poll_sample::<E>();
                *searching = E::PERSISTENT_RUNTIME_WORKERS && E::runtime_search::<true>();
                if !E::PERSISTENT_RUNTIME_WORKERS || *searching {
                    let mut one = (batch.random >> 32) as u32;
                    let two = batch.random as u32;
                    one ^= one << 17;
                    one = one ^ two ^ (one >> 7) ^ (two >> 16);
                    batch.random = (u64::from(two) << 32) | u64::from(one);
                    let victim_start = ((u64::from(two.wrapping_add(one)) * domain.batches.len() as u64) >> 32) as usize;
                    selected = (0..domain.batches.len()).find_map(|offset| {
                        let victim = &domain.batches[(victim_start + offset) % domain.batches.len()];
                        if core::ptr::eq(owned, victim) {
                            return None;
                        }
                        unsafe { victim.spawned.steal::<false>(Some(&owned.spawned)) }
                            .map(|task| unsafe {
                            crate::runtime::slab::slot::TaskSlot::from_queued_pointer(task)
                        })
                    });
                    if selected.is_none() {
                        selected = self.take_injected(domain, &owned.spawned, 1).map(|(task, slot)| (task, Some(slot)));
                    }
                }
            }
            let Some((task, slot)) = selected else {
                if E::PERSISTENT_RUNTIME_WORKERS
                    && *searching
                    && empty_searches < 32
                {
                    empty_searches += 1;
                    core::hint::spin_loop();
                    continue;
                }
                break;
            };
            empty_searches = 0;
            if batch.poll_started.is_none() {
                batch.start_poll_sample::<E>();
            }
            if !continued_lifo {
                batch.poll_count += 1;
            }
            if E::PERSISTENT_RUNTIME_WORKERS && *searching {
                let last = E::runtime_search::<false>();
                *searching = false;
                if last && self.has_runnable_tasks(Some(domain)) {
                    self.try_schedule::<false>();
                }
            }
            crate::runtime::slab::ptr::poll_slab_task::<E>(table, task, slot);
            ran += 1;
            if with_executor_local::<E, _>(|tls| tls.batch.get() != core::ptr::from_ref(owned)) {
                return (ran, 0);
            }
            lifo_chain = true;
            if ran % 61 == 0 {
                table.drain_retired();
                drain_retired_block_on_states::<E>();
                self.runtime().domains.drain_retired();
                if domain.state() != ExecutorDomainState::Active
                    || self.runtime().domains.has_competition(domain.id())
                {
                    let poll_time_ns = unsafe { (*owned.batch.get()).poll_time_ns as u64 };
                    domain.poll_time_ns.store(poll_time_ns.max(1), Ordering::Relaxed);
                    break;
                }
            }
        }
        let batch = unsafe { &mut *owned.batch.get() };
        batch.finish_poll_sample::<E>();
        if budget != usize::MAX {
            domain.poll_time_ns.store((batch.poll_time_ns as u64).max(1), Ordering::Relaxed);
        }
        (ran, batch.elapsed_ns)
    }

}

#[inline(never)]
pub extern "C" fn pump_trampoline<E: ExecutorPlatform>(_ctx: usize) {
    GlobalAsyncExecutor::<E>::global().pump();
}
