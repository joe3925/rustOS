use crate::domain::{BatchSlot, ExecutorDomain};
use crate::global_async::WorkerShared;
use crate::growable_slab::SlabHandle;
use core::cell::{Cell, RefCell};

pub type JobFn = extern "C" fn(usize);

#[derive(Clone, Copy)]
pub struct Job {
    pub f: JobFn,
    pub a: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CurrentExecutorContext {
    pub task_id: usize,
    pub domain_id: u64,
}

pub(crate) struct SlabCache {
    pub owner: *const (),
    pub handles: [Option<SlabHandle>; 8],
    pub flush: Option<unsafe fn(*const (), &mut [Option<SlabHandle>])>,
}

impl SlabCache {
    pub const fn new() -> Self {
        Self {
            owner: core::ptr::null(),
            handles: [None; 8],
            flush: None,
        }
    }
}

pub struct ExecutorThreadLocal<E: ExecutorPlatform> {
    pub(crate) current: Cell<Option<CurrentExecutorContext>>,
    pub(crate) worker: Cell<*const WorkerShared>,
    pub(crate) batch: Cell<*const BatchSlot>,
    pub(crate) active_domain: Cell<*const ExecutorDomain<E>>,
    pub(crate) ready_cursor: Cell<usize>,
    pub(crate) allocation_cursor: Cell<usize>,
    pub(crate) caches: RefCell<[SlabCache; 1]>,
}

impl<E: ExecutorPlatform> ExecutorThreadLocal<E> {
    pub const fn new() -> Self {
        Self {
            current: Cell::new(None),
            worker: Cell::new(core::ptr::null()),
            batch: Cell::new(core::ptr::null()),
            active_domain: Cell::new(core::ptr::null()),
            ready_cursor: Cell::new(0),
            allocation_cursor: Cell::new(0),
            caches: RefCell::new([const { SlabCache::new() }; 1]),
        }
    }
}

pub(crate) fn with_executor_local<E: ExecutorPlatform, R>(
    f: impl FnOnce(&ExecutorThreadLocal<E>) -> R,
) -> R {
    E::with_executor_local(f)
}

pub(crate) struct ExecutorBatchGuard<E: ExecutorPlatform> {
    pub previous_domain: *const ExecutorDomain<E>,
    pub previous_batch: *const BatchSlot,
}

impl<E: ExecutorPlatform> Drop for ExecutorBatchGuard<E> {
    fn drop(&mut self) {
        crate::global_async::GlobalAsyncExecutor::<E>::global().release_local_batch::<false>(false);
        with_executor_local::<E, _>(|tls| {
            tls.active_domain.set(self.previous_domain);
            tls.batch.set(self.previous_batch);
        });
    }
}

pub(crate) struct ExecutorSuspendGuard<E: ExecutorPlatform> {
    worker: *const WorkerShared,
    domain: *const ExecutorDomain<E>,
}

impl<E: ExecutorPlatform> ExecutorSuspendGuard<E> {
    pub(crate) fn enter() -> Self {
        crate::global_async::GlobalAsyncExecutor::<E>::global().release_local_batch::<true>(true);
        with_executor_local::<E, _>(|tls| Self {
            worker: tls.worker.replace(core::ptr::null()),
            domain: tls.active_domain.replace(core::ptr::null()),
        })
    }
}

impl<E: ExecutorPlatform> Drop for ExecutorSuspendGuard<E> {
    fn drop(&mut self) {
        with_executor_local::<E, _>(|tls| {
            tls.worker.set(self.worker);
            tls.active_domain.set(self.domain);
        });
    }
}

pub fn current_executor_context<E: ExecutorPlatform>() -> Option<CurrentExecutorContext> {
    with_executor_local::<E, _>(|tls| tls.current.get())
}

pub struct CurrentExecutorContextGuard<E: ExecutorPlatform> {
    _platform: core::marker::PhantomData<fn() -> E>,
    previous: Option<CurrentExecutorContext>,
}

impl<E: ExecutorPlatform> CurrentExecutorContextGuard<E> {
    pub fn enter(context: CurrentExecutorContext) -> Self {
        let previous = with_executor_local::<E, _>(|tls| tls.current.replace(Some(context)));

        Self {
            previous,
            _platform: core::marker::PhantomData,
        }
    }
}

impl<E: ExecutorPlatform> Drop for CurrentExecutorContextGuard<E> {
    fn drop(&mut self) {
        with_executor_local::<E, _>(|tls| tls.current.set(self.previous));
    }
}

pub trait ExecutorPlatform: Sized + Send + Sync + 'static {
    fn global_executor() -> &'static crate::global_async::GlobalAsyncExecutor<Self>;
    fn with_executor_local<R>(f: impl FnOnce(&ExecutorThreadLocal<Self>) -> R) -> R;
    fn init_runtime(max_threads: usize, max_jobs: usize);
    fn init_blocking(max_threads: usize);
    fn submit_runtime(job: Job) -> bool;
    fn submit_blocking(job: Job);
    fn submit_blocking_many(jobs: &[Job]);
    fn try_steal_blocking_one() -> bool;
    fn yield_now();
    fn print(string: &str);
    #[cfg_attr(irq_check, irq::context)]
    fn in_interrupt_context() -> bool;
}
