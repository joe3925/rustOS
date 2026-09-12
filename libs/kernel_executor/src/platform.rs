use crate::domain::ExecutorDomain;
use crate::global_async::WorkerShared;
use crate::growable_slab::SlabHandle;
use core::cell::{Cell, RefCell};
use spin::Once;

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

pub(crate) struct ExecutorThreadLocal {
    pub current: Cell<Option<CurrentExecutorContext>>,
    pub worker: Cell<*const WorkerShared>,
    pub active_domain: Cell<*const ExecutorDomain>,
    pub ready_cursor: Cell<usize>,
    pub allocation_cursor: Cell<usize>,
    pub caches: RefCell<[SlabCache; 8]>,
}

impl ExecutorThreadLocal {
    const fn new() -> Self {
        Self {
            current: Cell::new(None),
            worker: Cell::new(core::ptr::null()),
            active_domain: Cell::new(core::ptr::null()),
            ready_cursor: Cell::new(0),
            allocation_cursor: Cell::new(0),
            caches: RefCell::new([const { SlabCache::new() }; 8]),
        }
    }
}

#[cfg(not(any(test, loom, feature = "loom")))]
#[thread_local]
static EXECUTOR_CONTEXT: ExecutorThreadLocal = ExecutorThreadLocal::new();

#[cfg(any(test, loom, feature = "loom"))]
std::thread_local! {
    static EXECUTOR_CONTEXT: ExecutorThreadLocal = const { ExecutorThreadLocal::new() };
}

pub(crate) fn with_executor_local<R>(f: impl FnOnce(&ExecutorThreadLocal) -> R) -> R {
    #[cfg(not(any(test, loom, feature = "loom")))]
    {
        f(&EXECUTOR_CONTEXT)
    }
    #[cfg(any(test, loom, feature = "loom"))]
    {
        EXECUTOR_CONTEXT.with(f)
    }
}

pub(crate) struct ExecutorBatchGuard {
    pub previous_domain: *const ExecutorDomain,
    pub previous_caches: Option<[SlabCache; 8]>,
}

impl Drop for ExecutorBatchGuard {
    fn drop(&mut self) {
        crate::global_async::GlobalAsyncExecutor::global().flush_local_task();
        with_executor_local(|tls| {
            let mut caches = tls.caches.borrow_mut();
            for cache in &mut *caches {
                if let Some(flush) = cache.flush.take() {
                    unsafe { flush(cache.owner, &mut cache.handles) };
                    cache.owner = core::ptr::null();
                }
            }
            if let Some(previous) = self.previous_caches.take() {
                *caches = previous;
            }
            tls.active_domain.set(self.previous_domain);
        });
    }
}

pub(crate) struct ExecutorSuspendGuard {
    worker: *const WorkerShared,
    domain: *const ExecutorDomain,
}

impl ExecutorSuspendGuard {
    pub(crate) fn enter() -> Self {
        crate::global_async::GlobalAsyncExecutor::global().flush_local_task();
        with_executor_local(|tls| Self {
            worker: tls.worker.replace(core::ptr::null()),
            domain: tls.active_domain.replace(core::ptr::null()),
        })
    }
}

impl Drop for ExecutorSuspendGuard {
    fn drop(&mut self) {
        with_executor_local(|tls| {
            tls.worker.set(self.worker);
            tls.active_domain.set(self.domain);
        });
    }
}

pub trait ExecutorPlatform: Send + Sync {
    fn init_runtime(&self, max_threads: usize, max_jobs: usize);
    fn init_blocking(&self, max_threads: usize);
    fn submit_runtime(&self, job: Job) -> bool;
    fn submit_blocking(&self, job: Job);
    fn submit_blocking_many(&self, jobs: &[Job]);
    fn try_steal_blocking_one(&self) -> bool;
    fn yield_now(&self);
    fn print(&self, string: &str);
    fn in_interrupt_context(&self) -> bool;
}
pub static PLATFORM: Once<&'static dyn ExecutorPlatform> = Once::new();

pub fn init(platform: &'static dyn ExecutorPlatform) {
    PLATFORM.call_once(|| platform);
}

pub fn platform() -> &'static dyn ExecutorPlatform {
    PLATFORM
        .get()
        .copied()
        .expect("executor platform not initialized")
}

pub fn current_executor_context() -> Option<CurrentExecutorContext> {
    with_executor_local(|tls| tls.current.get())
}

pub fn in_interrupt_context() -> bool {
    PLATFORM
        .get()
        .is_some_and(|platform| platform.in_interrupt_context())
}

pub struct CurrentExecutorContextGuard {
    previous: Option<CurrentExecutorContext>,
}

impl CurrentExecutorContextGuard {
    pub fn enter(context: CurrentExecutorContext) -> Self {
        let previous = with_executor_local(|tls| tls.current.replace(Some(context)));

        Self { previous }
    }
}

impl Drop for CurrentExecutorContextGuard {
    fn drop(&mut self) {
        with_executor_local(|tls| tls.current.set(self.previous));
    }
}
