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

pub(crate) struct ExecutorThreadLocal {
    pub current: Cell<Option<CurrentExecutorContext>>,
    pub worker: Cell<*const WorkerShared>,
    pub batch: Cell<*const BatchSlot>,
    pub active_domain: Cell<*const ExecutorDomain>,
    pub ready_cursor: Cell<usize>,
    pub allocation_cursor: Cell<usize>,
    pub caches: RefCell<[SlabCache; 1]>,
}

impl ExecutorThreadLocal {
    const fn new() -> Self {
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
    pub previous_batch: *const BatchSlot,
}

impl Drop for ExecutorBatchGuard {
    fn drop(&mut self) {
        crate::global_async::GlobalAsyncExecutor::global().release_local_batch::<false>(false);
        with_executor_local(|tls| {
            tls.active_domain.set(self.previous_domain);
            tls.batch.set(self.previous_batch);
        });
    }
}

pub(crate) struct ExecutorSuspendGuard {
    worker: *const WorkerShared,
    domain: *const ExecutorDomain,
}

impl ExecutorSuspendGuard {
    pub(crate) fn enter() -> Self {
        crate::global_async::GlobalAsyncExecutor::global().release_local_batch::<true>(true);
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

unsafe extern "Rust" {
    #[link_name = "__kernel_executor_platform_init_runtime"]
    pub safe fn init_runtime(max_threads: usize, max_jobs: usize);
    #[link_name = "__kernel_executor_platform_init_blocking"]
    pub safe fn init_blocking(max_threads: usize);
    #[link_name = "__kernel_executor_platform_submit_runtime"]
    pub safe fn submit_runtime(job: Job) -> bool;
    #[link_name = "__kernel_executor_platform_submit_blocking"]
    pub safe fn submit_blocking(job: Job);
    #[link_name = "__kernel_executor_platform_submit_blocking_many"]
    pub safe fn submit_blocking_many(jobs: &[Job]);
    #[link_name = "__kernel_executor_platform_try_steal_blocking_one"]
    pub safe fn try_steal_blocking_one() -> bool;
    #[link_name = "__kernel_executor_platform_yield_now"]
    pub safe fn yield_now();
    #[link_name = "__kernel_executor_platform_print"]
    pub safe fn print(string: &str);
    #[link_name = "__kernel_executor_platform_in_interrupt_context"]
    #[cfg_attr(irq_check, irq::context)]
    pub safe fn in_interrupt_context() -> bool;
}

pub fn current_executor_context() -> Option<CurrentExecutorContext> {
    with_executor_local(|tls| tls.current.get())
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
