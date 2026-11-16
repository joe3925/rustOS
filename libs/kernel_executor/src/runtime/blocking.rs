use crate::platform::ExecutorPlatform;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::future::Future;
use core::mem::MaybeUninit;
use core::pin::Pin;
use core::ptr;
use core::task::{Context, Poll, Waker};

use crate::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};
use crate::sync::{Arc, Mutex};

use crate::domain::{ExecutorDomainId, ExecutorDomainState};
use crate::global_async::GlobalAsyncExecutor;
use crate::platform::Job;
use crate::runtime::runtime::{submit_blocking, submit_blocking_many};
use kernel_sync::completion::TaskOutcome;

const STATE_PENDING: u8 = 0;
const STATE_COMPLETE: u8 = 1;
const STATE_CONSUMED: u8 = 2;
const STATE_RUNNING: u8 = 3;
const STATE_CANCELLED: u8 = 4;

pub struct SharedTaskHeader<R> {
    result: UnsafeCell<MaybeUninit<R>>,
    state: AtomicU8,
    waker: Mutex<Option<Waker>>,
    domain_id: AtomicU64,
    registry_index: AtomicUsize,
}

impl<R> SharedTaskHeader<R> {
    fn new() -> Self {
        Self {
            result: UnsafeCell::new(MaybeUninit::uninit()),
            state: AtomicU8::new(STATE_PENDING),
            waker: Mutex::new(None),
            domain_id: AtomicU64::new(0),
            registry_index: AtomicUsize::new(0),
        }
    }

    fn store_result(&self, result: R) {
        // SAFETY: Only the worker thread writes to result and it happens exactly once.
        unsafe {
            (*self.result.get()).write(result);
        }
        self.state.store(STATE_COMPLETE, Ordering::Release);
    }

    fn try_start_running(&self) -> bool {
        self.state
            .compare_exchange(
                STATE_PENDING,
                STATE_RUNNING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    fn take_result(&self) -> Option<TaskOutcome<R>> {
        let state = self.state.load(Ordering::Acquire);
        if state != STATE_COMPLETE && state != STATE_CANCELLED {
            return None;
        }

        self.state.store(STATE_CONSUMED, Ordering::Release);
        Some(if state == STATE_CANCELLED {
            TaskOutcome::Cancelled
        } else {
            TaskOutcome::Completed(unsafe { (*self.result.get()).assume_init_read() })
        })
    }

    fn register_waker(&self, waker: &Waker) {
        let mut guard = self.waker.lock();
        let replace = match guard.as_ref() {
            Some(current) => !current.will_wake(waker),
            None => true,
        };

        if replace {
            *guard = Some(waker.clone());
        }
    }

    fn take_waker(&self) -> Option<Waker> {
        self.waker.lock().take()
    }

    fn drop_waker(&self) {
        self.waker.lock().take();
    }
}

#[repr(C)]
struct SharedTask<F, R> {
    header: SharedTaskHeader<R>,
    future: UnsafeCell<Option<F>>,
}

impl<F, R> SharedTask<F, R> {
    fn new(func: F) -> Self {
        Self {
            header: SharedTaskHeader::new(),
            future: UnsafeCell::new(Some(func)),
        }
    }
}

unsafe impl<F: Send, R: Send> Send for SharedTask<F, R> {}
unsafe impl<F: Send, R: Send> Sync for SharedTask<F, R> {}
unsafe impl<R: Send> Send for SharedTaskHeader<R> {}
unsafe impl<R: Send> Sync for SharedTaskHeader<R> {}

pub(crate) struct BlockingEntry {
    domain_id: ExecutorDomainId,
    ptr: *const (),
    cancel: unsafe fn(*const ()),
}

unsafe impl Send for BlockingEntry {}

unsafe fn cancel_registered<E: ExecutorPlatform, F, R>(ptr: *const ()) {
    let task = unsafe { Arc::from_raw(ptr.cast::<SharedTask<F, R>>()) };
    if task.header.try_start_running() {
        let raw = task.header.domain_id.load(Ordering::Acquire);
        let _context = (raw != 0).then(|| {
            crate::platform::CurrentExecutorContextGuard::<E>::enter(
                crate::platform::CurrentExecutorContext {
                    task_id: 0,
                    domain_id: raw,
                },
            )
        });
        drop(unsafe { (*task.future.get()).take() });
        task.header.state.store(STATE_CANCELLED, Ordering::Release);
        if let Some(waker) = task.header.take_waker() {
            waker.wake();
        }
    }
}

pub(crate) fn cancel_domain_jobs<E: ExecutorPlatform>(
    domain_id: ExecutorDomainId,
    cursor: &mut [usize; 2],
    mut remaining: usize,
) -> bool {
    if cursor[1] == usize::MAX {
        cursor[1] = GlobalAsyncExecutor::<E>::global().blocking_tasks.lock().len();
    }
    while cursor[0] < cursor[1] {
        if remaining == 0 {
            return false;
        }
        let entry = {
            let mut entries = GlobalAsyncExecutor::<E>::global().blocking_tasks.lock();
            let entry = &mut entries[cursor[0]];
            if entry
                .as_ref()
                .is_some_and(|entry| entry.domain_id == domain_id)
            {
                entry.take()
            } else {
                None
            }
        };
        cursor[0] += 1;
        remaining -= 1;
        if let Some(entry) = entry {
            unsafe {
                (entry.cancel)(entry.ptr);
            }
        }
    }
    true
}

#[cfg(miri)]
#[derive(Clone, Copy)]
struct ErasedBlockingTaskPtr(*const ());

#[cfg(miri)]
unsafe impl Send for ErasedBlockingTaskPtr {}

#[cfg(miri)]
static MIRI_BLOCKING_TASKS: Mutex<Vec<Option<ErasedBlockingTaskPtr>>> = Mutex::new(Vec::new());

#[cfg(miri)]
fn register_blocking_task<F, R>(task: Arc<SharedTask<F, R>>) -> usize {
    let ptr = Arc::into_raw(task).cast::<()>();
    let mut tasks = MIRI_BLOCKING_TASKS.lock();

    for (idx, slot) in tasks.iter_mut().enumerate() {
        if slot.is_none() {
            *slot = Some(ErasedBlockingTaskPtr(ptr));
            return idx + 1;
        }
    }

    tasks.push(Some(ErasedBlockingTaskPtr(ptr)));
    tasks.len()
}

#[cfg(miri)]
unsafe fn take_blocking_task<F, R>(ctx: usize) -> Arc<SharedTask<F, R>> {
    let Some(idx) = ctx.checked_sub(1) else {
        panic!("blocking ctx passed is null handle");
    };

    let ptr = MIRI_BLOCKING_TASKS
        .lock()
        .get_mut(idx)
        .and_then(Option::take)
        .expect("blocking ctx handle missing");

    Arc::from_raw(ptr.0.cast::<SharedTask<F, R>>())
}

impl<R> Drop for SharedTaskHeader<R> {
    fn drop(&mut self) {
        if self.state.load(Ordering::Acquire) == STATE_COMPLETE {
            // SAFETY: result was initialized if state == COMPLETE.
            unsafe { (*self.result.get()).assume_init_drop() };
        }
        self.drop_waker();
    }
}

fn drop_shared_task<F, R>(ptr: *const SharedTaskHeader<R>) {
    // SAFETY: ptr was produced by Arc::into_raw on Arc<SharedTask<F, R>>.
    unsafe {
        drop(Arc::from_raw(ptr as *const SharedTask<F, R>));
    }
}

pub struct BlockingJoin<R> {
    ptr: *const SharedTaskHeader<R>,
    drop_fn: fn(*const SharedTaskHeader<R>),
}

impl<R> BlockingJoin<R> {
    fn new(ptr: *const SharedTaskHeader<R>, drop_fn: fn(*const SharedTaskHeader<R>)) -> Self {
        Self { ptr, drop_fn }
    }
}

impl<R> Drop for BlockingJoin<R> {
    fn drop(&mut self) {
        if self.ptr.is_null() {
            return;
        }
        unsafe { (&*self.ptr).drop_waker() };
        (self.drop_fn)(self.ptr);
        self.ptr = ptr::null();
    }
}

unsafe impl<R: Send + 'static> Send for BlockingJoin<R> {}
unsafe impl<R: Send + 'static> Sync for BlockingJoin<R> {}

impl<R: Send + 'static> Future for BlockingJoin<R> {
    type Output = TaskOutcome<R>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let header = unsafe { &*self.ptr };
        if let Some(res) = header.take_result() {
            return Poll::Ready(res);
        }

        header.register_waker(cx.waker());

        match header.take_result() { Some(res) => {
            // Result arrived after we registered the waker. Clear any stored
            // waker to avoid keeping an unnecessary ref alive.
            header.drop_waker();
            Poll::Ready(res)
        } _ => {
            Poll::Pending
        }}
    }
}

extern "C" fn blocking_trampoline<E: ExecutorPlatform, F, R>(ctx: usize)
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    #[cfg(miri)]
    if ctx == 0 {
        panic!("blocking ctx passed is null handle");
    }

    #[cfg(not(miri))]
    if ctx < 0x1000 {
        panic!("blocking ctx passed is null ptr");
    }

    #[cfg(miri)]
    let task = unsafe { take_blocking_task::<F, R>(ctx) };

    #[cfg(not(miri))]
    let task = unsafe { Arc::from_raw(ctx as *const SharedTask<F, R>) };
    let raw = task.header.domain_id.load(Ordering::Acquire);
    let run = || {
        let header = &task.header;
        if !header.try_start_running() {
            return;
        }
        let registry = header.registry_index.swap(0, Ordering::AcqRel);
        if registry != 0 {
            let entry = GlobalAsyncExecutor::<E>::global().blocking_tasks.lock()[registry - 1].take();
            if let Some(entry) = entry {
                unsafe {
                    (entry.cancel)(entry.ptr);
                }
            }
        }
        let _context = (raw != 0).then(|| {
            crate::platform::CurrentExecutorContextGuard::<E>::enter(
                crate::platform::CurrentExecutorContext {
                    task_id: 0,
                    domain_id: raw,
                },
            )
        });
        let f = unsafe { (*task.future.get()).take() }.expect("blocking func missing");
        header.store_result(f());
        if let Some(waker) = header.take_waker() {
            waker.wake();
        }
    };
    if raw == 0 {
        run();
    } else {
        GlobalAsyncExecutor::<E>::global().with_executor_domain(
            ExecutorDomainId::from_raw(raw),
            |domain| {
                if domain.state() == ExecutorDomainState::Active {
                    run();
                }
            },
        );
    }
}

fn prepare_blocking<E: ExecutorPlatform, F, R>(func: F) -> (BlockingJoin<R>, Option<Job>)
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let task = Arc::new(SharedTask::<F, R>::new(func));
    let join_ptr = Arc::into_raw(task.clone()) as *const SharedTaskHeader<R>;
    let raw =
        crate::platform::current_executor_context::<E>().map_or(0, |context| context.domain_id);
    task.header.domain_id.store(raw, Ordering::Release);
    let prepare = || {
        if raw != 0 && ExecutorDomainId::from_raw(raw).slot() >= 4 {
            let entry = BlockingEntry {
                domain_id: ExecutorDomainId::from_raw(raw),
                ptr: Arc::into_raw(task.clone()).cast(),
                cancel: cancel_registered::<E, F, R>,
            };
            let mut entries = GlobalAsyncExecutor::<E>::global().blocking_tasks.lock();
            let index = entries
                .iter()
                .position(Option::is_none)
                .unwrap_or(entries.len());
            if index == entries.len() {
                entries.push(Some(entry));
            } else {
                entries[index] = Some(entry);
            }
            task.header
                .registry_index
                .store(index + 1, Ordering::Release);
        }
        #[cfg(miri)]
        let ptr = register_blocking_task(task.clone());
        #[cfg(not(miri))]
        let ptr = Arc::into_raw(task.clone()) as usize;
        Job {
            f: blocking_trampoline::<E, F, R>,
            a: ptr,
        }
    };
    let job = if raw == 0 {
        Some(prepare())
    } else {
        GlobalAsyncExecutor::<E>::global()
            .with_executor_domain(ExecutorDomainId::from_raw(raw), |domain| {
                (domain.state() == ExecutorDomainState::Active).then(prepare)
            })
            .flatten()
    };
    if job.is_none() {
        unsafe {
            cancel_registered::<E, F, R>(Arc::into_raw(task.clone()).cast());
        }
    }
    (BlockingJoin::new(join_ptr, drop_shared_task::<F, R>), job)
}

pub fn spawn_blocking<E: ExecutorPlatform, F, R>(func: F) -> BlockingJoin<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let (join, job) = prepare_blocking::<E, _, _>(func);
    if let Some(job) = job {
        submit_blocking::<E>(job.f, job.a);
    }
    join
}

pub fn spawn_blocking_many<E: ExecutorPlatform, F, R>(funcs: Vec<F>) -> Vec<BlockingJoin<R>>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let count = funcs.len();
    if count == 0 {
        return Vec::new();
    }

    let mut joins = Vec::with_capacity(count);
    let mut jobs = Vec::with_capacity(count);

    for func in funcs {
        let (join, job) = prepare_blocking::<E, _, _>(func);
        if let Some(job) = job { jobs.push(job); }
        joins.push(join);
    }

    submit_blocking_many::<E>(&jobs);
    joins
}

#[cfg(all(test, not(any(loom, feature = "loom"))))]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    fn run_same_blocking_task_twice<F>(
        task: Arc<SharedTask<F, usize>>,
        header: *const SharedTaskHeader<usize>,
    ) where
        F: FnOnce() -> usize + Send + 'static,
    {
        let ctx1 = Arc::into_raw(task.clone()) as usize;
        let ctx2 = Arc::into_raw(task) as usize;

        blocking_trampoline::<crate::test_support::TestExecutorPlatform, F, usize>(ctx1);
        blocking_trampoline::<crate::test_support::TestExecutorPlatform, F, usize>(ctx2);

        let header = unsafe { &*header };
        assert_eq!(header.take_result(), Some(TaskOutcome::Completed(321)));
    }

    // This test covers the blocking trampoline's reentry guard. If a worker and
    // a steal path both try to execute the same blocking job, the closure must run
    // once and the second trampoline entry must return before touching the job.
    #[test]
    fn blocking_trampoline_runs_shared_task_at_most_once_when_reentered() {
        let runs = Arc::new(AtomicUsize::new(0));
        let runs_for_task = runs.clone();
        let task = Arc::new(SharedTask::new(move || {
            runs_for_task.fetch_add(1, Ordering::AcqRel);
            321usize
        }));
        let result_owner = task.clone();
        let header = &result_owner.header as *const SharedTaskHeader<usize>;

        run_same_blocking_task_twice(task, header);

        assert_eq!(runs.load(Ordering::Acquire), 1);
    }
}

#[cfg(all(test, any(loom, feature = "loom")))]
mod loom_tests {
    use super::*;
    use crate::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use crate::sync::{exhaustive_model, Arc};
    use core::mem::ManuallyDrop;
    use core::task::{RawWaker, RawWakerVTable, Waker};

    struct ModelWakeCounter {
        wakes: AtomicUsize,
    }

    unsafe fn clone_model_waker(ptr: *const ()) -> RawWaker {
        let arc =
            ManuallyDrop::new(unsafe { std::sync::Arc::from_raw(ptr.cast::<ModelWakeCounter>()) });
        let cloned = std::sync::Arc::clone(&arc);
        RawWaker::new(
            std::sync::Arc::into_raw(cloned).cast::<()>(),
            &MODEL_WAKER_VTABLE,
        )
    }

    unsafe fn wake_model_waker(ptr: *const ()) {
        let arc = unsafe { std::sync::Arc::from_raw(ptr.cast::<ModelWakeCounter>()) };
        arc.wakes.fetch_add(1, Ordering::AcqRel);
    }

    unsafe fn wake_model_waker_by_ref(ptr: *const ()) {
        let arc =
            ManuallyDrop::new(unsafe { std::sync::Arc::from_raw(ptr.cast::<ModelWakeCounter>()) });
        arc.wakes.fetch_add(1, Ordering::AcqRel);
    }

    unsafe fn drop_model_waker(ptr: *const ()) {
        drop(unsafe { std::sync::Arc::from_raw(ptr.cast::<ModelWakeCounter>()) });
    }

    static MODEL_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
        clone_model_waker,
        wake_model_waker,
        wake_model_waker_by_ref,
        drop_model_waker,
    );

    fn model_waker(counter: std::sync::Arc<ModelWakeCounter>) -> Waker {
        let raw = RawWaker::new(
            std::sync::Arc::into_raw(counter).cast::<()>(),
            &MODEL_WAKER_VTABLE,
        );
        unsafe { Waker::from_raw(raw) }
    }

    // Models two execution paths racing to run the same blocking task. The
    // PENDING -> RUNNING guard must allow exactly one path to store a result.
    #[test]
    fn loom_blocking_running_guard_allows_one_runner() {
        exhaustive_model(|| {
            let header = Arc::new(SharedTaskHeader::<usize>::new());
            let runs = Arc::new(AtomicUsize::new(0));

            let header_a = header.clone();
            let runs_a = runs.clone();
            let runner_a = loom::thread::spawn(move || {
                if header_a.try_start_running() {
                    runs_a.fetch_add(1, Ordering::AcqRel);
                    header_a.store_result(11);
                }
            });

            let header_b = header.clone();
            let runs_b = runs.clone();
            let runner_b = loom::thread::spawn(move || {
                if header_b.try_start_running() {
                    runs_b.fetch_add(1, Ordering::AcqRel);
                    header_b.store_result(22);
                }
            });

            runner_a.join().expect("runner A panicked");
            runner_b.join().expect("runner B panicked");

            assert_eq!(runs.load(Ordering::Acquire), 1);
            assert!(matches!(header.take_result(), Some(TaskOutcome::Completed(11 | 22))));
        });
    }

    // Models BlockingJoin::poll racing with worker completion. If the join side
    // actually returns Pending, completion must have retained and woken its waker.
    #[test]
    fn loom_blocking_join_pending_poll_gets_completion_wake() {
        exhaustive_model(|| {
            let header = Arc::new(SharedTaskHeader::<usize>::new());
            let counter = std::sync::Arc::new(ModelWakeCounter {
                wakes: AtomicUsize::new(0),
            });
            let returned_pending = Arc::new(AtomicBool::new(false));
            let waker = model_waker(counter.clone());

            let waiter_header = header.clone();
            let waiter_pending = returned_pending.clone();
            let waiter = loom::thread::spawn(move || {
                if waiter_header.take_result().is_none() {
                    waiter_header.register_waker(&waker);

                    if waiter_header.take_result().is_some() {
                        waiter_header.drop_waker();
                    } else {
                        waiter_pending.store(true, Ordering::Release);
                    }
                }
            });

            let worker_header = header.clone();
            let worker = loom::thread::spawn(move || {
                worker_header.store_result(33);
                if let Some(waker) = worker_header.take_waker() {
                    waker.wake();
                }
            });

            waiter.join().expect("waiter panicked");
            worker.join().expect("worker panicked");

            if returned_pending.load(Ordering::Acquire) {
                assert_eq!(counter.wakes.load(Ordering::Acquire), 1);
                assert_eq!(header.take_result(), Some(TaskOutcome::Completed(33)));
            }
        });
    }
}
