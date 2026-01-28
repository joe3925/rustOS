use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::future::Future;
use core::mem::MaybeUninit;
use core::pin::Pin;
use core::ptr;
use core::sync::atomic::{AtomicU8, Ordering};
use core::task::{Context, Poll};
use spin::Mutex;

use crate::scheduling::runtime::runtime::{submit_blocking, submit_blocking_many};
use crate::structs::thread_pool::Job;
use super::waker::{self, Continuation};

const STATE_PENDING: u8 = 0;
const STATE_COMPLETE: u8 = 1;
const STATE_CONSUMED: u8 = 2;
const STATE_RUNNING: u8 = 3;

struct SharedTaskHeader<R> {
    result: UnsafeCell<MaybeUninit<R>>,
    state: AtomicU8,
    cont: Mutex<Option<usize>>,
}

impl<R> SharedTaskHeader<R> {
    fn new() -> Self {
        Self {
            result: UnsafeCell::new(MaybeUninit::uninit()),
            state: AtomicU8::new(STATE_PENDING),
            cont: Mutex::new(None),
        }
    }

    fn store_result(&self, result: R) {
        // SAFETY: Only the worker thread writes to result and it happens exactly once.
        unsafe {
            (*self.result.get()).write(result);
        }
        self.state.store(STATE_COMPLETE, Ordering::Release);
    }

    fn take_result(&self) -> Option<R> {
        if self.state.load(Ordering::Acquire) != STATE_COMPLETE {
            return None;
        }

        self.state.store(STATE_CONSUMED, Ordering::Release);
        // SAFETY: state prevents double-read; result was written exactly once.
        Some(unsafe { (*self.result.get()).assume_init_read() })
    }

    fn register_continuation(&self, cont: usize) {
        let mut guard = self.cont.lock();
        if let Some(prev) = guard.replace(cont) {
            drop_continuation(prev, true);
        }
    }

    fn take_continuation(&self) -> Option<usize> {
        let mut guard = self.cont.lock();
        guard.take()
    }

    fn drop_continuation(&self) {
        if let Some(prev) = self.take_continuation() {
            drop_continuation(prev, true);
        }
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

impl<R> Drop for SharedTaskHeader<R> {
    fn drop(&mut self) {
        if self.state.load(Ordering::Acquire) == STATE_COMPLETE {
            // SAFETY: result was initialized if state == COMPLETE.
            unsafe { (*self.result.get()).assume_init_drop() };
        }
        self.drop_continuation();
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
    pub fn new(ptr: *const SharedTaskHeader<R>, drop_fn: fn(*const SharedTaskHeader<R>)) -> Self {
        Self { ptr, drop_fn }
    }
}

impl<R> Drop for BlockingJoin<R> {
    fn drop(&mut self) {
        if self.ptr.is_null() {
            return;
        }
        unsafe { (&*self.ptr).drop_continuation() };
        (self.drop_fn)(self.ptr);
        self.ptr = ptr::null();
    }
}

unsafe impl<R: Send + 'static> Send for BlockingJoin<R> {}
unsafe impl<R: Send + 'static> Sync for BlockingJoin<R> {}

impl<R: Send + 'static> Future for BlockingJoin<R> {
    type Output = R;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<R> {
        let header = unsafe { &*self.ptr };
        if let Some(res) = header.take_result() {
            return Poll::Ready(res);
        }

        if let Some(cont) = waker::continuation_from_waker(cx.waker()) {
            let boxed = Box::into_raw(Box::new(cont));
            header.register_continuation(boxed as usize);
        }

        if let Some(res) = header.take_result() {
            Poll::Ready(res)
        } else {
            Poll::Pending
        }
    }
}

pub extern "win64" fn blocking_trampoline<F, R>(ctx: usize)
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    if ctx < 0x1000 {
        panic!("blocking ctx passed is null ptr");
    }

    let task = unsafe { Arc::from_raw(ctx as *const SharedTask<F, R>) };
    let header = &task.header;

    // Ensure the blocking task runs at most once. If a steal path races a worker and
    // re-enters with the same ctx, bail out instead of double-running and panicking.
    if header
        .state
        .compare_exchange(STATE_PENDING, STATE_RUNNING, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }

    // SAFETY: Only this worker thread accesses the function slot.
    let f = unsafe { (*task.future.get()).take() }.expect("blocking func missing");
    let result = f();

    header.store_result(result);

    if let Some(cont_ptr) = header.take_continuation() {
        run_continuation(cont_ptr);
    }
}

pub fn spawn_blocking<F, R>(func: F) -> BlockingJoin<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let task = Arc::new(SharedTask::<F, R>::new(func));
    let join_ptr = Arc::into_raw(task.clone()) as *const SharedTaskHeader<R>;
    let ptr = Arc::into_raw(task) as usize;

    submit_blocking(blocking_trampoline::<F, R>, ptr);
    BlockingJoin::new(join_ptr, drop_shared_task::<F, R>)
}

/// Spawns multiple blocking tasks in a batch, reducing lock contention on the thread pool.
/// Returns a Vec of BlockingJoin handles that can be awaited.
pub fn spawn_blocking_many<F, R>(funcs: Vec<F>) -> Vec<BlockingJoin<R>>
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
        let task = Arc::new(SharedTask::<F, R>::new(func));
        let join_ptr = Arc::into_raw(task.clone()) as *const SharedTaskHeader<R>;
        let ptr = Arc::into_raw(task) as usize;

        jobs.push(Job {
            f: blocking_trampoline::<F, R>,
            a: ptr,
        });
        joins.push(BlockingJoin::new(join_ptr, drop_shared_task::<F, R>));
    }

    submit_blocking_many(&jobs);
    joins
}

const ASSIST_BUDGET: usize = 1;

fn run_continuation(cont_ptr: usize) {
    if cont_ptr == 0 {
        return;
    }
    let cont = unsafe { Box::from_raw(cont_ptr as *mut Continuation) };
    let mut remaining = ASSIST_BUDGET;
    if remaining > 0 {
        (cont.tramp)(cont.ctx);
        remaining -= 1;
    }
    drop(cont);
}

fn drop_continuation(ptr: usize, call_drop: bool) {
    if ptr == 0 {
        return;
    }
    let cont = unsafe { Box::from_raw(ptr as *mut Continuation) };
    if call_drop {
        unsafe { (cont.drop_fn)(cont.ctx) };
    }
    drop(cont);
}
