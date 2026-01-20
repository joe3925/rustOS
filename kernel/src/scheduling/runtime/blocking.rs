use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::future::Future;
use core::pin::Pin;
use core::ptr;
use core::sync::atomic::{AtomicU8, Ordering};
use core::task::{Context, Poll, Waker};
use spin::Mutex;

use crate::scheduling::runtime::runtime::{submit_blocking, submit_blocking_many};
use crate::structs::thread_pool::Job;

const STATE_PENDING: u8 = 0;
const STATE_COMPLETE: u8 = 1;
const STATE_CONSUMED: u8 = 2;

struct SharedTaskHeader<R> {
    result: UnsafeCell<Option<R>>,
    waker: Mutex<Option<Waker>>,
    state: AtomicU8,
}

impl<R> SharedTaskHeader<R> {
    fn new() -> Self {
        Self {
            result: UnsafeCell::new(None),
            waker: Mutex::new(None),
            state: AtomicU8::new(STATE_PENDING),
        }
    }

    fn record_waker(&self, waker: &Waker) {
        let mut w = self.waker.lock();
        *w = Some(waker.clone());
    }

    fn try_take_result(&self) -> Option<R> {
        if self.state.load(Ordering::Acquire) == STATE_COMPLETE {
            // SAFETY: Only the worker thread writes the result, and once state is COMPLETE the
            // result will not be modified again.
            let res = unsafe { (*self.result.get()).take() };
            self.state.store(STATE_CONSUMED, Ordering::Release);
            res
        } else {
            None
        }
    }

    fn store_result(&self, result: R) {
        // SAFETY: Only the worker thread writes to result and it happens exactly once.
        unsafe {
            *self.result.get() = Some(result);
        }
        self.state.store(STATE_COMPLETE, Ordering::Release);
    }

    fn wake(&self) {
        if let Some(w) = self.waker.lock().take() {
            w.wake();
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

        if let Some(res) = header.try_take_result() {
            return Poll::Ready(res);
        }

        header.record_waker(cx.waker());

        if let Some(res) = header.try_take_result() {
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

    // SAFETY: Only this worker thread accesses the function slot.
    let f = unsafe { (*task.future.get()).take() }.expect("blocking func missing");
    let result = f();

    task.header.store_result(result);
    task.header.wake();
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
