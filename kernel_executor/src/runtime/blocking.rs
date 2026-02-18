use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::future::Future;
use core::mem::MaybeUninit;
use core::pin::Pin;
use core::ptr;
use core::sync::atomic::{AtomicU8, Ordering};
use core::task::{Context, Poll, Waker};
use spin::Mutex;

use crate::platform::Job;
use crate::runtime::runtime::{submit_blocking, submit_blocking_many};

const STATE_PENDING: u8 = 0;
const STATE_COMPLETE: u8 = 1;
const STATE_CONSUMED: u8 = 2;
const STATE_RUNNING: u8 = 3;

pub struct SharedTaskHeader<R> {
    result: UnsafeCell<MaybeUninit<R>>,
    state: AtomicU8,
    waker: Mutex<Option<Waker>>,
}

impl<R> SharedTaskHeader<R> {
    fn new() -> Self {
        Self {
            result: UnsafeCell::new(MaybeUninit::uninit()),
            state: AtomicU8::new(STATE_PENDING),
            waker: Mutex::new(None),
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
    pub fn new(ptr: *const SharedTaskHeader<R>, drop_fn: fn(*const SharedTaskHeader<R>)) -> Self {
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
    type Output = R;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<R> {
        let header = unsafe { &*self.ptr };
        if let Some(res) = header.take_result() {
            return Poll::Ready(res);
        }

        header.register_waker(cx.waker());

        if let Some(res) = header.take_result() {
            // Result arrived after we registered the waker. Clear any stored
            // waker to avoid keeping an unnecessary ref alive.
            header.drop_waker();
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
        .compare_exchange(
            STATE_PENDING,
            STATE_RUNNING,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return;
    }

    // SAFETY: Only this worker thread accesses the function slot.
    let f = unsafe { (*task.future.get()).take() }.expect("blocking func missing");
    let result = f();

    header.store_result(result);

    if let Some(w) = header.take_waker() {
        w.wake();
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
