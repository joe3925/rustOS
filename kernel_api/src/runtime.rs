extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::task::Wake;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll, Waker};
use spin::Mutex;

use kernel_sys::{
    kernel_spawn_blocking_raw, kernel_spawn_detached_ffi, kernel_spawn_ffi,
    try_steal_blocking_one as sys_try_steal_blocking_one,
};
use kernel_types::async_ffi::{FfiFuture, FutureExt};

/// Spawn an async task on the kernel executor (shared singleton in the kernel).
pub fn spawn<F>(future: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    unsafe { kernel_spawn_ffi(future.into_ffi()) };
}

/// Spawn a detached async task (fire-and-forget).
pub fn spawn_detached<F>(future: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    unsafe { kernel_spawn_detached_ffi(future.into_ffi()) };
}

/// Block the current thread until the future completes using a local waker and optional stealing from the kernel blocking pool.
pub fn block_on<F: Future>(future: F) -> F::Output {
    let mut pinned = Box::pin(future);
    let notify = Arc::new(ThreadNotify::new());
    let waker = Waker::from(notify.clone());
    let mut cx = Context::from_waker(&waker);

    loop {
        match Pin::new(&mut pinned).as_mut().poll(&mut cx) {
            Poll::Ready(out) => return out,
            Poll::Pending => {
                if !notify.take_ready() {
                    let _ = unsafe { sys_try_steal_blocking_one() };
                }
            }
        }
    }
}

/// Minimal blocking join handle executed on the kernel blocking pool.
pub struct BlockingJoin<R> {
    state: Arc<BlockingState<R>>,
}

struct BlockingState<R> {
    result: Mutex<Option<R>>,
    ready: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

impl<R> BlockingState<R> {
    fn new() -> Self {
        Self {
            result: Mutex::new(None),
            ready: AtomicBool::new(false),
            waker: Mutex::new(None),
        }
    }

    fn store(&self, value: R) {
        *self.result.lock() = Some(value);
        self.ready.store(true, Ordering::Release);
        if let Some(w) = self.waker.lock().take() {
            w.wake();
        }
    }
}

impl<R> Future for BlockingJoin<R> {
    type Output = R;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<R> {
        if self.state.ready.load(Ordering::Acquire) {
            if let Some(v) = self.state.result.lock().take() {
                return Poll::Ready(v);
            }
        }
        *self.state.waker.lock() = Some(cx.waker().clone());
        Poll::Pending
    }
}

extern "win64" fn blocking_trampoline<F, R>(ctx: usize)
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let ptr = ctx as *mut (Arc<BlockingState<R>>, Option<F>);
    let boxed = unsafe { Box::from_raw(ptr) };
    let (state, func_opt) = *boxed;
    if let Some(f) = func_opt {
        let res = f();
        state.store(res);
    }
}

pub fn spawn_blocking<F, R>(func: F) -> BlockingJoin<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let state = Arc::new(BlockingState::new());
    let pair = Box::new((state.clone(), Some(func)));
    let ctx = Box::into_raw(pair) as usize;
    unsafe {
        kernel_spawn_blocking_raw(blocking_trampoline::<F, R>, ctx);
    }
    BlockingJoin { state }
}

pub fn spawn_blocking_many<F, R>(funcs: Vec<F>) -> Vec<BlockingJoin<R>>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    if funcs.is_empty() {
        return Vec::new();
    }
    let mut joins = Vec::with_capacity(funcs.len());
    for f in funcs {
        joins.push(spawn_blocking(f));
    }
    joins
}

/// Best-effort steal of one blocking task from the kernel blocking pool.
pub fn try_steal_blocking_one() -> bool {
    unsafe { sys_try_steal_blocking_one() }
}

struct ThreadNotify {
    ready: AtomicBool,
}

impl ThreadNotify {
    fn new() -> Self {
        Self {
            ready: AtomicBool::new(false),
        }
    }

    fn take_ready(&self) -> bool {
        self.ready.swap(false, Ordering::AcqRel)
    }
}

impl Wake for ThreadNotify {
    fn wake(self: Arc<Self>) {
        self.ready.store(true, Ordering::Release);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.ready.store(true, Ordering::Release);
    }
}
