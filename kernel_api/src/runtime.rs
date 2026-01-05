use core::{
    alloc::Layout,
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll, Waker},
};

use alloc::{boxed::Box, sync::Arc, task::Wake};

use kernel_sys::{
    kernel_async_submit, kernel_spawn_ffi, submit_blocking_internal, try_steal_blocking_one,
};
use kernel_types::async_ffi::{FfiFuture, FutureExt};
use spin::Mutex;

pub fn spawn<F>(future: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    unsafe { kernel_spawn_ffi(future.into_ffi()) };
}

pub fn spawn_ffi(fut: FfiFuture<()>) {
    unsafe { kernel_spawn_ffi(fut) };
}

pub fn submit(trampoline: extern "win64" fn(usize), ctx: usize) {
    unsafe { kernel_async_submit(trampoline, ctx) };
}

pub fn submit_blocking(trampoline: extern "win64" fn(usize), ctx: usize) {
    unsafe { submit_blocking_internal(trampoline, ctx) };
}

pub struct ThreadNotify {
    ready: AtomicBool,
}

impl ThreadNotify {
    pub fn new() -> Self {
        Self {
            ready: AtomicBool::new(false),
        }
    }

    pub fn take_ready(&self) -> bool {
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
                    if !unsafe { try_steal_blocking_one() } {}
                }
            }
        }
    }
}
pub struct BlockingState<F, R> {
    func: Mutex<Option<F>>,
    result: Mutex<Option<R>>,
    waker: Mutex<Option<Waker>>,
}

impl<F, R> BlockingState<F, R> {
    pub fn new(func: F) -> Self {
        Self {
            func: Mutex::new(Some(func)),
            result: Mutex::new(None),
            waker: Mutex::new(None),
        }
    }
}

pub struct BlockingJoin<F, R> {
    state: Arc<BlockingState<F, R>>,
}

impl<F, R> BlockingJoin<F, R> {
    pub fn new(state: Arc<BlockingState<F, R>>) -> Self {
        Self { state }
    }
}

impl<F, R> Future for BlockingJoin<F, R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    type Output = R;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<R> {
        {
            let mut w = self.state.waker.lock();
            *w = Some(cx.waker().clone());
        }

        let mut g = self.state.result.lock();
        match g.take() {
            Some(r) => Poll::Ready(r),
            None => Poll::Pending,
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

    let state = unsafe { Arc::from_raw(ctx as *const BlockingState<F, R>) };

    let f = {
        let mut g = state.func.lock();
        g.take().expect("blocking func missing")
    };

    let result = f();

    {
        let mut g = state.result.lock();
        *g = Some(result);
    }

    let w = {
        let mut g = state.waker.lock();
        g.take()
    };

    if let Some(w) = w {
        w.wake();
    }
}

pub fn spawn_blocking<F, R>(func: F) -> BlockingJoin<F, R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let state = Arc::new(BlockingState::<F, R>::new(func));

    let ptr = Arc::into_raw(state.clone()) as usize;
    submit_blocking(blocking_trampoline::<F, R>, ptr);

    BlockingJoin::new(state)
}
