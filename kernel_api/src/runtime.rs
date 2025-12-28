use core::{
    alloc::Layout,
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll, Waker},
};

use alloc::{boxed::Box, sync::Arc, task::Wake};

use kernel_sys::{kernel_async_submit, kernel_spawn_ffi, submit_blocking_internal};
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
            Poll::Pending => if !notify.take_ready() {},
        }
    }
}
pub struct BlockingInner<R> {
    result: Mutex<Option<R>>,
    waker: Mutex<Option<Waker>>,
}

impl<R> BlockingInner<R> {
    pub fn new() -> Self {
        Self {
            result: Mutex::new(None),
            waker: Mutex::new(None),
        }
    }
}

pub struct BlockingJoin<R> {
    inner: Arc<BlockingInner<R>>,
}

impl<R> BlockingJoin<R> {
    pub fn new(inner: Arc<BlockingInner<R>>) -> Self {
        Self { inner }
    }
}

impl<R: Send + 'static> Future for BlockingJoin<R> {
    type Output = R;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<R> {
        {
            let mut w = self.inner.waker.lock();
            *w = Some(cx.waker().clone());
        }

        let mut result_guard = self.inner.result.lock();
        match result_guard.take() {
            Some(res) => Poll::Ready(res),
            None => Poll::Pending,
        }
    }
}

pub struct BlockingTask<F, R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    func: Option<F>,
    inner: Arc<BlockingInner<R>>,
}

pub extern "win64" fn blocking_trampoline<F, R>(ctx: usize)
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    if ctx < 0x1000 {
        panic!("blocking ctx passed is null ptr");
    }

    let mut task = unsafe { Box::from_raw(ctx as *mut BlockingTask<F, R>) };

    let f = task.func.take().expect("blocking func missing");
    let result = f();

    {
        let mut g = task.inner.result.lock();
        *g = Some(result);
    }

    let waker_opt = {
        let mut w = task.inner.waker.lock();
        w.take()
    };

    if let Some(w) = waker_opt {
        w.wake();
    }
}

pub fn spawn_blocking<F, R>(func: F) -> BlockingJoin<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let inner = Arc::new(BlockingInner::<R>::new());
    let task = BlockingTask::<F, R> {
        func: Some(func),
        inner: inner.clone(),
    };

    let ptr = Box::into_raw(Box::new(task)) as usize;
    submit_blocking(blocking_trampoline::<F, R>, ptr);

    BlockingJoin::new(inner)
}
