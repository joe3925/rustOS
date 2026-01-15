use alloc::boxed::Box;
use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use spin::Mutex;

use crate::scheduling::runtime::runtime::submit_blocking;

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
        if let Some(res) = result_guard.take() {
            Poll::Ready(res)
        } else {
            Poll::Pending
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
        let mut result_guard = task.inner.result.lock();
        *result_guard = Some(result);
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
    let inner = Arc::new(BlockingInner::new());
    let task = BlockingTask {
        func: Some(func),
        inner: inner.clone(),
    };
    let ptr = Box::into_raw(Box::new(task)) as usize;

    submit_blocking(blocking_trampoline::<F, R>, ptr);
    BlockingJoin::new(inner)
}
