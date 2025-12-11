#![no_std]
extern crate alloc;

pub mod block_on;
mod task;
mod waker;

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use spin::Mutex;

use task::FutureTask;

pub use block_on::block_on;

use crate::task::poll_trampoline;

unsafe extern "win64" {
    fn _driver_runtime_submit_task(trampoline: extern "win64" fn(usize), ctx: usize);
    fn _driver_runtime_submit_blocking_task(trampoline: extern "win64" fn(usize), ctx: usize);
    fn task_yield();
}

pub fn spawn<F>(future: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    let task = Arc::new(FutureTask::new(future));
    let ptr = Arc::into_raw(task) as usize;
    unsafe {
        _driver_runtime_submit_task(poll_trampoline::<F>, ptr);
    }
}

pub(crate) fn submit_raw(ptr: usize) {
    unsafe {
        _driver_runtime_submit_task(poll_trampoline::<u64>, ptr);
    }
}

struct BlockingInner<R> {
    result: Mutex<Option<R>>,
    waker: Mutex<Option<Waker>>,
}

impl<R> BlockingInner<R> {
    fn new() -> Self {
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
    fn new(inner: Arc<BlockingInner<R>>) -> Self {
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

struct BlockingTask<F, R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    func: Option<F>,
    inner: Arc<BlockingInner<R>>,
}

extern "win64" fn blocking_trampoline<F, R>(ctx: usize)
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    if ctx < 0x1000 {
        panic!("blocking ctx passed is null ptr");
    }

    let mut task: Box<BlockingTask<F, R>> =
        unsafe { Box::from_raw(ctx as *mut BlockingTask<F, R>) };

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

    unsafe {
        _driver_runtime_submit_blocking_task(blocking_trampoline::<F, R>, ptr);
    }

    BlockingJoin::new(inner)
}
