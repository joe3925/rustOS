use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use spin::Mutex;

pub use super::block_on::block_on;
pub use super::blocking::{spawn_blocking, BlockingJoin};

use crate::static_handlers::task_yield;
use crate::{
    static_handlers::{submit_blocking_internal, submit_runtime_internal},
    structs::thread_pool::ThreadPool,
};

use super::task::FutureTask;

lazy_static::lazy_static! {
    pub static ref RUNTIME_POOL: Arc<ThreadPool> = ThreadPool::new(3);
    pub static ref BLOCKING_POOL: Arc<ThreadPool> = ThreadPool::new(3);
}

pub(crate) fn submit_global(trampoline: extern "win64" fn(usize), ctx: usize) {
    unsafe {
        _driver_runtime_submit_task(trampoline, ctx);
    }
}

pub(crate) fn submit_blocking(trampoline: extern "win64" fn(usize), ctx: usize) {
    unsafe {
        _driver_runtime_submit_blocking_task(trampoline, ctx);
    }
}

pub(crate) fn yield_now() {
    unsafe {
        task_yield();
    }
}
pub extern "win64" fn try_steal_blocking_one() -> bool {
    BLOCKING_POOL.try_execute_one()
}
pub fn spawn<F, T>(future: F) -> JoinHandle<T>
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let inner = Arc::new(Mutex::new(JoinInner {
        result: None,
        waker: None,
    }));

    let inner_clone = inner.clone();

    let wrapped = async move {
        let result = future.await;
        let waker = {
            let mut guard = inner_clone.lock();
            guard.result = Some(result);
            guard.waker.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
    };

    let task = Arc::new(FutureTask::new(wrapped));
    task.enqueue();

    JoinHandle { inner }
}

#[no_mangle]
unsafe extern "win64" fn _driver_runtime_submit_task(
    trampoline: extern "win64" fn(usize),
    ctx: usize,
) {
    submit_runtime_internal(trampoline, ctx);
}

#[no_mangle]
unsafe extern "win64" fn _driver_runtime_submit_blocking_task(
    trampoline: extern "win64" fn(usize),
    ctx: usize,
) {
    submit_blocking_internal(trampoline, ctx);
}
struct JoinInner<T> {
    result: Option<T>,
    waker: Option<Waker>,
}

pub struct JoinHandle<T> {
    inner: Arc<Mutex<JoinInner<T>>>,
}

impl<T> Future for JoinHandle<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<T> {
        let mut guard = self.inner.lock();
        if let Some(result) = guard.result.take() {
            Poll::Ready(result)
        } else {
            guard.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}
pub fn spawn_detached<F>(future: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    let task = Arc::new(FutureTask::new(future));
    task.enqueue();
}
pub struct JoinAll<F>
where
    F: Future,
{
    futures: Vec<Pin<Box<F>>>,
    done: Vec<Option<F::Output>>,
    remaining: usize,
}

impl<F> JoinAll<F>
where
    F: Future,
{
    pub fn new(fs: Vec<F>) -> Self {
        let remaining = fs.len();
        let mut futures = Vec::with_capacity(remaining);
        for f in fs {
            futures.push(Box::pin(f));
        }
        Self {
            futures,
            done: (0..remaining).map(|_| None).collect(),
            remaining,
        }
    }
}

impl<F> Future for JoinAll<F>
where
    F: Future,
{
    type Output = Vec<F::Output>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        if this.remaining == 0 {
            let mut out = Vec::with_capacity(this.done.len());
            for v in this.done.iter_mut() {
                out.push(v.take().unwrap());
            }
            return Poll::Ready(out);
        }

        for i in 0..this.futures.len() {
            if this.done[i].is_some() {
                continue;
            }

            match this.futures[i].as_mut().poll(cx) {
                Poll::Ready(v) => {
                    this.done[i] = Some(v);
                    this.remaining -= 1;
                }
                Poll::Pending => {}
            }
        }

        if this.remaining == 0 {
            let mut out = Vec::with_capacity(this.done.len());
            for v in this.done.iter_mut() {
                out.push(v.take().unwrap());
            }
            Poll::Ready(out)
        } else {
            Poll::Pending
        }
    }
}
