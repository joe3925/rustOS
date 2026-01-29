use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

pub use super::block_on::block_on;
pub use super::blocking::{spawn_blocking, spawn_blocking_many, BlockingJoin};

use crate::platform::{platform, Job};

use super::slab::get_task_slab;
use super::task::{FutureTask, JoinableTask, TaskPoll};

pub(crate) fn submit_global(trampoline: extern "win64" fn(usize), ctx: usize) {
    platform().submit_runtime(Job {
        f: trampoline,
        a: ctx,
    });
}

pub(crate) fn submit_blocking(trampoline: extern "win64" fn(usize), ctx: usize) {
    platform().submit_blocking(Job {
        f: trampoline,
        a: ctx,
    });
}

pub(crate) fn submit_blocking_many(jobs: &[Job]) {
    platform().submit_blocking_many(jobs);
}

pub fn yield_now() {
    platform().yield_now();
}

pub extern "win64" fn try_steal_blocking_one() -> bool {
    platform().try_steal_blocking_one()
}

/// Spawns a future and returns a JoinHandle to await its result.
/// Uses a single Arc allocation for both the task and result storage.
pub fn spawn<F, T>(future: F) -> JoinHandle<T>
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let task = Arc::new(JoinableTask::new(future));
    task.enqueue();
    JoinHandle { task }
}

pub struct JoinHandle<T: Send + 'static> {
    task: Arc<JoinableTask<T>>,
}

impl<T: Send + 'static> Future for JoinHandle<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<T> {
        if let Some(result) = self.task.take_result() {
            Poll::Ready(result)
        } else {
            self.task.set_waker(cx.waker().clone());
            // Check again in case result arrived between take_result and set_waker
            if let Some(result) = self.task.take_result() {
                Poll::Ready(result)
            } else {
                Poll::Pending
            }
        }
    }
}

/// Spawns a detached future that runs to completion without a JoinHandle.
///
/// This function tries to allocate from the task slab first for better performance.
/// If the slab is full, it falls back to Arc-based allocation.
pub fn spawn_detached<F>(future: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    let slab = get_task_slab();

    // Try slab allocation first
    if let Some(slot_handle) = slab.allocate() {
        slot_handle.init_and_enqueue(future);
    } else {
        // Fallback to Arc-based allocation
        slab.record_fallback();
        let task = Arc::new(FutureTask::new(future));
        task.enqueue();
    }
}

/// State of each future in JoinAll - either still running or completed with result.
enum FutureSlot<F: Future> {
    Running(F),
    Done(Option<F::Output>),
}

/// Joins multiple futures of the same type, returning their results in order.
/// Stores futures inline without boxing, saving one heap allocation per future.
pub struct JoinAll<F: Future> {
    slots: Vec<FutureSlot<F>>,
    remaining: usize,
}

impl<F: Future> JoinAll<F> {
    pub fn new(fs: Vec<F>) -> Self {
        let remaining = fs.len();
        let slots = fs.into_iter().map(FutureSlot::Running).collect();
        Self { slots, remaining }
    }
}

impl<F: Future> Future for JoinAll<F> {
    type Output = Vec<F::Output>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: We never move the futures out of the Vec, only poll them in place.
        // The Vec itself may reallocate but we don't add elements after construction.
        let this = unsafe { self.get_unchecked_mut() };

        if this.remaining == 0 {
            let mut out = Vec::with_capacity(this.slots.len());
            for slot in this.slots.iter_mut() {
                if let FutureSlot::Done(result) = slot {
                    out.push(result.take().expect("result already taken"));
                }
            }
            return Poll::Ready(out);
        }

        for slot in this.slots.iter_mut() {
            if let FutureSlot::Running(fut) = slot {
                // SAFETY: The future is stored inline in the Vec which is pinned.
                // We don't move it, we just poll it in place.
                let pinned = unsafe { Pin::new_unchecked(fut) };
                match pinned.poll(cx) {
                    Poll::Ready(result) => {
                        *slot = FutureSlot::Done(Some(result));
                        this.remaining -= 1;
                    }
                    Poll::Pending => {}
                }
            }
        }

        if this.remaining == 0 {
            let mut out = Vec::with_capacity(this.slots.len());
            for slot in this.slots.iter_mut() {
                if let FutureSlot::Done(result) = slot {
                    out.push(result.take().expect("result already taken"));
                }
            }
            Poll::Ready(out)
        } else {
            Poll::Pending
        }
    }
}
