use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use crossbeam_queue::SegQueue;

use spin::Mutex;

pub use super::block_on::block_on;
pub use super::blocking::{spawn_blocking, spawn_blocking_many, BlockingJoin};

use crate::global_async::GlobalAsyncExecutor;
use crate::platform::{platform, Job};

use super::slab::get_task_slab;
use super::task::{FutureTask, JoinableTask, TaskPoll};

pub(crate) fn submit_global(trampoline: extern "win64" fn(usize), ctx: usize) {
    GlobalAsyncExecutor::global().submit(trampoline, ctx);
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
            self.task.update_waker(cx.waker());
            // Check again in case result arrived between take_result and set_waker
            if let Some(result) = self.task.take_result() {
                Poll::Ready(result)
            } else {
                Poll::Pending
            }
        }
    }
}

/// Spawns a detached future, preferring slab allocation before falling back to Arc.
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

enum FutureSlot<F: Future> {
    Running(F),
    Done(Option<F::Output>),
}

struct JoinAllShared {
    parent: Mutex<Option<Waker>>,
    ready_queue: SegQueue<usize>,
}

struct IndexedWakerData {
    shared: Arc<JoinAllShared>,
    index: usize,
}

unsafe fn indexed_waker_clone(ptr: *const ()) -> RawWaker {
    let data = &*(ptr as *const IndexedWakerData);
    let cloned = Box::new(IndexedWakerData {
        shared: data.shared.clone(),
        index: data.index,
    });
    RawWaker::new(Box::into_raw(cloned) as *const (), &INDEXED_WAKER_VTABLE)
}

unsafe fn indexed_waker_wake(ptr: *const ()) {
    let data = Box::from_raw(ptr as *mut IndexedWakerData);
    data.shared.ready_queue.push(data.index);
    let guard = data.shared.parent.lock();
    if let Some(w) = guard.as_ref() {
        w.wake_by_ref();
    }
    drop(guard);
}

unsafe fn indexed_waker_wake_by_ref(ptr: *const ()) {
    let data = &*(ptr as *const IndexedWakerData);
    data.shared.ready_queue.push(data.index);
    let guard = data.shared.parent.lock();
    if let Some(w) = guard.as_ref() {
        w.wake_by_ref();
    }
    drop(guard);
}

unsafe fn indexed_waker_drop(ptr: *const ()) {
    drop(Box::from_raw(ptr as *mut IndexedWakerData));
}

static INDEXED_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
    indexed_waker_clone,
    indexed_waker_wake,
    indexed_waker_wake_by_ref,
    indexed_waker_drop,
);

impl JoinAllShared {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            parent: Mutex::new(None),
            ready_queue: SegQueue::new(),
        })
    }

    fn update_parent(&self, waker: &Waker) {
        let mut guard = self.parent.lock();
        if guard.as_ref().map_or(true, |w| !w.will_wake(waker)) {
            *guard = Some(waker.clone());
        }
    }

    fn make_waker(self: &Arc<Self>, index: usize) -> Waker {
        let data = Box::new(IndexedWakerData {
            shared: self.clone(),
            index,
        });
        unsafe {
            Waker::from_raw(RawWaker::new(
                Box::into_raw(data) as *const (),
                &INDEXED_WAKER_VTABLE,
            ))
        }
    }
}

/// Joins multiple futures, storing them inline and using indexed wakers to avoid O(n^2) rescans.
pub struct JoinAll<F: Future> {
    slots: Vec<FutureSlot<F>>,
    remaining: usize,
    shared: Arc<JoinAllShared>,
    first_poll: bool,
}

impl<F: Future> JoinAll<F> {
    pub fn new(fs: Vec<F>) -> Self {
        let remaining = fs.len();
        let slots = fs.into_iter().map(FutureSlot::Running).collect();
        Self {
            slots,
            remaining,
            shared: JoinAllShared::new(),
            first_poll: true,
        }
    }
}

impl<F: Future> Future for JoinAll<F> {
    type Output = Vec<F::Output>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
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

        this.shared.update_parent(cx.waker());

        if this.first_poll {
            // First poll: must poll every child once to register their wakers.
            this.first_poll = false;
            for (i, slot) in this.slots.iter_mut().enumerate() {
                if let FutureSlot::Running(fut) = slot {
                    let waker = this.shared.make_waker(i);
                    let mut child_cx = Context::from_waker(&waker);
                    let pinned = unsafe { Pin::new_unchecked(fut) };
                    if let Poll::Ready(result) = pinned.poll(&mut child_cx) {
                        *slot = FutureSlot::Done(Some(result));
                        this.remaining -= 1;
                    }
                }
            }
        } else {
            // Subsequent polls: only re-poll children that were woken.
            while let Some(idx) = this.shared.ready_queue.pop() {
                if idx >= this.slots.len() {
                    continue;
                }
                let slot = &mut this.slots[idx];
                if let FutureSlot::Running(fut) = slot {
                    let waker = this.shared.make_waker(idx);
                    let mut child_cx = Context::from_waker(&waker);
                    let pinned = unsafe { Pin::new_unchecked(fut) };
                    if let Poll::Ready(result) = pinned.poll(&mut child_cx) {
                        *slot = FutureSlot::Done(Some(result));
                        this.remaining -= 1;
                    }
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
