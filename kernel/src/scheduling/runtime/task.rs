use alloc::boxed::Box;
use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll, Waker};

use spin::Mutex;

use crate::scheduling::runtime::runtime::submit_global;
use crate::scheduling::runtime::waker;

/// Trait for type-erased task polling. Allows the executor to poll tasks
/// without knowing the concrete future or output type.
pub trait TaskPoll: Send + Sync {
    fn poll_once(self: Arc<Self>);
    fn enqueue(self: &Arc<Self>);
    fn is_completed(&self) -> bool;
    fn is_queued(&self) -> bool;
    fn set_queued(&self, val: bool);
}

/// A detached task with no return value - used by spawn_detached().
pub struct FutureTask {
    future: Mutex<Option<Pin<Box<dyn Future<Output = ()> + Send + 'static>>>>,
    queued: AtomicBool,
    completed: AtomicBool,
}

impl FutureTask {
    pub fn new(future: impl Future<Output = ()> + Send + 'static) -> Self {
        Self {
            future: Mutex::new(Some(Box::pin(future))),
            queued: AtomicBool::new(false),
            completed: AtomicBool::new(false),
        }
    }
}

impl TaskPoll for FutureTask {
    fn enqueue(self: &Arc<Self>) {
        if self.completed.load(Ordering::Acquire) {
            return;
        }

        if self.queued.swap(true, Ordering::AcqRel) {
            return;
        }

        let ptr = Arc::into_raw(self.clone()) as usize;
        submit_global(poll_trampoline::<Self>, ptr);
    }

    fn poll_once(self: Arc<Self>) {
        self.queued.store(false, Ordering::Release);

        if self.completed.load(Ordering::Acquire) {
            return;
        }

        let w = waker::create_from_task_poll(self.clone());
        let mut cx = Context::from_waker(&w);

        let poll_res = {
            let mut guard = self.future.lock();
            let Some(fut) = guard.as_mut() else {
                self.completed.store(true, Ordering::Release);
                return;
            };
            fut.as_mut().poll(&mut cx)
        };

        if let Poll::Ready(()) = poll_res {
            let mut guard = self.future.lock();
            *guard = None;
            self.completed.store(true, Ordering::Release);
        }
    }

    fn is_completed(&self) -> bool {
        self.completed.load(Ordering::Acquire)
    }

    fn is_queued(&self) -> bool {
        self.queued.load(Ordering::Acquire)
    }

    fn set_queued(&self, val: bool) {
        self.queued.store(val, Ordering::Release);
    }
}

/// A joinable task that stores the result for the JoinHandle to retrieve.
/// This combines FutureTask + JoinInner into a single Arc allocation.
pub struct JoinableTask<T: Send + 'static> {
    future: Mutex<Option<Pin<Box<dyn Future<Output = T> + Send + 'static>>>>,
    result: Mutex<Option<T>>,
    waker: Mutex<Option<Waker>>,
    queued: AtomicBool,
    completed: AtomicBool,
}

impl<T: Send + 'static> JoinableTask<T> {
    pub fn new(future: impl Future<Output = T> + Send + 'static) -> Self {
        Self {
            future: Mutex::new(Some(Box::pin(future))),
            result: Mutex::new(None),
            waker: Mutex::new(None),
            queued: AtomicBool::new(false),
            completed: AtomicBool::new(false),
        }
    }

    /// Take the result if available. Called by JoinHandle::poll.
    pub fn take_result(&self) -> Option<T> {
        self.result.lock().take()
    }

    /// Store a waker to be notified when the task completes.
    pub fn set_waker(&self, waker: Waker) {
        *self.waker.lock() = Some(waker);
    }
}

impl<T: Send + 'static> TaskPoll for JoinableTask<T> {
    fn enqueue(self: &Arc<Self>) {
        if self.completed.load(Ordering::Acquire) {
            return;
        }

        if self.queued.swap(true, Ordering::AcqRel) {
            return;
        }

        let ptr = Arc::into_raw(self.clone()) as usize;
        submit_global(poll_trampoline::<Self>, ptr);
    }

    fn poll_once(self: Arc<Self>) {
        self.queued.store(false, Ordering::Release);

        if self.completed.load(Ordering::Acquire) {
            return;
        }

        let w = waker::create_from_task_poll(self.clone());
        let mut cx = Context::from_waker(&w);

        let poll_res = {
            let mut guard = self.future.lock();
            let Some(fut) = guard.as_mut() else {
                self.completed.store(true, Ordering::Release);
                return;
            };
            fut.as_mut().poll(&mut cx)
        };

        if let Poll::Ready(result) = poll_res {
            // Store result and clean up future
            {
                let mut guard = self.future.lock();
                *guard = None;
            }
            {
                let mut guard = self.result.lock();
                *guard = Some(result);
            }
            self.completed.store(true, Ordering::Release);

            // Wake the JoinHandle if it's waiting
            if let Some(w) = self.waker.lock().take() {
                w.wake();
            }
        }
    }

    fn is_completed(&self) -> bool {
        self.completed.load(Ordering::Acquire)
    }

    fn is_queued(&self) -> bool {
        self.queued.load(Ordering::Acquire)
    }

    fn set_queued(&self, val: bool) {
        self.queued.store(val, Ordering::Release);
    }
}

#[inline(never)]
pub extern "win64" fn poll_trampoline<T: TaskPoll>(ctx: usize) {
    let task = unsafe { Arc::from_raw(ctx as *const T) };
    task.poll_once();
}
