use alloc::boxed::Box;
use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU8, Ordering};
use core::task::{Context, Poll, Waker};

use spin::Mutex;

use crate::scheduling::runtime::runtime::submit_global;
use crate::scheduling::runtime::waker;

/// Task state machine. Transitions:
///   IDLE -> QUEUED      (enqueue: task submitted to thread pool)
///   QUEUED -> POLLING    (poll_once: worker begins polling)
///   POLLING -> IDLE      (poll returned Pending, no wake during poll)
///   POLLING -> NOTIFIED  (wake() called while poll is in-flight)
///   POLLING -> COMPLETED (poll returned Ready)
///   NOTIFIED -> QUEUED   (poll finished Pending, re-enqueue because wake arrived)
///   NOTIFIED -> COMPLETED(poll returned Ready, wake is stale)
pub const STATE_IDLE: u8 = 0;
pub const STATE_QUEUED: u8 = 1;
pub const STATE_POLLING: u8 = 2;
pub const STATE_NOTIFIED: u8 = 3;
pub const STATE_COMPLETED: u8 = 4;

/// Trait for type-erased task polling. Allows the executor to poll tasks
/// without knowing the concrete future or output type.
pub trait TaskPoll: Send + Sync {
    fn poll_once(self: Arc<Self>);
    /// Called when already in POLLING state (from inline poll path).
    fn poll_once_inline(self: Arc<Self>);
    fn enqueue(self: &Arc<Self>);
    fn is_completed(&self) -> bool;
    /// Attempt to transition from IDLE to POLLING for inline poll.
    /// Returns true if the transition succeeded.
    fn try_start_inline_poll(&self) -> bool;
}

/// A detached task with no return value - used by spawn_detached().
pub struct FutureTask {
    future: Mutex<Option<Pin<Box<dyn Future<Output = ()> + Send + 'static>>>>,
    state: AtomicU8,
}

impl FutureTask {
    pub fn new(future: impl Future<Output = ()> + Send + 'static) -> Self {
        Self {
            future: Mutex::new(Some(Box::pin(future))),
            state: AtomicU8::new(STATE_IDLE),
        }
    }
}

impl TaskPoll for FutureTask {
    fn enqueue(self: &Arc<Self>) {
        // Try IDLE -> QUEUED. If the task is in any other state, the
        // notification is either already pending or will be picked up
        // when the current poll finishes (POLLING -> NOTIFIED).
        let prev = self.state.compare_exchange(
            STATE_IDLE,
            STATE_QUEUED,
            Ordering::AcqRel,
            Ordering::Acquire,
        );

        match prev {
            Ok(_) => {
                // Successfully IDLE -> QUEUED, submit to thread pool
                let ptr = Arc::into_raw(self.clone()) as usize;
                submit_global(poll_trampoline::<Self>, ptr);
            }
            Err(STATE_POLLING) => {
                // A thread is currently polling. Upgrade to NOTIFIED so it
                // re-enqueues after polling completes. Use compare_exchange
                // because another wake() might race us here too.
                let _ = self.state.compare_exchange(
                    STATE_POLLING,
                    STATE_NOTIFIED,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                );
                // If this CAS fails, the state is already NOTIFIED or
                // COMPLETED, both of which are fine.
            }
            Err(_) => {
                // QUEUED, NOTIFIED, or COMPLETED — nothing to do
            }
        }
    }

    fn poll_once(self: Arc<Self>) {
        // Transition QUEUED -> POLLING
        let prev = self.state.compare_exchange(
            STATE_QUEUED,
            STATE_POLLING,
            Ordering::AcqRel,
            Ordering::Acquire,
        );

        if prev.is_err() {
            // Task was completed or state changed unexpectedly; bail out.
            return;
        }

        let w = waker::create_from_task_poll(self.clone());
        let mut cx = Context::from_waker(&w);

        let poll_res = {
            let mut guard = self.future.lock();
            let Some(fut) = guard.as_mut() else {
                self.state.store(STATE_COMPLETED, Ordering::Release);
                return;
            };
            fut.as_mut().poll(&mut cx)
        };

        if let Poll::Ready(()) = poll_res {
            let mut guard = self.future.lock();
            *guard = None;
            self.state.store(STATE_COMPLETED, Ordering::Release);
            return;
        }

        // Poll returned Pending. Transition POLLING -> IDLE, unless
        // a wake() upgraded us to NOTIFIED.
        let prev = self.state.compare_exchange(
            STATE_POLLING,
            STATE_IDLE,
            Ordering::AcqRel,
            Ordering::Acquire,
        );

        if let Err(STATE_NOTIFIED) = prev {
            // Wake was called during poll — re-enqueue immediately.
            // Transition NOTIFIED -> QUEUED and submit.
            self.state.store(STATE_QUEUED, Ordering::Release);
            let ptr = Arc::into_raw(self.clone()) as usize;
            submit_global(poll_trampoline::<Self>, ptr);
        }
    }

    fn poll_once_inline(self: Arc<Self>) {
        // Already in POLLING state (caller did IDLE -> POLLING).
        let w = waker::create_from_task_poll(self.clone());
        let mut cx = Context::from_waker(&w);

        let poll_res = {
            let mut guard = self.future.lock();
            let Some(fut) = guard.as_mut() else {
                self.state.store(STATE_COMPLETED, Ordering::Release);
                return;
            };
            fut.as_mut().poll(&mut cx)
        };

        if let Poll::Ready(()) = poll_res {
            let mut guard = self.future.lock();
            *guard = None;
            self.state.store(STATE_COMPLETED, Ordering::Release);
            return;
        }

        let prev = self.state.compare_exchange(
            STATE_POLLING,
            STATE_IDLE,
            Ordering::AcqRel,
            Ordering::Acquire,
        );

        if let Err(STATE_NOTIFIED) = prev {
            self.state.store(STATE_QUEUED, Ordering::Release);
            let ptr = Arc::into_raw(self.clone()) as usize;
            submit_global(poll_trampoline::<Self>, ptr);
        }
    }

    fn is_completed(&self) -> bool {
        self.state.load(Ordering::Acquire) == STATE_COMPLETED
    }

    fn try_start_inline_poll(&self) -> bool {
        self.state
            .compare_exchange(STATE_IDLE, STATE_POLLING, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
}

/// A joinable task that stores the result for the JoinHandle to retrieve.
/// This combines FutureTask + JoinInner into a single Arc allocation.
pub struct JoinableTask<T: Send + 'static> {
    future: Mutex<Option<Pin<Box<dyn Future<Output = T> + Send + 'static>>>>,
    result: Mutex<Option<T>>,
    waker: Mutex<Option<Waker>>,
    state: AtomicU8,
}

impl<T: Send + 'static> JoinableTask<T> {
    pub fn new(future: impl Future<Output = T> + Send + 'static) -> Self {
        Self {
            future: Mutex::new(Some(Box::pin(future))),
            result: Mutex::new(None),
            waker: Mutex::new(None),
            state: AtomicU8::new(STATE_IDLE),
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
        let prev = self.state.compare_exchange(
            STATE_IDLE,
            STATE_QUEUED,
            Ordering::AcqRel,
            Ordering::Acquire,
        );

        match prev {
            Ok(_) => {
                let ptr = Arc::into_raw(self.clone()) as usize;
                submit_global(poll_trampoline::<Self>, ptr);
            }
            Err(STATE_POLLING) => {
                let _ = self.state.compare_exchange(
                    STATE_POLLING,
                    STATE_NOTIFIED,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                );
            }
            Err(_) => {}
        }
    }

    fn poll_once(self: Arc<Self>) {
        let prev = self.state.compare_exchange(
            STATE_QUEUED,
            STATE_POLLING,
            Ordering::AcqRel,
            Ordering::Acquire,
        );

        if prev.is_err() {
            return;
        }

        let w = waker::create_from_task_poll(self.clone());
        let mut cx = Context::from_waker(&w);

        let poll_res = {
            let mut guard = self.future.lock();
            let Some(fut) = guard.as_mut() else {
                self.state.store(STATE_COMPLETED, Ordering::Release);
                return;
            };
            fut.as_mut().poll(&mut cx)
        };

        if let Poll::Ready(result) = poll_res {
            {
                let mut guard = self.future.lock();
                *guard = None;
            }
            {
                let mut guard = self.result.lock();
                *guard = Some(result);
            }
            self.state.store(STATE_COMPLETED, Ordering::Release);

            // Wake the JoinHandle if it's waiting
            if let Some(w) = self.waker.lock().take() {
                w.wake();
            }
            return;
        }

        // Pending — transition POLLING -> IDLE, or handle NOTIFIED
        let prev = self.state.compare_exchange(
            STATE_POLLING,
            STATE_IDLE,
            Ordering::AcqRel,
            Ordering::Acquire,
        );

        if let Err(STATE_NOTIFIED) = prev {
            self.state.store(STATE_QUEUED, Ordering::Release);
            let ptr = Arc::into_raw(self.clone()) as usize;
            submit_global(poll_trampoline::<Self>, ptr);
        }
    }

    fn poll_once_inline(self: Arc<Self>) {
        let w = waker::create_from_task_poll(self.clone());
        let mut cx = Context::from_waker(&w);

        let poll_res = {
            let mut guard = self.future.lock();
            let Some(fut) = guard.as_mut() else {
                self.state.store(STATE_COMPLETED, Ordering::Release);
                return;
            };
            fut.as_mut().poll(&mut cx)
        };

        if let Poll::Ready(result) = poll_res {
            {
                let mut guard = self.future.lock();
                *guard = None;
            }
            {
                let mut guard = self.result.lock();
                *guard = Some(result);
            }
            self.state.store(STATE_COMPLETED, Ordering::Release);

            if let Some(w) = self.waker.lock().take() {
                w.wake();
            }
            return;
        }

        let prev = self.state.compare_exchange(
            STATE_POLLING,
            STATE_IDLE,
            Ordering::AcqRel,
            Ordering::Acquire,
        );

        if let Err(STATE_NOTIFIED) = prev {
            self.state.store(STATE_QUEUED, Ordering::Release);
            let ptr = Arc::into_raw(self.clone()) as usize;
            submit_global(poll_trampoline::<Self>, ptr);
        }
    }

    fn is_completed(&self) -> bool {
        self.state.load(Ordering::Acquire) == STATE_COMPLETED
    }

    fn try_start_inline_poll(&self) -> bool {
        self.state
            .compare_exchange(STATE_IDLE, STATE_POLLING, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
}

#[inline(never)]
pub extern "win64" fn poll_trampoline<T: TaskPoll>(ctx: usize) {
    let task = unsafe { Arc::from_raw(ctx as *const T) };
    task.poll_once();
}
