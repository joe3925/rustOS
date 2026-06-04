use alloc::boxed::Box;
use core::cell::UnsafeCell;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};

use crate::sync::atomic::{AtomicU8, Ordering};
use crate::sync::{Arc, Mutex};

use crate::global_async::{DomainId, KERNEL_NORMAL_DOMAIN};

use super::runtime::submit_global_to_domain;
use super::waker;

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

#[inline]
fn transition_enqueue(state: &AtomicU8) -> bool {
    // Retry loop to handle the race between POLLING+IDLE and our
    // POLLING+NOTIFIED attempt. Without the loop, observing POLLING
    // then racing with the poll_once POLLING+IDLE transition causes
    // the NOTIFIED CAS to fail with IDLE, silently dropping the wake.
    loop {
        match state.compare_exchange_weak(
            STATE_IDLE,
            STATE_QUEUED,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(STATE_POLLING) => {
                match state.compare_exchange(
                    STATE_POLLING,
                    STATE_NOTIFIED,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => return false,
                    Err(STATE_IDLE) => continue,
                    Err(_) => return false,
                }
            }
            Err(_) => return false,
        }
    }
}

#[inline]
fn transition_pending_poll_complete(state: &AtomicU8) -> bool {
    let prev = state.compare_exchange(
        STATE_POLLING,
        STATE_IDLE,
        Ordering::AcqRel,
        Ordering::Acquire,
    );

    if let Err(STATE_NOTIFIED) = prev {
        state.store(STATE_QUEUED, Ordering::Release);
        return true;
    }

    false
}

pub trait TaskPoll: Send + Sync {
    fn poll_once(self: Arc<Self>);
    fn poll_once_inline(self: Arc<Self>);
    fn enqueue(self: &Arc<Self>);
    fn is_completed(&self) -> bool;
    fn try_start_inline_poll(&self) -> bool;
}

pub struct FutureTask {
    /// Safety: exclusive access is guaranteed by the task state machine —
    /// only the thread in POLLING state touches this field.
    future: UnsafeCell<Option<Pin<Box<dyn Future<Output = ()> + Send + 'static>>>>,
    state: AtomicU8,
    domain_id: DomainId,
}

// Safety: The future is Send, and exclusive access is enforced by the state machine.
unsafe impl Send for FutureTask {}
unsafe impl Sync for FutureTask {}

impl FutureTask {
    pub fn new(future: impl Future<Output = ()> + Send + 'static) -> Self {
        Self::new_in_domain(KERNEL_NORMAL_DOMAIN, future)
    }

    pub fn new_in_domain(
        domain_id: DomainId,
        future: impl Future<Output = ()> + Send + 'static,
    ) -> Self {
        Self {
            future: UnsafeCell::new(Some(Box::pin(future))),
            state: AtomicU8::new(STATE_IDLE),
            domain_id,
        }
    }
}

impl TaskPoll for FutureTask {
    fn enqueue(self: &Arc<Self>) {
        if transition_enqueue(&self.state) {
            let ptr = Arc::into_raw(self.clone()) as usize;
            submit_global_to_domain(self.domain_id, poll_trampoline::<Self>, ptr);
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

        // Safety: state machine guarantees exclusive access — only one thread
        // can CAS QUEUED→POLLING, so no concurrent access to the future.
        let future_ref = unsafe { &mut *self.future.get() };

        let poll_res = {
            let Some(fut) = future_ref.as_mut() else {
                self.state.store(STATE_COMPLETED, Ordering::Release);
                return;
            };
            fut.as_mut().poll(&mut cx)
        };

        if let Poll::Ready(()) = poll_res {
            // Safety: still in POLLING state, exclusive access.
            unsafe { *self.future.get() = None };
            self.state.store(STATE_COMPLETED, Ordering::Release);
            return;
        }

        // Poll returned Pending. If a wake arrived while polling, re-enqueue.
        if transition_pending_poll_complete(&self.state) {
            let ptr = Arc::into_raw(self.clone()) as usize;
            submit_global_to_domain(self.domain_id, poll_trampoline::<Self>, ptr);
        }
    }

    fn poll_once_inline(self: Arc<Self>) {
        // Already in POLLING state (caller did IDLE -> POLLING).
        let w = waker::create_from_task_poll(self.clone());
        let mut cx = Context::from_waker(&w);

        // Safety: caller transitioned IDLE→POLLING, exclusive access guaranteed.
        let future_ref = unsafe { &mut *self.future.get() };

        let poll_res = {
            let Some(fut) = future_ref.as_mut() else {
                self.state.store(STATE_COMPLETED, Ordering::Release);
                return;
            };
            fut.as_mut().poll(&mut cx)
        };

        if let Poll::Ready(()) = poll_res {
            unsafe { *self.future.get() = None };
            self.state.store(STATE_COMPLETED, Ordering::Release);
            return;
        }

        if transition_pending_poll_complete(&self.state) {
            let ptr = Arc::into_raw(self.clone()) as usize;
            submit_global_to_domain(self.domain_id, poll_trampoline::<Self>, ptr);
        }
    }

    fn is_completed(&self) -> bool {
        self.state.load(Ordering::Acquire) == STATE_COMPLETED
    }

    fn try_start_inline_poll(&self) -> bool {
        self.state
            .compare_exchange(
                STATE_IDLE,
                STATE_POLLING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }
}

pub struct JoinableTask<T: Send + 'static> {
    /// Safety: exclusive access is guaranteed by the task state machine —
    /// only the thread in POLLING state touches this field.
    future: UnsafeCell<Option<Pin<Box<dyn Future<Output = T> + Send + 'static>>>>,
    result: Mutex<Option<T>>,
    waker: Mutex<Option<Waker>>,
    state: AtomicU8,
    domain_id: DomainId,
}

// Safety: The future is Send, and exclusive access is enforced by the state machine.
// result and waker are protected by Mutex.
unsafe impl<T: Send + 'static> Send for JoinableTask<T> {}
unsafe impl<T: Send + 'static> Sync for JoinableTask<T> {}

impl<T: Send + 'static> JoinableTask<T> {
    pub fn new(future: impl Future<Output = T> + Send + 'static) -> Self {
        Self::new_in_domain(KERNEL_NORMAL_DOMAIN, future)
    }

    pub fn new_in_domain(
        domain_id: DomainId,
        future: impl Future<Output = T> + Send + 'static,
    ) -> Self {
        Self {
            future: UnsafeCell::new(Some(Box::pin(future))),
            result: Mutex::new(None),
            waker: Mutex::new(None),
            state: AtomicU8::new(STATE_IDLE),
            domain_id,
        }
    }

    pub fn take_result(&self) -> Option<T> {
        self.result.lock().take()
    }

    pub fn set_waker(&self, waker: Waker) {
        *self.waker.lock() = Some(waker);
    }

    pub fn update_waker(&self, waker: &Waker) {
        let mut guard = self.waker.lock();
        if guard.as_ref().is_none_or(|w| !w.will_wake(waker)) {
            *guard = Some(waker.clone());
        }
    }
}

impl<T: Send + 'static> TaskPoll for JoinableTask<T> {
    fn enqueue(self: &Arc<Self>) {
        if transition_enqueue(&self.state) {
            let ptr = Arc::into_raw(self.clone()) as usize;
            submit_global_to_domain(self.domain_id, poll_trampoline::<Self>, ptr);
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

        // Safety: state machine guarantees exclusive access — only one thread
        // can CAS QUEUED→POLLING, so no concurrent access to the future.
        let future_ref = unsafe { &mut *self.future.get() };

        let poll_res = {
            let Some(fut) = future_ref.as_mut() else {
                self.state.store(STATE_COMPLETED, Ordering::Release);
                return;
            };
            fut.as_mut().poll(&mut cx)
        };

        if let Poll::Ready(result) = poll_res {
            // Safety: still in POLLING state, exclusive access.
            unsafe { *self.future.get() = None };
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

        // Pending. If a wake arrived while polling, re-enqueue.
        if transition_pending_poll_complete(&self.state) {
            let ptr = Arc::into_raw(self.clone()) as usize;
            submit_global_to_domain(self.domain_id, poll_trampoline::<Self>, ptr);
        }
    }

    fn poll_once_inline(self: Arc<Self>) {
        let w = waker::create_from_task_poll(self.clone());
        let mut cx = Context::from_waker(&w);

        // Safety: caller transitioned IDLE→POLLING, exclusive access guaranteed.
        let future_ref = unsafe { &mut *self.future.get() };

        let poll_res = {
            let Some(fut) = future_ref.as_mut() else {
                self.state.store(STATE_COMPLETED, Ordering::Release);
                return;
            };
            fut.as_mut().poll(&mut cx)
        };

        if let Poll::Ready(result) = poll_res {
            unsafe { *self.future.get() = None };
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

        if transition_pending_poll_complete(&self.state) {
            let ptr = Arc::into_raw(self.clone()) as usize;
            submit_global_to_domain(self.domain_id, poll_trampoline::<Self>, ptr);
        }
    }

    fn is_completed(&self) -> bool {
        self.state.load(Ordering::Acquire) == STATE_COMPLETED
    }

    fn try_start_inline_poll(&self) -> bool {
        self.state
            .compare_exchange(
                STATE_IDLE,
                STATE_POLLING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }
}

#[inline(never)]
pub extern "win64" fn poll_trampoline<T: TaskPoll>(ctx: usize) {
    let task = unsafe { Arc::from_raw(ctx as *const T) };
    task.poll_once();
}

#[cfg(all(test, any(loom, feature = "loom")))]
mod loom_tests {
    use super::*;
    use crate::sync::atomic::{AtomicU8, Ordering};
    use crate::sync::{exhaustive_model, Arc};

    // Models the wake-vs-pending-poll race used by both FutureTask and
    // JoinableTask. No interleaving may leave the task IDLE after a wake raced
    // with the poll completion path; it must end up QUEUED for another poll.
    #[test]
    fn loom_arc_task_enqueue_pending_poll_race_requeues() {
        exhaustive_model(|| {
            let state = Arc::new(AtomicU8::new(STATE_POLLING));

            let poller_state = state.clone();
            let poller = loom::thread::spawn(move || {
                transition_pending_poll_complete(&poller_state);
            });

            let enqueue_state = state.clone();
            let enqueue = loom::thread::spawn(move || {
                transition_enqueue(&enqueue_state);
            });

            poller.join().expect("poller thread panicked");
            enqueue.join().expect("enqueue thread panicked");

            assert_eq!(state.load(Ordering::Acquire), STATE_QUEUED);
        });
    }
}
