use core::task::{Context, Poll};

#[cfg(not(any(loom, feature = "loom")))]
use alloc::sync::Arc;
use crossbeam_queue::SegQueue;
#[cfg(not(any(loom, feature = "loom")))]
use futures_core::task::__internal::AtomicWaker;
#[cfg(any(loom, feature = "loom"))]
use loom::{future::AtomicWaker, sync::Arc};

use crate::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const CLOSED: usize = 1usize << (usize::BITS - 1);
const PRODUCER_MASK: usize = !CLOSED;

#[inline]
fn wait_for_producer() {
    #[cfg(any(loom, feature = "loom"))]
    loom::thread::yield_now();
    #[cfg(not(any(loom, feature = "loom")))]
    core::hint::spin_loop();
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsyncRecvError {
    Empty,
    Closed,
}

struct Waiter {
    waker: AtomicWaker,
    armed: AtomicBool,
}

impl Waiter {
    #[cfg(not(any(loom, feature = "loom")))]
    fn register(&self, waker: &core::task::Waker) {
        self.waker.register(waker);
    }

    #[cfg(any(loom, feature = "loom"))]
    fn register(&self, waker: &core::task::Waker) {
        self.waker.register(waker.clone());
    }
}

/// A reusable registration owned by one receive future.
///
/// Keeping the registration separate from the queue prevents repeated polls
/// from allocating duplicate waiter entries. A queued registration may outlive
/// a cancelled future until the next notification, but its `Arc` keeps that
/// storage valid and its disarmed state prevents a stale wake.
pub struct WaitRegistration {
    inner: Arc<Waiter>,
}

impl WaitRegistration {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Waiter {
                waker: AtomicWaker::new(),
                armed: AtomicBool::new(false),
            }),
        }
    }

    pub fn disarm(&self) {
        self.inner.armed.store(false, Ordering::Release);
    }
}

impl Default for WaitRegistration {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for WaitRegistration {
    fn drop(&mut self) {
        self.disarm();
    }
}

pub struct AsyncMpmcQueue<T> {
    queue: SegQueue<T>,
    waiters: SegQueue<Arc<Waiter>>,
    state: AtomicUsize,
}

impl<T> AsyncMpmcQueue<T> {
    pub fn new() -> Self {
        Self {
            queue: SegQueue::new(),
            waiters: SegQueue::new(),
            state: AtomicUsize::new(0),
        }
    }

    fn reserve_producer(&self) -> bool {
        let mut state = self.state.load(Ordering::Acquire);
        loop {
            if state & CLOSED != 0 {
                return false;
            }
            assert!(
                state & PRODUCER_MASK != PRODUCER_MASK,
                "too many active producers"
            );
            match self.state.compare_exchange_weak(
                state,
                state + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(next) => state = next,
            }
        }
    }

    pub fn push(&self, value: T) -> Result<(), T> {
        if !self.reserve_producer() {
            return Err(value);
        }

        self.queue.push(value);
        self.state.fetch_sub(1, Ordering::Release);
        self.wake_waiters();
        Ok(())
    }

    pub fn try_pop(&self) -> Result<T, AsyncRecvError> {
        if let Some(value) = self.queue.pop() {
            return Ok(value);
        }
        if self.is_closed() {
            Err(AsyncRecvError::Closed)
        } else {
            Err(AsyncRecvError::Empty)
        }
    }

    pub fn poll_pop(
        &self,
        registration: &WaitRegistration,
        cx: &mut Context<'_>,
    ) -> Poll<Result<T, AsyncRecvError>> {
        if let Ok(value) = self.try_pop() {
            registration.disarm();
            return Poll::Ready(Ok(value));
        }
        if self.is_closed() {
            registration.disarm();
            return Poll::Ready(Err(AsyncRecvError::Closed));
        }

        registration.inner.register(cx.waker());
        if !registration.inner.armed.swap(true, Ordering::AcqRel) {
            self.waiters.push(registration.inner.clone());
        }

        // Registration must precede this second observation. An enqueue racing
        // before registration is found here; one racing after it wakes us.
        match self.try_pop() {
            Ok(value) => {
                registration.disarm();
                Poll::Ready(Ok(value))
            }
            Err(AsyncRecvError::Closed) => {
                registration.disarm();
                Poll::Ready(Err(AsyncRecvError::Closed))
            }
            Err(AsyncRecvError::Empty) => Poll::Pending,
        }
    }

    fn wake_waiters(&self) {
        while let Some(waiter) = self.waiters.pop() {
            if waiter.armed.swap(false, Ordering::AcqRel) {
                waiter.waker.wake();
            }
        }
    }

    pub fn shutdown(&self) {
        self.state.fetch_or(CLOSED, Ordering::AcqRel);
        while self.state.load(Ordering::Acquire) & PRODUCER_MASK != 0 {
            wait_for_producer();
        }
        while self.queue.pop().is_some() {}
        self.wake_waiters();
    }

    pub fn is_closed(&self) -> bool {
        self.state.load(Ordering::Acquire) & CLOSED != 0
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

impl<T> Default for AsyncMpmcQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Drop for AsyncMpmcQueue<T> {
    fn drop(&mut self) {
        while self.queue.pop().is_some() {}
        while self.waiters.pop().is_some() {}
    }
}

#[cfg(all(test, feature = "std", not(any(loom, feature = "loom"))))]
mod tests {
    use super::{AsyncMpmcQueue, AsyncRecvError, WaitRegistration};
    use alloc::sync::Arc;
    use alloc::task::Wake;
    use core::task::{Context, Waker};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Counter(AtomicUsize);

    impl Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn fifo_and_shutdown() {
        let queue = AsyncMpmcQueue::new();
        queue.push(1).unwrap();
        queue.push(2).unwrap();
        assert_eq!(queue.try_pop(), Ok(1));
        assert_eq!(queue.try_pop(), Ok(2));
        assert_eq!(queue.try_pop(), Err(AsyncRecvError::Empty));
        queue.shutdown();
        assert_eq!(queue.try_pop(), Err(AsyncRecvError::Closed));
        assert_eq!(queue.push(3), Err(3));
    }

    #[test]
    fn enqueue_wakes_every_armed_receiver() {
        let queue = AsyncMpmcQueue::<usize>::new();
        let first = WaitRegistration::new();
        let second = WaitRegistration::new();
        let first_count = Arc::new(Counter(AtomicUsize::new(0)));
        let second_count = Arc::new(Counter(AtomicUsize::new(0)));
        let first_waker = Waker::from(first_count.clone());
        let second_waker = Waker::from(second_count.clone());

        assert!(queue
            .poll_pop(&first, &mut Context::from_waker(&first_waker))
            .is_pending());
        assert!(queue
            .poll_pop(&second, &mut Context::from_waker(&second_waker))
            .is_pending());
        queue.push(7).unwrap();

        assert_eq!(first_count.0.load(Ordering::Relaxed), 1);
        assert_eq!(second_count.0.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn repeated_poll_does_not_duplicate_registration() {
        let queue = AsyncMpmcQueue::<usize>::new();
        let registration = WaitRegistration::new();
        let count = Arc::new(Counter(AtomicUsize::new(0)));
        let waker = Waker::from(count.clone());
        let mut cx = Context::from_waker(&waker);

        assert!(queue.poll_pop(&registration, &mut cx).is_pending());
        assert!(queue.poll_pop(&registration, &mut cx).is_pending());
        queue.push(1).unwrap();
        assert_eq!(count.0.load(Ordering::Relaxed), 1);
    }
}
