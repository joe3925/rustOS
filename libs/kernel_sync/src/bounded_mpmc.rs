use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::bounded_wait_queue::{BoundedWaitQueue, BoundedWaitQueueEnqueue, BoundedWaitQueueError};
use crate::mpmc::{RecvError, TryRecvError};
use crate::platform::{ParkReason, Platform};
use kernel_types::bounded_mpmc::{BoundedMpmcPushError, BoundedMpmcQueue};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundedSendError<T> {
    Full(T),
    Disconnected(T),
}

struct BoundedMpmcInner<P: Platform, T> {
    queue: BoundedMpmcQueue<T>,
    receivers_waiting: BoundedWaitQueue<P>,
    sender_count: AtomicUsize,
    receiver_count: AtomicUsize,
    closed: AtomicBool,
}

pub struct BoundedSender<P: Platform, T> {
    inner: Arc<BoundedMpmcInner<P, T>>,
}

pub struct BoundedReceiver<P: Platform, T> {
    inner: Arc<BoundedMpmcInner<P, T>>,
}

pub fn bounded_mpmc_channel<P: Platform, T>(
    capacity: usize,
    max_consumers: usize,
) -> (BoundedSender<P, T>, BoundedReceiver<P, T>) {
    assert!(capacity > 0);
    assert!(max_consumers > 0);

    let inner = Arc::new(BoundedMpmcInner {
        queue: BoundedMpmcQueue::new(capacity),
        receivers_waiting: BoundedWaitQueue::new(max_consumers),
        sender_count: AtomicUsize::new(1),
        receiver_count: AtomicUsize::new(1),
        closed: AtomicBool::new(false),
    });

    let sender = BoundedSender {
        inner: inner.clone(),
    };

    let receiver = BoundedReceiver { inner };

    (sender, receiver)
}

impl<P: Platform, T> BoundedSender<P, T> {
    pub fn try_send(&self, value: T) -> Result<(), BoundedSendError<T>> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(BoundedSendError::Disconnected(value));
        }

        match self.inner.queue.try_push(value) {
            Ok(()) => {
                self.inner.receivers_waiting.wake_one();
                Ok(())
            }
            Err(BoundedMpmcPushError::Full(value)) => {
                if self.inner.closed.load(Ordering::Acquire) {
                    Err(BoundedSendError::Disconnected(value))
                } else {
                    Err(BoundedSendError::Full(value))
                }
            }
            _ => unreachable!(),
        }
    }

    pub fn is_disconnected(&self) -> bool {
        self.inner.closed.load(Ordering::Acquire)
    }

    pub fn len(&self) -> usize {
        self.inner.queue.len()
    }

    pub fn capacity(&self) -> usize {
        self.inner.queue.capacity()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.queue.is_empty()
    }

    pub fn is_full(&self) -> bool {
        self.inner.queue.is_full()
    }
}

impl<P: Platform, T> Clone for BoundedSender<P, T> {
    fn clone(&self) -> Self {
        self.inner.sender_count.fetch_add(1, Ordering::AcqRel);

        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<P: Platform, T> Drop for BoundedSender<P, T> {
    fn drop(&mut self) {
        let prev = self.inner.sender_count.fetch_sub(1, Ordering::AcqRel);

        if prev == 1 {
            self.inner.receivers_waiting.wake_all();
        }
    }
}

impl<P: Platform, T> BoundedReceiver<P, T> {
    pub fn recv(&self) -> Result<T, RecvError> {
        loop {
            if let Some(value) = self.inner.queue.try_pop() {
                return Ok(value);
            }

            if self.inner.sender_count.load(Ordering::Acquire) == 0 {
                if let Some(value) = self.inner.queue.try_pop() {
                    return Ok(value);
                }

                return Err(RecvError);
            }

            match self.inner.receivers_waiting.enqueue_current() {
                Ok(BoundedWaitQueueEnqueue::Queued) => {}
                Ok(BoundedWaitQueueEnqueue::Woken) => continue,
                Err(BoundedWaitQueueError::AlreadyQueued) => {
                    if self.inner.receivers_waiting.is_current_enqueued() {
                        P::park_current(ParkReason::ChannelRecv);
                        self.inner.receivers_waiting.clear_current_if_queued();
                    }

                    continue;
                }
                Err(BoundedWaitQueueError::NoCurrentTask) => continue,
                Err(BoundedWaitQueueError::Full) => {
                    if let Some(value) = self.inner.queue.try_pop() {
                        return Ok(value);
                    }

                    if self.inner.sender_count.load(Ordering::Acquire) == 0 {
                        if let Some(value) = self.inner.queue.try_pop() {
                            return Ok(value);
                        }

                        return Err(RecvError);
                    }

                    P::spin_loop();
                    continue;
                }
            }

            if let Some(value) = self.inner.queue.try_pop() {
                self.inner.receivers_waiting.clear_current_if_queued();
                return Ok(value);
            }

            if self.inner.sender_count.load(Ordering::Acquire) == 0 {
                self.inner.receivers_waiting.clear_current_if_queued();

                if let Some(value) = self.inner.queue.try_pop() {
                    return Ok(value);
                }

                return Err(RecvError);
            }

            if !self.inner.receivers_waiting.is_current_enqueued() {
                continue;
            }

            P::park_current(ParkReason::ChannelRecv);
            self.inner.receivers_waiting.clear_current_if_queued();
        }
    }

    pub fn try_recv(&self) -> Result<T, TryRecvError> {
        if let Some(value) = self.inner.queue.try_pop() {
            Ok(value)
        } else if self.inner.sender_count.load(Ordering::Acquire) == 0 {
            if let Some(value) = self.inner.queue.try_pop() {
                Ok(value)
            } else {
                Err(TryRecvError::Disconnected)
            }
        } else {
            Err(TryRecvError::Empty)
        }
    }

    pub fn is_disconnected(&self) -> bool {
        self.inner.sender_count.load(Ordering::Acquire) == 0
    }

    pub fn len(&self) -> usize {
        self.inner.queue.len()
    }

    pub fn capacity(&self) -> usize {
        self.inner.queue.capacity()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.queue.is_empty()
    }

    pub fn is_full(&self) -> bool {
        self.inner.queue.is_full()
    }
}

impl<P: Platform, T> Clone for BoundedReceiver<P, T> {
    fn clone(&self) -> Self {
        self.inner.receiver_count.fetch_add(1, Ordering::AcqRel);

        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<P: Platform, T> Drop for BoundedReceiver<P, T> {
    fn drop(&mut self) {
        let prev = self.inner.receiver_count.fetch_sub(1, Ordering::AcqRel);

        if prev == 1 {
            self.inner.closed.store(true, Ordering::Release);
        }
    }
}

unsafe impl<P: Platform, T: Send> Send for BoundedSender<P, T> {}
unsafe impl<P: Platform, T: Send> Sync for BoundedSender<P, T> {}
unsafe impl<P: Platform, T: Send> Send for BoundedReceiver<P, T> {}
unsafe impl<P: Platform, T: Send> Sync for BoundedReceiver<P, T> {}
