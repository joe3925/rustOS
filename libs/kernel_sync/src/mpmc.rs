use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use crossbeam_queue::SegQueue;

use crate::platform::Platform;
use crate::wait_queue::WaitQueue;
use kernel_types::io::TreiberStack;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendError<T>(pub T);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecvError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TryRecvError {
    Empty,
    Disconnected,
}

struct MpmcInner<P: Platform, T> {
    inbox: TreiberStack<T>,
    queue: SegQueue<T>,
    draining: AtomicBool,
    receivers_waiting: WaitQueue<P>,
    sender_count: AtomicUsize,
    receiver_count: AtomicUsize,
    closed: AtomicBool,
}

pub struct Sender<P: Platform, T> {
    inner: Arc<MpmcInner<P, T>>,
}

pub struct Receiver<P: Platform, T> {
    inner: Arc<MpmcInner<P, T>>,
}

pub fn mpmc_channel<P: Platform, T>() -> (Sender<P, T>, Receiver<P, T>) {
    let inner = Arc::new(MpmcInner {
        inbox: TreiberStack::new(),
        queue: SegQueue::new(),
        draining: AtomicBool::new(false),
        receivers_waiting: WaitQueue::new(),
        sender_count: AtomicUsize::new(1),
        receiver_count: AtomicUsize::new(1),
        closed: AtomicBool::new(false),
    });

    let sender = Sender {
        inner: inner.clone(),
    };
    let receiver = Receiver { inner };

    (sender, receiver)
}

impl<P: Platform, T> MpmcInner<P, T> {
    fn drain_inbox(&self) {
        if self
            .draining
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        loop {
            self.inbox.drain_fifo(|item| {
                self.queue.push(item);
            });

            self.draining.store(false, Ordering::Release);

            if self.inbox.is_empty() {
                break;
            }

            if self
                .draining
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                break;
            }
        }
    }
}

impl<P: Platform, T> Sender<P, T> {
    pub fn send(&self, value: T) -> Result<(), SendError<T>> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(SendError(value));
        }

        self.inner.inbox.push(value);
        self.inner.drain_inbox();

        if let Some(task) = self.inner.receivers_waiting.dequeue_one() {
            P::unpark(&task);
        }

        Ok(())
    }

    pub fn is_disconnected(&self) -> bool {
        self.inner.closed.load(Ordering::Acquire)
    }
}

impl<P: Platform, T> Clone for Sender<P, T> {
    fn clone(&self) -> Self {
        self.inner.sender_count.fetch_add(1, Ordering::AcqRel);
        Sender {
            inner: self.inner.clone(),
        }
    }
}

impl<P: Platform, T> Drop for Sender<P, T> {
    fn drop(&mut self) {
        let prev = self.inner.sender_count.fetch_sub(1, Ordering::AcqRel);
        if prev == 1 {
            for task in self.inner.receivers_waiting.dequeue_all() {
                P::unpark(&task);
            }
        }
    }
}

impl<P: Platform, T> Receiver<P, T> {
    pub fn recv(&self) -> Result<T, RecvError> {
        loop {
            self.inner.drain_inbox();
            if let Some(value) = self.inner.queue.pop() {
                return Ok(value);
            }

            if self.inner.sender_count.load(Ordering::Acquire) == 0 {
                self.inner.drain_inbox();
                if let Some(value) = self.inner.queue.pop() {
                    return Ok(value);
                }
                return Err(RecvError);
            }

            if !self.inner.receivers_waiting.enqueue_current() {
                continue;
            }

            self.inner.drain_inbox();
            if let Some(value) = self.inner.queue.pop() {
                self.inner.receivers_waiting.clear_current_if_queued();
                return Ok(value);
            }

            if self.inner.sender_count.load(Ordering::Acquire) == 0 {
                self.inner.receivers_waiting.clear_current_if_queued();
                self.inner.drain_inbox();
                if let Some(value) = self.inner.queue.pop() {
                    return Ok(value);
                }
                return Err(RecvError);
            }

            if !self.inner.receivers_waiting.is_current_enqueued() {
                continue;
            }
            P::park_current();
            self.inner.receivers_waiting.clear_current_if_queued();
        }
    }

    pub fn try_recv(&self) -> Result<T, TryRecvError> {
        self.inner.drain_inbox();
        if let Some(value) = self.inner.queue.pop() {
            Ok(value)
        } else if self.inner.sender_count.load(Ordering::Acquire) == 0 {
            self.inner.drain_inbox();
            if let Some(value) = self.inner.queue.pop() {
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

    pub fn is_empty(&self) -> bool {
        self.inner.queue.is_empty()
    }
}

impl<P: Platform, T> Clone for Receiver<P, T> {
    fn clone(&self) -> Self {
        self.inner.receiver_count.fetch_add(1, Ordering::AcqRel);
        Receiver {
            inner: self.inner.clone(),
        }
    }
}

impl<P: Platform, T> Drop for Receiver<P, T> {
    fn drop(&mut self) {
        let prev = self.inner.receiver_count.fetch_sub(1, Ordering::AcqRel);
        if prev == 1 {
            self.inner.closed.store(true, Ordering::Release);
        }
    }
}

unsafe impl<P: Platform, T: Send> Send for Sender<P, T> {}
unsafe impl<P: Platform, T: Send> Sync for Sender<P, T> {}
unsafe impl<P: Platform, T: Send> Send for Receiver<P, T> {}
unsafe impl<P: Platform, T: Send> Sync for Receiver<P, T> {}
