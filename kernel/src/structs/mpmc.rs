use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use crossbeam_queue::SegQueue;
use x86_64::instructions::interrupts::without_interrupts;

use crate::scheduling::scheduler::SCHEDULER;
use crate::scheduling::state::BlockReason;
use crate::structs::wait_queue::WaitQueue;

/// Error returned when sending on a disconnected channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendError<T>(pub T);

/// Error returned when receiving on a disconnected channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecvError;

/// Result of a non-blocking receive attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TryRecvError {
    /// No message available, but channel is still open.
    Empty,
    /// Channel is disconnected (all senders dropped).
    Disconnected,
}

struct MpmcInner<T> {
    /// Lock-free queue for message storage.
    queue: SegQueue<T>,
    /// Wait queue for blocked receivers.
    receivers_waiting: WaitQueue,
    /// Number of active senders.
    sender_count: AtomicUsize,
    /// Number of active receivers.
    receiver_count: AtomicUsize,
    /// Whether the channel has been closed.
    closed: AtomicBool,
}

/// The sending half of an MPMC channel.
///
/// Senders can be cloned to create multiple producers.
/// When all senders are dropped, the channel becomes disconnected
/// and receivers will return `RecvError` after draining the queue.
pub struct Sender<T> {
    inner: Arc<MpmcInner<T>>,
}

/// The receiving half of an MPMC channel.
///
/// Receivers can be cloned to create multiple consumers.
/// When all receivers are dropped, senders will get `SendError`.
pub struct Receiver<T> {
    inner: Arc<MpmcInner<T>>,
}

/// Creates a new MPMC channel, returning the sender/receiver halves.
///
/// All data sent on the [`Sender`] will become available on any [`Receiver`]
/// in FIFO order. The channel is unbounded.
///
/// Both [`Sender`] and [`Receiver`] can be cloned for multiple producers
/// and multiple consumers.
pub fn mpmc_channel<T>() -> (Sender<T>, Receiver<T>) {
    let inner = Arc::new(MpmcInner {
        queue: SegQueue::new(),
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

impl<T> Sender<T> {
    /// Sends a value on this channel.
    ///
    /// This will not block. If all receivers have been dropped, this returns
    /// `Err(SendError(value))` with the value back.
    pub fn send(&self, value: T) -> Result<(), SendError<T>> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(SendError(value));
        }
        without_interrupts(|| {
            self.inner.queue.push(value);
        });

        if let Some(task) = without_interrupts(|| self.inner.receivers_waiting.dequeue_one()) {
            SCHEDULER.unpark(&task);
        }

        Ok(())
    }

    /// Returns `true` if all receivers have been dropped.
    pub fn is_disconnected(&self) -> bool {
        self.inner.closed.load(Ordering::Acquire)
    }
}

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        self.inner.sender_count.fetch_add(1, Ordering::AcqRel);
        Sender {
            inner: self.inner.clone(),
        }
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        let prev = self.inner.sender_count.fetch_sub(1, Ordering::AcqRel);
        if prev == 1 {
            for task in without_interrupts(|| self.inner.receivers_waiting.dequeue_all()) {
                SCHEDULER.unpark(&task);
            }
        }
    }
}

impl<T> Receiver<T> {
    /// Blocks until a message is received or the channel disconnects.
    ///
    /// If all senders have been dropped and the queue is empty,
    /// this returns `Err(RecvError)`.
    pub fn recv(&self) -> Result<T, RecvError> {
        loop {
            if let Some(value) = without_interrupts(|| self.inner.queue.pop()) {
                return Ok(value);
            }

            if self.inner.sender_count.load(Ordering::Acquire) == 0 {
                if let Some(value) = without_interrupts(|| self.inner.queue.pop()) {
                    return Ok(value);
                }
                return Err(RecvError);
            }

            if !without_interrupts(|| self.inner.receivers_waiting.enqueue_current()) {
                continue;
            }

            if let Some(value) = without_interrupts(|| self.inner.queue.pop()) {
                self.inner.receivers_waiting.clear_current_if_queued();
                return Ok(value);
            }

            if self.inner.sender_count.load(Ordering::Acquire) == 0 {
                self.inner.receivers_waiting.clear_current_if_queued();
                if let Some(value) = without_interrupts(|| self.inner.queue.pop()) {
                    return Ok(value);
                }
                return Err(RecvError);
            }

            SCHEDULER.park_current(BlockReason::ChannelRecv);
            self.inner.receivers_waiting.clear_current_if_queued();
        }
    }

    /// Attempts to receive a message without blocking.
    ///
    /// Returns `Ok(value)` if a message was available,
    /// `Err(TryRecvError::Empty)` if no message but channel is open,
    /// `Err(TryRecvError::Disconnected)` if all senders dropped and queue empty.
    pub fn try_recv(&self) -> Result<T, TryRecvError> {
        if let Some(value) = without_interrupts(|| self.inner.queue.pop()) {
            Ok(value)
        } else if self.inner.sender_count.load(Ordering::Acquire) == 0 {
            if let Some(value) = without_interrupts(|| self.inner.queue.pop()) {
                Ok(value)
            } else {
                Err(TryRecvError::Disconnected)
            }
        } else {
            Err(TryRecvError::Empty)
        }
    }

    /// Returns `true` if all senders have been dropped.
    pub fn is_disconnected(&self) -> bool {
        self.inner.sender_count.load(Ordering::Acquire) == 0
    }

    /// Returns `true` if the queue is empty.
    ///
    /// Note: This is a snapshot and may be stale by the time it's used.
    pub fn is_empty(&self) -> bool {
        self.inner.queue.is_empty()
    }
}

impl<T> Clone for Receiver<T> {
    fn clone(&self) -> Self {
        self.inner.receiver_count.fetch_add(1, Ordering::AcqRel);
        Receiver {
            inner: self.inner.clone(),
        }
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        let prev = self.inner.receiver_count.fetch_sub(1, Ordering::AcqRel);
        if prev == 1 {
            // Last receiver dropped - mark channel as closed
            self.inner.closed.store(true, Ordering::Release);
        }
    }
}

// Safety: Channel can be shared if T is Send
unsafe impl<T: Send> Send for Sender<T> {}
unsafe impl<T: Send> Sync for Sender<T> {}
unsafe impl<T: Send> Send for Receiver<T> {}
unsafe impl<T: Send> Sync for Receiver<T> {}
