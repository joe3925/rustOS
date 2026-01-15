use alloc::collections::VecDeque;
use alloc::sync::Arc;

use crate::structs::condvar::Condvar;
use crate::structs::sleep_mutex::SleepMutex;

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

struct ChanInner<T> {
    queue: VecDeque<T>,
    sender_count: usize,
    receiver_alive: bool,
}

struct Channel<T> {
    inner: SleepMutex<ChanInner<T>>,
    not_empty: Condvar,
}

/// The sending half of a channel.
///
/// Senders can be cloned to create multiple producers.
/// When all senders are dropped, the channel becomes disconnected
/// and receivers will return `RecvError` after draining the queue.
pub struct Sender<T> {
    channel: Arc<Channel<T>>,
}

/// The receiving half of a channel.
///
/// There can only be one receiver (the channel is MPSC).
/// When the receiver is dropped, all senders will get `SendError`.
pub struct Receiver<T> {
    channel: Arc<Channel<T>>,
}

/// Creates a new asynchronous channel, returning the sender/receiver halves.
///
/// All data sent on the [`Sender`] will become available on the [`Receiver`]
/// in the same order as it was sent. The channel is unbounded.
///
/// The [`Sender`] can be cloned to send from multiple tasks, while the
/// [`Receiver`] cannot be cloned (single consumer).
pub fn channel<T>() -> (Sender<T>, Receiver<T>) {
    let channel = Arc::new(Channel {
        inner: SleepMutex::new(ChanInner {
            queue: VecDeque::new(),
            sender_count: 1,
            receiver_alive: true,
        }),
        not_empty: Condvar::new(),
    });

    let sender = Sender {
        channel: channel.clone(),
    };
    let receiver = Receiver { channel };

    (sender, receiver)
}

impl<T> Sender<T> {
    /// Sends a value on this channel.
    ///
    /// This will not block. If the receiver has been dropped, this returns
    /// `Err(SendError(value))` with the value back.
    pub fn send(&self, value: T) -> Result<(), SendError<T>> {
        {
            let mut inner = self.channel.inner.lock();

            if !inner.receiver_alive {
                return Err(SendError(value));
            }

            inner.queue.push_back(value);
        }

        // Notify outside the lock to reduce contention
        self.channel.not_empty.notify_one();
        Ok(())
    }

    /// Returns `true` if the receiver has been dropped.
    pub fn is_disconnected(&self) -> bool {
        !self.channel.inner.lock().receiver_alive
    }
}

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        let mut inner = self.channel.inner.lock();
        inner.sender_count += 1;
        drop(inner);

        Sender {
            channel: self.channel.clone(),
        }
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        let should_notify = {
            let mut inner = self.channel.inner.lock();
            inner.sender_count -= 1;
            inner.sender_count == 0
        };

        // Wake all waiting receivers so they can see the channel is closed
        if should_notify {
            self.channel.not_empty.notify_all();
        }
    }
}

impl<T> Receiver<T> {
    /// Blocks until a message is received or the channel disconnects.
    ///
    /// If all senders have been dropped and the queue is empty,
    /// this returns `Err(RecvError)`.
    pub fn recv(&self) -> Result<T, RecvError> {
        let mut inner = self.channel.inner.lock();

        loop {
            // Try to get a message
            if let Some(value) = inner.queue.pop_front() {
                return Ok(value);
            }

            // Queue is empty - check if channel is disconnected
            if inner.sender_count == 0 {
                return Err(RecvError);
            }

            // Wait for a message or disconnect
            inner = self.channel.not_empty.wait(inner);
        }
    }

    /// Attempts to receive a message without blocking.
    ///
    /// Returns `Ok(value)` if a message was available,
    /// `Err(TryRecvError::Empty)` if no message but channel is open,
    /// `Err(TryRecvError::Disconnected)` if all senders dropped and queue empty.
    pub fn try_recv(&self) -> Result<T, TryRecvError> {
        let mut inner = self.channel.inner.lock();

        if let Some(value) = inner.queue.pop_front() {
            return Ok(value);
        }

        if inner.sender_count == 0 {
            Err(TryRecvError::Disconnected)
        } else {
            Err(TryRecvError::Empty)
        }
    }

    /// Returns `true` if all senders have been dropped.
    pub fn is_disconnected(&self) -> bool {
        self.channel.inner.lock().sender_count == 0
    }

    /// Returns the number of messages currently in the queue.
    pub fn len(&self) -> usize {
        self.channel.inner.lock().queue.len()
    }

    /// Returns `true` if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.channel.inner.lock().queue.is_empty()
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        let mut inner = self.channel.inner.lock();
        inner.receiver_alive = false;
        // Senders will see receiver_alive = false on next send
    }
}

// Safety: Channel can be shared if T is Send
unsafe impl<T: Send> Send for Sender<T> {}
unsafe impl<T: Send> Sync for Sender<T> {}
unsafe impl<T: Send> Send for Receiver<T> {}
// Receiver is !Sync because only one task should receive at a time
