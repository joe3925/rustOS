use alloc::collections::VecDeque;
use alloc::sync::Arc;

use crate::condvar::Condvar;
use crate::platform::Platform;
use crate::sleep_mutex::SleepMutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendError<T>(pub T);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecvError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TryRecvError {
    Empty,
    Disconnected,
}

struct ChanInner<T> {
    queue: VecDeque<T>,
    sender_count: usize,
    receiver_alive: bool,
}

struct Channel<P: Platform, T> {
    inner: SleepMutex<P, ChanInner<T>>,
    not_empty: Condvar<P>,
}

pub struct Sender<P: Platform, T> {
    channel: Arc<Channel<P, T>>,
}

pub struct Receiver<P: Platform, T> {
    channel: Arc<Channel<P, T>>,
}

pub fn channel<P: Platform, T>() -> (Sender<P, T>, Receiver<P, T>) {
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

impl<P: Platform, T> Sender<P, T> {
    pub fn send(&self, value: T) -> Result<(), SendError<T>> {
        {
            let mut inner = self.channel.inner.lock();

            if !inner.receiver_alive {
                return Err(SendError(value));
            }

            inner.queue.push_back(value);
        }

        self.channel.not_empty.notify_one();
        Ok(())
    }

    pub fn is_disconnected(&self) -> bool {
        !self.channel.inner.lock().receiver_alive
    }
}

impl<P: Platform, T> Clone for Sender<P, T> {
    fn clone(&self) -> Self {
        let mut inner = self.channel.inner.lock();
        inner.sender_count += 1;
        drop(inner);

        Sender {
            channel: self.channel.clone(),
        }
    }
}

impl<P: Platform, T> Drop for Sender<P, T> {
    fn drop(&mut self) {
        let should_notify = {
            let mut inner = self.channel.inner.lock();
            inner.sender_count -= 1;
            inner.sender_count == 0
        };

        if should_notify {
            self.channel.not_empty.notify_all();
        }
    }
}

impl<P: Platform, T> Receiver<P, T> {
    pub fn recv(&self) -> Result<T, RecvError> {
        let mut inner = self.channel.inner.lock();

        loop {
            if let Some(value) = inner.queue.pop_front() {
                return Ok(value);
            }

            if inner.sender_count == 0 {
                return Err(RecvError);
            }

            inner = self.channel.not_empty.wait(inner);
        }
    }

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

    pub fn is_disconnected(&self) -> bool {
        self.channel.inner.lock().sender_count == 0
    }

    pub fn len(&self) -> usize {
        self.channel.inner.lock().queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.channel.inner.lock().queue.is_empty()
    }
}

impl<P: Platform, T> Drop for Receiver<P, T> {
    fn drop(&mut self) {
        let mut inner = self.channel.inner.lock();
        inner.receiver_alive = false;
    }
}

unsafe impl<P: Platform, T: Send> Send for Sender<P, T> {}
unsafe impl<P: Platform, T: Send> Sync for Sender<P, T> {}
unsafe impl<P: Platform, T: Send> Send for Receiver<P, T> {}
