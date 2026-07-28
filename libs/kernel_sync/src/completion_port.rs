use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use kernel_types::bounded_mpmc::{BoundedMpmcPushError, BoundedMpmcQueue};
use kernel_types::completion::{CompletionPermit, TaskCompletion};
use spin::RwLock;

use crate::bounded_wait_queue::{BoundedWaitQueue, BoundedWaitQueueEnqueue, BoundedWaitQueueError};
use crate::mpmc::{RecvError, TryRecvError};
use crate::platform::Platform;

struct PortChunk<T> {
    queue: BoundedMpmcQueue<TaskCompletion<T>>,
    available: AtomicUsize,
    capacity: usize,
}

impl<T> PortChunk<T> {
    fn new(capacity: usize) -> Self {
        Self {
            queue: BoundedMpmcQueue::new(capacity),
            available: AtomicUsize::new(capacity),
            capacity,
        }
    }

    fn try_reserve(&self) -> bool {
        self.available
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
            .is_ok()
    }

    fn is_idle(&self) -> bool {
        self.available.load(Ordering::Acquire) == self.capacity && self.queue.is_empty()
    }
}

pub struct CompletionPort<P: Platform, T> {
    chunks: RwLock<Vec<Arc<PortChunk<T>>>>,
    waiters: BoundedWaitQueue<P>,
    chunk_capacity: usize,
    capacity: AtomicUsize,
    outstanding: AtomicUsize,
    reserve_hint: AtomicUsize,
    recv_hint: AtomicUsize,
    closed: AtomicBool,
}

pub struct PortPermit<P: Platform, T> {
    port: Arc<CompletionPort<P, T>>,
    chunk: Arc<PortChunk<T>>,
    consumed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortReserveError {
    Closed,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortResizeError {
    Closed,
    AllocationFailed,
    CapacityOverflow,
    InvalidTarget,
    InUse,
}

impl<P: Platform, T: Send + 'static> CompletionPort<P, T> {
    pub fn new(initial_capacity: usize, chunk_capacity: usize) -> Arc<Self> {
        assert!(initial_capacity > 0);
        assert!(chunk_capacity > 0);
        let mut chunks = Vec::new();
        let mut remaining = initial_capacity;
        while remaining != 0 {
            let size = remaining.min(chunk_capacity);
            chunks.push(Arc::new(PortChunk::new(size)));
            remaining -= size;
        }
        Arc::new(Self {
            chunks: RwLock::new(chunks),
            waiters: BoundedWaitQueue::new_chunked(chunk_capacity, chunk_capacity),
            chunk_capacity,
            capacity: AtomicUsize::new(initial_capacity),
            outstanding: AtomicUsize::new(0),
            reserve_hint: AtomicUsize::new(0),
            recv_hint: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
        })
    }

    pub fn try_reserve(self: &Arc<Self>) -> Result<PortPermit<P, T>, PortReserveError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(PortReserveError::Closed);
        }
        let chunks = self.chunks.read();
        let count = chunks.len();
        let start = self.reserve_hint.fetch_add(1, Ordering::Relaxed);
        for offset in 0..count {
            let chunk = &chunks[(start + offset) % count];
            if chunk.try_reserve() {
                self.outstanding.fetch_add(1, Ordering::AcqRel);
                return Ok(PortPermit {
                    port: self.clone(),
                    chunk: chunk.clone(),
                    consumed: false,
                });
            }
        }
        Err(PortReserveError::Full)
    }

    pub fn try_grow(&self, additional_capacity: usize) -> Result<usize, PortResizeError> {
        if additional_capacity == 0 {
            return Ok(self.capacity());
        }
        if self.closed.load(Ordering::Acquire) {
            return Err(PortResizeError::Closed);
        }
        let mut chunks = self.chunks.write();
        let current = self.capacity.load(Ordering::Acquire);
        let new_capacity = current
            .checked_add(additional_capacity)
            .ok_or(PortResizeError::CapacityOverflow)?;
        let mut remaining = additional_capacity;
        chunks
            .try_reserve(additional_capacity.div_ceil(self.chunk_capacity))
            .map_err(|_| PortResizeError::AllocationFailed)?;
        while remaining != 0 {
            let size = remaining.min(self.chunk_capacity);
            chunks.push(Arc::new(PortChunk::new(size)));
            remaining -= size;
        }
        self.capacity.store(new_capacity, Ordering::Release);
        Ok(new_capacity)
    }

    /// Shrinks to `target_capacity` only when whole idle chunks reach that
    /// target exactly. Failure leaves the port unchanged.
    pub fn try_shrink_to(&self, target_capacity: usize) -> Result<usize, PortResizeError> {
        let mut chunks = self.chunks.write();
        let current = self.capacity.load(Ordering::Acquire);
        if target_capacity == 0 || target_capacity > current {
            return Err(PortResizeError::InvalidTarget);
        }
        if target_capacity == current {
            return Ok(current);
        }

        let required = current - target_capacity;
        let idle_capacity = chunks
            .iter()
            .filter(|chunk| chunk.is_idle())
            .map(|chunk| chunk.capacity)
            .sum::<usize>();
        if idle_capacity < required {
            return Err(PortResizeError::InUse);
        }

        let mut selected = Vec::new();
        selected
            .try_reserve(chunks.len())
            .map_err(|_| PortResizeError::AllocationFailed)?;
        let mut remaining = required;
        for (index, chunk) in chunks.iter().enumerate().rev() {
            if remaining == 0 {
                break;
            }
            if chunk.capacity <= remaining && chunk.is_idle() {
                selected.push(index);
                remaining -= chunk.capacity;
            }
        }
        if remaining != 0 {
            return Err(PortResizeError::InvalidTarget);
        }

        for index in selected {
            chunks.remove(index);
        }
        self.capacity.store(target_capacity, Ordering::Release);
        Ok(target_capacity)
    }

    pub fn try_recv(&self) -> Result<TaskCompletion<T>, TryRecvError> {
        let chunks = self.chunks.read();
        let count = chunks.len();
        let start = self.recv_hint.fetch_add(1, Ordering::Relaxed);
        for offset in 0..count {
            let chunk = &chunks[(start + offset) % count];
            if let Some(value) = chunk.queue.try_pop() {
                chunk.available.fetch_add(1, Ordering::Release);
                self.outstanding.fetch_sub(1, Ordering::AcqRel);
                return Ok(value);
            }
        }
        if self.closed.load(Ordering::Acquire) {
            Err(TryRecvError::Disconnected)
        } else {
            Err(TryRecvError::Empty)
        }
    }

    pub fn recv(&self) -> Result<TaskCompletion<T>, RecvError> {
        loop {
            if let Ok(value) = self.try_recv() {
                return Ok(value);
            }
            if self.closed.load(Ordering::Acquire) {
                return Err(RecvError);
            }
            match self.waiters.enqueue_current() {
                Ok(BoundedWaitQueueEnqueue::Queued) => {}
                Ok(BoundedWaitQueueEnqueue::Woken) | Err(BoundedWaitQueueError::AlreadyQueued) => {
                    continue
                }
                Err(BoundedWaitQueueError::NoCurrentTask) => {
                    P::spin_loop();
                    continue;
                }
                Err(BoundedWaitQueueError::Full | BoundedWaitQueueError::AllocationFailed) => {
                    P::spin_loop();
                    continue;
                }
            }
            if let Ok(value) = self.try_recv() {
                self.waiters.clear_current_if_queued();
                return Ok(value);
            }
            if self.waiters.is_current_enqueued() {
                P::park_current();
                self.waiters.clear_current_if_queued();
            }
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity.load(Ordering::Acquire)
    }

    pub fn outstanding(&self) -> usize {
        self.outstanding.load(Ordering::Acquire)
    }

    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.waiters.wake_all();
    }
}

impl<P: Platform, T: Send + 'static> CompletionPermit<T> for PortPermit<P, T> {
    fn complete(mut self, completion: TaskCompletion<T>) {
        loop {
            match self.chunk.queue.try_push_wait_free(completion) {
                Ok(()) => break,
                Err(BoundedMpmcPushError::Contended(value)) => {
                    core::hint::spin_loop();
                    // The reservation guarantees this cannot become full.
                    if let Ok(()) = self.chunk.queue.try_push(value) {
                        break;
                    }
                    unreachable!("reserved completion slot became unavailable");
                }
                Err(BoundedMpmcPushError::Full(_)) => {
                    panic!("reserved completion slot became full")
                }
            }
        }
        self.consumed = true;
        self.port.waiters.wake_one();
    }
}

impl<P: Platform, T> Drop for PortPermit<P, T> {
    fn drop(&mut self) {
        if !self.consumed {
            self.chunk.available.fetch_add(1, Ordering::Release);
            self.port.outstanding.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

unsafe impl<P: Platform, T: Send> Send for CompletionPort<P, T> {}
unsafe impl<P: Platform, T: Send> Sync for CompletionPort<P, T> {}
