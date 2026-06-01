use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::bounded_wait_queue::{BoundedWaitQueue, BoundedWaitQueueEnqueue, BoundedWaitQueueError};
use crate::mpmc::{RecvError, TryRecvError};
use crate::platform::{ParkReason, Platform};

const SLOT_EMPTY: usize = 0;
const SLOT_RESERVED: usize = 1;
const SLOT_FULL: usize = 2;
const SLOT_TAKING: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundedSendError<T> {
    Full(T),
    Disconnected(T),
}

struct QueueSlot<T> {
    state: AtomicUsize,
    value: UnsafeCell<MaybeUninit<T>>,
}

impl<T> QueueSlot<T> {
    fn new() -> Self {
        Self {
            state: AtomicUsize::new(SLOT_EMPTY),
            value: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    #[inline]
    unsafe fn write_value(&self, value: T) {
        (*self.value.get()).write(value);
    }

    #[inline]
    unsafe fn read_value(&self) -> T {
        (*self.value.get()).assume_init_read()
    }

    #[inline]
    unsafe fn drop_value(&self) {
        (*self.value.get()).assume_init_drop();
    }
}

unsafe impl<T: Send> Send for QueueSlot<T> {}
unsafe impl<T: Send> Sync for QueueSlot<T> {}

struct WaitFreeBoundedQueue<T> {
    slots: Vec<QueueSlot<T>>,
    push_hint: AtomicUsize,
    pop_hint: AtomicUsize,
    free_slots: AtomicUsize,
    len: AtomicUsize,
}

impl<T> WaitFreeBoundedQueue<T> {
    fn new(capacity: usize) -> Self {
        assert!(capacity > 0);

        let mut slots = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            slots.push(QueueSlot::new());
        }

        Self {
            slots,
            push_hint: AtomicUsize::new(0),
            pop_hint: AtomicUsize::new(0),
            free_slots: AtomicUsize::new(capacity),
            len: AtomicUsize::new(0),
        }
    }
    // TODO: temp fix, this can be made wait free with a per slot permit
    fn try_push(&self, value: T) -> Result<(), T> {
        loop {
            if self
                .free_slots
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |free| {
                    if free != 0 {
                        Some(free - 1)
                    } else {
                        None
                    }
                })
                .is_err()
            {
                return Err(value);
            }

            let cap = self.slots.len();
            let start = self.push_hint.fetch_add(1, Ordering::Relaxed);

            for offset in 0..cap {
                let idx = start.wrapping_add(offset) % cap;
                let slot = &self.slots[idx];

                if slot
                    .state
                    .compare_exchange(
                        SLOT_EMPTY,
                        SLOT_RESERVED,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_err()
                {
                    continue;
                }

                unsafe {
                    slot.write_value(value);
                }

                slot.state.store(SLOT_FULL, Ordering::Release);
                self.len.fetch_add(1, Ordering::Release);
                return Ok(());
            }

            self.free_slots.fetch_add(1, Ordering::Release);
            core::hint::spin_loop();
        }
    }

    fn try_pop(&self) -> Option<T> {
        let cap = self.slots.len();
        let start = self.pop_hint.fetch_add(1, Ordering::Relaxed);

        for offset in 0..cap {
            let idx = start.wrapping_add(offset) % cap;
            let slot = &self.slots[idx];

            if slot
                .state
                .compare_exchange(SLOT_FULL, SLOT_TAKING, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                continue;
            }

            let value = unsafe { slot.read_value() };

            slot.state.store(SLOT_EMPTY, Ordering::Release);
            self.len.fetch_sub(1, Ordering::Release);
            self.free_slots.fetch_add(1, Ordering::Release);

            return Some(value);
        }

        None
    }

    fn capacity(&self) -> usize {
        self.slots.len()
    }

    fn len_approx(&self) -> usize {
        self.len.load(Ordering::Acquire)
    }

    fn is_empty_approx(&self) -> bool {
        self.len_approx() == 0
    }

    fn is_full_approx(&self) -> bool {
        self.free_slots.load(Ordering::Acquire) == 0
    }
}

impl<T> Drop for WaitFreeBoundedQueue<T> {
    fn drop(&mut self) {
        for slot in &self.slots {
            if slot.state.load(Ordering::Acquire) == SLOT_FULL {
                unsafe {
                    slot.drop_value();
                }

                slot.state.store(SLOT_EMPTY, Ordering::Release);
            }
        }
    }
}

unsafe impl<T: Send> Send for WaitFreeBoundedQueue<T> {}
unsafe impl<T: Send> Sync for WaitFreeBoundedQueue<T> {}

struct BoundedMpmcInner<P: Platform, T> {
    queue: WaitFreeBoundedQueue<T>,
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
        queue: WaitFreeBoundedQueue::new(capacity),
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
            Err(value) => {
                if self.inner.closed.load(Ordering::Acquire) {
                    Err(BoundedSendError::Disconnected(value))
                } else {
                    Err(BoundedSendError::Full(value))
                }
            }
        }
    }

    pub fn is_disconnected(&self) -> bool {
        self.inner.closed.load(Ordering::Acquire)
    }

    pub fn len(&self) -> usize {
        self.inner.queue.len_approx()
    }

    pub fn capacity(&self) -> usize {
        self.inner.queue.capacity()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.queue.is_empty_approx()
    }

    pub fn is_full(&self) -> bool {
        self.inner.queue.is_full_approx()
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
        self.inner.queue.len_approx()
    }

    pub fn capacity(&self) -> usize {
        self.inner.queue.capacity()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.queue.is_empty_approx()
    }

    pub fn is_full(&self) -> bool {
        self.inner.queue.is_full_approx()
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
