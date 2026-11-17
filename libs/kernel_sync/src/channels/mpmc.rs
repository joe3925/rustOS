use crate::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::ptr;
use core::sync::atomic::AtomicPtr;

use crate::platform::contract::Platform;
use crate::queues::bounded_mpmc::{
    BoundedMpmcPopError, BoundedMpmcPushError, MpmcQueue, wait_for_segment_writer,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendError<T>(pub T);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundedSendError<T> {
    Full(T),
    Disconnected(T),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrySendError<T> {
    Full(T),
    Contended(T),
    Disconnected(T),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecvError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TryRecvError {
    Empty,
    Disconnected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitFreeRecvError {
    Empty,
    Contended,
    Disconnected,
}

const WAITER_EMPTY: usize = 0;
const WAITER_PREPARING: usize = 1;
const WAITER_WAITING: usize = 2;
const WAITER_WAKING: usize = 3;
const WAITER_NOTIFIED: usize = 4;
const WAITER_CLEARING: usize = 5;
const WAITER_SPINNING: usize = 6;

struct ReceiverSlot<P: Platform> {
    state: AtomicUsize,
    task: UnsafeCell<Option<P::Task>>,
}

struct ReceiverBlock<P: Platform> {
    slots: Vec<ReceiverSlot<P>>,
    waiting: AtomicUsize,
    spinning: AtomicUsize,
    next: AtomicPtr<ReceiverBlock<P>>,
}

struct ReceiverRegistration<'a, P: Platform> {
    slot: &'a ReceiverSlot<P>,
    waiting: &'a AtomicUsize,
    spinning: &'a AtomicUsize,
    mask: usize,
}

impl<P: Platform> Drop for ReceiverRegistration<'_, P> {
    #[cfg_attr(irq_check, irq::forbidden)]
    fn drop(&mut self) {
        loop {
            let state = self.slot.state.load(Ordering::Acquire);
            if state == WAITER_WAKING {
                P::spin_loop();
                continue;
            }
            if self
                .slot
                .state
                .compare_exchange(state, WAITER_CLEARING, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                self.waiting.fetch_and(!self.mask, Ordering::AcqRel);
                self.spinning.fetch_and(!self.mask, Ordering::AcqRel);
                unsafe {
                    drop((*self.slot.task.get()).take());
                }
                self.slot.state.store(WAITER_EMPTY, Ordering::Release);
                return;
            }
        }
    }
}

struct MpmcInner<P: Platform, T> {
    queue: MpmcQueue<T>,
    receivers: AtomicPtr<ReceiverBlock<P>>,
    receiver_block_capacity: usize,
    sender_count: AtomicUsize,
    receiver_count: AtomicUsize,
    closed: AtomicBool,
}

impl<P: Platform, T> MpmcInner<P, T> {
    fn wake_receivers(&self, mut remaining: usize) {
        if remaining == 0 {
            return;
        }
        let wake_all = remaining == usize::MAX;
        let mut block = self.receivers.load(Ordering::Acquire);
        while !block.is_null() {
            let receivers = unsafe { &*block };
            let mut visited = 0;
            for candidates in [&receivers.spinning, &receivers.waiting] {
                loop {
                    if !wake_all && self.queue.is_empty() {
                        return;
                    }
                    let mut selected = 0;
                    let _ =
                        candidates.fetch_update(Ordering::AcqRel, Ordering::Acquire, |waiting| {
                            let eligible = waiting & !visited;
                            let mut next = eligible;
                            if remaining == 1 {
                                next &= next.wrapping_sub(1);
                            } else if remaining >= eligible.count_ones() as usize {
                                next = 0;
                            } else {
                                for _ in 0..remaining {
                                    next &= next.wrapping_sub(1);
                                }
                            }
                            selected = eligible ^ next;
                            Some(waiting & !selected)
                        });
                    if selected == 0 {
                        break;
                    }
                    visited |= selected;
                    while selected != 0 {
                        let index = selected.trailing_zeros() as usize;
                        selected &= selected - 1;
                        let slot = &receivers.slots[index];
                        if slot
                            .state
                            .compare_exchange(
                                WAITER_SPINNING,
                                WAITER_NOTIFIED,
                                Ordering::AcqRel,
                                Ordering::Acquire,
                            )
                            .is_ok()
                        {
                            remaining -= 1;
                            if remaining == 0 {
                                return;
                            }
                        } else if slot
                            .state
                            .compare_exchange(
                                WAITER_WAITING,
                                WAITER_WAKING,
                                Ordering::AcqRel,
                                Ordering::Acquire,
                            )
                            .is_ok()
                        {
                            if let Some(task) = unsafe { &*slot.task.get() } {
                                P::unpark(task);
                            }
                            slot.state.store(WAITER_NOTIFIED, Ordering::Release);
                            remaining -= 1;
                            if remaining == 0 {
                                return;
                            }
                        } else if slot
                            .state
                            .compare_exchange(
                                WAITER_PREPARING,
                                WAITER_NOTIFIED,
                                Ordering::AcqRel,
                                Ordering::Acquire,
                            )
                            .is_ok()
                        {
                            remaining -= 1;
                            if remaining == 0 {
                                return;
                            }
                        }
                    }
                }
            }
            block = receivers.next.load(Ordering::Acquire);
        }
    }
}

impl<P: Platform, T> Drop for MpmcInner<P, T> {
    fn drop(&mut self) {
        let mut block = *self.receivers.get_mut();
        while !block.is_null() {
            let owned = unsafe { Box::from_raw(block) };
            block = owned.next.load(Ordering::Relaxed);
            drop(owned);
        }
    }
}

pub struct Sender<P: Platform, T, const GROWABLE: bool = true> {
    inner: Arc<MpmcInner<P, T>>,
}

pub struct Receiver<P: Platform, T, const GROWABLE: bool = true> {
    inner: Arc<MpmcInner<P, T>>,
}

pub type BoundedSender<P, T> = Sender<P, T, false>;
pub type BoundedReceiver<P, T> = Receiver<P, T, false>;

pub fn bounded_mpmc_channel<P: Platform, T>(
    capacity: usize,
    max_consumers: usize,
) -> (BoundedSender<P, T>, BoundedReceiver<P, T>) {
    channel::<P, T, false>(capacity, max_consumers)
}

pub fn mpmc_channel<P: Platform, T>() -> (Sender<P, T>, Receiver<P, T>) {
    channel::<P, T, true>(64, 64)
}

pub(crate) fn channel<P: Platform, T, const GROWABLE: bool>(
    capacity: usize,
    max_consumers: usize,
) -> (Sender<P, T, GROWABLE>, Receiver<P, T, GROWABLE>) {
    assert!(max_consumers > 0);
    let max_consumers = max_consumers.min(usize::BITS as usize);
    let queue = MpmcQueue::with_growth(capacity, GROWABLE);
    let mut slots = Vec::with_capacity(max_consumers);
    for _ in 0..max_consumers {
        slots.push(ReceiverSlot {
            state: AtomicUsize::new(WAITER_EMPTY),
            task: UnsafeCell::new(None),
        });
    }
    let receivers = Box::into_raw(Box::new(ReceiverBlock {
        slots,
        waiting: AtomicUsize::new(0),
        spinning: AtomicUsize::new(0),
        next: AtomicPtr::new(ptr::null_mut()),
    }));
    let inner = Arc::new(MpmcInner {
        queue,
        receivers: AtomicPtr::new(receivers),
        receiver_block_capacity: max_consumers,
        sender_count: AtomicUsize::new(1),
        receiver_count: AtomicUsize::new(1),
        closed: AtomicBool::new(false),
    });
    (
        Sender {
            inner: inner.clone(),
        },
        Receiver { inner },
    )
}

impl<P: Platform, T, const GROWABLE: bool> Sender<P, T, GROWABLE> {
    pub(crate) fn send_many(&self, values: &[T]) -> usize
    where
        T: Copy,
    {
        let mut sent = 0;
        'values: for &value in values {
            let mut value = value;
            loop {
                if self.inner.closed.load(Ordering::Acquire) {
                    break 'values;
                }
                match self.inner.queue.try_push_wait_free(value) {
                    Ok(()) => {
                        sent += 1;
                        break;
                    }
                    Err(BoundedMpmcPushError::Full(next)) => {
                        if !GROWABLE {
                            break;
                        }
                        value = next;
                        self.inner.queue.grow();
                    }
                    Err(BoundedMpmcPushError::Contended(next)) => {
                        value = next;
                        P::spin_loop();
                    }
                }
            }
        }
        self.inner.wake_receivers(sent);
        sent
    }

    pub fn send(&self, mut value: T) -> Result<(), SendError<T>> {
        loop {
            match self.try_send_no_alloc(value) {
                Ok(()) => return Ok(()),
                Err(TrySendError::Disconnected(value)) => return Err(SendError(value)),
                Err(TrySendError::Full(next_value)) => {
                    if !GROWABLE {
                        return Err(SendError(next_value));
                    }
                    value = next_value;
                    self.inner.queue.grow();
                }
                Err(TrySendError::Contended(next_value)) => {
                    value = next_value;
                    P::spin_loop();
                }
            }
        }
    }

    pub fn try_send(&self, mut value: T) -> Result<(), BoundedSendError<T>> {
        loop {
            match self.try_send_no_alloc(value) {
                Ok(()) => return Ok(()),
                Err(TrySendError::Full(value)) => return Err(BoundedSendError::Full(value)),
                Err(TrySendError::Disconnected(value)) => {
                    return Err(BoundedSendError::Disconnected(value));
                }
                Err(TrySendError::Contended(next_value)) => {
                    value = next_value;
                    P::spin_loop();
                }
            }
        }
    }

    pub fn try_send_no_alloc(&self, value: T) -> Result<(), TrySendError<T>> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(TrySendError::Disconnected(value));
        }
        match self.inner.queue.try_push_wait_free(value) {
            Ok(()) => {
                self.inner.wake_receivers(1);
                Ok(())
            }
            Err(BoundedMpmcPushError::Full(value)) => {
                Err(if self.inner.closed.load(Ordering::Acquire) {
                    TrySendError::Disconnected(value)
                } else {
                    TrySendError::Full(value)
                })
            }
            Err(BoundedMpmcPushError::Contended(value)) => Err(TrySendError::Contended(value)),
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

impl<P: Platform, T, const GROWABLE: bool> Clone for Sender<P, T, GROWABLE> {
    fn clone(&self) -> Self {
        self.inner.sender_count.fetch_add(1, Ordering::AcqRel);
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<P: Platform, T, const GROWABLE: bool> Drop for Sender<P, T, GROWABLE> {
    fn drop(&mut self) {
        if self.inner.sender_count.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.inner.wake_receivers(usize::MAX);
        }
    }
}

impl<P: Platform, T, const GROWABLE: bool> Receiver<P, T, GROWABLE> {
    #[cfg_attr(irq_check, irq::forbidden)]
    pub fn recv(&self) -> Result<T, RecvError> {
        self.recv_with_spin(0)
    }

    #[cfg_attr(irq_check, irq::forbidden)]
    pub(crate) fn recv_with_spin(&self, spins: usize) -> Result<T, RecvError> {
        loop {
            match self.try_recv() {
                Ok(value) => return Ok(value),
                Err(TryRecvError::Disconnected) => return Err(RecvError),
                Err(TryRecvError::Empty) => {}
            }
            let Some(task) = P::current_task() else {
                P::spin_loop();
                continue;
            };
            let mut block = self.inner.receivers.load(Ordering::Acquire);
            let mut reserved = None;
            while !block.is_null() {
                let receivers = unsafe { &*block };
                for (index, slot) in receivers.slots.iter().enumerate() {
                    if slot
                        .state
                        .compare_exchange(
                            WAITER_EMPTY,
                            WAITER_PREPARING,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        reserved = Some(ReceiverRegistration {
                            slot,
                            waiting: &receivers.waiting,
                            spinning: &receivers.spinning,
                            mask: 1usize << index,
                        });
                        break;
                    }
                }
                if reserved.is_some() {
                    break;
                }
                let next = receivers.next.load(Ordering::Acquire);
                if next.is_null() {
                    let mut slots = Vec::with_capacity(self.inner.receiver_block_capacity);
                    for _ in 0..self.inner.receiver_block_capacity {
                        slots.push(ReceiverSlot {
                            state: AtomicUsize::new(WAITER_EMPTY),
                            task: UnsafeCell::new(None),
                        });
                    }
                    let allocated = Box::into_raw(Box::new(ReceiverBlock {
                        slots,
                        waiting: AtomicUsize::new(0),
                        spinning: AtomicUsize::new(0),
                        next: AtomicPtr::new(ptr::null_mut()),
                    }));
                    block = match receivers.next.compare_exchange(
                        ptr::null_mut(),
                        allocated,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => allocated,
                        Err(published) => {
                            unsafe {
                                drop(Box::from_raw(allocated));
                            }
                            published
                        }
                    };
                } else {
                    block = next;
                }
            }
            let Some(registration) = reserved else {
                continue;
            };
            let slot = registration.slot;
            unsafe {
                *slot.task.get() = Some(task);
            }
            if spins != 0 {
                slot.state.store(WAITER_SPINNING, Ordering::Release);
                if registration
                    .spinning
                    .compare_exchange(0, registration.mask, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    for _ in 0..spins {
                        match self.try_recv() {
                            Ok(value) => return Ok(value),
                            Err(TryRecvError::Disconnected) => return Err(RecvError),
                            Err(TryRecvError::Empty) => {}
                        }
                        if slot.state.load(Ordering::Acquire) != WAITER_SPINNING {
                            break;
                        }
                        P::spin_loop();
                    }
                    registration
                        .spinning
                        .fetch_and(!registration.mask, Ordering::AcqRel);
                }
            }
            if slot
                .state
                .compare_exchange(
                    if spins == 0 {
                        WAITER_PREPARING
                    } else {
                        WAITER_SPINNING
                    },
                    WAITER_WAITING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                drop(registration);
                continue;
            }
            registration
                .waiting
                .fetch_or(registration.mask, Ordering::AcqRel);
            match self.try_recv() {
                Ok(value) => return Ok(value),
                Err(TryRecvError::Disconnected) => return Err(RecvError),
                Err(TryRecvError::Empty) => {}
            }
            if slot.state.load(Ordering::Acquire) == WAITER_WAITING {
                P::park_current();
            }
            drop(registration);
        }
    }

    pub fn try_recv(&self) -> Result<T, TryRecvError> {
        loop {
            match self.try_recv_wait_free() {
                Ok(value) => return Ok(value),
                Err(WaitFreeRecvError::Empty) => return Err(TryRecvError::Empty),
                Err(WaitFreeRecvError::Disconnected) => return Err(TryRecvError::Disconnected),
                Err(WaitFreeRecvError::Contended) if GROWABLE => wait_for_segment_writer(),
                Err(WaitFreeRecvError::Contended) => core::hint::spin_loop(),
            }
        }
    }

    pub fn try_recv_wait_free(&self) -> Result<T, WaitFreeRecvError> {
        match self.inner.queue.try_pop_wait_free() {
            Ok(value) => Ok(value),
            Err(BoundedMpmcPopError::Contended) => Err(WaitFreeRecvError::Contended),
            Err(BoundedMpmcPopError::Empty) if self.is_disconnected() => self
                .inner
                .queue
                .try_pop_wait_free()
                .map_err(|err| match err {
                    BoundedMpmcPopError::Empty => WaitFreeRecvError::Disconnected,
                    BoundedMpmcPopError::Contended => WaitFreeRecvError::Contended,
                }),
            Err(BoundedMpmcPopError::Empty) => Err(WaitFreeRecvError::Empty),
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

impl<P: Platform, T, const GROWABLE: bool> Clone for Receiver<P, T, GROWABLE> {
    fn clone(&self) -> Self {
        self.inner.receiver_count.fetch_add(1, Ordering::AcqRel);
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<P: Platform, T, const GROWABLE: bool> Drop for Receiver<P, T, GROWABLE> {
    fn drop(&mut self) {
        if self.inner.receiver_count.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.inner.closed.store(true, Ordering::Release);
        }
    }
}

unsafe impl<P: Platform, T: Send, const GROWABLE: bool> Send for Sender<P, T, GROWABLE> {}
unsafe impl<P: Platform, T: Send, const GROWABLE: bool> Sync for Sender<P, T, GROWABLE> {}
unsafe impl<P: Platform, T: Send, const GROWABLE: bool> Send for Receiver<P, T, GROWABLE> {}
unsafe impl<P: Platform, T: Send, const GROWABLE: bool> Sync for Receiver<P, T, GROWABLE> {}
