use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundedMpmcPushError<T> {
    Full(T),
    Contended(T),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundedMpmcPopError {
    Empty,
    Contended,
}

struct QueueSlot<T> {
    sequence: AtomicUsize,
    value: UnsafeCell<MaybeUninit<T>>,
}

impl<T> QueueSlot<T> {
    fn new(sequence: usize) -> Self {
        Self {
            sequence: AtomicUsize::new(sequence),
            value: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    #[inline]
    unsafe fn write_value(&self, value: T) {
        unsafe {
            (*self.value.get()).write(value);
        }
    }

    #[inline]
    unsafe fn read_value(&self) -> T {
        unsafe { (*self.value.get()).assume_init_read() }
    }

    #[inline]
    unsafe fn drop_value(&self) {
        unsafe {
            (*self.value.get()).assume_init_drop();
        }
    }
}

unsafe impl<T: Send> Send for QueueSlot<T> {}
unsafe impl<T: Send> Sync for QueueSlot<T> {}

struct MpmcRing<T> {
    slots: Vec<QueueSlot<T>>,
    push_pos: AtomicUsize,
    pop_pos: AtomicUsize,
    len: AtomicUsize,
}

impl<T> MpmcRing<T> {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0);
        assert!(capacity <= isize::MAX as usize);

        let mut slots = Vec::with_capacity(capacity);

        for i in 0..capacity {
            slots.push(QueueSlot::new(i));
        }

        Self {
            slots,
            push_pos: AtomicUsize::new(0),
            pop_pos: AtomicUsize::new(0),
            len: AtomicUsize::new(0),
        }
    }

    pub fn try_push_wait_free(&self, value: T) -> Result<(), BoundedMpmcPushError<T>> {
        let cap = self.slots.len();
        let len = self.len.load(Ordering::Acquire);

        if len >= cap {
            return Err(BoundedMpmcPushError::Full(value));
        }

        if self
            .len
            .compare_exchange(len, len + 1, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(BoundedMpmcPushError::Contended(value));
        }

        let pos = self.push_pos.load(Ordering::Relaxed);
        let slot = &self.slots[pos % cap];

        let seq = slot.sequence.load(Ordering::Acquire);
        let diff = sequence_diff(seq, pos);

        if diff == 0 {
            if self
                .push_pos
                .compare_exchange(
                    pos,
                    pos.wrapping_add(1),
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_err()
            {
                self.len.fetch_sub(1, Ordering::Release);
                return Err(BoundedMpmcPushError::Contended(value));
            }

            unsafe {
                slot.write_value(value);
            }

            slot.sequence.store(pos.wrapping_add(1), Ordering::Release);
            Ok(())
        } else if diff < 0 {
            self.len.fetch_sub(1, Ordering::Release);
            Err(BoundedMpmcPushError::Full(value))
        } else {
            self.len.fetch_sub(1, Ordering::Release);
            Err(BoundedMpmcPushError::Contended(value))
        }
    }

    pub fn try_pop_wait_free(&self) -> Result<T, BoundedMpmcPopError> {
        let cap = self.slots.len();
        let pos = self.pop_pos.load(Ordering::Relaxed);
        let slot = &self.slots[pos % cap];

        let seq = slot.sequence.load(Ordering::Acquire);
        let diff = sequence_diff(seq, pos.wrapping_add(1));

        if diff == 0 {
            if self
                .pop_pos
                .compare_exchange(
                    pos,
                    pos.wrapping_add(1),
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_err()
            {
                return Err(BoundedMpmcPopError::Contended);
            }

            let value = unsafe { slot.read_value() };

            slot.sequence
                .store(pos.wrapping_add(cap), Ordering::Release);

            self.len.fetch_sub(1, Ordering::Release);

            Ok(value)
        } else if diff < 0 {
            Err(BoundedMpmcPopError::Empty)
        } else {
            Err(BoundedMpmcPopError::Contended)
        }
    }
    pub fn capacity(&self) -> usize {
        self.slots.len()
    }

    pub fn len(&self) -> usize {
        self.len.load(Ordering::Acquire)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn is_full(&self) -> bool {
        self.len() >= self.capacity()
    }
}

impl<T> Drop for MpmcRing<T> {
    fn drop(&mut self) {
        let cap = self.slots.len();
        let head = self.pop_pos.load(Ordering::Relaxed);
        let tail = self.push_pos.load(Ordering::Relaxed);
        let count = tail.wrapping_sub(head).min(cap);

        for offset in 0..count {
            let pos = head.wrapping_add(offset);
            let slot = &self.slots[pos % cap];

            if slot.sequence.load(Ordering::Acquire) == pos.wrapping_add(1) {
                unsafe {
                    slot.drop_value();
                }

                slot.sequence
                    .store(pos.wrapping_add(cap), Ordering::Release);
            }
        }
    }
}

const SEGMENT_CLOSED: usize = 1 << (usize::BITS - 1);

struct QueueSegment<T> {
    ring: MpmcRing<T>,
    next: AtomicPtr<QueueSegment<T>>,
    writers: AtomicUsize,
}

pub struct MpmcQueue<T> {
    first: *mut QueueSegment<T>,
    head: AtomicPtr<QueueSegment<T>>,
    tail: AtomicPtr<QueueSegment<T>>,
    len: AtomicUsize,
    growable: bool,
}

pub type BoundedMpmcQueue<T> = MpmcQueue<T>;

impl<T> MpmcQueue<T> {
    pub fn new(capacity: usize) -> Self {
        Self::with_growth(capacity, false)
    }

    pub fn with_growth(capacity: usize, growable: bool) -> Self {
        let first = Box::into_raw(Box::new(QueueSegment {
            ring: MpmcRing::new(capacity),
            next: AtomicPtr::new(ptr::null_mut()),
            writers: AtomicUsize::new(0),
        }));
        Self {
            first,
            head: AtomicPtr::new(first),
            tail: AtomicPtr::new(first),
            len: AtomicUsize::new(0),
            growable,
        }
    }

    pub fn try_push_wait_free(&self, value: T) -> Result<(), BoundedMpmcPushError<T>> {
        let tail = self.tail.load(Ordering::Acquire);
        let segment = unsafe { &*tail };
        if self.growable {
            let next = segment.next.load(Ordering::Acquire);
            if !next.is_null() {
                segment.writers.fetch_or(SEGMENT_CLOSED, Ordering::AcqRel);
                let _ = self
                    .tail
                    .compare_exchange(tail, next, Ordering::AcqRel, Ordering::Acquire);
                return Err(BoundedMpmcPushError::Contended(value));
            }
            let writers = segment.writers.load(Ordering::Acquire);
            if writers & SEGMENT_CLOSED != 0 || writers == SEGMENT_CLOSED - 1 {
                return Err(BoundedMpmcPushError::Contended(value));
            }
            if segment
                .writers
                .compare_exchange(writers, writers + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return Err(BoundedMpmcPushError::Contended(value));
            }
        }
        self.len.fetch_add(1, Ordering::AcqRel);
        let result = segment.ring.try_push_wait_free(value);
        if result.is_err() {
            self.len.fetch_sub(1, Ordering::AcqRel);
        }
        if self.growable {
            segment.writers.fetch_sub(1, Ordering::Release);
        }
        result
    }

    pub fn try_push(&self, mut value: T) -> Result<(), BoundedMpmcPushError<T>> {
        loop {
            match self.try_push_wait_free(value) {
                Ok(()) => return Ok(()),
                Err(BoundedMpmcPushError::Full(value)) => {
                    return Err(BoundedMpmcPushError::Full(value));
                }
                Err(BoundedMpmcPushError::Contended(next_value)) => {
                    value = next_value;
                    core::hint::spin_loop();
                }
            }
        }
    }

    pub fn grow(&self) -> usize {
        let tail = self.tail.load(Ordering::Acquire);
        let segment = unsafe { &*tail };
        if !self.growable || !segment.ring.is_full() {
            return self.capacity();
        }
        let mut next = segment.next.load(Ordering::Acquire);
        if next.is_null() {
            let capacity = segment
                .ring
                .capacity()
                .checked_mul(2)
                .filter(|capacity| *capacity <= isize::MAX as usize)
                .expect("MPMC queue capacity overflow");
            let allocated = Box::into_raw(Box::new(QueueSegment {
                ring: MpmcRing::new(capacity),
                next: AtomicPtr::new(ptr::null_mut()),
                writers: AtomicUsize::new(0),
            }));
            next = match segment.next.compare_exchange(
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
        }
        segment.writers.fetch_or(SEGMENT_CLOSED, Ordering::AcqRel);
        let _ = self
            .tail
            .compare_exchange(tail, next, Ordering::AcqRel, Ordering::Acquire);
        unsafe { (*next).ring.capacity() }
    }

    pub fn try_pop_wait_free(&self) -> Result<T, BoundedMpmcPopError> {
        let head = self.head.load(Ordering::Acquire);
        let segment = unsafe { &*head };
        match segment.ring.try_pop_wait_free() {
            Ok(value) => {
                self.len.fetch_sub(1, Ordering::AcqRel);
                Ok(value)
            }
            Err(BoundedMpmcPopError::Contended) => Err(BoundedMpmcPopError::Contended),
            Err(BoundedMpmcPopError::Empty) => {
                let writers = segment.writers.load(Ordering::Acquire);
                if writers & SEGMENT_CLOSED == 0 {
                    return Err(BoundedMpmcPopError::Empty);
                }
                if writers & !SEGMENT_CLOSED != 0 || !segment.ring.is_empty() {
                    return Err(BoundedMpmcPopError::Contended);
                }
                let next = segment.next.load(Ordering::Acquire);
                if !next.is_null() {
                    let _ =
                        self.head
                            .compare_exchange(head, next, Ordering::AcqRel, Ordering::Acquire);
                }
                Err(BoundedMpmcPopError::Contended)
            }
        }
    }

    pub fn try_pop(&self) -> Option<T> {
        loop {
            match self.try_pop_wait_free() {
                Ok(value) => return Some(value),
                Err(BoundedMpmcPopError::Empty) => return None,
                Err(BoundedMpmcPopError::Contended) => core::hint::spin_loop(),
            }
        }
    }

    pub fn capacity(&self) -> usize {
        unsafe { (*self.tail.load(Ordering::Acquire)).ring.capacity() }
    }

    pub fn len(&self) -> usize {
        self.len.load(Ordering::Acquire)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn is_full(&self) -> bool {
        unsafe { (*self.tail.load(Ordering::Acquire)).ring.is_full() }
    }
}

impl<T> Drop for MpmcQueue<T> {
    fn drop(&mut self) {
        let mut segment = self.first;
        while !segment.is_null() {
            let owned = unsafe { Box::from_raw(segment) };
            segment = owned.next.load(Ordering::Relaxed);
            drop(owned);
        }
    }
}

unsafe impl<T: Send> Send for MpmcQueue<T> {}
unsafe impl<T: Send> Sync for MpmcQueue<T> {}

#[inline]
fn sequence_diff(a: usize, b: usize) -> isize {
    a.wrapping_sub(b) as isize
}
