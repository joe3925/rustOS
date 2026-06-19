use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicUsize, Ordering};

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

pub struct BoundedMpmcQueue<T> {
    slots: Vec<QueueSlot<T>>,
    push_pos: AtomicUsize,
    pop_pos: AtomicUsize,
    len: AtomicUsize,
}

impl<T> BoundedMpmcQueue<T> {
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

    pub fn try_pop(&self) -> Option<T> {
        loop {
            match self.try_pop_wait_free() {
                Ok(value) => return Some(value),
                Err(BoundedMpmcPopError::Empty) => return None,
                Err(BoundedMpmcPopError::Contended) => core::hint::spin_loop(),
            }
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

impl<T> Drop for BoundedMpmcQueue<T> {
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

unsafe impl<T: Send> Send for BoundedMpmcQueue<T> {}
unsafe impl<T: Send> Sync for BoundedMpmcQueue<T> {}

#[inline]
fn sequence_diff(a: usize, b: usize) -> isize {
    a.wrapping_sub(b) as isize
}
