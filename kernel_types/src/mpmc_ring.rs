use core::array;
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RingError {
    Full,
    Empty,
    BadCapacity,
}

#[repr(align(64))]
pub struct CachePadded<T>(pub T);

struct Slot<T> {
    sequence: AtomicUsize,
    value: UnsafeCell<MaybeUninit<T>>,
}

pub struct MpmcRing<T, const CAP: usize> {
    enqueue_pos: CachePadded<AtomicUsize>,
    dequeue_pos: CachePadded<AtomicUsize>,
    slots: [Slot<T>; CAP],
}

unsafe impl<T: Send, const CAP: usize> Send for MpmcRing<T, CAP> {}
unsafe impl<T: Send, const CAP: usize> Sync for MpmcRing<T, CAP> {}

impl<T, const CAP: usize> MpmcRing<T, CAP> {
    pub fn new() -> Self {
        assert!(CAP > 0);
        assert!(CAP <= isize::MAX as usize);

        Self {
            enqueue_pos: CachePadded(AtomicUsize::new(0)),
            dequeue_pos: CachePadded(AtomicUsize::new(0)),
            slots: array::from_fn(|i| Slot {
                sequence: AtomicUsize::new(i),
                value: UnsafeCell::new(MaybeUninit::uninit()),
            }),
        }
    }

    pub fn try_push(&self, value: T) -> Result<(), T> {
        let mut pos = self.enqueue_pos.0.load(Ordering::Relaxed);

        loop {
            let slot = &self.slots[pos % CAP];
            let seq = slot.sequence.load(Ordering::Acquire);
            let diff = seq.wrapping_sub(pos) as isize;

            if diff == 0 {
                match self.enqueue_pos.0.compare_exchange_weak(
                    pos,
                    pos.wrapping_add(1),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        unsafe {
                            (*slot.value.get()).write(value);
                        }

                        slot.sequence.store(pos.wrapping_add(1), Ordering::Release);
                        return Ok(());
                    }
                    Err(next) => {
                        pos = next;
                    }
                }
            } else if diff < 0 {
                return Err(value);
            } else {
                pos = self.enqueue_pos.0.load(Ordering::Relaxed);
            }
        }
    }

    pub fn try_pop(&self) -> Option<T> {
        let mut pos = self.dequeue_pos.0.load(Ordering::Relaxed);

        loop {
            let slot = &self.slots[pos % CAP];
            let seq = slot.sequence.load(Ordering::Acquire);
            let diff = seq.wrapping_sub(pos.wrapping_add(1)) as isize;

            if diff == 0 {
                match self.dequeue_pos.0.compare_exchange_weak(
                    pos,
                    pos.wrapping_add(1),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        let value = unsafe { (*slot.value.get()).assume_init_read() };
                        slot.sequence
                            .store(pos.wrapping_add(CAP), Ordering::Release);
                        return Some(value);
                    }
                    Err(next) => {
                        pos = next;
                    }
                }
            } else if diff < 0 {
                return None;
            } else {
                pos = self.dequeue_pos.0.load(Ordering::Relaxed);
            }
        }
    }

    pub fn capacity(&self) -> usize {
        CAP
    }

    pub fn len_approx(&self) -> usize {
        let enqueue = self.enqueue_pos.0.load(Ordering::Acquire);
        let dequeue = self.dequeue_pos.0.load(Ordering::Acquire);
        enqueue.wrapping_sub(dequeue).min(CAP)
    }

    pub fn is_empty_approx(&self) -> bool {
        self.len_approx() == 0
    }

    pub fn is_full_approx(&self) -> bool {
        self.len_approx() == CAP
    }
}

impl<T, const CAP: usize> Drop for MpmcRing<T, CAP> {
    fn drop(&mut self) {
        while self.try_pop().is_some() {}
    }
}
