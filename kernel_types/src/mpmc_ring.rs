use alloc::boxed::Box;
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RingError {
    Full,
    Empty,
    Contended,
    BadCapacity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TryPushError<T> {
    Full(T),
    Contended(T),
}

impl<T> TryPushError<T> {
    #[inline]
    pub fn into_inner(self) -> T {
        match self {
            Self::Full(value) | Self::Contended(value) => value,
        }
    }

    #[inline]
    pub fn kind(&self) -> RingError {
        match self {
            Self::Full(_) => RingError::Full,
            Self::Contended(_) => RingError::Contended,
        }
    }
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
    slots: Box<[Slot<T>]>,
}

unsafe impl<T: Send, const CAP: usize> Send for MpmcRing<T, CAP> {}
unsafe impl<T: Send, const CAP: usize> Sync for MpmcRing<T, CAP> {}

impl<T, const CAP: usize> MpmcRing<T, CAP> {
    pub fn new() -> Self {
        assert!(CAP > 1);
        assert!(CAP <= isize::MAX as usize);

        let mut slots = Box::<[Slot<T>]>::new_uninit_slice(CAP);
        for (i, slot) in slots.iter_mut().enumerate() {
            slot.write(Slot {
                sequence: AtomicUsize::new(i),
                value: UnsafeCell::new(MaybeUninit::uninit()),
            });
        }
        let slots = unsafe { slots.assume_init() };

        Self {
            enqueue_pos: CachePadded(AtomicUsize::new(0)),
            dequeue_pos: CachePadded(AtomicUsize::new(0)),
            slots,
        }
    }

    pub fn try_push(&self, value: T) -> Result<(), TryPushError<T>> {
        let pos = self.enqueue_pos.0.load(Ordering::Relaxed);
        let slot = &self.slots[pos % CAP];
        let seq = slot.sequence.load(Ordering::Acquire);
        let diff = seq.wrapping_sub(pos) as isize;

        if diff == 0 {
            match self.enqueue_pos.0.compare_exchange(
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
                    Ok(())
                }
                Err(_) => Err(TryPushError::Contended(value)),
            }
        } else if diff < 0 {
            Err(TryPushError::Full(value))
        } else {
            Err(TryPushError::Contended(value))
        }
    }

    pub fn push(&self, mut value: T) -> Result<(), T> {
        loop {
            match self.try_push(value) {
                Ok(()) => return Ok(()),
                Err(TryPushError::Full(value)) => return Err(value),
                Err(TryPushError::Contended(next_value)) => {
                    value = next_value;
                    core::hint::spin_loop();
                }
            }
        }
    }

    pub fn try_pop(&self) -> Result<T, RingError> {
        let pos = self.dequeue_pos.0.load(Ordering::Relaxed);
        let slot = &self.slots[pos % CAP];
        let seq = slot.sequence.load(Ordering::Acquire);
        let diff = seq.wrapping_sub(pos.wrapping_add(1)) as isize;

        if diff == 0 {
            match self.dequeue_pos.0.compare_exchange(
                pos,
                pos.wrapping_add(1),
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    let value = unsafe { (*slot.value.get()).assume_init_read() };
                    slot.sequence
                        .store(pos.wrapping_add(CAP), Ordering::Release);
                    Ok(value)
                }
                Err(_) => Err(RingError::Contended),
            }
        } else if diff < 0 {
            Err(RingError::Empty)
        } else {
            Err(RingError::Contended)
        }
    }

    pub fn pop(&self) -> Option<T> {
        loop {
            match self.try_pop() {
                Ok(value) => return Some(value),
                Err(RingError::Empty) => return None,
                Err(RingError::Contended) => core::hint::spin_loop(),
                Err(RingError::Full | RingError::BadCapacity) => unreachable!(),
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
        while self.pop().is_some() {}
    }
}
