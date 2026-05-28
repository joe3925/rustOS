use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::platform::Platform;

static NEXT_BOUNDED_WAIT_QUEUE_ID: AtomicU64 = AtomicU64::new(1);

const SLOT_EMPTY: usize = 0;
const SLOT_RESERVED: usize = 1;
const SLOT_WAITING: usize = 2;
const SLOT_WAKING: usize = 3;
const SLOT_CLEARING: usize = 4;

fn alloc_wait_queue_id() -> u64 {
    NEXT_BOUNDED_WAIT_QUEUE_ID.fetch_add(1, Ordering::Relaxed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundedWaitQueueError {
    NoCurrentTask,
    AlreadyQueued,
    Full,
}

struct WaitSlot<P: Platform> {
    state: AtomicUsize,
    task_id: AtomicU64,
    task: UnsafeCell<Option<P::Task>>,
}

impl<P: Platform> WaitSlot<P> {
    const fn new() -> Self {
        Self {
            state: AtomicUsize::new(SLOT_EMPTY),
            task_id: AtomicU64::new(0),
            task: UnsafeCell::new(None),
        }
    }

    #[inline]
    unsafe fn write_task(&self, task: P::Task) {
        self.task_id.store(P::task_id(&task), Ordering::Release);
        *self.task.get() = Some(task);
    }

    #[inline]
    unsafe fn take_task(&self) -> Option<P::Task> {
        let task = (*self.task.get()).take();
        self.task_id.store(0, Ordering::Release);
        task
    }

    #[inline]
    fn task_id(&self) -> u64 {
        self.task_id.load(Ordering::Acquire)
    }

    #[inline]
    unsafe fn task_is(&self, target: &P::Task) -> bool {
        match (*self.task.get()).as_ref() {
            Some(task) => P::same_task(task, target),
            None => false,
        }
    }
}

unsafe impl<P: Platform> Send for WaitSlot<P> {}
unsafe impl<P: Platform> Sync for WaitSlot<P> {}

pub struct BoundedWaitQueue<P: Platform> {
    id: u64,
    slots: Vec<WaitSlot<P>>,
    enqueue_hint: AtomicUsize,
    dequeue_hint: AtomicUsize,
    len: AtomicUsize,
}

impl<P: Platform> BoundedWaitQueue<P> {
    pub fn new(max_waiters: usize) -> Self {
        assert!(max_waiters > 0);

        let mut slots = Vec::with_capacity(max_waiters);
        for _ in 0..max_waiters {
            slots.push(WaitSlot::new());
        }

        Self {
            id: alloc_wait_queue_id(),
            slots,
            enqueue_hint: AtomicUsize::new(0),
            dequeue_hint: AtomicUsize::new(0),
            len: AtomicUsize::new(0),
        }
    }

    #[inline]
    pub fn id(&self) -> u64 {
        self.id
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.slots.len()
    }

    pub fn enqueue_current(&self) -> Result<(), BoundedWaitQueueError> {
        let current = match P::current_task() {
            Some(task) => task,
            None => return Err(BoundedWaitQueueError::NoCurrentTask),
        };

        self.enqueue(&current)
    }

    pub fn enqueue(&self, task: &P::Task) -> Result<(), BoundedWaitQueueError> {
        if !P::mark_waiting(task, self.id) {
            return Err(BoundedWaitQueueError::AlreadyQueued);
        }

        let cap = self.slots.len();
        let start = self.enqueue_hint.fetch_add(1, Ordering::Relaxed);

        for offset in 0..cap {
            let idx = (start + offset) % cap;
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
                slot.write_task(task.clone());
            }

            self.len.fetch_add(1, Ordering::Release);
            slot.state.store(SLOT_WAITING, Ordering::Release);
            return Ok(());
        }

        let _ = P::clear_waiting(task, self.id);
        Err(BoundedWaitQueueError::Full)
    }

    pub fn dequeue_one(&self) -> Option<P::Task> {
        let cap = self.slots.len();
        loop {
            if self.len.load(Ordering::Acquire) == 0 {
                return None;
            }

            let start = self.dequeue_hint.fetch_add(1, Ordering::Relaxed);
            for offset in 0..cap {
                let idx = (start + offset) % cap;
                let slot = &self.slots[idx];
                if slot
                    .state
                    .compare_exchange(
                        SLOT_WAITING,
                        SLOT_WAKING,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_err()
                {
                    continue;
                }
                let task = unsafe { slot.take_task() };
                slot.state.store(SLOT_EMPTY, Ordering::Release);
                self.len.fetch_sub(1, Ordering::Release);
                let task = match task {
                    Some(task) => task,
                    None => continue,
                };
                let _ = P::clear_waiting(&task, self.id);
                return Some(task);
            }

            P::spin_loop();
        }
    }

    pub fn wake_one(&self) -> bool {
        let task = match self.dequeue_one() {
            Some(task) => task,
            None => return false,
        };

        P::unpark(&task);
        true
    }

    pub fn wake_all(&self) -> usize {
        let mut count = 0usize;

        while let Some(task) = self.dequeue_one() {
            P::unpark(&task);
            count += 1;
        }

        count
    }

    pub fn is_current_enqueued(&self) -> bool {
        let current = match P::current_task() {
            Some(task) => task,
            None => return false,
        };

        P::is_waiting(&current, self.id)
    }

    pub fn clear_current_if_queued(&self) -> bool {
        let current = match P::current_task() {
            Some(task) => task,
            None => return false,
        };

        if !P::is_waiting(&current, self.id) {
            return false;
        }

        let current_id = P::task_id(&current);
        let cap = self.slots.len();
        for idx in 0..cap {
            let slot = &self.slots[idx];
            if slot.task_id() != current_id {
                continue;
            }

            if slot
                .state
                .compare_exchange(
                    SLOT_WAITING,
                    SLOT_CLEARING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                continue;
            }

            let is_target = unsafe { slot.task_is(&current) };
            if is_target {
                let _ = unsafe { slot.take_task() };
                slot.state.store(SLOT_EMPTY, Ordering::Release);
                self.len.fetch_sub(1, Ordering::Release);
                let _ = P::clear_waiting(&current, self.id);
                return true;
            }
            slot.state.store(SLOT_WAITING, Ordering::Release);
        }
        false
    }

    pub fn len(&self) -> usize {
        self.len.load(Ordering::Acquire)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

unsafe impl<P: Platform> Send for BoundedWaitQueue<P> {}
unsafe impl<P: Platform> Sync for BoundedWaitQueue<P> {}
