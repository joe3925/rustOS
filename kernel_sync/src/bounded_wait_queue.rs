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
const SLOT_CANCELING: usize = 5;

fn alloc_wait_queue_id() -> u64 {
    NEXT_BOUNDED_WAIT_QUEUE_ID.fetch_add(1, Ordering::Relaxed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundedWaitQueueError {
    NoCurrentTask,
    AlreadyQueued,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundedWaitQueueEnqueue {
    Queued,
    Woken,
}

enum WakeResult<P: Platform> {
    None,
    CanceledReserved,
    Task(P::Task),
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
        let id = P::task_id(&task);
        *self.task.get() = Some(task);
        self.task_id.store(id, Ordering::Release);
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

    pub fn enqueue_current(&self) -> Result<BoundedWaitQueueEnqueue, BoundedWaitQueueError> {
        let current = match P::current_task() {
            Some(task) => task,
            None => return Err(BoundedWaitQueueError::NoCurrentTask),
        };

        self.enqueue(&current)
    }

    pub fn enqueue(
        &self,
        task: &P::Task,
    ) -> Result<BoundedWaitQueueEnqueue, BoundedWaitQueueError> {
        if !P::mark_waiting(task, self.id) {
            return Err(BoundedWaitQueueError::AlreadyQueued);
        }

        let cap = self.slots.len();
        let start = self.enqueue_hint.fetch_add(1, Ordering::Relaxed);

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

            self.len.fetch_add(1, Ordering::Release);

            if slot.state.load(Ordering::Acquire) == SLOT_CANCELING {
                slot.state.store(SLOT_EMPTY, Ordering::Release);
                self.len.fetch_sub(1, Ordering::Release);
                let _ = P::clear_waiting(task, self.id);
                return Ok(BoundedWaitQueueEnqueue::Woken);
            }

            unsafe {
                slot.write_task(task.clone());
            }

            match slot.state.compare_exchange(
                SLOT_RESERVED,
                SLOT_WAITING,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(BoundedWaitQueueEnqueue::Queued),
                Err(SLOT_CANCELING) => {
                    let _ = unsafe { slot.take_task() };
                    slot.state.store(SLOT_EMPTY, Ordering::Release);
                    self.len.fetch_sub(1, Ordering::Release);
                    let _ = P::clear_waiting(task, self.id);
                    return Ok(BoundedWaitQueueEnqueue::Woken);
                }
                Err(_) => {
                    let _ = unsafe { slot.take_task() };
                    slot.state.store(SLOT_EMPTY, Ordering::Release);
                    self.len.fetch_sub(1, Ordering::Release);
                    let _ = P::clear_waiting(task, self.id);
                    panic!("bounded wait queue slot corrupted during enqueue");
                }
            }
        }

        let _ = P::clear_waiting(task, self.id);
        Err(BoundedWaitQueueError::Full)
    }

    fn dequeue_one_for_wake(&self) -> WakeResult<P> {
        let cap = self.slots.len();
        let start = self.dequeue_hint.fetch_add(1, Ordering::Relaxed);

        for offset in 0..cap {
            let idx = start.wrapping_add(offset) % cap;
            let slot = &self.slots[idx];

            if slot
                .state
                .compare_exchange(
                    SLOT_WAITING,
                    SLOT_WAKING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                let task = unsafe { slot.take_task() };
                slot.state.store(SLOT_EMPTY, Ordering::Release);
                self.len.fetch_sub(1, Ordering::Release);

                let Some(task) = task else {
                    return WakeResult::None;
                };

                let _ = P::clear_waiting(&task, self.id);
                return WakeResult::Task(task);
            }

            if slot
                .state
                .compare_exchange(
                    SLOT_RESERVED,
                    SLOT_CANCELING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                return WakeResult::CanceledReserved;
            }
        }

        WakeResult::None
    }

    pub fn dequeue_one(&self) -> Option<P::Task> {
        match self.dequeue_one_for_wake() {
            WakeResult::Task(task) => Some(task),
            WakeResult::None | WakeResult::CanceledReserved => None,
        }
    }

    pub fn wake_one(&self) -> bool {
        match self.dequeue_one_for_wake() {
            WakeResult::None => false,
            WakeResult::CanceledReserved => true,
            WakeResult::Task(task) => {
                P::unpark(&task);
                true
            }
        }
    }

    pub fn wake_all(&self) -> usize {
        let cap = self.slots.len();
        let start = self.dequeue_hint.fetch_add(cap, Ordering::Relaxed);
        let mut count = 0usize;

        for offset in 0..cap {
            let idx = start.wrapping_add(offset) % cap;
            let slot = &self.slots[idx];

            if slot
                .state
                .compare_exchange(
                    SLOT_WAITING,
                    SLOT_WAKING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                let task = unsafe { slot.take_task() };
                slot.state.store(SLOT_EMPTY, Ordering::Release);
                self.len.fetch_sub(1, Ordering::Release);

                if let Some(task) = task {
                    let _ = P::clear_waiting(&task, self.id);
                    P::unpark(&task);
                    count += 1;
                }

                continue;
            }

            if slot
                .state
                .compare_exchange(
                    SLOT_RESERVED,
                    SLOT_CANCELING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                count += 1;
            }
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
