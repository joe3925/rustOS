use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::drivers::interrupt_index::current_cpu_id;
use crate::scheduling::scheduler::SCHEDULER;
use crate::scheduling::task::{TaskHandle, WAIT_QUEUE_NONE};

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

struct WaitSlot {
    state: AtomicUsize,
    task: UnsafeCell<Option<TaskHandle>>,
}

impl WaitSlot {
    const fn new() -> Self {
        Self {
            state: AtomicUsize::new(SLOT_EMPTY),
            task: UnsafeCell::new(None),
        }
    }

    #[inline]
    unsafe fn write_task(&self, task: TaskHandle) {
        *self.task.get() = Some(task);
    }

    #[inline]
    unsafe fn take_task(&self) -> Option<TaskHandle> {
        (*self.task.get()).take()
    }

    #[inline]
    unsafe fn task_is(&self, target: &TaskHandle) -> bool {
        match (*self.task.get()).as_ref() {
            Some(task) => Arc::ptr_eq(task, target),
            None => false,
        }
    }
}

unsafe impl Send for WaitSlot {}
unsafe impl Sync for WaitSlot {}

pub struct BoundedWaitQueue {
    id: u64,
    slots: Vec<WaitSlot>,
    enqueue_hint: AtomicUsize,
    dequeue_hint: AtomicUsize,
    len: AtomicUsize,
}

impl BoundedWaitQueue {
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
        let cpu_id = current_cpu_id();

        let current = match SCHEDULER.get_current_task(cpu_id) {
            Some(task) => task,
            None => return Err(BoundedWaitQueueError::NoCurrentTask),
        };

        self.enqueue(&current)
    }

    pub fn enqueue(&self, task: &TaskHandle) -> Result<(), BoundedWaitQueueError> {
        if task
            .wait_next
            .compare_exchange(
                WAIT_QUEUE_NONE,
                self.id,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
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

        let _ = task.wait_next.compare_exchange(
            self.id,
            WAIT_QUEUE_NONE,
            Ordering::AcqRel,
            Ordering::Acquire,
        );

        Err(BoundedWaitQueueError::Full)
    }

    pub fn dequeue_one(&self) -> Option<TaskHandle> {
        let cap = self.slots.len();
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
            let _ = task.wait_next.compare_exchange(
                self.id,
                WAIT_QUEUE_NONE,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            return Some(task);
        }
        None
    }
    pub fn wake_one(&self) -> bool {
        let task = match self.dequeue_one() {
            Some(task) => task,
            None => return false,
        };

        SCHEDULER.unpark(&task);
        true
    }

    pub fn wake_all(&self) -> usize {
        let mut count = 0usize;

        while let Some(task) = self.dequeue_one() {
            SCHEDULER.unpark(&task);
            count += 1;
        }

        count
    }

    pub fn is_current_enqueued(&self) -> bool {
        let cpu_id = current_cpu_id();

        let current = match SCHEDULER.get_current_task(cpu_id) {
            Some(task) => task,
            None => return false,
        };

        current.wait_next.load(Ordering::Acquire) == self.id
    }

    pub fn clear_current_if_queued(&self) -> bool {
        let cpu_id = current_cpu_id();
        let current = match SCHEDULER.get_current_task(cpu_id) {
            Some(task) => task,
            None => return false,
        };
        if current.wait_next.load(Ordering::Acquire) != self.id {
            return false;
        }
        let cap = self.slots.len();
        for idx in 0..cap {
            let slot = &self.slots[idx];
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
                let _ = current.wait_next.compare_exchange(
                    self.id,
                    WAIT_QUEUE_NONE,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
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

unsafe impl Send for BoundedWaitQueue {}
unsafe impl Sync for BoundedWaitQueue {}
