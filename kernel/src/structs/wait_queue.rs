//! Wait queue for blocking synchronization primitives (SegQueue-based).
//!
//! This implementation uses `crossbeam_queue::SegQueue` for a lock-free MPMC queue.
//! Membership/duplication is still enforced with `TaskRef.wait_next` as a per-task
//! "queued on queue_id" flag.
//!
//! Notes:
//! - Because SegQueue cannot remove arbitrary elements, a task that cancels its wait
//!   (permit arrives before it actually blocks) may leave a stale entry in the queue.
//!   Dequeue filters these by checking/clearing `wait_next` atomically.

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use alloc::vec::Vec;
use crossbeam_queue::SegQueue;

use crate::drivers::interrupt_index::current_cpu_id;
use crate::scheduling::scheduler::SCHEDULER;
use crate::scheduling::task::{TaskHandle, WAIT_QUEUE_NONE};

static NEXT_WAIT_QUEUE_ID: AtomicU64 = AtomicU64::new(1);

fn alloc_wait_queue_id() -> u64 {
    NEXT_WAIT_QUEUE_ID.fetch_add(1, Ordering::Relaxed)
}

pub struct WaitQueue {
    id: u64,
    q: SegQueue<TaskHandle>,
    len: AtomicUsize,
}

impl WaitQueue {
    pub fn new() -> Self {
        Self {
            id: alloc_wait_queue_id(),
            q: SegQueue::new(),
            len: AtomicUsize::new(0),
        }
    }

    #[inline]
    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn enqueue_current(&self) -> bool {
        let cpu_id = current_cpu_id() as usize;
        let current = match SCHEDULER.get_current_task(cpu_id) {
            Some(t) => t,
            None => return false,
        };
        self.enqueue(&current)
    }

    pub fn enqueue(&self, task: &TaskHandle) -> bool {
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
            return false;
        }

        self.len.fetch_add(1, Ordering::Release);
        self.q.push(task.clone());
        true
    }

    pub fn dequeue_one(&self) -> Option<TaskHandle> {
        loop {
            let task = self.q.pop()?;

            if task
                .wait_next
                .compare_exchange(
                    self.id,
                    WAIT_QUEUE_NONE,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                self.len.fetch_sub(1, Ordering::Release);
                return Some(task);
            }
        }
    }

    pub fn dequeue_all(&self) -> Vec<TaskHandle> {
        let mut out = Vec::new();
        while let Some(t) = self.dequeue_one() {
            out.push(t);
        }
        out
    }

    pub fn is_current_enqueued(&self) -> bool {
        let cpu_id = current_cpu_id() as usize;
        let current = match SCHEDULER.get_current_task(cpu_id) {
            Some(t) => t,
            None => return false,
        };
        current.wait_next.load(Ordering::Acquire) == self.id
    }

    pub fn clear_current_if_queued(&self) -> bool {
        let cpu_id = current_cpu_id() as usize;
        let current = match SCHEDULER.get_current_task(cpu_id) {
            Some(t) => t,
            None => return false,
        };

        if current
            .wait_next
            .compare_exchange(
                self.id,
                WAIT_QUEUE_NONE,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            self.len.fetch_sub(1, Ordering::Release);
            true
        } else {
            false
        }
    }

    pub fn len(&self) -> usize {
        self.len.load(Ordering::Acquire)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for WaitQueue {
    fn default() -> Self {
        Self::new()
    }
}

unsafe impl Send for WaitQueue {}
unsafe impl Sync for WaitQueue {}
