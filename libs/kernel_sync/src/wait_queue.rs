use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::platform::Platform;
use kernel_types::io::TreiberStack;
static NEXT_WAIT_QUEUE_ID: AtomicU64 = AtomicU64::new(1);

fn alloc_wait_queue_id() -> u64 {
    NEXT_WAIT_QUEUE_ID.fetch_add(1, Ordering::Relaxed)
}

pub struct WaitQueue<P: Platform> {
    id: u64,
    q: TreiberStack<P::Task>,
    len: AtomicUsize,
}

impl<P: Platform> WaitQueue<P> {
    pub fn new() -> Self {
        Self {
            id: alloc_wait_queue_id(),
            q: TreiberStack::new(),
            len: AtomicUsize::new(0),
        }
    }

    #[inline]
    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn enqueue_current(&self) -> bool {
        let current = match P::current_task() {
            Some(t) => t,
            None => return false,
        };
        self.enqueue(&current)
    }

    pub fn enqueue(&self, task: &P::Task) -> bool {
        if !P::mark_waiting(task, self.id) {
            return false;
        }

        self.len.fetch_add(1, Ordering::Release);
        self.q.push(task.clone());
        true
    }

    pub fn dequeue_one(&self) -> Option<P::Task> {
        loop {
            let task = self.q.pop()?;

            if P::clear_waiting(&task, self.id) {
                self.len.fetch_sub(1, Ordering::Release);
                return Some(task);
            }
        }
    }

    pub fn dequeue_all(&self) -> Vec<P::Task> {
        let mut out = Vec::new();
        while let Some(t) = self.dequeue_one() {
            out.push(t);
        }
        out
    }

    pub fn is_current_enqueued(&self) -> bool {
        let current = match P::current_task() {
            Some(t) => t,
            None => return false,
        };
        P::is_waiting(&current, self.id)
    }

    pub fn clear_current_if_queued(&self) -> bool {
        let current = match P::current_task() {
            Some(t) => t,
            None => return false,
        };

        if P::clear_waiting(&current, self.id) {
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

impl<P: Platform> Default for WaitQueue<P> {
    fn default() -> Self {
        Self::new()
    }
}

unsafe impl<P: Platform> Send for WaitQueue<P> {}
unsafe impl<P: Platform> Sync for WaitQueue<P> {}
