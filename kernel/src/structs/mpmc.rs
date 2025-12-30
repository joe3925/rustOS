use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::hint::spin_loop;
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
use spin::RwLock;

use crate::memory::paging::stack::StackSize;
use crate::scheduling::scheduler::SCHEDULER;
use crate::scheduling::task::Task;
use crate::structs::thread_pool::Job;

struct Node {
    job: Option<Job>,
    next: AtomicPtr<Node>,
}

/// Lock-free MPMC queue using Michael-Scott algorithm variant
pub struct LockFreeQueue {
    head: AtomicPtr<Node>,
    tail: AtomicPtr<Node>,
    len: AtomicUsize,
}

impl LockFreeQueue {
    pub fn new() -> Self {
        let sentinel = Box::into_raw(Box::new(Node {
            job: None,
            next: AtomicPtr::new(ptr::null_mut()),
        }));
        Self {
            head: AtomicPtr::new(sentinel),
            tail: AtomicPtr::new(sentinel),
            len: AtomicUsize::new(0),
        }
    }

    pub fn push(&self, job: Job) {
        let node = Box::into_raw(Box::new(Node {
            job: Some(job),
            next: AtomicPtr::new(ptr::null_mut()),
        }));

        loop {
            let tail = self.tail.load(Ordering::Acquire);
            let tail_next = unsafe { (*tail).next.load(Ordering::Acquire) };

            if tail_next.is_null() {
                if unsafe {
                    (*tail)
                        .next
                        .compare_exchange(
                            ptr::null_mut(),
                            node,
                            Ordering::Release,
                            Ordering::Relaxed,
                        )
                        .is_ok()
                } {
                    let _ = self.tail.compare_exchange(
                        tail,
                        node,
                        Ordering::Release,
                        Ordering::Relaxed,
                    );
                    self.len.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            } else {
                let _ = self.tail.compare_exchange(
                    tail,
                    tail_next,
                    Ordering::Release,
                    Ordering::Relaxed,
                );
            }
        }
    }

    pub fn pop(&self) -> Option<Job> {
        loop {
            let head = self.head.load(Ordering::Acquire);
            let tail = self.tail.load(Ordering::Acquire);
            let head_next = unsafe { (*head).next.load(Ordering::Acquire) };

            if head == tail {
                if head_next.is_null() {
                    return None;
                }
                let _ = self.tail.compare_exchange(
                    tail,
                    head_next,
                    Ordering::Release,
                    Ordering::Relaxed,
                );
            } else {
                let job = unsafe { (*head_next).job };

                if self
                    .head
                    .compare_exchange(head, head_next, Ordering::Release, Ordering::Relaxed)
                    .is_ok()
                {
                    unsafe {
                        let _ = Box::from_raw(head);
                    }
                    self.len.fetch_sub(1, Ordering::Relaxed);
                    return job;
                }
            }
        }
    }

    pub fn len(&self) -> usize {
        self.len.load(Ordering::Relaxed)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Drop for LockFreeQueue {
    fn drop(&mut self) {
        while self.pop().is_some() {}
        let sentinel = self.head.load(Ordering::Relaxed);
        if !sentinel.is_null() {
            unsafe {
                let _ = Box::from_raw(sentinel);
            }
        }
    }
}

unsafe impl Send for LockFreeQueue {}
unsafe impl Sync for LockFreeQueue {}
