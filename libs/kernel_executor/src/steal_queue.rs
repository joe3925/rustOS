//! Bounded Chase-Lev queue of slab IDs: one owner, multiple thieves.
//! Atomic slots allow a losing thief to read a slot while the owner reuses it.
//! Overflow goes to the domain's existing intrusive queues; no resizing or
//! allocation occurs on push, pop, or steal.

use crate::sync::atomic::{AtomicUsize, Ordering, fence};

#[repr(align(64))]
struct Index(AtomicUsize);

pub(crate) struct StealQueue<const N: usize> {
    top: Index,
    bottom: Index,
    slots: [AtomicUsize; N],
}

impl<const N: usize> StealQueue<N> {
    pub fn new() -> Self {
        assert!(N.is_power_of_two() && N <= isize::MAX as usize);
        Self {
            top: Index(AtomicUsize::new(0)),
            bottom: Index(AtomicUsize::new(0)),
            slots: core::array::from_fn(|_| AtomicUsize::new(0)),
        }
    }

    pub fn has_work(&self) -> bool {
        let top = self.top.0.load(Ordering::Acquire);
        let bottom = self.bottom.0.load(Ordering::Acquire);
        (bottom.wrapping_sub(top) as isize) > 0
    }

    /// # Safety
    /// Only the current batch owner may push/pop, with ownership handed over
    /// using the batch state/ready bitmap's release/acquire protocol.
    pub unsafe fn push(&self, task: usize) -> bool {
        let bottom = self.bottom.0.load(Ordering::Relaxed);
        let top = self.top.0.load(Ordering::Acquire);
        if bottom.wrapping_sub(top) >= N {
            return false;
        }
        self.slots[bottom & (N - 1)].store(task, Ordering::Relaxed);
        fence(Ordering::Release);
        self.bottom
            .0
            .store(bottom.wrapping_add(1), Ordering::Relaxed);
        true
    }

    /// # Safety
    /// See `push`. Cleanup may also pop after all domain readers have left.
    pub unsafe fn pop(&self) -> Option<usize> {
        let bottom = self.bottom.0.load(Ordering::Relaxed).wrapping_sub(1);
        self.bottom.0.store(bottom, Ordering::Relaxed);
        fence(Ordering::SeqCst);
        let top = self.top.0.load(Ordering::Acquire);
        let size = bottom.wrapping_sub(top) as isize;
        if size < 0 {
            self.bottom
                .0
                .store(bottom.wrapping_add(1), Ordering::Relaxed);
            return None;
        }
        let task = self.slots[bottom & (N - 1)].load(Ordering::Relaxed);
        if size == 0 {
            let won = self
                .top
                .0
                .compare_exchange(
                    top,
                    top.wrapping_add(1),
                    Ordering::SeqCst,
                    Ordering::Relaxed,
                )
                .is_ok();
            self.bottom
                .0
                .store(bottom.wrapping_add(1), Ordering::Relaxed);
            if !won {
                return None;
            }
        }
        Some(task)
    }

    pub fn steal(&self) -> Option<usize> {
        loop {
            let top = self.top.0.load(Ordering::Acquire);
            fence(Ordering::SeqCst);
            let bottom = self.bottom.0.load(Ordering::Acquire);
            if (bottom.wrapping_sub(top) as isize) <= 0 {
                return None;
            }
            let task = self.slots[top & (N - 1)].load(Ordering::Relaxed);
            if self
                .top
                .0
                .compare_exchange(
                    top,
                    top.wrapping_add(1),
                    Ordering::SeqCst,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                return Some(task);
            }
        }
    }
}

#[cfg(all(test, not(any(loom, feature = "loom"))))]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn order_overflow_and_counter_wrap() {
        let q = StealQueue::<4>::new();
        q.top.0.store(usize::MAX - 1, Ordering::Relaxed);
        q.bottom.0.store(usize::MAX - 1, Ordering::Relaxed);
        unsafe {
            assert_eq!(q.pop(), None);
            for id in 1..=4 {
                assert!(q.push(id));
            }
            assert!(!q.push(5));
            assert_eq!(q.steal(), Some(1));
            assert_eq!(q.pop(), Some(4));
            assert_eq!(q.steal(), Some(2));
            assert_eq!(q.pop(), Some(3));
            assert_eq!(q.pop(), None);
        }
        assert!(!q.has_work());
    }

    #[test]
    fn owner_and_four_thieves_execute_every_id_once() {
        const TASKS: usize = 100_000;
        let q = Arc::new(StealQueue::<64>::new());
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let thieves: std::vec::Vec<_> = (0..4)
            .map(|_| {
                let q = q.clone();
                let done = done.clone();
                std::thread::spawn(move || {
                    let mut ids = std::vec::Vec::new();
                    while !done.load(Ordering::Acquire) || q.has_work() {
                        if let Some(id) = q.steal() {
                            ids.push(id);
                        } else {
                            std::thread::yield_now();
                        }
                    }
                    ids
                })
            })
            .collect();
        let mut ids = std::vec::Vec::new();
        for id in 1..=TASKS {
            while !unsafe { q.push(id) } {
                if let Some(id) = unsafe { q.pop() } {
                    ids.push(id);
                }
            }
            if id % 3 == 0 {
                if let Some(id) = unsafe { q.pop() } {
                    ids.push(id);
                }
            }
        }
        done.store(true, Ordering::Release);
        while let Some(id) = unsafe { q.pop() } {
            ids.push(id);
        }
        for thief in thieves {
            ids.extend(thief.join().unwrap());
        }
        ids.sort_unstable();
        assert_eq!(ids, (1..=TASKS).collect::<std::vec::Vec<_>>());
    }
}

#[cfg(all(test, any(loom, feature = "loom")))]
mod loom_tests {
    use super::*;
    use loom::{sync::Arc, thread};

    #[test]
    fn last_item_race() {
        crate::sync::exhaustive_model(|| {
            let q = Arc::new(StealQueue::<2>::new());
            assert!(unsafe { q.push(1) });
            let other = q.clone();
            let thief = thread::spawn(move || [other.steal(), other.steal()]);
            let a = unsafe { q.pop() };
            assert!(unsafe { q.push(2) });
            let b = unsafe { q.pop() };
            let stolen = thief.join().unwrap();
            let mut ids: std::vec::Vec<_> =
                [a, b, stolen[0], stolen[1]].into_iter().flatten().collect();
            while let Some(id) = unsafe { q.pop() } {
                ids.push(id);
            }
            ids.sort_unstable();
            assert_eq!(ids, [1, 2]);
        });
    }

    #[test]
    fn slot_reuse_while_thief_reads() {
        crate::sync::exhaustive_model(|| {
            let q = Arc::new(StealQueue::<2>::new());
            assert!(unsafe { q.push(1) });
            assert!(unsafe { q.push(2) });
            let other = q.clone();
            let thief = thread::spawn(move || [other.steal(), other.steal()]);
            let a = unsafe { q.pop() };
            // Reuse a ring slot while a thief may still be reading it.
            assert!(unsafe { q.push(3) });
            let b = unsafe { q.pop() };
            let stolen = thief.join().unwrap();
            let mut ids: std::vec::Vec<_> =
                [a, b, stolen[0], stolen[1]].into_iter().flatten().collect();
            while let Some(id) = unsafe { q.pop() } {
                ids.push(id);
            }
            ids.sort_unstable();
            assert_eq!(ids, [1, 2, 3]);
        });
    }
}
