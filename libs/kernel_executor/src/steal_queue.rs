use alloc::boxed::Box;
use crate::sync::atomic::{AtomicU32, AtomicU64, Ordering};
#[cfg(any(loom, feature = "loom"))]
use loom::cell::UnsafeCell;
#[cfg(not(any(loom, feature = "loom")))]
use core::cell::UnsafeCell;

pub(crate) struct OverflowTasks<'a, const N: usize> {
    queue: &'a StealQueue<N>,
    cursor: u32,
    remaining: usize,
    last: Option<usize>,
}

impl<const N: usize> Iterator for OverflowTasks<'_, N> {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining != 0 {
            self.remaining -= 1;
            let task = unsafe { self.queue.read(self.cursor) };
            self.cursor = self.cursor.wrapping_add(1);
            Some(task)
        } else {
            self.last.take()
        }
    }
}

pub(crate) struct StealQueue<const N: usize> {
    head: AtomicU64,
    tail: AtomicU32,
    slots: Box<[UnsafeCell<usize>; N]>,
}

unsafe impl<const N: usize> Send for StealQueue<N> {}
unsafe impl<const N: usize> Sync for StealQueue<N> {}

#[inline]
fn pack(steal: u32, real: u32) -> u64 {
    u64::from(real) | (u64::from(steal) << 32)
}

#[inline]
fn unpack(head: u64) -> (u32, u32) {
    ((head >> 32) as u32, head as u32)
}

impl<const N: usize> StealQueue<N> {
    pub fn new() -> Self {
        assert!(N >= 2 && N.is_power_of_two() && N <= u32::MAX as usize / 2);
        Self {
            head: AtomicU64::new(0),
            tail: AtomicU32::new(0),
            slots: Box::new(core::array::from_fn(|_| UnsafeCell::new(0))),
        }
    }

    #[inline]
    unsafe fn read(&self, position: u32) -> usize {
        let slot = &self.slots[position as usize & (N - 1)];
        #[cfg(any(loom, feature = "loom"))]
        { slot.with(|ptr| unsafe { *ptr }) }
        #[cfg(not(any(loom, feature = "loom")))]
        { unsafe { *slot.get() } }
    }

    #[inline]
    unsafe fn write(&self, position: u32, task: usize) {
        let slot = &self.slots[position as usize & (N - 1)];
        #[cfg(any(loom, feature = "loom"))]
        slot.with_mut(|ptr| unsafe { *ptr = task });
        #[cfg(not(any(loom, feature = "loom")))]
        unsafe { *slot.get() = task };
    }

    pub fn len(&self) -> usize {
        let (_, head) = unpack(self.head.load(Ordering::Acquire));
        self.tail.load(Ordering::Acquire).wrapping_sub(head) as usize
    }

    pub fn has_work(&self) -> bool {
        self.len() != 0
    }

    pub fn remaining_slots(&self) -> usize {
        let (steal, _) = unpack(self.head.load(Ordering::Acquire));
        N - self.tail.load(Ordering::Relaxed).wrapping_sub(steal) as usize
    }

    pub unsafe fn push(&self, task: usize) -> bool {
        let (steal, _) = unpack(self.head.load(Ordering::Acquire));
        let tail = self.tail.load(Ordering::Relaxed);
        if tail.wrapping_sub(steal) as usize >= N {
            return false;
        }
        unsafe { self.write(tail, task) };
        self.tail.store(tail.wrapping_add(1), Ordering::Release);
        true
    }

    pub unsafe fn push_or_overflow(
        &self,
        task: usize,
        overflow: impl FnOnce(&mut OverflowTasks<'_, N>),
    ) {
        loop {
            let head = self.head.load(Ordering::Acquire);
            let (steal, real) = unpack(head);
            let tail = self.tail.load(Ordering::Relaxed);
            if (tail.wrapping_sub(steal) as usize) < N {
                unsafe { self.write(tail, task) };
                self.tail.store(tail.wrapping_add(1), Ordering::Release);
                return;
            }
            if steal != real {
                overflow(&mut OverflowTasks { queue: self, cursor: 0, remaining: 0, last: Some(task) });
                return;
            }
            if self.head.compare_exchange_weak(
                head, pack(tail, tail), Ordering::Release, Ordering::Relaxed,
            ).is_err() {
                continue;
            }
            self.tail.store(tail.wrapping_add((N / 2) as u32), Ordering::Release);
            let mut tasks = OverflowTasks {
                queue: self,
                cursor: real.wrapping_add((N / 2) as u32),
                remaining: N / 2,
                last: Some(task),
            };
            overflow(&mut tasks);
            return;
        }
    }

    pub unsafe fn pop(&self) -> Option<usize> {
        let mut head = self.head.load(Ordering::Acquire);
        loop {
            let (steal, real) = unpack(head);
            if real == self.tail.load(Ordering::Relaxed) {
                return None;
            }
            let next_real = real.wrapping_add(1);
            let next = pack(if steal == real { next_real } else { steal }, next_real);
            match self.head.compare_exchange_weak(head, next, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Some(unsafe { self.read(real) }),
                Err(actual) => head = actual,
            }
        }
    }

    pub unsafe fn steal<const COPY_FIRST: bool>(&self, destination: Option<&Self>) -> Option<usize> {
        debug_assert!(!COPY_FIRST || destination.is_some());
        let tail = if let Some(target) = destination {
            debug_assert!(!core::ptr::eq(self, target));
            let tail = target.tail.load(Ordering::Relaxed);
            let (steal, _) = unpack(target.head.load(Ordering::Acquire));
            if tail.wrapping_sub(steal) as usize > N / 2 {
                return None;
            }
            tail
        } else {
            0
        };
        let mut previous = self.head.load(Ordering::Acquire);
        let (first, count, mut claimed) = loop {
            let (steal, real) = unpack(previous);
            if steal != real {
                return None;
            }
            let available = self.tail.load(Ordering::Acquire).wrapping_sub(real);
            if available == 0 {
                return None;
            }
            let count = if destination.is_some() { available - available / 2 } else { 1 };
            let next = pack(steal, real.wrapping_add(count));
            match self.head.compare_exchange_weak(previous, next, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => break (real, count, next),
                Err(actual) => previous = actual,
            }
        };
        let mut task = 0;
        for offset in 0..count {
            task = unsafe { self.read(first.wrapping_add(offset)) };
            if let Some(target) = destination {
                unsafe { target.write(tail.wrapping_add(offset), task) };
            }
        }
        loop {
            let (_, real) = unpack(claimed);
            match self.head.compare_exchange_weak(
                claimed, pack(real, real), Ordering::AcqRel, Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => claimed = actual,
            }
        }
        if let Some(target) = destination {
            let published = count - u32::from(!COPY_FIRST);
            if published != 0 {
                target.tail.store(tail.wrapping_add(published), Ordering::Release);
            }
        }
        Some(task)
    }
}

#[cfg(all(test, not(any(loom, feature = "loom"))))]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn order_overflow_and_counter_wrap() {
        let q = StealQueue::<4>::new();
        q.head.store(pack(u32::MAX - 1, u32::MAX - 1), Ordering::Relaxed);
        q.tail.store(u32::MAX - 1, Ordering::Relaxed);
        unsafe {
            assert_eq!(q.pop(), None);
            for id in 1..=4 {
                assert!(q.push(id));
            }
            assert!(!q.push(5));
            assert_eq!(q.steal::<false>(None), Some(1));
            assert_eq!(q.pop(), Some(2));
            assert_eq!(q.steal::<false>(None), Some(3));
            assert_eq!(q.pop(), Some(4));
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
                        if let Some(id) = unsafe { q.steal::<false>(None) } {
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
            let thief = thread::spawn(move || unsafe { [other.steal::<false>(None), other.steal::<false>(None)] });
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
            let thief = thread::spawn(move || unsafe { [other.steal::<false>(None), other.steal::<false>(None)] });
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
