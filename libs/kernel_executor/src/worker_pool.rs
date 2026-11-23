use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering, fence};
use crossbeam_queue::ArrayQueue;

pub use kernel_sync::platform::worker::WorkerPlatform;

const UNPARKED: usize = 1 << 16;
const SEARCH_MASK: usize = UNPARKED - 1;

#[repr(align(64))]
struct Worker<P: WorkerPlatform> {
    registered: AtomicBool,
    searching: AtomicBool,
    sleeping: AtomicU32,
    wait_handle: P::WaitHandle,
}

impl<P: WorkerPlatform> Worker<P> {
    fn wait(&self) {
        for _ in 0..P::SPIN_LIMIT {
            if self.sleeping.load(Ordering::Acquire) == 0 {
                return;
            }
            core::hint::spin_loop();
        }
        let _ = self.sleeping.compare_exchange(1, 2, Ordering::AcqRel, Ordering::Acquire);
        while self.sleeping.load(Ordering::Acquire) != 0 {
            P::wait(&self.wait_handle);
        }
    }

    fn wake(&self) {
        if self.sleeping.swap(0, Ordering::AcqRel) == 2 {
            P::signal(&self.wait_handle);
        }
    }
}

#[repr(align(64))]
struct Sleepers {
    indices: UnsafeCell<Vec<usize>>,
    locked: AtomicBool,
}

unsafe impl Sync for Sleepers {}

struct Shared<P: WorkerPlatform> {
    jobs: ArrayQueue<(extern "C" fn(usize), usize)>,
    idle: AtomicUsize,
    state: AtomicUsize,
    sleepers: Sleepers,
    stopping: AtomicBool,
    workers: Box<[Worker<P>]>,
}

impl<P: WorkerPlatform> Shared<P> {
    fn wake_bootstrap(&self) {
        let mut idle = self.idle.load(Ordering::Acquire);
        while idle != 0 {
            let index = idle.trailing_zeros() as usize;
            match self.idle.compare_exchange_weak(
                idle, idle & !(1usize << index), Ordering::AcqRel, Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.workers[index].wake();
                    return;
                }
                Err(actual) => idle = actual,
            }
        }
    }
}

pub struct RuntimePool<P: WorkerPlatform> {
    shared: Arc<Shared<P>>,
}

impl<P: WorkerPlatform> RuntimePool<P> {
    pub fn new(workers: usize, capacity: usize) -> Self {
        assert!(workers != 0 && workers <= usize::BITS as usize && capacity != 0);
        let shared = Arc::new(Shared::<P> {
            jobs: ArrayQueue::new(capacity),
            idle: AtomicUsize::new(0),
            state: AtomicUsize::new(0),
            sleepers: Sleepers { indices: UnsafeCell::new(Vec::with_capacity(workers)), locked: AtomicBool::new(false) },
            stopping: AtomicBool::new(false),
            workers: (0..workers).map(|_| Worker {
                registered: AtomicBool::new(false),
                searching: AtomicBool::new(false),
                sleeping: AtomicU32::new(0),
                wait_handle: P::create_wait_handle(),
            }).collect(),
        });
        for index in 0..workers {
            let shared = shared.clone();
            P::spawn_worker(index, move || {
                let worker = &shared.workers[index];
                P::init_worker(index, &worker.wait_handle);
                let bit = 1usize << index;
                loop {
                    if let Some((function, context)) = shared.jobs.pop() {
                        function(context);
                        continue;
                    }
                    worker.sleeping.store(1, Ordering::Release);
                    shared.idle.fetch_or(bit, Ordering::SeqCst);
                    if let Some((function, context)) = shared.jobs.pop() {
                        if shared.idle.fetch_and(!bit, Ordering::AcqRel) & bit == 0 {
                            worker.wait();
                        }
                        worker.sleeping.store(0, Ordering::Release);
                        function(context);
                        continue;
                    }
                    if shared.stopping.load(Ordering::Acquire) {
                        shared.idle.fetch_and(!bit, Ordering::AcqRel);
                        break;
                    }
                    worker.wait();
                    shared.idle.fetch_and(!bit, Ordering::AcqRel);
                }
            });
        }
        Self { shared }
    }

    pub fn submit(&self, function: extern "C" fn(usize), context: usize) -> bool {
        if self.shared.jobs.push((function, context)).is_err() {
            return false;
        }
        fence(Ordering::SeqCst);
        self.shared.wake_bootstrap();
        true
    }

    pub fn wake(&self, idle_only: bool, active: usize) -> bool {
        let state = self.shared.state.fetch_add(0, Ordering::SeqCst);
        if state & SEARCH_MASK != 0 || state / UNPARKED >= self.shared.workers.len() {
            return true;
        }
        if idle_only && state / UNPARKED != 0 {
            return false;
        }
        if self.shared.sleepers.locked.swap(true, Ordering::AcqRel) {
            return true;
        }
        let notified = (|| {
            let sleepers = unsafe { &mut *self.shared.sleepers.indices.get() };
            let state = self.shared.state.fetch_add(0, Ordering::SeqCst);
            if state & SEARCH_MASK != 0 || state / UNPARKED >= self.shared.workers.len()
                || (idle_only && state / UNPARKED != 0)
            {
                return (None, true);
            }
            let Some(index) = sleepers.pop() else {
                return (None, active == self.shared.workers.len());
            };
            self.shared.state.fetch_add(UNPARKED + 1, Ordering::SeqCst);
            self.shared.workers[index].searching.store(true, Ordering::Release);
            (Some(index), true)
        })();
        self.shared.sleepers.locked.swap(false, Ordering::AcqRel);
        if let Some(index) = notified.0 {
            self.shared.workers[index].wake();
        }
        notified.1
    }

    pub fn search<const START: bool>(&self) -> bool {
        let worker = &self.shared.workers[P::worker_index()];
        if !worker.registered.load(Ordering::Relaxed) {
            worker.registered.store(true, Ordering::Relaxed);
            self.shared.state.fetch_add(UNPARKED, Ordering::SeqCst);
        }
        if START {
            if worker.searching.load(Ordering::Acquire) {
                return true;
            }
            let state = self.shared.state.load(Ordering::SeqCst);
            if 2 * (state & SEARCH_MASK) >= self.shared.workers.len() {
                return false;
            }
            self.shared.state.fetch_add(1, Ordering::SeqCst);
            worker.searching.store(true, Ordering::Relaxed);
            return true;
        }
        if worker.searching.swap(false, Ordering::Relaxed) {
            self.shared.state.fetch_sub(1, Ordering::SeqCst) & SEARCH_MASK == 1
        } else {
            false
        }
    }

    pub fn wait(&self, work_pending: impl FnOnce() -> bool) -> bool {
        let index = P::worker_index();
        let worker = &self.shared.workers[index];
        worker.sleeping.store(1, Ordering::Release);
        if self.shared.sleepers.locked.swap(true, Ordering::AcqRel) {
            worker.sleeping.store(0, Ordering::Release);
            return true;
        }
        let last = {
            let sleepers = unsafe { &mut *self.shared.sleepers.indices.get() };
            debug_assert!(!sleepers.contains(&index));
            debug_assert!(sleepers.len() < sleepers.capacity());
            let searching = worker.searching.swap(false, Ordering::Relaxed);
            let previous = self.shared.state.fetch_sub(UNPARKED + usize::from(searching), Ordering::SeqCst);
            sleepers.push(index);
            previous & SEARCH_MASK == usize::from(searching)
        };
        self.shared.sleepers.locked.swap(false, Ordering::AcqRel);
        let pending = last && work_pending();
        if self.shared.stopping.load(Ordering::Acquire) {
            worker.sleeping.store(0, Ordering::Release);
            return false;
        }
        if pending {
            self.wake(false, self.shared.workers.len());
        }
        if pending && !self.shared.sleepers.locked.swap(true, Ordering::AcqRel) {
            let removed = {
                let sleepers = unsafe { &mut *self.shared.sleepers.indices.get() };
                if let Some(position) = sleepers.iter().position(|&worker| worker == index) {
                    sleepers.swap_remove(position);
                    self.shared.state.fetch_add(UNPARKED, Ordering::SeqCst);
                    true
                } else {
                    false
                }
            };
            self.shared.sleepers.locked.swap(false, Ordering::AcqRel);
            if removed {
                worker.sleeping.store(0, Ordering::Release);
                return !self.shared.stopping.load(Ordering::Acquire);
            }
        }
        worker.wait();
        !self.shared.stopping.load(Ordering::Acquire)
    }

}

impl<P: WorkerPlatform> Drop for RuntimePool<P> {
    fn drop(&mut self) {
        self.shared.stopping.store(true, Ordering::Release);
        fence(Ordering::SeqCst);
        for worker in &self.shared.workers {
            worker.wake();
        }
    }
}
