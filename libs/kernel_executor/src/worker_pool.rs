use alloc::{boxed::Box, sync::Arc};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering, fence};
use crossbeam_queue::ArrayQueue;

pub use kernel_sync::platform::worker::WorkerPlatform;

#[repr(align(64))]
struct Worker<P: WorkerPlatform> {
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
        let _ = self
            .sleeping
            .compare_exchange(1, 2, Ordering::AcqRel, Ordering::Acquire);
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

struct Shared<P: WorkerPlatform> {
    jobs: ArrayQueue<(extern "C" fn(usize), usize)>,
    idle: AtomicUsize,
    resident_idle: AtomicUsize,
    searching: AtomicUsize,
    notified: AtomicUsize,
    preferred: AtomicUsize,
    stopping: AtomicBool,
    workers: Box<[Worker<P>]>,
}

impl<P: WorkerPlatform> Shared<P> {
    fn wake_one<const RESIDENT: bool>(&self, mask: &AtomicUsize) -> bool {
        let mut idle = mask.load(Ordering::Acquire);
        while idle != 0 {
            let preferred = self.preferred.load(Ordering::Relaxed);
            let index = if idle & (1usize << preferred) != 0 {
                preferred
            } else {
                idle.trailing_zeros() as usize
            };
            let bit = 1usize << index;
            match mask.compare_exchange_weak(idle, idle & !bit, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    if RESIDENT {
                        self.notified.store(index + 1, Ordering::Release);
                    }
                    self.workers[index].wake();
                    return true;
                }
                Err(actual) => idle = actual,
            }
        }
        false
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
            resident_idle: AtomicUsize::new(0),
            searching: AtomicUsize::new(0),
            notified: AtomicUsize::new(0),
            preferred: AtomicUsize::new(0),
            stopping: AtomicBool::new(false),
            workers: (0..workers)
                .map(|_| {
                    let wait_handle = P::create_wait_handle();
                    Worker::<P> {
                        sleeping: AtomicU32::new(0),
                        wait_handle,
                    }
                })
                .collect(),
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
                    shared.preferred.store(index, Ordering::Relaxed);
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
        self.shared.wake_one::<false>(&self.shared.idle);
        true
    }

    pub fn wake(&self, idle_only: bool, active: usize) -> bool {
        fence(Ordering::SeqCst);
        if self.shared.searching.load(Ordering::Acquire) != 0
            || self.shared.notified.load(Ordering::Acquire) != 0
        {
            return true;
        }
        if idle_only {
            return self
                .shared
                .resident_idle
                .load(Ordering::Acquire)
                .count_ones() as usize
                == active
                && self.shared.wake_one::<false>(&self.shared.resident_idle);
        }
        if self.shared.resident_idle.load(Ordering::Acquire) == 0 {
            return active == self.shared.workers.len();
        }
        if self
            .shared
            .notified
            .compare_exchange(0, usize::MAX, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return true;
        }
        if self.shared.wake_one::<true>(&self.shared.resident_idle) {
            return true;
        }
        self.shared.notified.store(0, Ordering::Release);
        false
    }

    pub fn search<const START: bool>(&self) {
        let index = P::worker_index();
        if START {
            self.shared
                .searching
                .fetch_or(1usize << index, Ordering::SeqCst);
            return;
        }
        self.shared
            .searching
            .fetch_and(!(1usize << index), Ordering::SeqCst);
        if self.shared.notified.load(Ordering::Acquire) == index + 1 {
            let _ = self.shared.notified.compare_exchange(
                index + 1,
                0,
                Ordering::SeqCst,
                Ordering::Acquire,
            );
        }
    }

    pub fn wait(&self, work_pending: impl FnOnce() -> bool) -> bool {
        let index = P::worker_index();
        let worker = &self.shared.workers[index];
        let bit = 1usize << index;
        worker.sleeping.store(1, Ordering::Release);
        self.shared.resident_idle.fetch_or(bit, Ordering::SeqCst);
        self.shared.preferred.store(index, Ordering::Relaxed);
        let pending = work_pending();
        let stopping = self.shared.stopping.load(Ordering::Acquire);
        if !pending && !stopping {
            worker.wait();
        }
        if self.shared.resident_idle.fetch_and(!bit, Ordering::AcqRel) & bit == 0 {
            worker.wait();
        }
        worker.sleeping.store(0, Ordering::Release);
        !stopping
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
