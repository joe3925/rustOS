// thread_pool.rs

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use spin::Mutex;

use crate::memory::paging::stack::StackSize;
use crate::scheduling::scheduler::{TaskHandle, SCHEDULER};
use crate::scheduling::task::Task;

pub type JobFn = extern "win64" fn(usize);

#[derive(Clone, Copy)]
struct Job {
    f: JobFn,
    a: usize,
}

pub struct ThreadPool {
    queue: Mutex<VecDeque<Job>>,
    parked_workers: Mutex<Vec<TaskHandle>>,
    num_workers: AtomicUsize,
    shutdown: AtomicBool,
}

struct WorkerArgs {
    pool: Arc<ThreadPool>,
}

impl ThreadPool {
    pub fn new(threads: usize) -> Arc<Self> {
        let pool = Arc::new(Self {
            queue: Mutex::new(VecDeque::new()),
            parked_workers: Mutex::new(Vec::with_capacity(threads)),
            num_workers: AtomicUsize::new(threads),
            shutdown: AtomicBool::new(false),
        });

        for _ in 0..threads {
            pool.spawn_worker();
        }

        pool
    }

    fn spawn_worker(self: &Arc<Self>) {
        let args = Box::new(WorkerArgs { pool: self.clone() });
        let args_ptr = Box::into_raw(args) as usize;
        let t = Task::new_kernel_mode(worker, args_ptr, StackSize::Tiny, "".into(), 0);
        SCHEDULER.add_task(t);
    }

    pub fn enable_dynamic(&self, _max_threads: usize) {}

    /// Submit a job to the thread pool.
    /// Wakes a parked worker if one is available.
    pub fn submit(&self, function: JobFn, context: usize) {
        let job = Job {
            f: function,
            a: context,
        };

        self.queue.lock().push_back(job);

        self.wake_one_worker();
    }

    /// Submit a job if the pool is able to run it.
    pub fn submit_if_runnable(&self, f: JobFn, a: usize) -> bool {
        if self.shutdown.load(Ordering::Acquire) {
            return false;
        }
        self.submit(f, a);
        true
    }

    /// Try to execute one job from the queue (for external callers).
    pub fn try_execute_one(&self) -> bool {
        let job = self.queue.lock().pop_front();
        if let Some(j) = job {
            (j.f)(j.a);
            return true;
        }
        false
    }

    /// Wake one parked worker to process jobs.
    fn wake_one_worker(&self) {
        let worker = self.parked_workers.lock().pop();
        if let Some(task_handle) = worker {
            SCHEDULER.wake_task(&task_handle);
        }
    }

    /// Wake all parked workers (used for shutdown or bulk wakeup).
    fn wake_all_workers(&self) {
        let workers: Vec<TaskHandle> = {
            let mut parked = self.parked_workers.lock();
            parked.drain(..).collect()
        };

        for task_handle in workers {
            SCHEDULER.wake_task(&task_handle);
        }
    }

    /// Shutdown the thread pool.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
        self.wake_all_workers();
    }

    /// Check if the pool is shutting down.
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Acquire)
    }

    /// Get the number of pending jobs.
    pub fn pending_jobs(&self) -> usize {
        self.queue.lock().len()
    }

    /// Get the number of parked workers.
    pub fn parked_worker_count(&self) -> usize {
        self.parked_workers.lock().len()
    }
}

impl Drop for ThreadPool {
    fn drop(&mut self) {
        self.shutdown();
    }
}

extern "win64" fn worker(args_ptr: usize) {
    let args = unsafe { Box::from_raw(args_ptr as *mut WorkerArgs) };
    let pool = args.pool;

    loop {
        // Check for shutdown
        if pool.shutdown.load(Ordering::Acquire) {
            return;
        }

        let job = pool.queue.lock().pop_front();

        if let Some(j) = job {
            (j.f)(j.a);
        } else {
            // No job available - park this worker

            let current_task = {
                let cpu_id = crate::drivers::interrupt_index::current_cpu_id() as usize;
                SCHEDULER.get_current_task(cpu_id)
            };

            if let Some(task_handle) = current_task {
                SCHEDULER.park_while(|| {
                    if pool.shutdown.load(Ordering::Acquire) {
                        return false;
                    }

                    let is_empty = pool.queue.lock().is_empty();

                    if is_empty {
                        pool.parked_workers.lock().push(task_handle.clone());
                        true
                    } else {
                        false
                    }
                });
            }
        }
    }
}
