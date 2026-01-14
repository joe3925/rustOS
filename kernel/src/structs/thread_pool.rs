// thread_pool.rs

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use crossbeam_queue::SegQueue;
use x86_64::instructions::interrupts::without_interrupts;

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
    queue: SegQueue<Job>,
    parked_workers: SegQueue<TaskHandle>,
    num_workers: AtomicUsize,
    shutdown: AtomicBool,

    job_count: AtomicUsize,
    parked_count: AtomicUsize,
}

struct WorkerArgs {
    pool: Arc<ThreadPool>,
}

impl ThreadPool {
    pub fn new(threads: usize) -> Arc<Self> {
        let pool = Arc::new(Self {
            queue: SegQueue::new(),
            parked_workers: SegQueue::new(),
            num_workers: AtomicUsize::new(threads),
            shutdown: AtomicBool::new(false),
            job_count: AtomicUsize::new(0),
            parked_count: AtomicUsize::new(0),
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

    pub fn submit(&self, function: JobFn, context: usize) {
        let job = Job {
            f: function,
            a: context,
        };

        self.queue.push(job);
        self.job_count.fetch_add(1, Ordering::Relaxed);

        self.wake_one_worker();
    }

    pub fn submit_if_runnable(&self, f: JobFn, a: usize) -> bool {
        if self.shutdown.load(Ordering::Acquire) {
            return false;
        }
        self.submit(f, a);
        true
    }

    pub fn try_execute_one(&self) -> bool {
        if let Some(j) = self.queue.pop() {
            self.job_count.fetch_sub(1, Ordering::Relaxed);
            (j.f)(j.a);
            return true;
        }
        false
    }

    fn wake_one_worker(&self) {
        without_interrupts(|| {
            if let Some(task_handle) = self.parked_workers.pop() {
                self.parked_count.fetch_sub(1, Ordering::Relaxed);
                SCHEDULER.wake_task(&task_handle);
            }
        });
    }

    fn wake_all_workers(&self) {
        without_interrupts(|| {
            while let Some(task_handle) = self.parked_workers.pop() {
                self.parked_count.fetch_sub(1, Ordering::Relaxed);
                SCHEDULER.wake_task(&task_handle);
            }
        });
    }

    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
        self.wake_all_workers();
    }

    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Acquire)
    }

    pub fn pending_jobs(&self) -> usize {
        self.job_count.load(Ordering::Acquire)
    }

    pub fn parked_worker_count(&self) -> usize {
        self.parked_count.load(Ordering::Acquire)
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
        if pool.shutdown.load(Ordering::Acquire) {
            return;
        }

        if let Some(j) = pool.queue.pop() {
            pool.job_count.fetch_sub(1, Ordering::Relaxed);
            (j.f)(j.a);
            continue;
        }

        let cpu_id = crate::drivers::interrupt_index::current_cpu_id() as usize;
        let current_task = SCHEDULER.get_current_task(cpu_id);
        let Some(task_handle) = current_task else {
            continue;
        };

        let mut inline_job: Option<Job> = None;

        let should_yield = x86_64::instructions::interrupts::without_interrupts(|| {
            if pool.shutdown.load(Ordering::Acquire) {
                return false;
            }

            if let Some(j) = pool.queue.pop() {
                pool.job_count.fetch_sub(1, Ordering::Relaxed);
                inline_job = Some(j);
                return false;
            }

            let cpu_id = crate::drivers::interrupt_index::current_cpu_id() as usize;
            let Some(task) = SCHEDULER.get_current_task(cpu_id) else {
                return false;
            };

            if !task.read().park_begin() {
                return false;
            }

            pool.parked_workers.push(task_handle.clone());
            pool.parked_count.fetch_add(1, Ordering::Relaxed);

            // Re-check queue after parking to prevent lost wakeup.
            // If a job was submitted between our first check and parking,
            // we must handle it instead of yielding.
            if let Some(j) = pool.queue.pop() {
                pool.job_count.fetch_sub(1, Ordering::Relaxed);
                pool.parked_count.fetch_sub(1, Ordering::Relaxed);
                task.read().park_abort();
                inline_job = Some(j);
                return false;
            }

            true
        });

        if let Some(j) = inline_job {
            (j.f)(j.a);
            continue;
        }

        if should_yield {
            unsafe { crate::static_handlers::task_yield() };
        }
    }
}
