use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use spin::Mutex;
use spin::RwLock;
use x86_64::instructions::interrupts::without_interrupts;

use crate::drivers::interrupt_index::current_cpu_id;
use crate::memory::paging::constants::KERNEL_STACK_SIZE;
use crate::scheduling::scheduler;
use crate::scheduling::scheduler::{TaskHandle, SCHEDULER};
use crate::scheduling::task::Task;

pub type JobFn = extern "win64" fn(usize);

#[derive(Clone, Copy)]
struct Job {
    f: JobFn,
    a: usize,
}

struct WorkerSlot {
    task: RwLock<Option<TaskHandle>>,
    queue: Mutex<Vec<Job>>,
}

pub struct ThreadPool {
    workers: Box<[WorkerSlot]>,
    worker_count: usize,
    next_worker: AtomicUsize,
    deferred: Mutex<Vec<Job>>,
    deferred_hint: AtomicBool,
}

struct WorkerArgs {
    pool: Arc<ThreadPool>,
    index: usize,
}

impl ThreadPool {
    pub fn new(threads: usize) -> Arc<Self> {
        let mut workers = Vec::with_capacity(threads);
        for _ in 0..threads {
            workers.push(WorkerSlot {
                task: RwLock::new(None),
                queue: Mutex::new(Vec::new()),
            });
        }

        let pool = Arc::new(Self {
            workers: workers.into_boxed_slice(),
            worker_count: threads,
            next_worker: AtomicUsize::new(0),
            deferred: Mutex::new(Vec::new()),
            deferred_hint: AtomicBool::new(false),
        });

        pool.start();
        pool
    }

    fn start(self: &Arc<Self>) {
        for i in 0..self.worker_count {
            let t = Task::new_kernel_mode(worker as usize, KERNEL_STACK_SIZE, "".into(), 0);

            let args = Box::new(WorkerArgs {
                pool: self.clone(),
                index: i,
            });
            let args_ptr = Box::into_raw(args) as usize;

            without_interrupts(|| {
                t.write().context.rdi = args_ptr as u64;
            });

            SCHEDULER.add_task(t);
        }
    }

    fn take_deferred(&self) -> Option<Job> {
        if !self.deferred_hint.load(Ordering::Acquire) {
            return None;
        }
        let mut dq = self.deferred.lock();
        let job = dq.pop();
        if dq.is_empty() {
            self.deferred_hint.store(false, Ordering::Release);
        }
        job
    }

    pub fn submit(&self, function: JobFn, context: usize) {
        let job = Job {
            f: function,
            a: context,
        };

        for slot in self.workers.iter() {
            let handle_opt = slot.task.read().clone();
            if let Some(handle) = handle_opt {
                let sleeping = {
                    let t = handle.read();
                    t.is_sleeping()
                };

                if sleeping {
                    {
                        let mut q = slot.queue.lock();
                        q.push(job);
                    }
                    SCHEDULER.wake_task(&handle);
                    return;
                }
            }
        }

        let start = self.next_worker.fetch_add(1, Ordering::Relaxed) % self.worker_count;

        for off in 0..self.worker_count {
            let idx = (start + off) % self.worker_count;
            let slot = &self.workers[idx];

            if let Some(mut guard) = slot.queue.try_lock() {
                guard.push(job);

                if let Some(handle) = slot.task.read().clone() {
                    SCHEDULER.wake_task(&handle);
                }
                return;
            }
        }

        let mut dq = self.deferred.lock();
        dq.push(job);
        self.deferred_hint.store(true, Ordering::Release);
    }

    pub fn submit_if_runnable(&self, f: JobFn, a: usize) -> bool {
        self.submit(f, a);
        true
    }

    pub fn try_execute_one(&self) -> bool {
        for slot in self.workers.iter() {
            let job_opt = {
                let mut q = slot.queue.lock();
                q.pop()
            };
            if let Some(job) = job_opt {
                (job.f)(job.a);
                return true;
            }
        }

        if let Some(job) = self.take_deferred() {
            (job.f)(job.a);
            return true;
        }

        false
    }
}

extern "C" fn worker(args_ptr: usize) {
    let args = unsafe { Box::from_raw(args_ptr as *mut WorkerArgs) };
    let pool = args.pool;
    let my_idx = args.index;

    let me = SCHEDULER
        .get_current_task(current_cpu_id())
        .expect("worker task missing");

    {
        let mut slot = pool.workers[my_idx].task.write();
        *slot = Some(me.clone());
    }

    loop {
        loop {
            let job_opt = {
                let mut q = pool.workers[my_idx].queue.lock();
                q.pop()
            };
            if let Some(job) = job_opt {
                (job.f)(job.a);

                if pool.deferred_hint.load(Ordering::Acquire) {
                    if let Some(djob) = pool.take_deferred() {
                        (djob.f)(djob.a);
                    }
                }

                continue;
            }
            break;
        }

        if pool.deferred_hint.load(Ordering::Acquire) {
            if let Some(job) = pool.take_deferred() {
                (job.f)(job.a);
                continue;
            }
        }

        SCHEDULER.sleep_and_yield();
    }
}
