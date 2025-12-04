use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use spin::Mutex;
use spin::RwLock;

use crate::drivers::interrupt_index::current_cpu_id;
use crate::memory::paging::constants::KERNEL_STACK_SIZE;
use crate::scheduling::scheduler;
use crate::scheduling::scheduler::TaskHandle;
use crate::scheduling::scheduler::SCHEDULER;
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
    workers: RwLock<Vec<WorkerSlot>>,
    base_workers: usize,
    max_workers: AtomicUsize,
    dynamic_enabled: AtomicBool,
    next_worker: AtomicUsize,
    deferred: Mutex<Vec<Job>>,
    deferred_hint: AtomicBool,
    self_arc: Mutex<Option<Arc<ThreadPool>>>,
}

struct WorkerArgs {
    pool: Arc<ThreadPool>,
    index: usize,
}

impl ThreadPool {
    pub fn new(threads: usize) -> Arc<Self> {
        let mut workers_vec = Vec::with_capacity(threads);
        for _ in 0..threads {
            workers_vec.push(WorkerSlot {
                task: RwLock::new(None),
                queue: Mutex::new(Vec::new()),
            });
        }

        let pool = Arc::new(Self {
            workers: RwLock::new(workers_vec),
            base_workers: threads,
            max_workers: AtomicUsize::new(threads),
            dynamic_enabled: AtomicBool::new(false),
            next_worker: AtomicUsize::new(0),
            deferred: Mutex::new(Vec::new()),
            deferred_hint: AtomicBool::new(false),
            self_arc: Mutex::new(None),
        });

        {
            let mut s = pool.self_arc.lock();
            *s = Some(pool.clone());
        }

        pool.start_initial();
        pool
    }

    fn start_initial(self: &Arc<Self>) {
        for i in 0..self.base_workers {
            self.spawn_worker(i);
        }
    }

    fn spawn_worker(self: &Arc<Self>, index: usize) {
        let args = Box::new(WorkerArgs {
            pool: self.clone(),
            index,
        });
        let args_ptr = Box::into_raw(args) as usize;
        let t = Task::new_kernel_mode(worker, args_ptr, KERNEL_STACK_SIZE, "".into(), 0);
        SCHEDULER.add_task(t);
    }

    fn get_self_arc(&self) -> Arc<ThreadPool> {
        let s = self.self_arc.lock();
        s.as_ref()
            .expect("ThreadPool self_arc not initialized")
            .clone()
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

    pub fn enable_dynamic(&self, max_threads: usize) {
        let min = self.base_workers;
        let max = if max_threads < min { min } else { max_threads };
        self.max_workers.store(max, Ordering::Release);
        self.dynamic_enabled.store(true, Ordering::Release);
    }

    fn try_grow(&self) {
        if !self.dynamic_enabled.load(Ordering::Acquire) {
            return;
        }

        let max = self.max_workers.load(Ordering::Acquire);

        {
            let workers = self.workers.read();
            if workers.len() >= max {
                return;
            }
        }

        let new_index;
        {
            let mut workers = self.workers.write();
            if workers.len() >= max {
                return;
            }
            new_index = workers.len();
            workers.push(WorkerSlot {
                task: RwLock::new(None),
                queue: Mutex::new(Vec::new()),
            });
        }

        let pool_arc = self.get_self_arc();
        pool_arc.spawn_worker(new_index);
    }

    pub fn submit(&self, function: JobFn, context: usize) {
        let job = Job {
            f: function,
            a: context,
        };

        {
            let workers = self.workers.read();
            for slot in workers.iter() {
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
        }

        {
            let workers = self.workers.read();
            let count = workers.len();
            if count != 0 {
                let start = self.next_worker.fetch_add(1, Ordering::Relaxed) % count;
                for off in 0..count {
                    let idx = (start + off) % count;
                    let slot = &workers[idx];

                    if let Some(mut guard) = slot.queue.try_lock() {
                        guard.push(job);

                        if let Some(handle) = slot.task.read().clone() {
                            SCHEDULER.wake_task(&handle);
                        }
                        return;
                    }
                }
            }
        }

        {
            let mut dq = self.deferred.lock();
            dq.push(job);
            self.deferred_hint.store(true, Ordering::Release);
        }

        self.try_grow();
    }

    pub fn submit_if_runnable(&self, f: JobFn, a: usize) -> bool {
        self.submit(f, a);
        true
    }

    pub fn try_execute_one(&self) -> bool {
        {
            let workers = self.workers.read();
            for slot in workers.iter() {
                let job_opt = {
                    let mut q = slot.queue.lock();
                    q.pop()
                };
                if let Some(job) = job_opt {
                    (job.f)(job.a);
                    return true;
                }
            }
        }

        if let Some(job) = self.take_deferred() {
            (job.f)(job.a);
            return true;
        }

        false
    }
}

extern "win64" fn worker(args_ptr: usize) {
    let args = unsafe { Box::from_raw(args_ptr as *mut WorkerArgs) };
    let pool = args.pool;
    let my_idx = args.index;

    let me = SCHEDULER
        .get_current_task(current_cpu_id())
        .expect("worker task missing");

    {
        let workers = pool.workers.read();
        let mut slot = workers[my_idx].task.write();
        *slot = Some(me.clone());
    }

    loop {
        loop {
            let job_opt = {
                let workers = pool.workers.read();
                let mut q = workers[my_idx].queue.lock();
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
