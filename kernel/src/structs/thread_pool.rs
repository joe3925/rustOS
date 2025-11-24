use alloc::boxed::Box;
use alloc::collections::vec_deque::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use spin::Mutex;
use x86_64::instructions::interrupts::without_interrupts;

use crate::drivers::interrupt_index::current_cpu_id;
use crate::memory::paging::constants::KERNEL_STACK_SIZE;
use crate::println;
use crate::scheduling::scheduler::{self, TaskHandle, SCHEDULER};
use crate::scheduling::task::Task;
use crate::static_handlers::task_yield;

pub type JobFn = extern "C" fn(usize);

#[derive(Clone, Copy)]
struct Job {
    f: JobFn,
    a: usize,
}

struct WorkerInner {
    q: VecDeque<Job>,
    sleeper: Option<TaskHandle>,
}

pub struct ThreadPool {
    workers: Box<[Mutex<WorkerInner>]>,
    last_worker_idx: AtomicUsize,
}

struct WorkerArgs {
    pool: Arc<ThreadPool>,
    index: usize,
}

impl ThreadPool {
    pub fn new(threads: usize) -> Arc<Self> {
        let mut worker_inners = Vec::with_capacity(threads);
        for _ in 0..threads {
            worker_inners.push(Mutex::new(WorkerInner {
                q: VecDeque::new(),
                sleeper: None,
            }));
        }

        let pool = Arc::new(Self {
            workers: worker_inners.into_boxed_slice(),
            last_worker_idx: AtomicUsize::new(0),
        });

        pool.start(threads);
        pool
    }

    fn start(self: &Arc<Self>, threads: usize) {
        for i in 0..threads {
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

    pub fn submit(&self, function: JobFn, context: usize) {
        let idx = self.last_worker_idx.fetch_add(1, Ordering::Relaxed) % self.workers.len();

        let to_wake = {
            let mut guard = self.workers[idx].lock();
            guard.q.push_back(Job {
                f: function,
                a: context,
            });
            guard.sleeper.take()
        };

        if let Some(t) = to_wake {
            without_interrupts(|| {
                t.write().wake();
            });
        }
    }

    pub fn submit_if_runnable(&self, f: JobFn, a: usize) -> bool {
        for worker_lock in self.workers.iter() {
            let mut guard = worker_lock.lock();
            if guard.sleeper.is_some() {
                guard.q.push_back(Job { f, a });
                let t = guard.sleeper.take().unwrap();

                without_interrupts(|| {
                    t.write().wake();
                });
                return true;
            }
        }
        false
    }
    pub fn try_execute_one(&self) -> bool {
        for worker_lock in self.workers.iter() {
            let job = {
                let mut guard = worker_lock.lock();
                guard.q.pop_front()
            };

            if let Some(j) = job {
                (j.f)(j.a);
                return true;
            }
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

    loop {
        let mut job = None;

        {
            let mut guard = pool.workers[my_idx].lock();
            job = guard.q.pop_front();
        }

        if job.is_none() {
            for i in 1..pool.workers.len() {
                let victim_idx = (my_idx + i) % pool.workers.len();

                if let Some(mut guard) = pool.workers[victim_idx].try_lock() {
                    if let Some(stolen) = guard.q.pop_front() {
                        job = Some(stolen);
                        break;
                    }
                }
            }
        }

        match job {
            Some(j) => {
                (j.f)(j.a);
            }
            None => {
                let mut guard = pool.workers[my_idx].lock();

                if guard.q.is_empty() {
                    guard.sleeper = Some(me.clone());

                    without_interrupts(|| {
                        me.write().is_sleeping = true;
                    });

                    drop(guard);

                    unsafe {
                        task_yield();
                    }
                }
            }
        }
    }
}
