#![allow(dead_code)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::memory::paging::stack::StackSize;
use crate::scheduling::scheduler::SCHEDULER;
use crate::scheduling::task::Task;
use crate::structs::condvar::Condvar;
use crate::structs::sleep_mutex::SleepMutex;

pub type JobFn = extern "win64" fn(usize);

#[derive(Clone, Copy)]
pub struct Job {
    pub f: JobFn,
    pub a: usize,
}

struct Shared {
    queue: SleepMutex<VecDeque<Job>>,
    not_empty: Condvar,

    shutdown: AtomicBool,
    job_count: AtomicUsize,
    num_workers: AtomicUsize,

    seq: AtomicUsize,
}

impl Shared {
    #[inline(always)]
    fn bump_seq(&self) {
        self.seq.fetch_add(1, Ordering::Release);
    }

    #[inline(always)]
    fn wake_one(&self) {
        self.not_empty.notify_one();
    }

    #[inline(always)]
    fn wake_all(&self) {
        self.not_empty.notify_all();
    }

    #[inline(always)]
    fn pop_job_locked(q: &mut VecDeque<Job>) -> Option<Job> {
        q.pop_front()
    }
}

struct WorkerCtx {
    shared: Arc<Shared>,
    _idx: usize,
}

pub struct ThreadPool {
    shared: Arc<Shared>,
}

impl ThreadPool {
    pub fn new(threads: usize) -> Self {
        assert!(threads > 0);

        let shared = Arc::new(Shared {
            queue: SleepMutex::new(VecDeque::new()),
            not_empty: Condvar::new(),

            shutdown: AtomicBool::new(false),
            job_count: AtomicUsize::new(0),
            num_workers: AtomicUsize::new(0),

            seq: AtomicUsize::new(0),
        });

        for i in 0..threads {
            shared.num_workers.fetch_add(1, Ordering::Release);

            let ctx = Box::new(WorkerCtx {
                shared: shared.clone(),
                _idx: i,
            });

            let name: String = alloc::format!("thread_pool_worker_{i}");
            let th = Task::new_kernel_mode(
                worker_entry,
                Box::into_raw(ctx) as usize,
                StackSize::Tiny,
                name,
                0,
            );
            SCHEDULER.spawn_task(th);
        }

        Self { shared }
    }

    pub fn submit(&self, function: JobFn, context: usize) {
        if self.shared.shutdown.load(Ordering::Acquire) {
            return;
        }

        {
            let mut q = self.shared.queue.lock();
            q.push_back(Job {
                f: function,
                a: context,
            });
            self.shared.job_count.fetch_add(1, Ordering::Release);
        }

        self.shared.bump_seq();
        self.shared.wake_one();
    }

    pub fn submit_many(&self, jobs: &[Job]) {
        if jobs.is_empty() {
            return;
        }
        if self.shared.shutdown.load(Ordering::Acquire) {
            return;
        }

        {
            let mut q = self.shared.queue.lock();
            for &j in jobs {
                q.push_back(j);
            }
            self.shared
                .job_count
                .fetch_add(jobs.len(), Ordering::Release);
        }

        self.shared.bump_seq();
        self.shared.wake_all();
    }

    pub fn submit_if_runnable(&self, f: JobFn, a: usize) {
        if self.shared.shutdown.load(Ordering::Acquire) {
            (f)(a);
            return;
        }
        self.submit(f, a);
    }

    pub fn try_execute_one(&self) -> bool {
        let job = {
            let mut q = self.shared.queue.lock();
            let Some(j) = Shared::pop_job_locked(&mut q) else {
                return false;
            };
            self.shared.job_count.fetch_sub(1, Ordering::AcqRel);
            j
        };

        (job.f)(job.a);
        true
    }

    pub fn shutdown(&self) {
        self.shared.shutdown.store(true, Ordering::Release);
        self.shared.bump_seq();
        self.shared.wake_all();
    }

    pub fn is_shutdown(&self) -> bool {
        self.shared.shutdown.load(Ordering::Acquire)
    }

    pub fn pending_jobs(&self) -> usize {
        self.shared.job_count.load(Ordering::Acquire)
    }

    pub fn workers(&self) -> usize {
        self.shared.num_workers.load(Ordering::Acquire)
    }
}

impl Drop for ThreadPool {
    fn drop(&mut self) {
        self.shutdown();
    }
}

extern "win64" fn worker_entry(ctx: usize) {
    let ctx = unsafe { Box::from_raw(ctx as *mut WorkerCtx) };
    let shared = ctx.shared.clone();
    drop(ctx);

    loop {
        let job_opt = {
            let mut q = shared.queue.lock();

            loop {
                if let Some(j) = Shared::pop_job_locked(&mut q) {
                    shared.job_count.fetch_sub(1, Ordering::AcqRel);
                    break Some(j);
                }

                if shared.shutdown.load(Ordering::Acquire) {
                    break None;
                }

                q = shared.not_empty.wait(q);
            }
        };

        let Some(job) = job_opt else {
            break;
        };

        (job.f)(job.a);
    }

    shared.num_workers.fetch_sub(1, Ordering::AcqRel);
}
