use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::memory::paging::stack::StackSize;
use crate::scheduling::scheduler::SCHEDULER;
use crate::scheduling::task::Task;
use crate::structs::mpmc::{mpmc_channel, Receiver, Sender};

pub type JobFn = extern "win64" fn(usize);

#[derive(Clone, Copy)]
pub struct Job {
    pub f: JobFn,
    pub a: usize,
}
impl From<(extern "win64" fn(usize), usize)> for Job {
    fn from(job: (extern "win64" fn(usize), usize)) -> Self {
        Job { f: job.0, a: job.1 }
    }
}

struct Shared {
    shutdown: AtomicBool,
    job_count: AtomicUsize,
    num_workers: AtomicUsize,
    total_workers: AtomicUsize,
}

struct WorkerCtx {
    shared: Arc<Shared>,
    receiver: Receiver<Job>,
    _idx: usize,
}

pub struct ThreadPool {
    shared: Arc<Shared>,
    sender: Sender<Job>,
    receiver: Receiver<Job>,
}

impl ThreadPool {
    pub fn new(threads: usize) -> Self {
        assert!(threads > 0);

        let (sender, receiver) = mpmc_channel::<Job>();

        let shared = Arc::new(Shared {
            total_workers: AtomicUsize::new(threads),
            shutdown: AtomicBool::new(false),
            job_count: AtomicUsize::new(0),
            num_workers: AtomicUsize::new(0),
        });

        for i in 0..threads {
            shared.num_workers.fetch_add(1, Ordering::Release);

            // Each worker gets its own cloned receiver
            let ctx = Box::new(WorkerCtx {
                shared: shared.clone(),
                receiver: receiver.clone(),
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

        Self {
            shared,
            sender,
            receiver,
        }
    }

    pub fn submit(&self, function: JobFn, context: usize) {
        if self.shared.shutdown.load(Ordering::Acquire) {
            return;
        }

        let job = Job {
            f: function,
            a: context,
        };

        if self.sender.send(job).is_ok() {
            self.shared.job_count.fetch_add(1, Ordering::Release);
        }
    }

    pub fn submit_many(&self, jobs: &[Job]) {
        if jobs.is_empty() {
            return;
        }
        if self.shared.shutdown.load(Ordering::Acquire) {
            return;
        }

        let mut sent = 0usize;
        for &job in jobs {
            if self.sender.send(job).is_ok() {
                sent += 1;
            }
        }
        if sent > 0 {
            self.shared.job_count.fetch_add(sent, Ordering::Release);
        }
    }

    pub fn submit_if_runnable(&self, f: JobFn, a: usize) {
        if self.shared.shutdown.load(Ordering::Acquire) {
            (f)(a);
            return;
        }
        self.submit(f, a);
    }

    pub fn try_execute_one(&self) -> bool {
        match self.receiver.try_recv() {
            Ok(job) => {
                self.shared.job_count.fetch_sub(1, Ordering::AcqRel);
                (job.f)(job.a);
                true
            }
            Err(_) => false,
        }
    }

    pub fn shutdown(&self) {
        self.shared.shutdown.store(true, Ordering::Release);
        // Dropping the sender will close the channel and wake all waiting receivers
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
        // sender is dropped here, which closes the channel
    }
}

extern "win64" fn worker_entry(ctx: usize) {
    let ctx = unsafe { Box::from_raw(ctx as *mut WorkerCtx) };
    let shared = ctx.shared.clone();
    let receiver = ctx.receiver.clone();
    drop(ctx);

    loop {
        // Check shutdown before blocking
        if shared.shutdown.load(Ordering::Acquire) {
            break;
        }

        // Block until a job is available or channel disconnects
        let job = match receiver.recv() {
            Ok(job) => job,
            Err(_) => {
                // Channel disconnected (all senders dropped)  exit
                break;
            }
        };

        // Decrement job count
        shared.job_count.fetch_sub(1, Ordering::AcqRel);

        // Execute the job
        (job.f)(job.a);
    }

    shared.num_workers.fetch_sub(1, Ordering::AcqRel);
}
