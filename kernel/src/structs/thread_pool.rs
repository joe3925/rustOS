use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::memory::paging::stack::StackSize;
use crate::scheduling::scheduler::SCHEDULER;
use crate::scheduling::task::Task;
use crate::scheduling::tls;
use crate::structs::bounded_mpmc::{
    bounded_mpmc_channel, BoundedReceiver, BoundedSendError, BoundedSender,
};
use crate::structs::mpmc::{mpmc_channel, Receiver, RecvError, Sender, TryRecvError};

pub type JobFn = extern "win64" fn(usize);

#[derive(Clone, Copy, Debug)]
pub struct Job {
    pub f: JobFn,
    pub a: usize,
}

impl From<(extern "win64" fn(usize), usize)> for Job {
    fn from(job: (extern "win64" fn(usize), usize)) -> Self {
        Job { f: job.0, a: job.1 }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmitError {
    Shutdown,
    Full,
    Disconnected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueSendError {
    Full,
    Disconnected,
}

#[derive(Clone, Copy, Debug)]
pub struct BoundedJobsConfig {
    pub max_jobs: usize,
    pub max_consumers: usize,
}

pub trait JobQueue: 'static {
    type Sender: Clone + Send + Sync + 'static;
    type Receiver: Clone + Send + Sync + 'static;
    type Config: Copy;

    fn channel(config: Self::Config) -> (Self::Sender, Self::Receiver);
    fn send(sender: &Self::Sender, job: Job) -> Result<(), QueueSendError>;
    fn recv(receiver: &Self::Receiver) -> Result<Job, RecvError>;
    fn try_recv(receiver: &Self::Receiver) -> Result<Job, TryRecvError>;
}

pub enum UnboundedJobs {}

impl JobQueue for UnboundedJobs {
    type Sender = Sender<Job>;
    type Receiver = Receiver<Job>;
    type Config = ();

    fn channel(_: Self::Config) -> (Self::Sender, Self::Receiver) {
        mpmc_channel::<Job>()
    }

    fn send(sender: &Self::Sender, job: Job) -> Result<(), QueueSendError> {
        sender.send(job).map_err(|_| QueueSendError::Disconnected)
    }

    fn recv(receiver: &Self::Receiver) -> Result<Job, RecvError> {
        receiver.recv()
    }

    fn try_recv(receiver: &Self::Receiver) -> Result<Job, TryRecvError> {
        receiver.try_recv()
    }
}

pub enum BoundedJobs {}

impl JobQueue for BoundedJobs {
    type Sender = BoundedSender<Job>;
    type Receiver = BoundedReceiver<Job>;
    type Config = BoundedJobsConfig;

    fn channel(config: Self::Config) -> (Self::Sender, Self::Receiver) {
        assert!(config.max_jobs > 0);
        assert!(config.max_consumers > 0);

        bounded_mpmc_channel::<Job>(config.max_jobs, config.max_consumers)
    }

    fn send(sender: &Self::Sender, job: Job) -> Result<(), QueueSendError> {
        sender.try_send(job).map_err(|err| match err {
            BoundedSendError::Full(_) => QueueSendError::Full,
            BoundedSendError::Disconnected(_) => QueueSendError::Disconnected,
        })
    }

    fn recv(receiver: &Self::Receiver) -> Result<Job, RecvError> {
        receiver.recv()
    }

    fn try_recv(receiver: &Self::Receiver) -> Result<Job, TryRecvError> {
        receiver.try_recv()
    }
}

struct Shared {
    shutdown: AtomicBool,
    num_workers: AtomicUsize,
    total_workers: AtomicUsize,
    work_amount_hint: AtomicUsize,
    block_on_enabled: bool,
}

struct WorkerCtx<Q: JobQueue> {
    shared: Arc<Shared>,
    receiver: Q::Receiver,
    _idx: usize,
}

pub struct ThreadPoolImpl<Q: JobQueue> {
    shared: Arc<Shared>,
    sender: Q::Sender,
    receiver: Q::Receiver,
    _queue: PhantomData<Q>,
}

pub type ThreadPool = ThreadPoolImpl<UnboundedJobs>;
pub type BoundedThreadPool = ThreadPoolImpl<BoundedJobs>;

impl ThreadPoolImpl<UnboundedJobs> {
    pub fn new(threads: usize) -> Self {
        Self::new_with_block_on(threads, false, ())
    }

    pub fn new_blocking(threads: usize) -> Self {
        Self::new_with_block_on(threads, true, ())
    }

    pub fn submit(&self, function: JobFn, context: usize) {
        let _ = self.try_submit(function, context);
    }
}

impl ThreadPoolImpl<BoundedJobs> {
    pub fn new(threads: usize, max_jobs: usize) -> Self {
        let config = BoundedJobsConfig {
            max_jobs,
            max_consumers: threads,
        };

        Self::new_with_block_on(threads, false, config)
    }

    pub fn new_blocking(threads: usize, max_jobs: usize) -> Self {
        let config = BoundedJobsConfig {
            max_jobs,
            max_consumers: threads,
        };

        Self::new_with_block_on(threads, true, config)
    }

    pub fn submit(&self, function: JobFn, context: usize) -> bool {
        self.try_submit(function, context).is_ok()
    }
}

impl<Q: JobQueue> ThreadPoolImpl<Q> {
    fn new_with_block_on(threads: usize, block_on_enabled: bool, config: Q::Config) -> Self {
        assert!(threads > 0);

        let (sender, receiver) = Q::channel(config);

        let shared = Arc::new(Shared {
            total_workers: AtomicUsize::new(threads),
            shutdown: AtomicBool::new(false),
            num_workers: AtomicUsize::new(0),
            work_amount_hint: AtomicUsize::new(0),
            block_on_enabled,
        });

        for i in 0..threads {
            shared.num_workers.fetch_add(1, Ordering::Release);

            let ctx = Box::new(WorkerCtx::<Q> {
                shared: shared.clone(),
                receiver: receiver.clone(),
                _idx: i,
            });

            let name: String = alloc::format!("thread_pool_worker_{i}");

            let th = Task::new_kernel_mode(
                worker_entry::<Q>,
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
            _queue: PhantomData,
        }
    }

    pub fn try_submit(&self, function: JobFn, context: usize) -> Result<(), SubmitError> {
        if self.shared.shutdown.load(Ordering::Acquire) {
            return Err(SubmitError::Shutdown);
        }

        self.shared.work_amount_hint.fetch_add(1, Ordering::Relaxed);

        let result = Q::send(
            &self.sender,
            Job {
                f: function,
                a: context,
            },
        );

        match result {
            Ok(()) => Ok(()),
            Err(err) => {
                self.shared.work_amount_hint.fetch_sub(1, Ordering::Relaxed);

                Err(match err {
                    QueueSendError::Full => SubmitError::Full,
                    QueueSendError::Disconnected => SubmitError::Disconnected,
                })
            }
        }
    }

    pub fn submit_many(&self, jobs: &[Job]) -> usize {
        if jobs.is_empty() {
            return 0;
        }

        if self.shared.shutdown.load(Ordering::Acquire) {
            return 0;
        }

        self.shared
            .work_amount_hint
            .fetch_add(jobs.len(), Ordering::Relaxed);

        let mut sent = 0usize;

        for &job in jobs {
            if Q::send(&self.sender, job).is_ok() {
                sent += 1;
            }
        }

        let failed = jobs.len() - sent;

        if failed != 0 {
            self.shared
                .work_amount_hint
                .fetch_sub(failed, Ordering::Relaxed);
        }

        sent
    }

    pub fn submit_if_runnable(&self, f: JobFn, a: usize) {
        if self.shared.shutdown.load(Ordering::Acquire) {
            (f)(a);
            return;
        }

        let _ = self.try_submit(f, a);
    }

    pub fn try_execute_one(&self) -> bool {
        match Q::try_recv(&self.receiver) {
            Ok(job) => {
                self.shared.work_amount_hint.fetch_sub(1, Ordering::Relaxed);
                (job.f)(job.a);
                true
            }
            Err(_) => false,
        }
    }

    pub fn shutdown(&self) {
        self.shared.shutdown.store(true, Ordering::Release);
    }

    pub fn is_shutdown(&self) -> bool {
        self.shared.shutdown.load(Ordering::Acquire)
    }

    pub fn workers(&self) -> usize {
        self.shared.num_workers.load(Ordering::Acquire)
    }

    pub fn total_workers(&self) -> usize {
        self.shared.total_workers.load(Ordering::Acquire)
    }

    pub fn work_amount_hint(&self) -> usize {
        self.shared.work_amount_hint.load(Ordering::Relaxed)
    }
}

impl<Q: JobQueue> Drop for ThreadPoolImpl<Q> {
    fn drop(&mut self) {
        self.shutdown();
    }
}

extern "win64" fn worker_entry<Q: JobQueue>(ctx: usize) {
    let ctx = unsafe { Box::from_raw(ctx as *mut WorkerCtx<Q>) };
    let shared = ctx.shared.clone();
    let receiver = ctx.receiver.clone();

    drop(ctx);

    if shared.block_on_enabled {
        tls::ensure_current_thread_runtime_initialized();
    }

    loop {
        if shared.shutdown.load(Ordering::Acquire) {
            break;
        }

        let job = match Q::recv(&receiver) {
            Ok(job) => job,
            Err(_) => break,
        };

        shared.work_amount_hint.fetch_sub(1, Ordering::Relaxed);

        (job.f)(job.a);
    }

    shared.num_workers.fetch_sub(1, Ordering::AcqRel);
}
