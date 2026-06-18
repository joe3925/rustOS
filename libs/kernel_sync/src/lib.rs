#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod bounded_mpmc;
pub mod bounded_wait_queue;
pub mod channel;
pub mod condvar;
pub mod mpmc;
pub mod platform;
pub mod sleep_mutex;
pub mod thread_pool;
pub mod wait_queue;

pub use bounded_mpmc::{bounded_mpmc_channel, BoundedReceiver, BoundedSendError, BoundedSender};
pub use bounded_wait_queue::{BoundedWaitQueue, BoundedWaitQueueError};
pub use channel::channel;
pub use condvar::Condvar;
pub use mpmc::mpmc_channel;
pub use platform::{ParkReason, Platform, ThreadEntry};
pub use sleep_mutex::{SleepMutex, SleepMutexGuard};
pub use thread_pool::{
    BoundedJobs, BoundedJobsConfig, BoundedThreadPool, Job, JobFn, JobQueue, QueueSendError,
    SubmitError, ThreadPool, ThreadPoolImpl, UnboundedJobs,
};
pub use wait_queue::WaitQueue;

#[cfg(all(test, feature = "std"))]
mod test;
