#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod async_mpmc;
pub mod bounded_mpmc;
pub mod bounded_wait_queue;
pub mod completion_port;
pub mod mpmc;
pub mod platform;
mod sync;
pub mod thread_pool;
pub mod wait_queue;

pub use async_mpmc::{AsyncMpmcQueue, AsyncRecvError, WaitRegistration};
pub use bounded_mpmc::{bounded_mpmc_channel, BoundedReceiver, BoundedSendError, BoundedSender};
pub use bounded_wait_queue::{BoundedWaitQueue, BoundedWaitQueueError};
pub use completion_port::{CompletionPort, PortPermit, PortReserveError, PortResizeError};
pub use mpmc::mpmc_channel;
pub use platform::{Platform, ThreadEntry};
pub use thread_pool::{
    BoundedJobs, BoundedJobsConfig, BoundedThreadPool, Job, JobFn, JobQueue, QueueSendError,
    SubmitError, ThreadPool, ThreadPoolImpl, UnboundedJobs,
};
pub use wait_queue::WaitQueue;

#[cfg(all(test, feature = "std", not(any(loom, feature = "loom"))))]
mod test;

#[cfg(all(test, any(loom, feature = "loom")))]
mod loom_tests;
