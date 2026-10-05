use alloc::string::String;
use alloc::sync::Arc;
use kernel_sync::{Platform, ThreadEntry};

use crate::memory::paging::stack::StackSize;
use crate::platform;
use crate::scheduling::scheduler::SCHEDULER;
use crate::scheduling::task::{Task, TaskHandle};
use crate::scheduling::tls;

pub enum KernelPlatform {}

impl Platform for KernelPlatform {
    type Task = TaskHandle;

    #[inline]
    fn current_task() -> Option<Self::Task> {
        SCHEDULER.get_local_current_task()
    }

    #[inline]
    fn task_id(task: &Self::Task) -> u64 {
        task.task_id()
    }

    #[inline]
    fn same_task(a: &Self::Task, b: &Self::Task) -> bool {
        Arc::ptr_eq(a, b)
    }

    #[inline]
    fn mark_waiting(task: &Self::Task, wait_queue_id: u64) -> bool {
        task.wait_next.mark(wait_queue_id)
    }

    #[inline]
    fn clear_waiting(task: &Self::Task, wait_queue_id: u64) -> bool {
        task.wait_next.clear(wait_queue_id)
    }

    #[inline]
    fn is_waiting(task: &Self::Task, wait_queue_id: u64) -> bool {
        task.wait_next.is_marked(wait_queue_id)
    }

    #[inline]
    fn unpark(task: &Self::Task) {
        SCHEDULER.unpark(task);
    }

    #[inline]
    fn park_current() {
        SCHEDULER.park_current();
    }

    fn spawn_thread(name: String, entry: ThreadEntry, context: usize) {
        let task = Task::new_kernel_mode(entry, context, StackSize::Tiny, name, 0);
        SCHEDULER.add_task(task);
    }

    #[inline]
    fn prepare_blocking_worker() {
        tls::ensure_current_thread_runtime_initialized();
    }
}

pub type WaitQueue = kernel_sync::queues::WaitQueue<KernelPlatform>;
pub type BoundedWaitQueue = kernel_sync::queues::BoundedWaitQueue<KernelPlatform>;
pub type MpmcSender<T> = kernel_sync::channels::mpmc::Sender<KernelPlatform, T>;
pub type MpmcReceiver<T> = kernel_sync::channels::mpmc::Receiver<KernelPlatform, T>;
pub type BoundedMpmcSender<T> = kernel_sync::channels::mpmc::BoundedSender<KernelPlatform, T>;
pub type BoundedMpmcReceiver<T> = kernel_sync::channels::mpmc::BoundedReceiver<KernelPlatform, T>;
pub type CompletionPort<T> = kernel_sync::completion::CompletionPort<KernelPlatform, T>;
pub type CompletionPortPermit<T> = kernel_sync::completion::PortPermit<KernelPlatform, T>;
pub type ThreadPool = kernel_sync::workers::thread_pool::ThreadPool<KernelPlatform>;
pub type BoundedThreadPool = kernel_sync::workers::thread_pool::BoundedThreadPool<KernelPlatform>;

#[inline]
pub fn mpmc_channel<T>() -> (MpmcSender<T>, MpmcReceiver<T>) {
    kernel_sync::channels::mpmc::mpmc_channel::<KernelPlatform, T>()
}

#[inline]
pub fn bounded_mpmc_channel<T>(
    capacity: usize,
    max_consumers: usize,
) -> (BoundedMpmcSender<T>, BoundedMpmcReceiver<T>) {
    kernel_sync::channels::mpmc::bounded_mpmc_channel::<KernelPlatform, T>(capacity, max_consumers)
}
