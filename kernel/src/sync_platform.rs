use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use kernel_sync::{Platform, ThreadEntry};

use crate::memory::paging::stack::StackSize;
use crate::platform;
use crate::scheduling::scheduler::SCHEDULER;
use crate::scheduling::task::{Task, TaskHandle, WAIT_QUEUE_NONE};
use crate::scheduling::tls;

pub enum KernelPlatform {}

impl Platform for KernelPlatform {
    type Task = TaskHandle;

    #[inline]
    fn current_task() -> Option<Self::Task> {
        let cpu_id = platform::current_cpu_id();
        SCHEDULER.get_current_task(cpu_id)
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
        task.wait_next
            .compare_exchange(
                WAIT_QUEUE_NONE,
                wait_queue_id,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    #[inline]
    fn clear_waiting(task: &Self::Task, wait_queue_id: u64) -> bool {
        task.wait_next
            .compare_exchange(
                wait_queue_id,
                WAIT_QUEUE_NONE,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    #[inline]
    fn is_waiting(task: &Self::Task, wait_queue_id: u64) -> bool {
        task.wait_next.load(Ordering::Acquire) == wait_queue_id
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
        let task = Task::new_kernel_mode(entry, context, StackSize::Huge, name, 0);
        SCHEDULER.add_task(task);
    }

    #[inline]
    fn prepare_blocking_worker() {
        tls::ensure_current_thread_runtime_initialized();
    }
}

pub type WaitQueue = kernel_sync::WaitQueue<KernelPlatform>;
pub type BoundedWaitQueue = kernel_sync::BoundedWaitQueue<KernelPlatform>;
pub type Condvar = kernel_sync::Condvar<KernelPlatform>;
pub type SleepMutex<T> = kernel_sync::SleepMutex<KernelPlatform, T>;
pub type SleepMutexGuard<'a, T> = kernel_sync::SleepMutexGuard<'a, KernelPlatform, T>;

pub type MpmcSender<T> = kernel_sync::mpmc::Sender<KernelPlatform, T>;
pub type MpmcReceiver<T> = kernel_sync::mpmc::Receiver<KernelPlatform, T>;
pub type BoundedMpmcSender<T> = kernel_sync::bounded_mpmc::BoundedSender<KernelPlatform, T>;
pub type BoundedMpmcReceiver<T> = kernel_sync::bounded_mpmc::BoundedReceiver<KernelPlatform, T>;
pub type ChannelSender<T> = kernel_sync::channel::Sender<KernelPlatform, T>;
pub type ChannelReceiver<T> = kernel_sync::channel::Receiver<KernelPlatform, T>;

pub type ThreadPool = kernel_sync::thread_pool::ThreadPool<KernelPlatform>;
pub type BoundedThreadPool = kernel_sync::thread_pool::BoundedThreadPool<KernelPlatform>;

#[inline]
pub fn mpmc_channel<T>() -> (MpmcSender<T>, MpmcReceiver<T>) {
    kernel_sync::mpmc::mpmc_channel::<KernelPlatform, T>()
}

#[inline]
pub fn bounded_mpmc_channel<T>(
    capacity: usize,
    max_consumers: usize,
) -> (BoundedMpmcSender<T>, BoundedMpmcReceiver<T>) {
    kernel_sync::bounded_mpmc::bounded_mpmc_channel::<KernelPlatform, T>(capacity, max_consumers)
}

#[inline]
pub fn channel<T>() -> (ChannelSender<T>, ChannelReceiver<T>) {
    kernel_sync::channel::channel::<KernelPlatform, T>()
}
