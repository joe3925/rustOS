use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::platform::{Platform, ThreadEntry};

const WAIT_QUEUE_NONE: u64 = 0;

static NEXT_TASK_ID: AtomicU64 = AtomicU64::new(1);

pub struct StdTask {
    id: u64,
    wait_next: AtomicU64,
    thread: ::std::thread::Thread,
}

impl StdTask {
    fn current() -> Arc<Self> {
        ::std::thread_local! {
            static CURRENT_TASK: Arc<StdTask> = Arc::new(StdTask {
                id: NEXT_TASK_ID.fetch_add(1, Ordering::Relaxed),
                wait_next: AtomicU64::new(WAIT_QUEUE_NONE),
                thread: ::std::thread::current(),
            });
        }

        CURRENT_TASK.with(Clone::clone)
    }
}

pub enum StdPlatform {}

impl Platform for StdPlatform {
    type Task = Arc<StdTask>;

    #[inline]
    fn current_task() -> Option<Self::Task> {
        Some(StdTask::current())
    }

    #[inline]
    fn task_id(task: &Self::Task) -> u64 {
        task.id
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
        task.thread.unpark();
    }

    #[inline]
    fn park_current() {
        ::std::thread::park();
    }

    fn spawn_thread(name: String, entry: ThreadEntry, context: usize) {
        ::std::thread::Builder::new()
            .name(name)
            .spawn(move || entry(context))
            .expect("failed to spawn std sync worker");
    }

    #[inline]
    fn spin_loop() {
        ::std::thread::yield_now();
    }
}
