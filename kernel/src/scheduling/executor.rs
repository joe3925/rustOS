use crate::structs::thread_pool::ThreadPool;
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use spin::Mutex;

lazy_static::lazy_static! {
    static ref EXECUTOR_POOL: Arc<ThreadPool> = crate::drivers::pnp::request::THREADS.clone();
}

pub type BoxFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

struct Task {
    future: Mutex<BoxFuture>,
}

impl Task {
    fn new<F>(future: F) -> Arc<Self>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        Arc::new(Self {
            future: Mutex::new(Box::pin(future)),
        })
    }

    fn from_boxed(future: BoxFuture) -> Arc<Self> {
        Arc::new(Self {
            future: Mutex::new(future),
        })
    }

    fn poll(self: &Arc<Self>) {
        let waker = waker_ref(self);
        let mut cx = Context::from_waker(&waker);
        let mut future_slot = self.future.lock();
        let _ = future_slot.as_mut().poll(&mut cx);
    }
}

/// Convenient Rust-only API: `spawn(async move { ... })`
pub fn spawn<F>(future: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    let task = Task::new(future);
    let task_ptr = Arc::into_raw(task) as usize;
    EXECUTOR_POOL.submit(task_poll_trampoline, task_ptr);
}

/// Exportable / non-generic API: pass in a boxed/pinned future.
#[no_mangle]
pub extern "win64" fn spawn_boxed(future: BoxFuture) {
    let task = Task::from_boxed(future);
    let task_ptr = Arc::into_raw(task) as usize;
    EXECUTOR_POOL.submit(task_poll_trampoline, task_ptr);
}

extern "win64" fn task_poll_trampoline(ptr: usize) {
    let task = unsafe { Arc::from_raw(ptr as *const Task) };
    task.poll();
}

fn waker_ref(task: &Arc<Task>) -> Waker {
    let raw = raw_waker(task.clone());
    unsafe { Waker::from_raw(raw) }
}

fn raw_waker(task: Arc<Task>) -> RawWaker {
    let ptr = Arc::into_raw(task) as *const ();
    RawWaker::new(ptr, &VTABLE)
}

unsafe fn waker_clone(ptr: *const ()) -> RawWaker {
    let task = Arc::from_raw(ptr as *const Task);
    let new_waker = raw_waker(task.clone());
    core::mem::forget(task);
    new_waker
}

unsafe fn waker_wake(ptr: *const ()) {
    let task = Arc::from_raw(ptr as *const Task);
    let raw_ptr = Arc::into_raw(task) as usize;
    EXECUTOR_POOL.submit(task_poll_trampoline, raw_ptr);
}

unsafe fn waker_wake_by_ref(ptr: *const ()) {
    let task = Arc::from_raw(ptr as *const Task);
    let job_task = task.clone();
    core::mem::forget(task);
    let raw_ptr = Arc::into_raw(job_task) as usize;
    EXECUTOR_POOL.submit(task_poll_trampoline, raw_ptr);
}

unsafe fn waker_drop(ptr: *const ()) {
    let _ = Arc::from_raw(ptr as *const Task);
}

static VTABLE: RawWakerVTable =
    RawWakerVTable::new(waker_clone, waker_wake, waker_wake_by_ref, waker_drop);
