use alloc::sync::Arc;
use core::future::Future;

pub use super::block_on::block_on;
pub use super::blocking::{spawn_blocking, BlockingJoin};

use crate::static_handlers::task_yield;
use crate::{
    static_handlers::{submit_blocking_internal, submit_runtime_internal},
    structs::thread_pool::ThreadPool,
};

use super::task::FutureTask;

lazy_static::lazy_static! {
    pub static ref RUNTIME_POOL: Arc<ThreadPool> = ThreadPool::new(2);
    pub static ref BLOCKING_POOL: Arc<ThreadPool> = ThreadPool::new(2);
}

pub(crate) fn submit_global(trampoline: extern "win64" fn(usize), ctx: usize) {
    unsafe {
        _driver_runtime_submit_task(trampoline, ctx);
    }
}

pub(crate) fn submit_blocking(trampoline: extern "win64" fn(usize), ctx: usize) {
    unsafe {
        _driver_runtime_submit_blocking_task(trampoline, ctx);
    }
}

pub(crate) fn yield_now() {
    unsafe {
        task_yield();
    }
}

pub fn spawn<F>(future: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    let task = Arc::new(FutureTask::new(future));
    task.enqueue();
}

#[no_mangle]
unsafe extern "win64" fn _driver_runtime_submit_task(
    trampoline: extern "win64" fn(usize),
    ctx: usize,
) {
    submit_runtime_internal(trampoline, ctx);
}

#[no_mangle]
unsafe extern "win64" fn _driver_runtime_submit_blocking_task(
    trampoline: extern "win64" fn(usize),
    ctx: usize,
) {
    submit_blocking_internal(trampoline, ctx);
}
