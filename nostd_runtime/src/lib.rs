#![no_std]
extern crate alloc;

pub mod block_on;
mod task;
mod waker;

use alloc::sync::Arc;
use core::future::Future;
use task::Task;

pub use block_on::block_on;

unsafe extern "win64" {
    fn _driver_runtime_submit_task(trampoline: extern "win64" fn(usize), ctx: usize);
}

pub fn spawn(future: impl Future<Output = ()> + Send + 'static) {
    let task = Arc::new(Task::new(future));
    let ptr = Arc::into_raw(task) as usize;

    unsafe {
        _driver_runtime_submit_task(Task::poll_trampoline, ptr);
    }
}

pub(crate) fn submit_raw(ptr: usize) {
    unsafe {
        _driver_runtime_submit_task(Task::poll_trampoline, ptr);
    }
}
