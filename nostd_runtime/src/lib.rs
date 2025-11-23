#![no_std]
extern crate alloc;

pub mod block_on;
mod task;
mod waker;

use alloc::sync::Arc;
use core::future::Future;
use task::FutureTask;

pub use block_on::block_on;

use crate::task::poll_trampoline;

unsafe extern "win64" {
    fn _driver_runtime_submit_task(trampoline: extern "C" fn(usize), ctx: usize);
}

pub fn spawn(future: impl Future<Output = ()> + Send + 'static) {
    let task = Arc::new(FutureTask::new(future));
    let ptr = Arc::into_raw(task) as usize;
    unsafe {
        _driver_runtime_submit_task(poll_trampoline, ptr);
    }
}

pub(crate) fn submit_raw(ptr: usize) {
    unsafe {
        _driver_runtime_submit_task(poll_trampoline, ptr);
    }
}
