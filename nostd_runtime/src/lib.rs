// lib.rs
#![no_std]

extern crate alloc;

pub mod block_on;
pub mod blocking;
mod executor;
mod task;
mod waker;

use alloc::sync::Arc;
use core::future::Future;

pub use block_on::block_on;
pub use blocking::{spawn_blocking, BlockingJoin};

use executor::Executor;

unsafe extern "win64" {
    fn _driver_runtime_submit_task(trampoline: extern "win64" fn(usize), ctx: usize);
    fn _driver_runtime_submit_blocking_task(trampoline: extern "win64" fn(usize), ctx: usize);
    fn task_yield();
}

pub(crate) fn submit_pump() {
    unsafe {
        _driver_runtime_submit_task(executor::pump_trampoline, 0);
    }
}

pub(crate) fn submit_blocking(trampoline: extern "win64" fn(usize), ctx: usize) {
    unsafe {
        _driver_runtime_submit_blocking_task(trampoline, ctx);
    }
}

pub(crate) fn yield_now() {
    unsafe {
        //task_yield();
    }
}

pub fn spawn<F>(future: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    Executor::global().spawn(future);
}
