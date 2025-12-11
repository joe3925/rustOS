use alloc::sync::Arc;

use crate::{
    static_handlers::{submit_blocking_internal, submit_runtime_internal},
    structs::thread_pool::ThreadPool,
};
lazy_static::lazy_static! {
    pub static ref RUNTIME_POOL: Arc<ThreadPool> = ThreadPool::new(16);
    pub static ref BLOCKING_POOL: Arc<ThreadPool> = ThreadPool::new(16);
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
