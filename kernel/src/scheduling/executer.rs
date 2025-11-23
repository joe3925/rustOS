use alloc::sync::Arc;

use crate::structs::thread_pool::ThreadPool;
lazy_static::lazy_static! {
    pub static ref RUNTIME_POOL: Arc<ThreadPool> = ThreadPool::new(6);
}
#[no_mangle]
unsafe extern "win64" fn _driver_runtime_submit_task(trampoline: extern "C" fn(usize), ctx: usize) {
    RUNTIME_POOL.submit(trampoline, ctx);
}
