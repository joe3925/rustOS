use alloc::sync::Arc;
use core::cell::Cell;

use crate::platform::{self, ActivePlatform, TaskPlatform};
use kernel_types::runtime::BlockOnThreadState;

pub type KernelTls = <ActivePlatform as TaskPlatform>::KernelTls;

#[thread_local]
pub(crate) static CURRENT_PROCESS_ID: Cell<u64> = Cell::new(0);

#[inline(always)]
pub(crate) unsafe fn activate(thread_pointer: u64) {
    unsafe { platform::activate_kernel_tls(thread_pointer) };
}

#[inline(always)]
pub fn ensure_current_thread_runtime_initialized() {
    platform::ensure_current_thread_runtime_initialized();
}

pub fn current_block_on_thread_state() -> Arc<BlockOnThreadState> {
    platform::current_block_on_thread_state()
}
