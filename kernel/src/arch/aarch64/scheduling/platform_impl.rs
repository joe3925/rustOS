use alloc::sync::Arc;

use kernel_types::arch::VirtAddr;
use kernel_types::runtime::BlockOnThreadState;

use crate::platform::TaskPlatform;

use super::super::platform::Aarch64Platform;
use super::state::{FpuState, TaskContext, TaskEntry};
use super::tls::{self, KernelTls};

impl TaskPlatform for Aarch64Platform {
    type TaskEntry = TaskEntry;
    type TaskContext = TaskContext;
    type FpuState = FpuState;
    type KernelTls = KernelTls;

    fn idle_task_entry() -> Self::TaskEntry {
        todo!()
    }
    fn new_user_task_context(
        _entry_point: Self::TaskEntry,
        _context: usize,
        _stack_top: VirtAddr,
    ) -> Self::TaskContext {
        todo!()
    }
    fn new_kernel_task_context(
        _entry_point: Self::TaskEntry,
        _context: usize,
        _stack_top: VirtAddr,
    ) -> Self::TaskContext {
        todo!()
    }
    fn mark_idle_task_context(_context: &mut Self::TaskContext) {
        todo!()
    }
    unsafe fn restore_task_context(_context: &Self::TaskContext, _target: *mut Self::TaskContext) {
        todo!()
    }
    fn save_fpu_state(_state: &mut Self::FpuState) {
        todo!()
    }
    fn restore_fpu_state(_state: &Self::FpuState) {
        todo!()
    }
    fn new_kernel_tls() -> Option<Self::KernelTls> {
        KernelTls::for_kernel_thread()
    }
    fn kernel_tls_thread_pointer(tls: &Self::KernelTls) -> u64 {
        tls.thread_pointer()
    }
    unsafe fn activate_kernel_tls(thread_pointer: u64) {
        unsafe { tls::activate(thread_pointer) }
    }
    fn ensure_current_thread_runtime_initialized() {
        tls::ensure_current_thread_runtime_initialized()
    }
    fn current_block_on_thread_state() -> Arc<BlockOnThreadState> {
        tls::current_block_on_thread_state()
    }
    fn request_task_yield() {
        todo!()
    }
}
