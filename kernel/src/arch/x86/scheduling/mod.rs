mod entry;
pub(crate) mod state;
pub(crate) mod tls;

use alloc::sync::Arc;
use core::arch::asm;
use kernel_types::arch::VirtAddr;
use kernel_types::runtime::BlockOnThreadState;
use spin::Mutex;

use crate::platform::{CpuPlatform, TaskPlatform};
use crate::structs::per_cpu::PERCPU_TLS_ARRAY_POINTER_OFF;

use self::state::{FpuState, State};
use super::gdt::PER_CPU_GDT;
use super::platform::X86Platform;

pub(crate) use entry::{idle_task, ipi_entry, task_return_trampoline, yield_interrupt_entry};

pub type TaskEntry = extern "C" fn(usize);

const C_SHADOW_SPACE_BYTES: u64 = 32;
const RETURN_ADDRESS_BYTES: u64 = 8;
const C_ENTRY_FRAME_BYTES: u64 = RETURN_ADDRESS_BYTES + C_SHADOW_SPACE_BYTES;
static BLOCK_ON_THREAD_STATE: Mutex<Option<Arc<BlockOnThreadState>>> = Mutex::new(None);

impl TaskPlatform for X86Platform {
    type TaskEntry = TaskEntry;
    type TaskContext = State;
    type FpuState = FpuState;
    type KernelTls = tls::KernelTls;

    fn idle_task_entry() -> Self::TaskEntry {
        idle_task
    }

    fn new_user_task_context(
        entry_point: Self::TaskEntry,
        context: usize,
        stack_top: VirtAddr,
    ) -> Self::TaskContext {
        let gdt = PER_CPU_GDT.lock();
        let platform_cpu_id = Self::current_platform_cpu_id() as usize;
        let mut state = State::new(0);
        state.rip = entry_point as u64;
        state.rcx = context as u64;
        state.rsp = initial_c_entry_rsp(stack_top.as_u64());
        state.rflags = 0x0000_0202;

        unsafe {
            *(state.rsp as *mut u64) = task_return_trampoline as *const () as u64;
        }

        let selectors = unsafe { gdt.selectors_per_cpu.get_by_id(platform_cpu_id) };
        state.cs = selectors.user_code_selector.0 as u64 | 3;
        state.ss = selectors.user_data_selector.0 as u64 | 3;
        state
    }

    fn new_kernel_task_context(
        entry_point: Self::TaskEntry,
        context: usize,
        stack_top: VirtAddr,
    ) -> Self::TaskContext {
        let gdt = PER_CPU_GDT.lock();
        let platform_cpu_id = Self::current_platform_cpu_id() as usize;
        let mut state = State::new(0);
        state.rip = entry_point as u64;
        state.rcx = context as u64;
        state.rsp = initial_c_entry_rsp(stack_top.as_u64());
        state.rflags = 0x0000_0202;

        unsafe {
            *(state.rsp as *mut u64) = task_return_trampoline as *const () as u64;
        }

        let selectors = unsafe { gdt.selectors_per_cpu.get_by_id(platform_cpu_id) };
        state.cs = selectors.kernel_code_selector.0 as u64;
        state.ss = selectors.kernel_data_selector.0 as u64;
        state
    }

    fn mark_idle_task_context(context: &mut Self::TaskContext) {
        context.r10 = crate::scheduling::task::IDLE_UUID_UPPER;
        context.r11 = crate::scheduling::task::IDLE_MAGIC_LOWER;
    }

    unsafe fn restore_task_context(context: &Self::TaskContext, target: *mut Self::TaskContext) {
        unsafe { context.restore(target) };
    }

    fn save_fpu_state(state: &mut Self::FpuState) {
        state.save();
    }

    fn restore_fpu_state(state: &Self::FpuState) {
        state.restore();
    }

    fn new_kernel_tls() -> Option<Self::KernelTls> {
        tls::KernelTls::for_kernel_thread()
    }

    fn kernel_tls_thread_pointer(tls: &Self::KernelTls) -> u64 {
        tls.thread_pointer()
    }

    unsafe fn activate_kernel_tls(thread_pointer: u64) {
        unsafe {
            asm!(
                "mov qword ptr gs:[{off}], {tls}",
                off = const PERCPU_TLS_ARRAY_POINTER_OFF,
                tls = in(reg) thread_pointer,
                options(nostack, preserves_flags)
            );
        }
    }

    fn ensure_current_thread_runtime_initialized() {
        let mut state = BLOCK_ON_THREAD_STATE.lock();
        if state.is_none() {
            *state = Some(Arc::new(BlockOnThreadState::new()));
        }
    }

    fn current_block_on_thread_state() -> Arc<BlockOnThreadState> {
        BLOCK_ON_THREAD_STATE
            .lock()
            .as_ref()
            .cloned()
            .expect("kernel block_on state is not initialized for the current thread")
    }

    fn request_task_yield() {
        unsafe { super::syscalls::task_yield_interrupt() };
    }
}

fn initial_c_entry_rsp(stack_top: u64) -> u64 {
    (stack_top & !0xf).saturating_sub(C_ENTRY_FRAME_BYTES)
}
