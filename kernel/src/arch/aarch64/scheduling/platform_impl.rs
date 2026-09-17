use alloc::sync::Arc;
use core::arch::global_asm;
use core::sync::atomic::Ordering;

use kernel_types::arch::VirtAddr;
use kernel_types::runtime::BlockOnThreadState;

use crate::memory::paging::layout::base_page_size;
use crate::platform::{self, CpuPlatform, PagingPlatform, TaskPlatform};
use crate::scheduling::scheduler::kernel_task_end;
use crate::scheduling::task::{IDLE_MAGIC_LOWER, IDLE_UUID_UPPER};

use super::super::platform::Aarch64Platform;
use super::state::{FpuState, TaskContext, TaskEntry};
use super::tls::{self, KernelTls};

const SPSR_M_EL0T: u64 = 0b0000;
const SPSR_M_EL1T: u64 = 0b0100;
const STACK_ALIGNMENT: u64 = 16;
const EXCEPTION_FRAME_SIZE: u64 = core::mem::size_of::<TaskContext>() as u64;

global_asm!(
    r#"
    .global aarch64_save_fpu_state
aarch64_save_fpu_state:
    stp q0, q1, [x0, #0]
    stp q2, q3, [x0, #32]
    stp q4, q5, [x0, #64]
    stp q6, q7, [x0, #96]
    stp q8, q9, [x0, #128]
    stp q10, q11, [x0, #160]
    stp q12, q13, [x0, #192]
    stp q14, q15, [x0, #224]
    stp q16, q17, [x0, #256]
    stp q18, q19, [x0, #288]
    stp q20, q21, [x0, #320]
    stp q22, q23, [x0, #352]
    stp q24, q25, [x0, #384]
    stp q26, q27, [x0, #416]
    stp q28, q29, [x0, #448]
    stp q30, q31, [x0, #480]

    mrs x1, fpcr
    mrs x2, fpsr
    add x3, x0, #512
    stp x1, x2, [x3]
    ret

    .global aarch64_restore_fpu_state
aarch64_restore_fpu_state:
    ldp q0, q1, [x0, #0]
    ldp q2, q3, [x0, #32]
    ldp q4, q5, [x0, #64]
    ldp q6, q7, [x0, #96]
    ldp q8, q9, [x0, #128]
    ldp q10, q11, [x0, #160]
    ldp q12, q13, [x0, #192]
    ldp q14, q15, [x0, #224]
    ldp q16, q17, [x0, #256]
    ldp q18, q19, [x0, #288]
    ldp q20, q21, [x0, #320]
    ldp q22, q23, [x0, #352]
    ldp q24, q25, [x0, #384]
    ldp q26, q27, [x0, #416]
    ldp q28, q29, [x0, #448]
    ldp q30, q31, [x0, #480]

    add x3, x0, #512
    ldp x1, x2, [x3]

    msr fpcr, x1
    msr fpsr, x2
    ret
"#
);

unsafe extern "C" {
    fn aarch64_save_fpu_state(state: *mut FpuState);
    fn aarch64_restore_fpu_state(state: *const FpuState);
}

extern "C" fn idle_task(_context: usize) {
    loop {
        platform::enable_interrupts_and_halt();
    }
}

extern "C" fn task_return_trampoline() -> ! {
    kernel_task_end()
}

impl TaskPlatform for Aarch64Platform {
    type TaskEntry = TaskEntry;
    type TaskContext = TaskContext;
    type FpuState = FpuState;
    type KernelTls = KernelTls;

    fn idle_task_entry() -> Self::TaskEntry {
        idle_task
    }

    fn new_user_task_context(
        entry_point: Self::TaskEntry,
        context: usize,
        stack_top: VirtAddr,
    ) -> Self::TaskContext {
        let mut state = TaskContext::new();

        state.x[0] = context as u64;

        state.x[18] = Aarch64Platform::current_percpu() as *const _ as u64;

        state.x[30] = task_return_trampoline as *const () as u64;

        state.sp = stack_top.as_u64() & !(STACK_ALIGNMENT - 1);
        state.elr = entry_point as u64;
        state.spsr = SPSR_M_EL0T;

        state
    }

    fn new_kernel_task_context(
        entry_point: Self::TaskEntry,
        context: usize,
        stack_top: VirtAddr,
    ) -> Self::TaskContext {
        let mut state = TaskContext::new();

        state.x[0] = context as u64;

        state.x[18] = Aarch64Platform::current_percpu() as *const _ as u64;

        state.x[30] = task_return_trampoline as *const () as u64;

        state.sp = stack_top.as_u64() & !(STACK_ALIGNMENT - 1);
        state.elr = entry_point as u64;
        state.spsr = SPSR_M_EL1T;

        state
    }

    fn mark_idle_task_context(context: &mut Self::TaskContext) {
        context.x[10] = IDLE_UUID_UPPER;
        context.x[11] = IDLE_MAGIC_LOWER;
    }

    unsafe fn restore_task_context(context: &Self::TaskContext, target: *mut Self::TaskContext) {
        let mut context = *context;

        context.x[18] = Aarch64Platform::current_percpu() as *const _ as u64;

        let page_size = base_page_size();
        let stack_page = VirtAddr::new(context.sp.saturating_sub(1) & !(page_size - 1));

        <Aarch64Platform as PagingPlatform>::local_flush_tlb_range(
            stack_page, page_size, page_size,
        );

        unsafe {
            target.write(context);
        }
    }

    fn save_fpu_state(state: &mut Self::FpuState) {
        let active_exception_fpu = Aarch64Platform::current_percpu()
            .active_exception_fpu
            .load(Ordering::Relaxed);

        if active_exception_fpu != 0 {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    active_exception_fpu as *const FpuState,
                    state as *mut FpuState,
                    1,
                );
            }

            return;
        }

        unsafe {
            aarch64_save_fpu_state(state);
        }
    }

    fn restore_fpu_state(state: &Self::FpuState) {
        let active_exception_fpu = Aarch64Platform::current_percpu()
            .active_exception_fpu
            .load(Ordering::Relaxed);

        if active_exception_fpu != 0 {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    state as *const FpuState,
                    active_exception_fpu as *mut FpuState,
                    1,
                );
            }

            return;
        }

        unsafe {
            aarch64_restore_fpu_state(state);
        }
    }

    fn new_kernel_tls() -> Option<Self::KernelTls> {
        KernelTls::for_kernel_thread()
    }

    fn kernel_tls_thread_pointer(tls: &Self::KernelTls) -> u64 {
        tls.thread_pointer()
    }

    unsafe fn activate_kernel_tls(thread_pointer: u64) {
        unsafe {
            tls::activate(thread_pointer);
        }
    }

    fn ensure_current_thread_runtime_initialized() {
        tls::ensure_current_thread_runtime_initialized()
    }

    fn current_block_on_thread_state() -> Arc<BlockOnThreadState> {
        tls::current_block_on_thread_state()
    }

    fn request_task_yield() {
        let target = platform::current_platform_cpu_id();

        let _ = platform::send_ipi(target, super::super::interrupts::controller::TASK_YIELD_SGI);
    }
}
