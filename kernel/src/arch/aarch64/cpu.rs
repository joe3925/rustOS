use core::arch::asm;

use alloc::vec::Vec;

use crate::{
    arch::aarch64::memory,
    drivers::ACPI::{PerCpu, alloc_or_get_percpu_for},
    platform::{CpuPlatform, current_percpu},
};

use super::platform::Aarch64Platform;
#[thread_local]
static mut EXECUTOR_TASK_ID: u64 = 0;
#[thread_local]
static mut EXECUTOR_DOMAIN_ID: u64 = 0;

#[inline(always)]
pub unsafe fn set_per_cpu(ptr: *const PerCpu) {
    asm!(
        "msr tpidr_el1, {ptr}",
        ptr = in(reg) ptr,
        options(nostack, preserves_flags)
    );
}
#[inline(always)]
pub fn per_cpu_ptr() -> *const PerCpu {
    let ptr: *const PerCpu;

    unsafe {
        asm!(
            "mrs {ptr}, tpidr_el1",
            ptr = out(reg) ptr,
            options(nomem, nostack, preserves_flags)
        );
    }

    ptr
}

impl CpuPlatform for Aarch64Platform {
    type PerCpuState = crate::drivers::ACPI::PerCpu;

    const MAX_CPUS: usize = 256;

    fn current_cpu_id() -> usize {
        *current_percpu().cpu_id.get().expect("no cpuid for core") as usize
    }
    fn current_logical_id() -> usize {
        todo!()
    }
    fn cpu_topology_ids() -> Vec<u8> {
        todo!()
    }
    fn processor_count() -> usize {
        todo!()
    }
    fn init_current_cpu_local_state(logical_id: u32) {
        let cpu = alloc_or_get_percpu_for(logical_id);
        unsafe { set_per_cpu(cpu as *const PerCpu) };
    }

    fn current_percpu() -> &'static Self::PerCpuState {
        unsafe { &*per_cpu_ptr() }
    }
    fn swap_executor_context(_task_id: u64, _domain_id: u64) -> (u64, u64) {
        todo!()
    }
    fn current_executor_context() -> (u64, u64) {
        todo!()
    }
    fn start_secondary_cpus() -> bool {
        todo!()
    }
    fn halt() -> ! {
        todo!()
    }
    fn broadcast_panic_stop() {
        todo!()
    }
}
