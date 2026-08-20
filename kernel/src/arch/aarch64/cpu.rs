use core::arch::asm;

use alloc::vec::Vec;

use crate::{
    drivers::ACPI::{PerCpu, alloc_or_get_percpu_for},
    platform::CpuPlatform,
};

use super::platform::Aarch64Platform;

pub unsafe fn set_per_cpu(ptr: *mut PerCpu) {
    asm!(
        "msr tpidr_el1, {ptr}",
        ptr = in(reg) ptr,
        options(nostack, preserves_flags)
    );
}

pub struct PerCpuState;

unsafe impl Send for PerCpuState {}
unsafe impl Sync for PerCpuState {}

impl CpuPlatform for Aarch64Platform {
    type PerCpuState = PerCpuState;

    const MAX_CPUS: usize = 256;

    fn current_cpu_id() -> usize {
        todo!()
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
        set_per_cpu()
    }

    fn current_percpu() -> &'static Self::PerCpuState {
        todo!()
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
