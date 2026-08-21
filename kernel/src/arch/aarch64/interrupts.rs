use kernel_types::irq::{MsiMessage, MsiRequest, PlatformCpuId};

use crate::platform::InterruptPlatform;

use super::platform::Aarch64Platform;

pub struct InterruptFrame;

impl InterruptPlatform for Aarch64Platform {
    type InterruptFrame = InterruptFrame;

    const DYNAMIC_VECTOR_START: u8 = 0;
    const DYNAMIC_VECTOR_END: u8 = u8::MAX;

    fn scheduler_ipi_vector() -> u8 {
        todo!()
    }
    fn timer_interrupt_vector() -> u8 {
        todo!()
    }
    fn tlb_shootdown_vector() -> u8 {
        todo!()
    }
    fn interrupts_enabled() -> bool {
        todo!()
    }
    fn current_is_in_interrupt() -> bool {
        todo!()
    }
    fn disable_interrupts() {
        todo!()
    }
    fn enable_interrupts() {
        todo!()
    }
    fn with_interrupts_disabled<T>(_f: impl FnOnce() -> T) -> T {
        todo!()
    }
    fn enable_interrupts_and_halt() {
        todo!()
    }
    fn end_interrupt(_vector: u8) {
        todo!()
    }
    fn send_ipi(_target_platform_cpu_id: PlatformCpuId, _vector: u8) -> bool {
        todo!()
    }
    fn broadcast_panic_stop() {
        todo!()
    }
    fn compose_msi_message(_request: &MsiRequest) -> Option<MsiMessage> {
        todo!()
    }
    fn is_reserved_vector(_vector: u8) -> bool {
        todo!()
    }
    fn gsi_to_vector(_gsi: u8) -> Option<u8> {
        todo!()
    }
    fn vector_to_gsi(_vector: u8) -> Option<u8> {
        todo!()
    }
    fn unmask_gsi_any_cpu(_gsi: u8, _vector: u8) {
        todo!()
    }
    fn enter_interrupt() -> bool {
        todo!()
    }
    fn leave_interrupt(_was_in_interrupt: bool) {
        todo!()
    }
}
