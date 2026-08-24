use core::sync::atomic::Ordering;

use aarch64_cpu::asm::barrier::{SY, isb};
use aarch64_cpu::asm::wfi;
use aarch64_cpu::registers::{DAIF, Readable, Writeable};
use kernel_types::irq::{HardwareInterruptId, MsiBindingRequest, MsiMessage, PlatformCpuId};

use crate::platform::{CpuPlatform, InterruptPlatform};

use super::controller::{
    PANIC_STOP_SGI, SCHEDULER_SGI, SPI_END, SPI_START, TLB_SHOOTDOWN_SGI, VIRTUAL_TIMER_PPI,
};
use super::entry::InterruptFrame;
use super::init::controller;
use crate::arch::aarch64::platform::Aarch64Platform;

impl InterruptPlatform for Aarch64Platform {
    type InterruptFrame = InterruptFrame;
    const DYNAMIC_VECTOR_START: u8 = SPI_START as u8;
    const DYNAMIC_VECTOR_END: u8 = u8::MAX;
    fn scheduler_ipi_vector() -> u8 {
        SCHEDULER_SGI
    }
    fn timer_interrupt_vector() -> u8 {
        VIRTUAL_TIMER_PPI
    }
    fn tlb_shootdown_vector() -> u8 {
        TLB_SHOOTDOWN_SGI
    }
    fn interrupts_enabled() -> bool {
        DAIF.get() & (1 << 7) == 0
    }
    fn current_is_in_interrupt() -> bool {
        Self::current_percpu()
            .is_in_interrupt
            .load(Ordering::Relaxed)
    }
    fn disable_interrupts() {
        DAIF.set(DAIF.get() | (1 << 7));
    }
    fn enable_interrupts() {
        DAIF.set(DAIF.get() & !(1 << 7));
    }
    fn with_interrupts_disabled<T>(f: impl FnOnce() -> T) -> T {
        let enabled = Self::interrupts_enabled();
        Self::disable_interrupts();
        let result = f();
        if enabled {
            Self::enable_interrupts();
        }
        result
    }
    fn enable_interrupts_and_halt() {
        Self::enable_interrupts();
        isb(SY);
        wfi();
    }
    fn end_interrupt(_vector: u8) {}
    fn send_ipi(target: PlatformCpuId, vector: u8) -> bool {
        controller().send_ipi(target, vector)
    }
    fn broadcast_panic_stop() {
        controller().broadcast_ipi(PANIC_STOP_SGI);
    }
    fn compose_msi_message(_request: &MsiBindingRequest, _vector: u8) -> Option<MsiMessage> {
        None
    }
    fn is_reserved_vector(vector: u8) -> bool {
        (vector as u32) < SPI_START
    }
    fn bind_wired_interrupt(source: HardwareInterruptId, interrupt_id: u32) -> bool {
        if source.0 != interrupt_id || !(SPI_START..=SPI_END).contains(&source.0) {
            return false;
        }
        controller().unmask_spi(source.0);
        true
    }
    fn unbind_wired_interrupt(source: HardwareInterruptId) {
        if (SPI_START..=SPI_END).contains(&source.0) {
            controller().mask_spi(source.0);
        }
    }
    fn wired_interrupt_id(source: HardwareInterruptId) -> Option<u32> {
        (SPI_START..=SPI_END)
            .contains(&source.0)
            .then_some(source.0)
    }
    fn enter_interrupt() -> bool {
        Self::current_percpu()
            .is_in_interrupt
            .swap(true, Ordering::AcqRel)
    }
    fn leave_interrupt(was_in_interrupt: bool) {
        if !was_in_interrupt {
            Self::current_percpu()
                .is_in_interrupt
                .store(false, Ordering::Release);
        }
    }
}
