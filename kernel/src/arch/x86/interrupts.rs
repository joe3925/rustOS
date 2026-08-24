pub use x86_64::instructions::hlt;
pub use x86_64::instructions::interrupts::*;

use kernel_types::irq::{
    HardwareInterruptId, MSI_KIND_MSI, MSI_KIND_MSIX, MSI_TARGET_ANY, MSI_TARGET_PLATFORM_CPU,
    MsiBindingRequest, MsiMessage, PlatformCpuId,
};
use x86_64::structures::idt::InterruptStackFrame;

use crate::platform::InterruptPlatform;

use super::drivers::interrupt_index::{
    APIC, IpiDest, IpiKind, LocalApic, current_is_in_interrupt_atomic, get_current_logical_id,
    send_eoi,
};
use super::platform::X86Platform;

impl InterruptPlatform for X86Platform {
    type InterruptFrame = InterruptStackFrame;

    const DYNAMIC_VECTOR_START: u8 = super::idt::DYNAMIC_VECTOR_START;
    const DYNAMIC_VECTOR_END: u8 = super::idt::DYNAMIC_VECTOR_END;

    fn scheduler_ipi_vector() -> u8 {
        super::idt::SCHED_IPI_VECTOR
    }

    fn timer_interrupt_vector() -> u8 {
        super::idt::TIMER_VECTOR
    }

    fn tlb_shootdown_vector() -> u8 {
        super::idt::TLB_FLUSH_VECTOR
    }

    fn interrupts_enabled() -> bool {
        x86_64::instructions::interrupts::are_enabled()
    }

    fn current_is_in_interrupt() -> bool {
        current_is_in_interrupt_atomic().load(core::sync::atomic::Ordering::Relaxed)
    }

    fn disable_interrupts() {
        x86_64::instructions::interrupts::disable();
    }

    fn enable_interrupts() {
        x86_64::instructions::interrupts::enable();
    }

    fn with_interrupts_disabled<T>(f: impl FnOnce() -> T) -> T {
        x86_64::instructions::interrupts::without_interrupts(f)
    }

    fn enable_interrupts_and_halt() {
        x86_64::instructions::interrupts::enable_and_hlt();
    }

    fn end_interrupt(vector: u8) {
        send_eoi(vector);
    }

    fn send_ipi(target_platform_cpu_id: PlatformCpuId, vector: u8) -> bool {
        if target_platform_cpu_id > u8::MAX as PlatformCpuId {
            return false;
        }

        let in_interrupt =
            current_is_in_interrupt_atomic().load(core::sync::atomic::Ordering::Acquire);

        if in_interrupt {
            let Some(apic) = APIC.try_lock() else {
                return false;
            };

            if let Some(apic) = apic.as_ref() {
                unsafe {
                    apic.lapic.send_ipi(
                        IpiDest::ApicId(target_platform_cpu_id as u8),
                        IpiKind::Fixed { vector },
                    );
                }
                return true;
            }

            return false;
        }

        unsafe {
            if let Some(apic) = APIC.lock().as_ref() {
                apic.lapic.send_ipi(
                    IpiDest::ApicId(target_platform_cpu_id as u8),
                    IpiKind::Fixed { vector },
                );
                return true;
            }
        }

        false
    }

    fn broadcast_panic_stop() {
        unsafe {
            if let Some(apic) = APIC.lock().as_ref() {
                apic.lapic.send_ipi(IpiDest::AllExcludingSelf, IpiKind::Nmi);
            }
        }
    }

    fn compose_msi_message(request: &MsiBindingRequest, vector: u8) -> Option<MsiMessage> {
        match request.kind {
            MSI_KIND_MSI | MSI_KIND_MSIX => {}
            _ => return None,
        }

        let destination = match request.target.mode {
            MSI_TARGET_ANY => get_current_logical_id() as u32,
            MSI_TARGET_PLATFORM_CPU => request.target.platform_cpu_id,
            _ => return None,
        };

        if destination > u8::MAX as u32 {
            return None;
        }

        let address = 0xFEE0_0000u64 | ((destination as u64) << 12);
        let data = vector as u32;

        Some(MsiMessage::new(address, data))
    }

    fn is_reserved_vector(vector: u8) -> bool {
        vector == super::idt::SYSCALL_VECTOR
    }

    fn bind_wired_interrupt(source: HardwareInterruptId, interrupt_id: u32) -> bool {
        let Ok(vector) = u8::try_from(interrupt_id) else {
            return false;
        };
        let guard = APIC.lock();
        let Some(apic) = guard.as_ref() else {
            return false;
        };
        apic.bind_wired_interrupt(source.0, vector, get_current_logical_id())
    }

    fn unbind_wired_interrupt(source: HardwareInterruptId) {
        if let Some(apic) = APIC.lock().as_ref() {
            apic.unbind_wired_interrupt(source.0);
        }
    }

    fn wired_interrupt_id(_source: HardwareInterruptId) -> Option<u32> {
        None
    }

    fn enter_interrupt() -> bool {
        current_is_in_interrupt_atomic().swap(true, core::sync::atomic::Ordering::AcqRel)
    }

    fn leave_interrupt(was_in_interrupt: bool) {
        if !was_in_interrupt {
            current_is_in_interrupt_atomic().store(false, core::sync::atomic::Ordering::Release);
        }
    }
}
