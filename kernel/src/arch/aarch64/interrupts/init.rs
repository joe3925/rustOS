use aarch64_cpu::asm::barrier::{SY, isb};
use aarch64_cpu::registers::{VBAR_EL1, Writeable};
use spin::Once;

use crate::platform::InterruptPlatform;

use super::controller::InterruptController;
use super::discovery::discover_gicv3;
use super::entry::aarch64_exception_vectors;
use super::gicv3::GicV3;
use crate::arch::aarch64::platform::Aarch64Platform;

static INTERRUPT_CONTROLLER: Once<InterruptController> = Once::new();

pub(super) fn controller() -> &'static InterruptController {
    INTERRUPT_CONTROLLER.get().expect("GIC is not initialized")
}

pub(crate) fn init_boot_interrupts() {
    VBAR_EL1.set(&raw const aarch64_exception_vectors as u64);
    isb(SY);
    let description = discover_gicv3().expect("firmware does not describe a supported GICv3");
    let gic = GicV3::new(description);
    gic.init_distributor();
    INTERRUPT_CONTROLLER.call_once(|| InterruptController::GicV3(gic));
    kernel_types::irq::set_irq_context_query(irq_context_query);
    kernel_types::irq::set_irq_interrupt_control(
        irq_interrupts_enabled,
        irq_interrupts_disable,
        irq_interrupts_enable,
        irq_interrupts_enable_and_halt,
    );
}

pub(crate) fn init_current_cpu_interrupts() {
    controller().init_current_cpu();
}

extern "C" fn irq_context_query() -> bool {
    Aarch64Platform::current_is_in_interrupt()
}

extern "C" fn irq_interrupts_enabled() -> bool {
    Aarch64Platform::interrupts_enabled()
}

extern "C" fn irq_interrupts_disable() {
    Aarch64Platform::disable_interrupts();
}

extern "C" fn irq_interrupts_enable() {
    Aarch64Platform::enable_interrupts();
}

extern "C" fn irq_interrupts_enable_and_halt() {
    Aarch64Platform::enable_interrupts_and_halt();
}
