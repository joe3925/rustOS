use super::super::super::interrupts::apic::local::send_eoi;
use crate::idt::interrupt_impl::InterruptGuard;

#[cfg_attr(irq_check, irq::context)]
#[unsafe(no_mangle)]
extern "C" fn tlb_flush_ipi() {
    let _guard = InterruptGuard::new();
    crate::memory::paging::tlb::handle_remote_tlb_shootdown();
    send_eoi();
}

crate::x86_interrupt_entry!(pub tlb_flush_entry, tlb_flush_ipi);
