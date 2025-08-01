use crate::drivers;
use crate::drivers::drive::ide_disk_driver::{primary_drive_irq_handler, secondary_drive_irq_handler};
use crate::drivers::kbd_driver::keyboard_interrupt_handler;
use crate::drivers::timer_driver::timer_interrupt_entry;
use crate::exception_handlers::exception_handlers;
use crate::gdt::{DOUBLE_FAULT_IST_INDEX};
use lazy_static::lazy_static;
use x86_64::structures::idt::InterruptDescriptorTable;
use x86_64::VirtAddr;

lazy_static! {
    pub static ref IDT: InterruptDescriptorTable = unsafe{
        let mut idt = InterruptDescriptorTable::new();
        idt.divide_error.set_handler_fn(exception_handlers::divide_by_zero_fault);
        idt.debug.set_handler_fn(exception_handlers::debug_exception);
        idt.non_maskable_interrupt.set_handler_fn(exception_handlers::non_maskable_interrupt);
        idt.breakpoint.set_handler_fn(exception_handlers::breakpoint_exception);
        idt.overflow.set_handler_fn(exception_handlers::overflow_exception);
        idt.bound_range_exceeded.set_handler_fn(exception_handlers::bound_range_exceeded_exception);
        idt.invalid_opcode.set_handler_fn(exception_handlers::invalid_opcode_exception);
        idt.device_not_available.set_handler_fn(exception_handlers::device_not_available_exception);
        idt.double_fault.set_handler_fn(exception_handlers::double_fault).set_stack_index(DOUBLE_FAULT_IST_INDEX);
        idt.invalid_tss.set_handler_fn(exception_handlers::invalid_tss_exception);
        idt.segment_not_present.set_handler_fn(exception_handlers::segment_not_present_exception);
        idt.stack_segment_fault.set_handler_fn(exception_handlers::stack_segment_fault);
        idt.general_protection_fault.set_handler_fn(exception_handlers::general_protection_fault);
        idt.page_fault.set_handler_fn(exception_handlers::page_fault);
        idt.x87_floating_point.set_handler_fn(exception_handlers::x87_floating_point_exception);
        idt.alignment_check.set_handler_fn(exception_handlers::alignment_check_exception);
        idt.machine_check.set_handler_fn(exception_handlers::machine_check_exception);
        idt.simd_floating_point.set_handler_fn(exception_handlers::simd_floating_point_exception);
        idt.virtualization.set_handler_fn(exception_handlers::virtualization_exception);

        //hardware interrupts
        idt[drivers::interrupt_index::InterruptIndex::Timer.as_u8()].set_handler_addr(VirtAddr::new(timer_interrupt_entry as u64)); // .set_stack_index(TIMER_IST_INDEX);
        idt[drivers::interrupt_index::InterruptIndex::KeyboardIndex.as_u8()].set_handler_fn(keyboard_interrupt_handler);
        idt[drivers::interrupt_index::InterruptIndex::PrimaryDrive.as_u8()].set_handler_fn(primary_drive_irq_handler);
        idt[drivers::interrupt_index::InterruptIndex::SecondaryDrive.as_u8()].set_handler_fn(secondary_drive_irq_handler);


        idt
    };
}
pub(crate) fn load_idt() {
    IDT.load();
    x86_64::instructions::interrupts::enable();
}