use crate::println;
use x86_64::registers::control::Cr2;
use x86_64::structures::idt::{InterruptStackFrame, PageFaultErrorCode};

pub(crate) extern "x86-interrupt" fn divide_by_zero_fault(stack_frame: InterruptStackFrame) {
    x86_64::instructions::bochs_breakpoint();
    panic!("EXCEPTION: DIVIDE BY ZERO\n{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn debug_exception(stack_frame: InterruptStackFrame) {
    x86_64::instructions::bochs_breakpoint();

    panic!("EXCEPTION: DEBUG\n{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn non_maskable_interrupt(stack_frame: InterruptStackFrame) {
    x86_64::instructions::bochs_breakpoint();

    panic!("EXCEPTION: NON MASKABLE INTERRUPT\n{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn breakpoint_exception(stack_frame: InterruptStackFrame) {
    x86_64::instructions::bochs_breakpoint();

    panic!("EXCEPTION: BREAKPOINT\n{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn overflow_exception(stack_frame: InterruptStackFrame) {
    x86_64::instructions::bochs_breakpoint();

    panic!("EXCEPTION: OVERFLOW\n{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn bound_range_exceeded_exception(stack_frame: InterruptStackFrame) {
    x86_64::instructions::bochs_breakpoint();

    panic!("EXCEPTION: BOUND RANGE EXCEEDED\n{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn invalid_opcode_exception(stack_frame: InterruptStackFrame) {
    x86_64::instructions::bochs_breakpoint();

    panic!("EXCEPTION: INVALID OPCODE\n{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn device_not_available_exception(stack_frame: InterruptStackFrame) {
    x86_64::instructions::bochs_breakpoint();

    panic!("EXCEPTION: DEVICE NOT AVAILABLE\n{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn double_fault(stack_frame: InterruptStackFrame, _error_code: u64) -> ! {
    x86_64::instructions::bochs_breakpoint();

    panic!("EXCEPTION: DOUBLE FAULT\n{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn invalid_tss_exception(stack_frame: InterruptStackFrame, _error_code: u64) {
    x86_64::instructions::bochs_breakpoint();

    panic!("EXCEPTION: INVALID TSS\n{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn segment_not_present_exception(stack_frame: InterruptStackFrame, _error_code: u64) {
    x86_64::instructions::bochs_breakpoint();

    panic!("EXCEPTION: SEGMENT NOT PRESENT\n{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn stack_segment_fault(stack_frame: InterruptStackFrame, _error_code: u64) {
    x86_64::instructions::bochs_breakpoint();

    panic!("EXCEPTION: STACK SEGMENT FAULT\n{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn general_protection_fault(
    stack_frame: InterruptStackFrame, error_code: u64,
) {
    x86_64::instructions::bochs_breakpoint();

    decode_gpf_error_code(error_code);
    panic!("EXCEPTION: GENERAL PROTECTION FAULT ERROR CODE(0x{:X}) \n{:#?}", error_code, stack_frame, );
}

//TODO: properly handle page faults
pub(crate) extern "x86-interrupt" fn page_fault(
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    x86_64::instructions::bochs_breakpoint();

    println!("page fault: {:?}", error_code);
    println!("attempted to access: {:?}", Cr2::read());
    println!("{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn x87_floating_point_exception(stack_frame: InterruptStackFrame) {
    x86_64::instructions::bochs_breakpoint();

    panic!("EXCEPTION: x87 FLOATING POINT\n{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn alignment_check_exception(stack_frame: InterruptStackFrame, _error_code: u64) {
    x86_64::instructions::bochs_breakpoint();

    panic!("EXCEPTION: ALIGNMENT CHECK\n{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn machine_check_exception(stack_frame: InterruptStackFrame) -> ! {
    x86_64::instructions::bochs_breakpoint();

    panic!("EXCEPTION: MACHINE CHECK\n{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn simd_floating_point_exception(stack_frame: InterruptStackFrame) {
    x86_64::instructions::bochs_breakpoint();

    panic!("EXCEPTION: SIMD FLOATING POINT\n{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn virtualization_exception(stack_frame: InterruptStackFrame) {
    x86_64::instructions::bochs_breakpoint();

    panic!("EXCEPTION: VIRTUALIZATION\n{:#?}", stack_frame);
}
fn decode_gpf_error_code(error_code: u64) {
    let source = error_code & 0b111;
    let table_indicator = (error_code >> 3) & 1;
    let index = (error_code >> 4) & 0x1FFF; // Bits 4-15

    println!("Decoded GPF Error Code:");
    match source {
        0 => println!("Source: GDT"),
        1 => println!("Source: IDT"),
        2 => println!("Source: LDT"),
        _ => println!("Source: Reserved"),
    }

    if table_indicator == 0 {
        println!("Table: GDT");
    } else {
        println!("Table: LDT");
    }

    println!("Segment Selector Index: {}", index);
}