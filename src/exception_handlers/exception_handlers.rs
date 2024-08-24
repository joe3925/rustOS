use x86_64::registers::control::Cr2;
use x86_64::structures::idt::{InterruptStackFrame, PageFaultErrorCode};
use crate::{println};

pub(crate) extern "x86-interrupt" fn divide_by_zero_fault(stack_frame: InterruptStackFrame) {
    panic!("EXCEPTION: DIVIDE BY ZERO\n{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn debug_exception(stack_frame: InterruptStackFrame) {
    panic!("EXCEPTION: DEBUG\n{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn non_maskable_interrupt(stack_frame: InterruptStackFrame) {
    panic!("EXCEPTION: NON MASKABLE INTERRUPT\n{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn breakpoint_exception(stack_frame: InterruptStackFrame) {
    panic!("EXCEPTION: BREAKPOINT\n{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn overflow_exception(stack_frame: InterruptStackFrame) {
    panic!("EXCEPTION: OVERFLOW\n{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn bound_range_exceeded_exception(stack_frame: InterruptStackFrame) {
    panic!("EXCEPTION: BOUND RANGE EXCEEDED\n{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn invalid_opcode_exception(stack_frame: InterruptStackFrame) {
    panic!("EXCEPTION: INVALID OPCODE\n{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn device_not_available_exception(stack_frame: InterruptStackFrame) {
    panic!("EXCEPTION: DEVICE NOT AVAILABLE\n{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn double_fault(stack_frame: InterruptStackFrame, _error_code: u64) -> ! {
    panic!("EXCEPTION: DOUBLE FAULT\n{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn invalid_tss_exception(stack_frame: InterruptStackFrame, _error_code: u64) {
    panic!("EXCEPTION: INVALID TSS\n{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn segment_not_present_exception(stack_frame: InterruptStackFrame, _error_code: u64) {
    panic!("EXCEPTION: SEGMENT NOT PRESENT\n{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn stack_segment_fault(stack_frame: InterruptStackFrame, _error_code: u64) {
    panic!("EXCEPTION: STACK SEGMENT FAULT\n{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn general_protection_fault(stack_frame: InterruptStackFrame, _error_code: u64) {
    panic!("EXCEPTION: GENERAL PROTECTION FAULT\n{:#?}", stack_frame);
}

//TODO: properly handle page faults
pub(crate) extern "x86-interrupt" fn page_fault(stack_frame: InterruptStackFrame, error_code: PageFaultErrorCode) {
    println!("page fault: {:?}", error_code);
    println!("attempted to access: {:?}", Cr2::read());
    println!("{:#?}", stack_frame);


}

pub(crate) extern "x86-interrupt" fn x87_floating_point_exception(stack_frame: InterruptStackFrame) {
    panic!("EXCEPTION: x87 FLOATING POINT\n{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn alignment_check_exception(stack_frame: InterruptStackFrame, _error_code: u64) {
    panic!("EXCEPTION: ALIGNMENT CHECK\n{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn machine_check_exception(stack_frame: InterruptStackFrame) -> ! {
    panic!("EXCEPTION: MACHINE CHECK\n{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn simd_floating_point_exception(stack_frame: InterruptStackFrame) {
    panic!("EXCEPTION: SIMD FLOATING POINT\n{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn virtualization_exception(stack_frame: InterruptStackFrame) {
    panic!("EXCEPTION: VIRTUALIZATION\n{:#?}", stack_frame);
}