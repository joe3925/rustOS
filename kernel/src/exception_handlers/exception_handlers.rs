use crate::memory::paging::tables::kernel_cr3;
use crate::println;
use alloc::fmt;
use x86_64::registers::control::{Cr2, Cr3};
use x86_64::structures::idt::{InterruptStackFrame, PageFaultErrorCode};

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

pub(crate) extern "x86-interrupt" fn bound_range_exceeded_exception(
    stack_frame: InterruptStackFrame,
) {
    panic!("EXCEPTION: BOUND RANGE EXCEEDED\n{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn invalid_opcode_exception(stack_frame: InterruptStackFrame) {
    panic!("EXCEPTION: INVALID OPCODE\n{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn device_not_available_exception(
    stack_frame: InterruptStackFrame,
) {
    panic!("EXCEPTION: DEVICE NOT AVAILABLE\n{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn double_fault(
    stack_frame: InterruptStackFrame,
    _error_code: u64,
) -> ! {
    panic!("EXCEPTION: DOUBLE FAULT\n{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn invalid_tss_exception(
    stack_frame: InterruptStackFrame,
    _error_code: u64,
) {
    panic!("EXCEPTION: INVALID TSS\n{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn segment_not_present_exception(
    stack_frame: InterruptStackFrame,
    _error_code: u64,
) {
    panic!("EXCEPTION: SEGMENT NOT PRESENT\n{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn stack_segment_fault(
    stack_frame: InterruptStackFrame,
    _error_code: u64,
) {
    panic!("EXCEPTION: STACK SEGMENT FAULT\n{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn general_protection_fault(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    let decoded = decode_gpf_error_code(error_code);
    panic!(
        "EXCEPTION: GENERAL PROTECTION FAULT\nerror_code=0x{:X}\n{}\n{:#?}",
        error_code, decoded, stack_frame,
    );
}

// TODO: properly handle page faults
pub(crate) extern "x86-interrupt" fn page_fault(
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    unsafe { Cr3::write(kernel_cr3(), Cr3::read().1) };

    let cr2 = Cr2::read();
    panic!(
        "EXCEPTION: PAGE FAULT\nerror_code={:?}\ncr2={:?}\n{:#?}",
        error_code, cr2, stack_frame
    );
}

pub(crate) extern "x86-interrupt" fn x87_floating_point_exception(
    stack_frame: InterruptStackFrame,
) {
    panic!("EXCEPTION: x87 FLOATING POINT\n{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn alignment_check_exception(
    stack_frame: InterruptStackFrame,
    _error_code: u64,
) {
    panic!("EXCEPTION: ALIGNMENT CHECK\n{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn machine_check_exception(
    stack_frame: InterruptStackFrame,
) -> ! {
    panic!("EXCEPTION: MACHINE CHECK\n{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn simd_floating_point_exception(
    stack_frame: InterruptStackFrame,
) {
    panic!("EXCEPTION: SIMD FLOATING POINT\n{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn virtualization_exception(stack_frame: InterruptStackFrame) {
    panic!("EXCEPTION: VIRTUALIZATION\n{:#?}", stack_frame);
}
#[derive(Clone, Copy)]
struct DecodedGpfErrorCode {
    source_bits: u64,
    table_indicator: u64,
    index: u64,
}

impl fmt::Display for DecodedGpfErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let source = match self.source_bits {
            0 => "GDT",
            1 => "IDT",
            2 => "LDT",
            _ => "Reserved",
        };

        let table = if self.table_indicator == 0 {
            "GDT"
        } else {
            "LDT"
        };

        write!(
            f,
            "Decoded GPF error code:\nsource={}\ntable={}\nsegment_selector_index={}",
            source, table, self.index
        )
    }
}

fn decode_gpf_error_code(error_code: u64) -> DecodedGpfErrorCode {
    DecodedGpfErrorCode {
        source_bits: error_code & 0b111,
        table_indicator: (error_code >> 3) & 1,
        index: (error_code >> 4) & 0x1FFF,
    }
}
