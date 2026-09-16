use crate::scheduling::scheduler::KernelFpuGuard;
use crate::scheduling::state::State;
use core::hint::black_box;
use core::sync::atomic::Ordering;

use super::super::memory::paging::tables::kernel_cr3;
use crate::println;
use crate::scheduling::task::{KernelStackFaultResolution, resolve_current_kernel_stack_fault};
use crate::util::{PANIC_ACTIVE, exception_panic};
use alloc::{fmt, format};
use x86_64::registers::control::{Cr2, Cr3};
use x86_64::structures::idt::{InterruptStackFrame, PageFaultErrorCode};

macro_rules! panic_exception {
    ($state:expr, $($message:tt)*) => {
        exception_panic(format!($($message)*), $state)
    };
}

#[kernel_macros::exception_handler]
pub(crate) fn divide_by_zero_fault(stack_frame: &mut State) {
    panic_exception!(
        stack_frame,
        "EXCEPTION: DIVIDE BY ZERO\n{:#?}",
        stack_frame.into_interrupt_stack_frame()
    );
}

#[kernel_macros::exception_handler]
pub(crate) fn debug_exception(stack_frame: &mut State) {
    panic_exception!(
        stack_frame,
        "EXCEPTION: DEBUG\n{:#?}",
        stack_frame.into_interrupt_stack_frame()
    );
}

#[kernel_macros::exception_handler]
pub(crate) fn non_maskable_interrupt(stack_frame: &mut State) {
    if PANIC_ACTIVE.load(Ordering::Acquire) {
        loop {}
    }
}

#[kernel_macros::exception_handler]
pub(crate) fn breakpoint_exception(stack_frame: &mut State) {
    if cfg!(debug_assertions) {
        println!("EXCEPTION: BREAKPOINT\n");
        black_box(0);
    } else {
        panic_exception!(
            stack_frame,
            "EXCEPTION: BREAKPOINT\n {:#?}",
            stack_frame.into_interrupt_stack_frame()
        );
    }
}

#[kernel_macros::exception_handler]
pub(crate) fn overflow_exception(stack_frame: &mut State) {
    panic_exception!(
        stack_frame,
        "EXCEPTION: OVERFLOW\n{:#?}",
        stack_frame.into_interrupt_stack_frame()
    );
}

#[kernel_macros::exception_handler]
pub(crate) fn bound_range_exceeded_exception(stack_frame: &mut State) {
    panic_exception!(
        stack_frame,
        "EXCEPTION: BOUND RANGE EXCEEDED\n{:#?}",
        stack_frame.into_interrupt_stack_frame()
    );
}

#[kernel_macros::exception_handler]
pub(crate) fn invalid_opcode_exception(stack_frame: &mut State) {
    panic_exception!(
        stack_frame,
        "EXCEPTION: INVALID OPCODE\n{:#?}",
        stack_frame.into_interrupt_stack_frame()
    );
}

#[kernel_macros::exception_handler]
pub(crate) fn device_not_available_exception(stack_frame: &mut State) {
    panic_exception!(
        stack_frame,
        "EXCEPTION: DEVICE NOT AVAILABLE\n{:#?}",
        stack_frame.into_interrupt_stack_frame()
    );
}

#[kernel_macros::exception_handler]
pub(crate) fn double_fault(stack_frame: &mut State, _error_code: u64) -> ! {
    panic_exception!(
        stack_frame,
        "EXCEPTION: DOUBLE FAULT\n{:#?}",
        stack_frame.into_interrupt_stack_frame()
    );
}

#[kernel_macros::exception_handler]
pub(crate) fn invalid_tss_exception(stack_frame: &mut State, _error_code: u64) {
    panic_exception!(
        stack_frame,
        "EXCEPTION: INVALID TSS\n{:#?}",
        stack_frame.into_interrupt_stack_frame()
    );
}

#[kernel_macros::exception_handler]
pub(crate) fn segment_not_present_exception(stack_frame: &mut State, _error_code: u64) {
    panic_exception!(
        stack_frame,
        "EXCEPTION: SEGMENT NOT PRESENT\n{:#?}",
        stack_frame.into_interrupt_stack_frame()
    );
}

#[kernel_macros::exception_handler]
pub(crate) fn stack_segment_fault(stack_frame: &mut State, _error_code: u64) {
    panic_exception!(
        stack_frame,
        "EXCEPTION: STACK SEGMENT FAULT\n{:#?}",
        stack_frame
    );
}

#[kernel_macros::exception_handler]
pub(crate) fn general_protection_fault(stack_frame: &mut State, error_code: u64) {
    let decoded = decode_gpf_error_code(error_code);
    panic_exception!(
        stack_frame,
        "EXCEPTION: GENERAL PROTECTION FAULT\nerror_code=0x{:X}\n{}\n{:#?}",
        error_code,
        decoded,
        stack_frame.into_interrupt_stack_frame(),
    );
}

#[kernel_macros::exception_handler]
pub(crate) fn page_fault(stack_frame: &mut State, error_code: PageFaultErrorCode) {
    let _fpu_guard = KernelFpuGuard::new();
    let fault = Cr2::read_raw();

    let is_protection = error_code.contains(PageFaultErrorCode::PROTECTION_VIOLATION);
    let is_user = error_code.contains(PageFaultErrorCode::USER_MODE);
    if error_code.contains(PageFaultErrorCode::INSTRUCTION_FETCH) {
        let rsp = stack_frame.rsp;
        unsafe {
            println!("  [rsp-0x20] = {:#x}", *((rsp - 0x20) as *const u64));
            println!("  [rsp-0x18] = {:#x}", *((rsp - 0x18) as *const u64));
            println!("  [rsp-0x10] = {:#x}", *((rsp - 0x10) as *const u64));
            println!("  [rsp-0x08] = {:#x}", *((rsp - 0x08) as *const u64));
            println!("  [rsp+0x00] = {:#x}", *((rsp + 0x00) as *const u64));
            println!("  [rsp+0x08] = {:#x}", *((rsp + 0x08) as *const u64));
            println!("  [rsp+0x10] = {:#x}", *((rsp + 0x10) as *const u64));
            println!("  [rsp+0x18] = {:#x}", *((rsp + 0x18) as *const u64));
        }
    }
    if !is_protection {
        if !is_user {
            match resolve_current_kernel_stack_fault(fault) {
                KernelStackFaultResolution::Grown => return,
                KernelStackFaultResolution::Overflow => {
                    unsafe { Cr3::write(kernel_cr3(), Cr3::read().1) };
                    panic_exception!(
                        stack_frame,
                        "KERNEL STACK OVERFLOW\nerror_code={:?}\ncr2={:#x}\n{:#?}",
                        error_code,
                        fault,
                        *stack_frame
                    );
                }
                KernelStackFaultResolution::GrowthFailed(error) => {
                    unsafe { Cr3::write(kernel_cr3(), Cr3::read().1) };
                    panic_exception!(
                        stack_frame,
                        "KERNEL STACK GROWTH FAILED\nerror_code={:?}\ncr2={:#x}\nerror={:?}\n{:#?}",
                        error_code,
                        fault,
                        error,
                        *stack_frame
                    );
                }
                KernelStackFaultResolution::NotStack => {}
            }
        }
    }

    unsafe { Cr3::write(kernel_cr3(), Cr3::read().1) };

    panic_exception!(
        stack_frame,
        "EXCEPTION: PAGE FAULT\nerror_code={:?}\ncr2={:#x}\n{:#?}",
        error_code,
        fault,
        stack_frame
    );
}

#[kernel_macros::exception_handler]
pub(crate) fn x87_floating_point_exception(stack_frame: &mut State) {
    panic_exception!(
        stack_frame,
        "EXCEPTION: x87 FLOATING POINT\n{:#?}",
        stack_frame.into_interrupt_stack_frame()
    );
}

#[kernel_macros::exception_handler]
pub(crate) fn alignment_check_exception(stack_frame: &mut State, _error_code: u64) {
    panic_exception!(
        stack_frame,
        "EXCEPTION: ALIGNMENT CHECK\n{:#?}",
        stack_frame.into_interrupt_stack_frame()
    );
}

#[kernel_macros::exception_handler]
pub(crate) fn machine_check_exception(stack_frame: &mut State) -> ! {
    panic_exception!(
        stack_frame,
        "EXCEPTION: MACHINE CHECK\n{:#?}",
        stack_frame.into_interrupt_stack_frame()
    );
}

#[kernel_macros::exception_handler]
pub(crate) fn simd_floating_point_exception(stack_frame: &mut State) {
    panic_exception!(
        stack_frame,
        "EXCEPTION: SIMD FLOATING POINT\n{:#?}",
        stack_frame.into_interrupt_stack_frame()
    );
}

#[kernel_macros::exception_handler]
pub(crate) fn virtualization_exception(stack_frame: &mut State) {
    panic_exception!(
        stack_frame,
        "EXCEPTION: VIRTUALIZATION\n{:#?}",
        stack_frame.into_interrupt_stack_frame()
    );
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
