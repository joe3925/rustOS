use crate::memory::paging::{stack::KERNEL_STACK_MAX_BYTES, tables::kernel_cr3};
use crate::println;
use crate::scheduling::scheduler::SCHEDULER;
use crate::scheduling::task::Task;
use crate::static_handlers::get_current_cpu_id;
use crate::util::PANIC_ACTIVE;
use alloc::fmt;
use x86_64::registers::control::{Cr2, Cr3};
use x86_64::structures::idt::{InterruptStackFrame, PageFaultErrorCode};
use x86_64::structures::paging::PageTableFlags;

pub(crate) extern "x86-interrupt" fn divide_by_zero_fault(stack_frame: InterruptStackFrame) {
    panic!("EXCEPTION: DIVIDE BY ZERO\n{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn debug_exception(stack_frame: InterruptStackFrame) {
    panic!("EXCEPTION: DEBUG\n{:#?}", stack_frame);
}

pub(crate) extern "x86-interrupt" fn non_maskable_interrupt(stack_frame: InterruptStackFrame) {
    if PANIC_ACTIVE.load(core::sync::atomic::Ordering::Acquire) {
        loop {}
    }
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

pub(crate) extern "x86-interrupt" fn page_fault(
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    const PAGE_SIZE: u64 = 4096;
    let fault = Cr2::read_raw();

    let is_protection = error_code.contains(PageFaultErrorCode::PROTECTION_VIOLATION);
    let is_user = error_code.contains(PageFaultErrorCode::USER_MODE);

    if !is_protection {
        if let Some(task) = SCHEDULER.get_current_task(get_current_cpu_id()) {
            let mut t = task.inner.write();
            if !t.is_user_mode && !is_user && t.guard_page != 0 {
                let max_depth = t.stack_start.saturating_sub(KERNEL_STACK_MAX_BYTES);
                let gp = t.guard_page;

                // Allow growth for faults anywhere within the 2MiB reserved window below stack_start.
                if fault >= max_depth && fault < t.stack_start {
                    let flags = PageTableFlags::PRESENT
                        | PageTableFlags::WRITABLE
                        | PageTableFlags::NO_EXECUTE;
                    while fault < t.guard_page + PAGE_SIZE {
                        match t.grow_stack(flags) {
                            Ok(true) => {}
                            _ => break,
                        }
                    }
                    if fault >= t.guard_page + PAGE_SIZE {
                        return;
                    }
                }

                if fault < gp {
                    unsafe { Cr3::write(kernel_cr3(), Cr3::read().1) };
                    panic!(
                        "KERNEL STACK OVERFLOW\nerror_code={:?}\ncr2={:#x}\n(task guard={:#x})\n{:#?}",
                        error_code,
                        fault,
                        gp,
                        stack_frame
                    );
                }
            }
        }
    }

    unsafe { Cr3::write(kernel_cr3(), Cr3::read().1) };

    panic!(
        "EXCEPTION: PAGE FAULT\nerror_code={:?}\ncr2={:#x}\n{:#?}",
        error_code, fault, stack_frame
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
