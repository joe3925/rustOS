use crate::scheduling::scheduler::KernelFpuGuard;
use crate::scheduling::state::State;
use core::hint::black_box;

use crate::memory::paging::stack::StackSize;
use crate::memory::paging::{stack::KERNEL_STACK_MAX_BYTES, tables::kernel_cr3};
use crate::println;
use crate::scheduling::scheduler::SCHEDULER;
use crate::static_handlers::get_current_cpu_id;
use crate::util::PANIC_ACTIVE;
use alloc::fmt;
use x86_64::registers::control::{Cr2, Cr3};
use x86_64::structures::idt::{InterruptStackFrame, PageFaultErrorCode};
use x86_64::structures::paging::PageTableFlags;
#[kernel_macros::exception_handler]
pub(crate) fn divide_by_zero_fault(stack_frame: &mut State) {
    panic!(
        "EXCEPTION: DIVIDE BY ZERO\n{:#?}",
        stack_frame.into_interrupt_stack_frame()
    );
}

#[kernel_macros::exception_handler]
pub(crate) fn debug_exception(stack_frame: &mut State) {
    panic!(
        "EXCEPTION: DEBUG\n{:#?}",
        stack_frame.into_interrupt_stack_frame()
    );
}

#[kernel_macros::exception_handler]
pub(crate) fn non_maskable_interrupt(stack_frame: &mut State) {
    if PANIC_ACTIVE.load(core::sync::atomic::Ordering::Acquire) {
        loop {}
    }
}

#[kernel_macros::exception_handler]
pub(crate) fn breakpoint_exception(stack_frame: &mut State) {
    println!("EXCEPTION: BREAKPOINT\n");
    black_box(0);
}

#[kernel_macros::exception_handler]
pub(crate) fn overflow_exception(stack_frame: &mut State) {
    panic!(
        "EXCEPTION: OVERFLOW\n{:#?}",
        stack_frame.into_interrupt_stack_frame()
    );
}

#[kernel_macros::exception_handler]
pub(crate) fn bound_range_exceeded_exception(stack_frame: &mut State) {
    panic!(
        "EXCEPTION: BOUND RANGE EXCEEDED\n{:#?}",
        stack_frame.into_interrupt_stack_frame()
    );
}

#[kernel_macros::exception_handler]
pub(crate) fn invalid_opcode_exception(stack_frame: &mut State) {
    panic!(
        "EXCEPTION: INVALID OPCODE\n{:#?}",
        stack_frame.into_interrupt_stack_frame()
    );
}

#[kernel_macros::exception_handler]
pub(crate) fn device_not_available_exception(stack_frame: &mut State) {
    panic!(
        "EXCEPTION: DEVICE NOT AVAILABLE\n{:#?}",
        stack_frame.into_interrupt_stack_frame()
    );
}

#[kernel_macros::exception_handler]
pub(crate) fn double_fault(stack_frame: &mut State, _error_code: u64) -> ! {
    panic!(
        "EXCEPTION: DOUBLE FAULT\n{:#?}",
        stack_frame.into_interrupt_stack_frame()
    );
}

#[kernel_macros::exception_handler]
pub(crate) fn invalid_tss_exception(stack_frame: &mut State, _error_code: u64) {
    panic!(
        "EXCEPTION: INVALID TSS\n{:#?}",
        stack_frame.into_interrupt_stack_frame()
    );
}

#[kernel_macros::exception_handler]
pub(crate) fn segment_not_present_exception(stack_frame: &mut State, _error_code: u64) {
    panic!(
        "EXCEPTION: SEGMENT NOT PRESENT\n{:#?}",
        stack_frame.into_interrupt_stack_frame()
    );
}

#[kernel_macros::exception_handler]
pub(crate) fn stack_segment_fault(stack_frame: &mut State, _error_code: u64) {
    panic!("EXCEPTION: STACK SEGMENT FAULT\n{:#?}", stack_frame);
}

#[kernel_macros::exception_handler]
pub(crate) fn general_protection_fault(stack_frame: &mut State, error_code: u64) {
    let decoded = decode_gpf_error_code(error_code);
    panic!(
        "EXCEPTION: GENERAL PROTECTION FAULT\nerror_code=0x{:X}\n{}\n{:#?}",
        error_code,
        decoded,
        stack_frame.into_interrupt_stack_frame(),
    );
}

#[kernel_macros::exception_handler]
pub(crate) fn page_fault(stack_frame: &mut State, error_code: PageFaultErrorCode) {
    let _fpu_guard = KernelFpuGuard::new();
    const PAGE_SIZE: u64 = 4096;
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
        if let Some(task) = SCHEDULER.get_current_task(get_current_cpu_id()) {
            if task
                .is_kernel_mode
                .load(core::sync::atomic::Ordering::Relaxed)
                && !is_user
            {
                let gp = task.guard_page.load(core::sync::atomic::Ordering::Acquire);
                if gp != 0 {
                    let stack_start = task.stack_start.load(core::sync::atomic::Ordering::Relaxed);
                    let max_depth = stack_start.saturating_sub(KERNEL_STACK_MAX_BYTES);

                    // Allow growth for faults anywhere within the 2MiB reserved window below stack_start.
                    if fault >= max_depth && fault < stack_start {
                        let flags = PageTableFlags::PRESENT
                            | PageTableFlags::WRITABLE
                            | PageTableFlags::NO_EXECUTE;
                        while fault
                            < task.guard_page.load(core::sync::atomic::Ordering::Acquire)
                                + PAGE_SIZE
                        {
                            match task.grow_stack(flags) {
                                Ok(true) => {}
                                Ok(false) => {
                                    println!("false");
                                    break;
                                }
                                Err(e) => {
                                    println!("grow stack error: {:#?}", e);
                                    break;
                                }
                            }
                        }
                        if fault
                            >= task.guard_page.load(core::sync::atomic::Ordering::Acquire)
                                + PAGE_SIZE
                        {
                            return;
                        }
                    }

                    let reserved_start = gp - StackSize::Huge2M.as_bytes();

                    if fault >= reserved_start && fault < gp {
                        unsafe { Cr3::write(kernel_cr3(), Cr3::read().1) };
                        panic!(
                            "KERNEL STACK OVERFLOW\nerror_code={:?}\ncr2={:#x}\n(task guard={:#x})\n{:#?}",
                            error_code,
                            fault,
                            gp,
                            *stack_frame
                        );
                    }
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

#[kernel_macros::exception_handler]
pub(crate) fn x87_floating_point_exception(stack_frame: &mut State) {
    panic!(
        "EXCEPTION: x87 FLOATING POINT\n{:#?}",
        stack_frame.into_interrupt_stack_frame()
    );
}

#[kernel_macros::exception_handler]
pub(crate) fn alignment_check_exception(stack_frame: &mut State, _error_code: u64) {
    panic!(
        "EXCEPTION: ALIGNMENT CHECK\n{:#?}",
        stack_frame.into_interrupt_stack_frame()
    );
}

#[kernel_macros::exception_handler]
pub(crate) fn machine_check_exception(stack_frame: &mut State) -> ! {
    panic!(
        "EXCEPTION: MACHINE CHECK\n{:#?}",
        stack_frame.into_interrupt_stack_frame()
    );
}

#[kernel_macros::exception_handler]
pub(crate) fn simd_floating_point_exception(stack_frame: &mut State) {
    panic!(
        "EXCEPTION: SIMD FLOATING POINT\n{:#?}",
        stack_frame.into_interrupt_stack_frame()
    );
}

#[kernel_macros::exception_handler]
pub(crate) fn virtualization_exception(stack_frame: &mut State) {
    panic!(
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
