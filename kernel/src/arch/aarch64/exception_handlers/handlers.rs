use crate::panic_exception;
use alloc::format;

use crate::scheduling::state::State;
use crate::scheduling::task::{KernelStackFaultResolution, resolve_current_kernel_stack_fault};
use crate::util::exception_panic;

use super::syndrome::*;
use super::{Aarch64ExceptionInfo, Aarch64ExceptionOrigin};

pub(crate) fn dispatch_sync(state: &mut State, origin: Aarch64ExceptionOrigin) {
    let syndrome: u64;
    let fault_address: u64;

    unsafe {
        core::arch::asm!(
            "mrs {value}, esr_el1",
            value = out(reg) syndrome,
            options(nomem, nostack, preserves_flags)
        );
        core::arch::asm!(
            "mrs {value}, far_el1",
            value = out(reg) fault_address,
            options(nomem, nostack, preserves_flags)
        );
    }

    let info = Aarch64ExceptionInfo {
        origin,
        syndrome,
        fault_address,
    };

    match exception_class(syndrome) {
        ESR_EL1_EC_DATA_ABORT_CURRENT_EL | ESR_EL1_EC_DATA_ABORT_LOWER_EL => {
            data_abort(state, info)
        }
        ESR_EL1_EC_INSTRUCTION_ABORT_CURRENT_EL | ESR_EL1_EC_INSTRUCTION_ABORT_LOWER_EL => {
            instruction_abort(state, info)
        }
        ESR_EL1_EC_BREAKPOINT_CURRENT_EL
        | ESR_EL1_EC_BREAKPOINT_LOWER_EL
        | ESR_EL1_EC_SOFTWARE_STEP_CURRENT_EL
        | ESR_EL1_EC_SOFTWARE_STEP_LOWER_EL
        | ESR_EL1_EC_WATCHPOINT_CURRENT_EL
        | ESR_EL1_EC_WATCHPOINT_LOWER_EL
        | ESR_EL1_EC_BRK => debug_exception(state, info),
        _ => unhandled_synchronous_exception(state, info),
    }
}

pub(crate) fn handle_fiq(state: &mut State, origin: Aarch64ExceptionOrigin) -> ! {
    panic_exception!(
        state,
        "AArch64 FIQ origin={origin:?} ELR={:#018x}",
        state.elr
    )
}

pub(crate) fn dispatch_serror(state: &mut State, origin: Aarch64ExceptionOrigin) -> ! {
    let syndrome: u64;

    unsafe {
        core::arch::asm!(
            "mrs {value}, esr_el1",
            value = out(reg) syndrome,
            options(nomem, nostack, preserves_flags)
        );
    }

    panic_exception!(
        state,
        "AArch64 SError origin={origin:?} ESR={syndrome:#018x} ELR={:#018x}",
        state.elr
    )
}

#[kernel_macros::exception_handler]
pub(crate) fn data_abort(state: &mut State, info: Aarch64ExceptionInfo) {
    if matches!(info.origin, Aarch64ExceptionOrigin::CurrentElSp0)
        && is_translation_fault(info.syndrome)
    {
        match resolve_current_kernel_stack_fault(info.fault_address) {
            KernelStackFaultResolution::Grown => return,
            KernelStackFaultResolution::Overflow => {
                panic_exception!(
                    state,
                    "AArch64 KERNEL STACK OVERFLOW ESR={:#018x} FAR={:#018x} ELR={:#018x}",
                    info.syndrome,
                    info.fault_address,
                    state.elr
                )
            }
            KernelStackFaultResolution::GrowthFailed(error) => {
                panic_exception!(
                    state,
                    "AArch64 KERNEL STACK GROWTH FAILED ESR={:#018x} FAR={:#018x} ELR={:#018x} error={error:?}",
                    info.syndrome,
                    info.fault_address,
                    state.elr
                )
            }
            KernelStackFaultResolution::NotStack => {}
        }
    }

    panic_exception!(
        state,
        "AArch64 DATA ABORT origin={:?} ESR={:#018x} FAR={:#018x} ELR={:#018x}",
        info.origin,
        info.syndrome,
        info.fault_address,
        state.elr
    )
}

#[kernel_macros::exception_handler]
pub(crate) fn instruction_abort(state: &mut State, info: Aarch64ExceptionInfo) -> ! {
    panic_exception!(
        state,
        "AArch64 INSTRUCTION ABORT origin={:?} ESR={:#018x} FAR={:#018x} ELR={:#018x}",
        info.origin,
        info.syndrome,
        info.fault_address,
        state.elr
    )
}

#[kernel_macros::exception_handler]
pub(crate) fn debug_exception(state: &mut State, info: Aarch64ExceptionInfo) -> ! {
    panic_exception!(
        state,
        "AArch64 DEBUG EXCEPTION origin={:?} ESR={:#018x} FAR={:#018x} ELR={:#018x}",
        info.origin,
        info.syndrome,
        info.fault_address,
        state.elr
    )
}

#[kernel_macros::exception_handler]
pub(crate) fn unhandled_synchronous_exception(state: &mut State, info: Aarch64ExceptionInfo) -> ! {
    panic_exception!(
        state,
        "AArch64 SYNCHRONOUS EXCEPTION origin={:?} ESR={:#018x} FAR={:#018x} ELR={:#018x}",
        info.origin,
        info.syndrome,
        info.fault_address,
        state.elr
    )
}
