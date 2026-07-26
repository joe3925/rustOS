use alloc::string::String;
use core::fmt;

use kernel_types::arch::VirtAddr;
use kernel_types::error::{
    BacktraceStatus as SharedBacktraceStatus, ErrorBacktrace, ErrorKind, KernelError,
};

use crate::executable::program::PROGRAM_MANAGER;
use crate::profiling::backtrace::{Backtrace, BacktraceStatus};

pub(crate) fn error<K>(kind: K) -> KernelError
where
    K: Into<ErrorKind>,
{
    KernelError::from_parts(kind.into(), None, Some(capture()))
}

#[track_caller]
pub(crate) fn error_with_message<K>(kind: K, message: fmt::Arguments<'_>) -> KernelError
where
    K: Into<ErrorKind>,
{
    KernelError::from_parts(kind.into(), Some(message), Some(capture()))
}

pub(crate) fn error_without_backtrace<K>(kind: K) -> KernelError
where
    K: Into<ErrorKind>,
{
    KernelError::from_parts(kind.into(), None, None)
}

pub(crate) fn capture() -> ErrorBacktrace {
    shared_backtrace(Backtrace::capture())
}

fn shared_backtrace(backtrace: Backtrace) -> ErrorBacktrace {
    let mut frames = [0usize; kernel_types::error::MAX_ERROR_BACKTRACE_DEPTH];
    let depth = backtrace.frames().len().min(frames.len());
    for (output, frame) in frames.iter_mut().zip(backtrace.frames()).take(depth) {
        *output = frame.instruction_pointer().as_u64() as usize;
    }

    let source = backtrace.status();
    let mut bits = 0;
    for (source_flag, shared_flag) in [
        (BacktraceStatus::TRUNCATED, SharedBacktraceStatus::TRUNCATED),
        (
            BacktraceStatus::NO_UNWIND_INFO,
            SharedBacktraceStatus::NO_UNWIND_INFO,
        ),
        (
            BacktraceStatus::BAD_STACK_READ,
            SharedBacktraceStatus::BAD_STACK_READ,
        ),
        (
            BacktraceStatus::BAD_UNWIND_INFO,
            SharedBacktraceStatus::BAD_UNWIND_INFO,
        ),
        (
            BacktraceStatus::UNSUPPORTED_OPERATION,
            SharedBacktraceStatus::UNSUPPORTED_OPERATION,
        ),
        (
            BacktraceStatus::LEAF_FALLBACK,
            SharedBacktraceStatus::LEAF_FALLBACK,
        ),
        (
            BacktraceStatus::UNKNOWN_FRAME,
            SharedBacktraceStatus::UNKNOWN_FRAME,
        ),
        (
            BacktraceStatus::STACK_BOUNDS_MISSING,
            SharedBacktraceStatus::STACK_BOUNDS_MISSING,
        ),
        (
            BacktraceStatus::MODULE_LOOKUP_UNAVAILABLE,
            SharedBacktraceStatus::MODULE_LOOKUP_UNAVAILABLE,
        ),
    ] {
        if source.contains(source_flag) {
            bits |= shared_flag.bits();
        }
    }

    ErrorBacktrace::from_frames(&frames[..depth], SharedBacktraceStatus::from_bits(bits))
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_capture_error_backtrace(output: &mut ErrorBacktrace) {
    *output = capture();
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_resolve_error_context_module(
    instruction_pointer: usize,
) -> Option<String> {
    let Some(program) = PROGRAM_MANAGER.get(0) else {
        return None;
    };
    let Some(module) = program
        .read()
        .module_containing(VirtAddr::new(instruction_pointer as u64))
    else {
        return None;
    };
    let Some(module) = module.try_read() else {
        return None;
    };
    let mut name = String::new();
    name.try_reserve_exact(module.title.len()).ok()?;
    name.push_str(&module.title);
    Some(name)
}
