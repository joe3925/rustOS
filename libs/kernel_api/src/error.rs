use core::fmt;

pub use kernel_types::error::{
    BacktraceStatus, DriverErrorKind, ErrorBacktrace, ErrorContext, ErrorKind, ErrorLocation,
    FileErrorKind, KernelError, RegistryErrorKind, RelatedError, ResultErrorContext,
};

pub fn error<K>(kind: K) -> KernelError
where
    K: Into<ErrorKind>,
{
    let mut backtrace = ErrorBacktrace::empty();
    unsafe {
        kernel_sys::kernel_capture_error_backtrace(&mut backtrace);
    }
    KernelError::from_parts(kind.into(), None, Some(backtrace))
}

#[track_caller]
pub fn error_with_message<K>(kind: K, message: fmt::Arguments<'_>) -> KernelError
where
    K: Into<ErrorKind>,
{
    let mut backtrace = ErrorBacktrace::empty();
    unsafe {
        kernel_sys::kernel_capture_error_backtrace(&mut backtrace);
    }
    KernelError::from_parts(kind.into(), Some(message), Some(backtrace))
}

pub fn error_without_backtrace<K>(kind: K) -> KernelError
where
    K: Into<ErrorKind>,
{
    KernelError::from_parts(kind.into(), None, None)
}
