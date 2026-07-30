use alloc::format;

use crate::error::{DriverErrorKind, ErrorBacktrace, KernelError, ResultErrorContext};

#[test]
fn dynamic_message_and_context_preserve_origin_trace() {
    let trace = ErrorBacktrace::from_frames(&[0x1000, 0x2000], Default::default());
    let error = KernelError::from_parts(
        DriverErrorKind::DeviceError.into(),
        Some(format_args!("command {:#x} failed", 0x14)),
        Some(trace),
    );

    let result: Result<(), KernelError> = Err(error.clone());
    let error = result
        .with_context(|| format!("initializing {}", "disk0"))
        .unwrap_err();

    assert_eq!(error.kind(), DriverErrorKind::DeviceError.into());
    assert_eq!(error.message(), Some("command 0x14 failed"));
    assert!(error.message_location().unwrap().file().contains("test"));
    assert_eq!(error.contexts().len(), 1);
    assert_eq!(error.contexts()[0].message(), "initializing disk0");
    assert_eq!(error.backtrace().unwrap().frames(), &[0x1000, 0x2000]);
    assert_eq!(error, error.clone());
}
