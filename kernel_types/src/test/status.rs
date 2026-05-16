use alloc::string::ToString;

use crate::status::{Data, DriverError, DriverStatus, FileStatus, RegError};

#[test]
fn driver_status_codes_round_trip_and_compare_by_code() {
    let cases = [
        (
            DriverStatus::Success,
            DriverStatus::STATUS_SUCCESS,
            "Success",
        ),
        (
            DriverStatus::PendingStep,
            DriverStatus::STATUS_PENDING_STEP,
            "PendingStep",
        ),
        (
            DriverStatus::ContinueStep,
            DriverStatus::STATUS_CONTINUE_STEP,
            "ContinueStep",
        ),
        (
            DriverStatus::InvalidParameter,
            DriverStatus::STATUS_INVALID_PARAMETER,
            "InvalidParameter",
        ),
        (
            DriverStatus::NoSuchDevice,
            DriverStatus::STATUS_NO_SUCH_DEVICE,
            "NoSuchDevice",
        ),
        (
            DriverStatus::Timeout,
            DriverStatus::STATUS_TIMEOUT,
            "Timeout",
        ),
    ];

    for (status, code, display) in cases {
        assert_eq!(status.code(), code);
        assert_eq!(DriverStatus::from(code), status);
        assert_eq!(status.to_string(), display);
    }

    assert_eq!(
        DriverStatus::device_error("specific message"),
        DriverStatus::device_error("different message")
    );
    assert_eq!(
        DriverStatus::from(DriverStatus::STATUS_DEVICE_ERROR),
        DriverStatus::device_error("Device error")
    );
    assert_eq!(DriverStatus::from(0x1234), DriverStatus::Unsuccessful);
}

#[test]
fn file_and_registry_error_conversions_preserve_semantics() {
    assert_eq!(FileStatus::Success.to_str(), "Success");
    assert_eq!(FileStatus::FileAlreadyExist.to_str(), "File already exists");
    assert!(matches!(
        DriverError::from(FileStatus::FileAlreadyExist),
        DriverError::DriverAlreadyInstalled
    ));

    match DriverError::from(FileStatus::PathNotFound) {
        DriverError::File(FileStatus::PathNotFound) => {}
        other => panic!("unexpected driver error: {other:?}"),
    }

    match RegError::from(FileStatus::AccessDenied) {
        RegError::FileIO {
            status: FileStatus::AccessDenied,
        } => {}
        other => panic!("unexpected registry error: {other:?}"),
    }
}

#[test]
fn registry_data_values_are_comparable() {
    assert_eq!(Data::U32(7), Data::U32(7));
    assert_ne!(Data::U32(7), Data::U64(7));
    assert_eq!(Data::Str("value".into()), Data::Str("value".into()));
}
