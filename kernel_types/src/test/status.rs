use alloc::string::ToString;

use crate::status::{Data, DriverError, DriverStatus, FileStatus, RegError};

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
