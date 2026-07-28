use alloc::sync::Arc;

use crate::async_ffi::{AbiFuture, FutureExt};
use crate::device::DeviceObject;
use crate::error::KernelError;
use crate::pnp::{BootType, DriverStep, PnpOp, PnpOps, StartDevice, UnhandledBehavior};

extern "C" fn start_device_handler(
    _dev: &Arc<DeviceObject>,
    _op: PnpOp,
    _request: &mut StartDevice,
) -> AbiFuture<Result<DriverStep, KernelError>> {
    async { Ok(DriverStep::Complete) }.into_abi()
}

#[test]
fn boot_type_parses_kernel_driver_start_modes() {
    assert_eq!(BootType::from_str("boot"), Some(BootType::Boot));
    assert_eq!(BootType::from_str("system"), None);
    assert_eq!(BootType::from_str("demand"), Some(BootType::Demand));
    assert_eq!(BootType::from_str("disabled"), Some(BootType::Disabled));
    assert_eq!(BootType::from_str("manual"), None);
    assert_eq!(BootType::Demand.as_u32(), 1);
}

#[test]
fn pnp_minor_defaults_distinguish_optional_queries_from_lifecycle_ops() {
    assert_eq!(
        PnpOp::StartDevice.unhandled_behavior(),
        UnhandledBehavior::Complete
    );
    assert_eq!(
        PnpOp::RemoveDevice.unhandled_behavior(),
        UnhandledBehavior::Complete
    );
    assert_eq!(
        PnpOp::QueryId.unhandled_behavior(),
        UnhandledBehavior::Error(crate::error::DriverErrorKind::NotImplemented)
    );
    assert_eq!(
        PnpOp::QueryResources.unhandled_behavior(),
        UnhandledBehavior::Error(crate::error::DriverErrorKind::NotImplemented)
    );
}

#[test]
fn pnp_ops_installs_handlers_by_minor_function() {
    let mut ops = PnpOps::new();

    assert!(ops.start_device.as_handler().is_none());
    ops.start_device.set(start_device_handler);
    assert!(ops.start_device.as_handler().is_some());
    assert!(ops.stop_device.as_handler().is_none());
}
