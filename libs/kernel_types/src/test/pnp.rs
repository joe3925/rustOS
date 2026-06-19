use alloc::sync::Arc;

use crate::async_ffi::{FfiFuture, FutureExt};
use crate::device::DeviceObject;
use crate::pnp::{BootType, DriverStep, PnpMinorFunction, PnpVtable};
use crate::request::{Pnp, RequestHandle};
use crate::status::DriverStatus;

extern "C" fn start_device_handler(
    _dev: &Arc<DeviceObject>,
    _handle: &mut RequestHandle<'_, Pnp<'_>>,
) -> FfiFuture<DriverStep> {
    async { DriverStep::complete(DriverStatus::Success) }.into_ffi()
}

#[test]
fn boot_type_parses_kernel_driver_start_modes() {
    assert_eq!(BootType::from_str("boot"), Some(BootType::Boot));
    assert_eq!(BootType::from_str("system"), Some(BootType::System));
    assert_eq!(BootType::from_str("demand"), Some(BootType::Demand));
    assert_eq!(BootType::from_str("disabled"), Some(BootType::Disabled));
    assert_eq!(BootType::from_str("manual"), None);
    assert_eq!(BootType::Demand.as_u32(), 2);
}

#[test]
fn pnp_minor_defaults_distinguish_optional_queries_from_lifecycle_ops() {
    assert_eq!(
        PnpMinorFunction::StartDevice.default_status_for_unhandled(),
        DriverStatus::Success
    );
    assert_eq!(
        PnpMinorFunction::RemoveDevice.default_status_for_unhandled(),
        DriverStatus::Success
    );
    assert_eq!(
        PnpMinorFunction::QueryId.default_status_for_unhandled(),
        DriverStatus::NotImplemented
    );
    assert_eq!(
        PnpMinorFunction::QueryResources.default_status_for_unhandled(),
        DriverStatus::NotImplemented
    );
}

#[test]
fn pnp_vtable_installs_handlers_by_minor_function() {
    let vtable = PnpVtable::new();

    assert!(vtable.get(PnpMinorFunction::StartDevice).is_none());
    vtable.set(PnpMinorFunction::StartDevice, start_device_handler);
    assert!(vtable.get(PnpMinorFunction::StartDevice).is_some());
    assert!(vtable.get(PnpMinorFunction::StopDevice).is_none());
}
