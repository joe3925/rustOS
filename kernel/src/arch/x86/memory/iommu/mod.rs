pub mod amd;
pub mod backend;
pub mod domain;
pub mod intel;
pub mod page_table;

use kernel_types::dma::DeviceMmuPlatformDeviceIdentity;

use self::backend::X86PlatformDeviceRoute;
use self::domain::IommuError;

pub(super) fn validate_platform_identity(
    identity: DeviceMmuPlatformDeviceIdentity,
) -> Result<(), IommuError> {
    if identity.iommu_id_count == 0
        || identity
            .iommu_id_base
            .checked_add(identity.iommu_id_count - 1)
            .is_none_or(|last| last > u16::MAX as u32)
    {
        Err(IommuError::Unsupported)
    } else {
        Ok(())
    }
}

pub(super) fn platform_translation_id_end(
    identity: DeviceMmuPlatformDeviceIdentity,
) -> Result<u32, IommuError> {
    validate_platform_identity(identity)?;
    identity
        .iommu_id_base
        .checked_add(identity.iommu_id_count)
        .ok_or(IommuError::Unsupported)
}

pub(super) fn platform_route_matches(
    route: &X86PlatformDeviceRoute,
    identity: DeviceMmuPlatformDeviceIdentity,
) -> bool {
    route.firmware_node == identity.firmware_node
        && route.translation_id_base == identity.iommu_id_base
        && route.translation_id_count == identity.iommu_id_count
}

pub(super) fn select_platform_route<'a>(
    routes: impl Iterator<Item = (usize, &'a X86PlatformDeviceRoute)>,
    identity: DeviceMmuPlatformDeviceIdentity,
) -> Result<(usize, u16), IommuError> {
    validate_platform_identity(identity)?;
    let mut found = None;
    for (index, route) in routes {
        if platform_route_matches(route, identity) {
            let source_id = route.translation_id_base as u16;
            if found.replace((index, source_id)).is_some() {
                return Err(IommuError::Unsupported);
            }
        }
    }
    found.ok_or(IommuError::Unsupported)
}
