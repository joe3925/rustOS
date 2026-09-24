use kernel_types::irq::{MsiBindingRequest, MsiMessage, PlatformCpuId};

use super::discovery::MsiControllerDescription;
use super::gicv2m::GicV2m;
use super::its::Its;

pub(super) struct MsiBinding {
    pub(super) message: MsiMessage,
    pub(super) spi: Option<(u32, PlatformCpuId)>,
}

pub(super) enum MsiInterruptController {
    Its(Its),
    GicV2m(GicV2m),
}

impl MsiInterruptController {
    pub(super) fn new(description: MsiControllerDescription) -> Option<Self> {
        match description {
            MsiControllerDescription::Its(base) => Its::new(base).map(Self::Its),
            MsiControllerDescription::GicV2m {
                base,
                spi_base,
                spi_count,
            } => GicV2m::new(base, spi_base, spi_count).map(Self::GicV2m),
        }
    }

    pub(super) fn init_cpu(
        &self,
        redistributor: usize,
        redistributor_phys: u64,
        cpu: PlatformCpuId,
    ) -> bool {
        match self {
            Self::Its(its) => its.init_cpu(redistributor, redistributor_phys, cpu),
            Self::GicV2m(_) => true,
        }
    }

    pub(super) fn bind(&self, request: &MsiBindingRequest, vector: u8) -> Option<MsiBinding> {
        match self {
            Self::Its(its) => Some(MsiBinding {
                message: its.bind(request, vector)?,
                spi: None,
            }),
            Self::GicV2m(gicv2m) => gicv2m.bind(request, vector),
        }
    }

    pub(super) fn unbind(&self, vector: u8) -> Option<u32> {
        match self {
            Self::Its(its) => {
                its.unbind(vector);
                None
            }
            Self::GicV2m(gicv2m) => gicv2m.unbind(vector),
        }
    }

    pub(super) fn spi_for_vector(&self, vector: u8) -> Option<u32> {
        match self {
            Self::Its(_) => None,
            Self::GicV2m(gicv2m) => gicv2m.spi_for_vector(vector),
        }
    }

    pub(super) fn vector_for_interrupt(&self, intid: u32) -> Option<u8> {
        match self {
            Self::Its(its) => its.vector_for_lpi(intid),
            Self::GicV2m(gicv2m) => gicv2m.vector_for_spi(intid),
        }
    }
}
