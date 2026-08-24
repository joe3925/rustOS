use super::entry::InterruptToken;
use super::gicv3::GicV3;
use kernel_types::irq::PlatformCpuId;

pub(super) const SCHEDULER_SGI: u8 = 1;
pub(super) const TLB_SHOOTDOWN_SGI: u8 = 2;
pub(super) const PANIC_STOP_SGI: u8 = 3;
pub(super) const VIRTUAL_TIMER_PPI: u8 = 27;
pub(super) const SPI_START: u32 = 32;
pub(super) const SPI_END: u32 = 1019;

pub(crate) enum InterruptController {
    GicV3(GicV3),
}

impl InterruptController {
    pub(crate) fn acknowledge(&self) -> Option<InterruptToken> {
        match self {
            Self::GicV3(gic) => gic.acknowledge(),
        }
    }

    pub(crate) fn end_interrupt(&self, token: InterruptToken) {
        match self {
            Self::GicV3(gic) => gic.end_interrupt(token),
        }
    }

    pub(crate) fn init_current_cpu(&self) {
        match self {
            Self::GicV3(gic) => gic.init_current_cpu(),
        }
    }

    pub(crate) fn send_ipi(&self, target: PlatformCpuId, vector: u8) -> bool {
        match self {
            Self::GicV3(gic) => gic.send_ipi(target, vector),
        }
    }

    pub(crate) fn broadcast_ipi(&self, vector: u8) {
        match self {
            Self::GicV3(gic) => gic.broadcast_ipi(vector),
        }
    }

    pub(crate) fn unmask_spi(&self, intid: u32) {
        match self {
            Self::GicV3(gic) => gic.unmask_spi(intid),
        }
    }

    pub(crate) fn mask_spi(&self, intid: u32) {
        match self {
            Self::GicV3(gic) => gic.mask_spi(intid),
        }
    }
}
