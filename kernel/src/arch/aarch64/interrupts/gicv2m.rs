use kernel_types::arch::PhysAddr;
use kernel_types::irq::{
    IrqSafeMutex, MSI_KIND_MSI, MSI_KIND_MSIX, MSI_TARGET_ANY, MSI_TARGET_PLATFORM_CPU,
    MsiBindingRequest, MsiMessage,
};
use kernel_types::memory::PhysicalMappingCache;

use crate::memory::paging::mmio::map_physical_pages;
use crate::platform::CpuPlatform;

use super::controller::{SPI_END, SPI_START};
use super::msi::MsiBinding;
use crate::arch::aarch64::platform::Aarch64Platform;

const FRAME_SIZE: u64 = 0x1000;
const MSI_TYPER: usize = 0x008;
const MSI_SETSPI_NS: u64 = 0x040;
const MAX_BINDINGS: usize = 224;

#[derive(Clone, Copy)]
struct Binding {
    vector: u8,
    intid: u32,
}

struct State {
    bindings: [Option<Binding>; MAX_BINDINGS],
}

pub(super) struct GicV2m {
    physical_base: u64,
    spi_base: u32,
    spi_count: u32,
    state: IrqSafeMutex<State>,
}

impl GicV2m {
    pub(super) fn new(
        physical_base: u64,
        described_spi_base: Option<u32>,
        described_spi_count: Option<u32>,
    ) -> Option<Self> {
        let registers = map_physical_pages(
            PhysAddr::new(physical_base),
            FRAME_SIZE,
            PhysicalMappingCache::Uncached,
        )
        .ok()?;
        let typer = unsafe { ((registers.address().as_u64() as usize + MSI_TYPER) as *const u32).read_volatile() };
        let spi_base = described_spi_base.unwrap_or((typer >> 16) & 0x3ff);
        let spi_count = described_spi_count.unwrap_or(typer & 0x3ff);
        let last = spi_base.checked_add(spi_count.checked_sub(1)?)?;
        if spi_base < SPI_START || last > SPI_END || spi_count as usize > MAX_BINDINGS {
            return None;
        }
        Some(Self {
            physical_base,
            spi_base,
            spi_count,
            state: IrqSafeMutex::new(State {
                bindings: [None; MAX_BINDINGS],
            }),
        })
    }

    pub(super) fn bind(&self, request: &MsiBindingRequest, vector: u8) -> Option<MsiBinding> {
        if !matches!(request.kind, MSI_KIND_MSI | MSI_KIND_MSIX) {
            return None;
        }
        let target = match request.target.mode {
            MSI_TARGET_ANY => Aarch64Platform::current_platform_cpu_id(),
            MSI_TARGET_PLATFORM_CPU => request.target.platform_cpu_id,
            _ => return None,
        };
        let mut state = self.state.lock();
        if state
            .bindings
            .iter()
            .flatten()
            .any(|binding| binding.vector == vector)
        {
            return None;
        }
        let index = (0..self.spi_count as usize).find(|index| state.bindings[*index].is_none())?;
        let intid = self.spi_base + index as u32;
        state.bindings[index] = Some(Binding { vector, intid });
        Some(MsiBinding {
            message: MsiMessage::new(self.physical_base + MSI_SETSPI_NS, intid),
            spi: Some((intid, target)),
        })
    }

    pub(super) fn unbind(&self, vector: u8) -> Option<u32> {
        let mut state = self.state.lock();
        let index = state
            .bindings
            .iter()
            .position(|slot| slot.is_some_and(|binding| binding.vector == vector))?;
        state.bindings[index].take().map(|binding| binding.intid)
    }

    pub(super) fn spi_for_vector(&self, vector: u8) -> Option<u32> {
        self.state
            .lock()
            .bindings
            .iter()
            .flatten()
            .find(|binding| binding.vector == vector)
            .map(|binding| binding.intid)
    }

    pub(super) fn vector_for_spi(&self, intid: u32) -> Option<u8> {
        let index = intid.checked_sub(self.spi_base)? as usize;
        self.state
            .lock()
            .bindings
            .get(index)
            .copied()
            .flatten()
            .filter(|binding| binding.intid == intid)
            .map(|binding| binding.vector)
    }
}
