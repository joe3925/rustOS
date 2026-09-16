use acpi::sdt::mcfg::Mcfg;
use alloc::vec::Vec;
use kernel_types::arch::PhysAddr;
use kernel_types::memory::PhysicalMappingCache;
use kernel_types::pci::PciConfigAddress;
use spin::Once;

use crate::machine::machine_info;
use crate::memory::paging::mmio::map_physical_pages;
use crate::platform::PciConfigPlatform;

use super::platform::Aarch64Platform;

const PCI_DEVICE_COUNT: u8 = 32;
const PCI_FUNCTION_COUNT: u8 = 8;
const PCI_FUNCTION_CONFIG_SPACE_SIZE: u16 = 4096;
const PCI_BUS_CONFIG_SPACE_SIZE: u64 = 1 << 20;

struct EcamMapping {
    base: usize,
    segment: u16,
    start_bus: u8,
    end_bus: u8,
}

static ECAM_MAPPINGS: Once<Vec<EcamMapping>> = Once::new();

fn config_address(address: PciConfigAddress) -> Option<*mut u32> {
    if address.device >= PCI_DEVICE_COUNT
        || address.function >= PCI_FUNCTION_COUNT
        || address.offset > PCI_FUNCTION_CONFIG_SPACE_SIZE - 4
    {
        return None;
    }

    let mappings = ECAM_MAPPINGS.call_once(|| {
        let mut mappings = Vec::new();
        let Some(tables) = machine_info().firmware().acpi_tables() else {
            return mappings;
        };
        let Some(mcfg) = tables.find_table::<Mcfg>() else {
            return mappings;
        };

        for entry in mcfg.get().entries() {
            let start_bus = entry.bus_number_start;
            let end_bus = entry.bus_number_end;
            let bus_count = end_bus.saturating_sub(start_bus) as u64 + 1;
            let size = bus_count * PCI_BUS_CONFIG_SPACE_SIZE;
            let Ok(base) = map_physical_pages(
                PhysAddr::new(entry.base_address),
                size,
                PhysicalMappingCache::Uncached,
            ) else {
                continue;
            };
            mappings.push(EcamMapping {
                base: base.as_u64() as usize,
                segment: entry.pci_segment_group,
                start_bus,
                end_bus,
            });
        }
        mappings
    });

    let mapping = mappings.iter().find(|mapping| {
        mapping.segment == address.segment
            && address.bus >= mapping.start_bus
            && address.bus <= mapping.end_bus
    })?;
    let bus = (address.bus - mapping.start_bus) as usize;
    let offset = (bus << 20)
        | ((address.device as usize) << 15)
        | ((address.function as usize) << 12)
        | address.aligned_u32_offset() as usize;
    Some((mapping.base + offset) as *mut u32)
}

impl PciConfigPlatform for Aarch64Platform {
    fn read_pci_config_u32(address: PciConfigAddress) -> Option<u32> {
        Some(unsafe { config_address(address)?.read_volatile() })
    }

    fn write_pci_config_u32(address: PciConfigAddress, value: u32) -> bool {
        let Some(pointer) = config_address(address) else {
            return false;
        };
        unsafe { pointer.write_volatile(value) };
        true
    }
}
