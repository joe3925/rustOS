use acpi::fadt::Fadt;
use acpi::madt::{Madt, MadtEntry};
use acpi::AcpiTables;
use alloc::vec::Vec;
use core::slice;
use device_tree::{DeviceTree, Node};

use crate::drivers::ACPI::ACPIImpl;
use crate::machine::{
    CpuTopologyError, FirmwareResources, MachineCpuTopology, MachineInterruptInfo,
    MachineProcessorInfo, PsciConduit,
};
use crate::platform::MachinePlatform;

use super::platform::Aarch64Platform;

impl MachinePlatform for Aarch64Platform {
    fn discover_cpu_topology(
        firmware: &FirmwareResources,
    ) -> Result<MachineCpuTopology, CpuTopologyError> {
        if let Some(topology) = discover_acpi_topology(firmware)? {
            return Ok(topology);
        }
        if let Some(topology) = discover_fdt_topology(firmware)? {
            return Ok(topology);
        }
        Ok(boot_cpu_topology())
    }

    fn discover_interrupt_info_from_acpi(
        tables: &AcpiTables<ACPIImpl>,
    ) -> Option<MachineInterruptInfo> {
        let madt = tables.find_table::<Madt>().ok()?;
        let distributor = madt.get().entries().find_map(|entry| match entry {
            MadtEntry::Gicd(gicd) => Some((gicd.gic_id, gicd.physical_base_address)),
            _ => None,
        })?;
        Some(MachineInterruptInfo {
            local_interrupt_controller_address: distributor.1,
            interrupt_controllers: alloc::vec![crate::machine::MachineInterruptControllerInfo {
                id: distributor.0.try_into().ok()?,
                address: distributor.1,
                global_system_interrupt_base: 0,
            }],
        })
    }
}

fn boot_cpu_topology() -> MachineCpuTopology {
    MachineCpuTopology {
        processors: alloc::vec![MachineProcessorInfo {
            cpu_id: 0,
            platform_cpu_id: 0,
            hardware_id: super::cpu::current_hardware_id(),
            is_boot_processor: true,
        }],
        psci_conduit: None,
    }
}

fn discover_acpi_topology(
    firmware: &FirmwareResources,
) -> Result<Option<MachineCpuTopology>, CpuTopologyError> {
    let Some(tables) = firmware.acpi_tables() else {
        return Ok(None);
    };
    let Ok(madt) = tables.find_table::<Madt>() else {
        return Ok(None);
    };
    let boot_hardware_id = super::cpu::current_hardware_id();
    let mut discovered = Vec::new();
    for entry in madt.get().entries() {
        if let MadtEntry::Gicc(gicc) = entry {
            let flags = gicc.flags;
            if flags & 1 == 0 && flags & (1 << 3) == 0 {
                continue;
            }
            let hardware_id = super::cpu::normalize_mpidr(gicc.mpidr);
            let platform_cpu_id = gicc.processor_uid;
            if discovered.iter().any(|processor: &MachineProcessorInfo| {
                processor.hardware_id == hardware_id || processor.platform_cpu_id == platform_cpu_id
            }) {
                return Err(CpuTopologyError {
                    reason: "ACPI contains duplicate CPU identifiers",
                });
            }
            discovered.push(MachineProcessorInfo {
                cpu_id: 0,
                platform_cpu_id,
                hardware_id,
                is_boot_processor: hardware_id == boot_hardware_id,
            });
        }
    }
    if discovered.is_empty() {
        return Ok(None);
    }
    normalize_cpu_order(&mut discovered, boot_hardware_id)?;
    let conduit = tables.find_table::<Fadt>().ok().and_then(|fadt| {
        let arm_boot_arch = fadt.arm_boot_arch;
        if !arm_boot_arch.implements_psci() {
            return None;
        }
        Some(if arm_boot_arch.use_hvc_as_psci_conduit() {
            PsciConduit::Hvc
        } else {
            PsciConduit::Smc
        })
    });
    if discovered.len() > 1 && conduit.is_none() {
        return Ok(None);
    }
    Ok(Some(MachineCpuTopology {
        processors: discovered,
        psci_conduit: conduit,
    }))
}

fn discover_fdt_topology(
    firmware: &FirmwareResources,
) -> Result<Option<MachineCpuTopology>, CpuTopologyError> {
    let Some(header_ptr) = firmware.fdt_header() else {
        return Ok(None);
    };
    let header = unsafe { &*header_ptr };
    if header.magic() != kernel_types::fdt::FdtHeader::MAGIC {
        return Err(CpuTopologyError {
            reason: "FDT has an invalid magic value",
        });
    }
    let length = header.total_size() as usize;
    if length < core::mem::size_of::<kernel_types::fdt::FdtHeader>() {
        return Err(CpuTopologyError {
            reason: "FDT is shorter than its header",
        });
    }
    let blob = unsafe { slice::from_raw_parts(header_ptr.cast::<u8>(), length) };
    let tree = DeviceTree::load(blob).map_err(|_| CpuTopologyError {
        reason: "FDT parsing failed",
    })?;
    let cpus = tree.find("/cpus").ok_or(CpuTopologyError {
        reason: "FDT does not contain a cpus node",
    })?;
    let address_cells = property_u32(cpus, "#address-cells").unwrap_or(1);
    if address_cells != 1 && address_cells != 2 {
        return Err(CpuTopologyError {
            reason: "FDT CPU address cell count is unsupported",
        });
    }
    let boot_hardware_id = super::cpu::current_hardware_id();
    let mut discovered = Vec::new();
    for node in cpus.children.iter() {
        if node.prop_str("device_type").ok() != Some("cpu") {
            continue;
        }
        let status = node.prop_str("status").ok();
        if matches!(status, Some("fail") | Some("failed")) {
            continue;
        }
        if !matches!(status, None | Some("okay") | Some("ok") | Some("disabled")) {
            continue;
        }
        let raw = node.prop_raw("reg").ok_or(CpuTopologyError {
            reason: "FDT CPU node has no reg property",
        })?;
        let hardware_id = match address_cells {
            1 if raw.len() >= 4 => u32::from_be_bytes(raw[0..4].try_into().unwrap()) as u64,
            2 if raw.len() >= 8 => u64::from_be_bytes(raw[0..8].try_into().unwrap()),
            _ => {
                return Err(CpuTopologyError {
                    reason: "FDT CPU reg property has an invalid size",
                });
            }
        };
        let hardware_id = super::cpu::normalize_mpidr(hardware_id);
        if hardware_id != boot_hardware_id && node.prop_str("enable-method").ok() != Some("psci") {
            return Err(CpuTopologyError {
                reason: "FDT CPU node does not use PSCI startup",
            });
        }
        if discovered
            .iter()
            .any(|processor: &MachineProcessorInfo| processor.hardware_id == hardware_id)
        {
            return Err(CpuTopologyError {
                reason: "FDT contains duplicate CPU identifiers",
            });
        }
        discovered.push(MachineProcessorInfo {
            cpu_id: 0,
            platform_cpu_id: discovered.len() as u32,
            hardware_id,
            is_boot_processor: hardware_id == boot_hardware_id,
        });
    }
    if discovered.is_empty() {
        return Ok(None);
    }
    normalize_cpu_order(&mut discovered, boot_hardware_id)?;
    let conduit =
        find_psci_node(&tree.root).and_then(|node| match node.prop_str("method").ok()? {
            "smc" => Some(PsciConduit::Smc),
            "hvc" => Some(PsciConduit::Hvc),
            _ => None,
        });
    if discovered.len() > 1 && conduit.is_none() {
        return Err(CpuTopologyError {
            reason: "FDT does not provide a supported PSCI conduit",
        });
    }
    Ok(Some(MachineCpuTopology {
        processors: discovered,
        psci_conduit: conduit,
    }))
}

fn normalize_cpu_order(
    processors: &mut Vec<MachineProcessorInfo>,
    boot_hardware_id: u64,
) -> Result<(), CpuTopologyError> {
    if processors.len() > 256 {
        return Err(CpuTopologyError {
            reason: "firmware topology exceeds the AArch64 CPU limit",
        });
    }
    let Some(boot_index) = processors
        .iter()
        .position(|processor| processor.hardware_id == boot_hardware_id)
    else {
        return Err(CpuTopologyError {
            reason: "firmware topology does not contain the boot CPU",
        });
    };
    processors.swap(0, boot_index);
    for (cpu_id, processor) in processors.iter_mut().enumerate() {
        processor.cpu_id = cpu_id;
        processor.is_boot_processor = cpu_id == 0;
    }
    Ok(())
}

fn property_u32(node: &Node, name: &str) -> Option<u32> {
    let raw = node.prop_raw(name)?;
    let bytes: [u8; 4] = raw.get(0..4)?.try_into().ok()?;
    Some(u32::from_be_bytes(bytes))
}

fn find_psci_node(node: &Node) -> Option<&Node> {
    let compatible = node.prop_raw("compatible");
    if compatible.is_some_and(|raw| {
        raw.split(|byte| *byte == 0)
            .any(|value| value == b"arm,psci-0.2" || value == b"arm,psci-1.0")
    }) {
        return Some(node);
    }
    node.children.iter().find_map(find_psci_node)
}
