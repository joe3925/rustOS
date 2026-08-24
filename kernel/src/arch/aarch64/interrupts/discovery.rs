use acpi::madt::{Madt, MadtEntry};
use device_tree::{DeviceTree, Node};

use crate::machine::machine_info;
use crate::util::boot_info;

#[derive(Clone, Copy)]
pub(super) struct GicDescription {
    pub(super) distributor: u64,
    pub(super) redistributor: u64,
    pub(super) redistributor_size: u64,
}

pub(super) fn discover_gicv3() -> Option<GicDescription> {
    discover_gicv3_acpi().or_else(discover_gicv3_fdt)
}

fn discover_gicv3_acpi() -> Option<GicDescription> {
    let tables = machine_info().firmware().acpi_tables()?;
    let madt = tables.find_table::<Madt>().ok()?;
    let mut distributor = None;
    let mut redistributor = None;
    let mut gicc_redistributor = None;
    for entry in madt.get().entries() {
        match entry {
            MadtEntry::Gicd(gicd) if gicd.gic_version == 3 || gicd.gic_version == 4 => {
                distributor = Some(gicd.physical_base_address)
            }
            MadtEntry::GicRedistributor(gicr) => {
                redistributor = Some((
                    gicr.discovery_range_base_address,
                    gicr.discovery_range_length as u64,
                ))
            }
            MadtEntry::Gicc(gicc) if gicc.gicr_base_address != 0 => {
                gicc_redistributor = Some(gicc.gicr_base_address)
            }
            _ => {}
        }
    }
    let (redistributor, redistributor_size) = redistributor.or_else(|| {
        let base = gicc_redistributor?;
        let cpu_count = machine_info().cpu_topology().processors.len() as u64;
        Some((base, cpu_count * 0x2_0000))
    })?;
    Some(GicDescription {
        distributor: distributor?,
        redistributor,
        redistributor_size,
    })
}

fn discover_gicv3_fdt() -> Option<GicDescription> {
    let header = boot_info().fdt_header.into_option()?;
    let header = unsafe { &*header.cast::<kernel_types::fdt::FdtHeader>() };
    let blob = unsafe {
        core::slice::from_raw_parts(
            header as *const _ as *const u8,
            header.total_size() as usize,
        )
    };
    let tree = DeviceTree::load(blob).ok()?;
    find_gicv3_node(&tree.root, 2, 2)
}

fn find_gicv3_node(
    node: &Node,
    parent_address_cells: u32,
    parent_size_cells: u32,
) -> Option<GicDescription> {
    let address_cells = node_u32(node, "#address-cells").unwrap_or(parent_address_cells);
    let size_cells = node_u32(node, "#size-cells").unwrap_or(parent_size_cells);
    if node.prop_raw("compatible").is_some_and(|value| {
        value
            .split(|byte| *byte == 0)
            .any(|part| part == b"arm,gic-v3")
    }) {
        let reg = node.prop_raw("reg")?;
        let stride = (parent_address_cells + parent_size_cells) as usize * 4;
        if stride == 0 || reg.len() < stride * 2 {
            return None;
        }
        return Some(GicDescription {
            distributor: read_cells(reg, 0, parent_address_cells)?,
            redistributor: read_cells(reg, stride, parent_address_cells)?,
            redistributor_size: read_cells(
                reg,
                stride + parent_address_cells as usize * 4,
                parent_size_cells,
            )?,
        });
    }
    node.children
        .iter()
        .find_map(|child| find_gicv3_node(child, address_cells, size_cells))
}

fn node_u32(node: &Node, name: &str) -> Option<u32> {
    let value = node.prop_raw(name)?;
    Some(u32::from_be_bytes(value.get(0..4)?.try_into().ok()?))
}

fn read_cells(value: &[u8], offset: usize, cells: u32) -> Option<u64> {
    if cells == 0 || cells > 2 {
        return None;
    }
    let mut result = 0u64;
    for index in 0..cells as usize {
        result = result << 32
            | u32::from_be_bytes(
                value
                    .get(offset + index * 4..offset + index * 4 + 4)?
                    .try_into()
                    .ok()?,
            ) as u64;
    }
    Some(result)
}
