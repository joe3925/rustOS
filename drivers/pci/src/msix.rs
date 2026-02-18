use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};

use kernel_api::device::DeviceObject;
use kernel_api::memory::{map_mmio_region, unmap_mmio_region};
use kernel_api::pnp::DriverStep;
use kernel_api::request::RequestHandle;
use kernel_api::status::DriverStatus;
use kernel_api::x86_64::{PhysAddr, VirtAddr};

use crate::dev_ext::{BarKind, PciPdoExt};

/// Single MSI-X entry setup request from child driver.
#[derive(Clone, Copy, Debug)]
pub struct MsixEntrySetup {
    pub table_index: u16,
    pub vector: u8,
    pub cpu: u8,
}

/// Parse MSI-X setup request from blob.
/// Format: num_entries(u16) + [table_index(u16) + vector(u8) + cpu(u8)] * N
fn parse_msix_setup_request(data: &[u8]) -> Option<Vec<MsixEntrySetup>> {
    if data.len() < 2 {
        return None;
    }

    let num_entries = u16::from_le_bytes([data[0], data[1]]) as usize;
    let expected_len = 2 + num_entries * 4;

    if data.len() < expected_len {
        return None;
    }

    let mut entries = Vec::with_capacity(num_entries);
    for i in 0..num_entries {
        let base = 2 + i * 4;
        let table_index = u16::from_le_bytes([data[base], data[base + 1]]);
        let vector = data[base + 2];
        let cpu = data[base + 3];
        entries.push(MsixEntrySetup {
            table_index,
            vector,
            cpu,
        });
    }

    Some(entries)
}

/// Read 16-bit value from config space.
#[inline]
unsafe fn cfg_read16(base: VirtAddr, offset: u16) -> u16 {
    let ptr = (base.as_u64() + offset as u64) as *const u16;
    unsafe { read_volatile(ptr) }
}

/// Write 16-bit value to config space.
#[inline]
unsafe fn cfg_write16(base: VirtAddr, offset: u16, value: u16) {
    let ptr = (base.as_u64() + offset as u64) as *mut u16;
    unsafe { write_volatile(ptr, value) }
}

/// Program MSI-X table and enable MSI-X capability.
pub async fn pci_setup_msix(dev: Arc<DeviceObject>, req: &mut RequestHandle<'_>) -> DriverStep {
    let ext = match dev.try_devext::<PciPdoExt>() {
        Ok(e) => e,
        Err(_) => return DriverStep::complete(DriverStatus::NoSuchDevice),
    };

    let msix = match ext.msix.as_ref() {
        Some(m) => m,
        None => return DriverStep::complete(DriverStatus::NotImplemented),
    };

    let entries = match {
        let r = req.read();
        parse_msix_setup_request(r.data.as_slice())
    } {
        Some(e) => e,
        None => return DriverStep::complete(DriverStatus::InvalidParameter),
    };

    for entry in &entries {
        if entry.table_index >= msix.table_size {
            return DriverStep::complete(DriverStatus::InvalidParameter);
        }
    }

    let table_bar = &ext.bars[msix.table_bar as usize];
    if table_bar.kind == BarKind::None {
        return DriverStep::complete(DriverStatus::NotImplemented);
    }

    let table_region_size = ((msix.table_size as u64 * 16) + 0xFFF) & !0xFFF;
    let table_phys = table_bar.base + msix.table_offset as u64;

    let table_va = match map_mmio_region(PhysAddr::new(table_phys), table_region_size) {
        Ok(va) => va,
        Err(_) => return DriverStep::complete(DriverStatus::InsufficientResources),
    };

    for entry in &entries {
        let entry_offset = entry.table_index as u64 * 16;
        let entry_va = table_va.as_u64() + entry_offset;

        // Message Address (x86 APIC): 0xFEE00000 | (cpu << 12)
        // Bits [19:12] = Destination ID (CPU)
        // Bits [11:4] = Reserved
        // Bit [3] = Redirection Hint (0)
        // Bit [2] = Destination Mode (0 = Physical)
        let msg_addr_lo: u32 = 0xFEE0_0000 | ((entry.cpu as u32) << 12);
        let msg_addr_hi: u32 = 0;

        // Message Data: vector number in bits [7:0]
        let msg_data: u32 = entry.vector as u32;

        // Vector Control: bit 0 = mask (0 = unmasked/enabled)
        let vector_ctrl_masked: u32 = 1;
        let vector_ctrl_unmasked: u32 = 0;

        unsafe {
            // Program entry while masked to avoid spurious interrupts on picky devices.
            write_volatile((entry_va + 12) as *mut u32, vector_ctrl_masked);
            write_volatile((entry_va + 0) as *mut u32, msg_addr_lo);
            write_volatile((entry_va + 4) as *mut u32, msg_addr_hi);
            write_volatile((entry_va + 8) as *mut u32, msg_data);
            write_volatile((entry_va + 12) as *mut u32, vector_ctrl_unmasked);
        }

        // Read back and verify
        let _rb_addr = unsafe { read_volatile((entry_va + 0) as *const u32) };
        let _rb_data = unsafe { read_volatile((entry_va + 8) as *const u32) };
        let _rb_ctrl = unsafe { read_volatile((entry_va + 12) as *const u32) };
    }

    let cfg_va = match map_mmio_region(PhysAddr::new(ext.cfg_phys), 4096) {
        Ok(va) => va,
        Err(_) => {
            let _ = unmap_mmio_region(table_va, table_region_size);
            return DriverStep::complete(DriverStatus::InsufficientResources);
        }
    };

    // Enable Bus Master (bit 2) and Memory Space (bit 1) in PCI Command register.
    // Bus Master is required for MSI-X since the device must perform memory writes.
    let cmd = unsafe { cfg_read16(cfg_va, 0x04) };

    unsafe { cfg_write16(cfg_va, 0x04, cmd | 0x06) };
    let _cmd_after = unsafe { cfg_read16(cfg_va, 0x04) };

    let msg_ctrl_offset = msix.cap_offset + 2;
    let msg_ctrl = unsafe { cfg_read16(cfg_va, msg_ctrl_offset) };

    let new_msg_ctrl = (msg_ctrl | (1 << 15)) & !(1 << 14); // Enable MSI-X, clear Function Mask
    unsafe { cfg_write16(cfg_va, msg_ctrl_offset, new_msg_ctrl) };
    let _msg_ctrl_after = unsafe { cfg_read16(cfg_va, msg_ctrl_offset) };

    let _ = unmap_mmio_region(cfg_va, 4096);
    let _ = unmap_mmio_region(table_va, table_region_size);

    DriverStep::complete(DriverStatus::Success)
}
