use alloc::sync::Arc;
use core::ptr::{read_volatile, write_volatile};

use kernel_api::device::DeviceObject;
use kernel_api::irq::irq_compose_msi_message;
use kernel_api::kernel_types::irq::{
    MSI_KIND_MSIX, MSI_TARGET_ANY, MSI_TARGET_PLATFORM_CPU, MsiRequest, MsiRequester,
};
use kernel_api::memory::{PhysAddr, VirtAddr, map_mmio_region, unmap_mmio_region};
use kernel_api::pnp::DriverStep;
use kernel_api::request::{DeviceControl, RequestHandle};
use kernel_api::status::DriverStatus;

use crate::dev_ext::{BarKind, PciPdoExt};

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
pub async fn pci_setup_msix<'req, 'data>(
    dev: Arc<DeviceObject>,
    req: &mut RequestHandle<'req, DeviceControl<'data>>,
) -> DriverStep {
    let ext = match dev.try_devext::<PciPdoExt>() {
        Ok(e) => e,
        Err(_) => return DriverStep::complete(DriverStatus::NoSuchDevice),
    };

    let msix = match ext.msix.as_ref() {
        Some(m) => m,
        None => return DriverStep::complete(DriverStatus::NotImplemented),
    };

    let msi_request = match {
        let data = req.data().read_only();
        data.view::<MsiRequest>().copied()
    } {
        Some(request) => request,
        None => return DriverStep::complete(DriverStatus::InvalidParameter),
    };

    if msi_request.kind != MSI_KIND_MSIX
        || msi_request.table_index >= msix.table_size
        || !matches!(
            msi_request.target.mode,
            MSI_TARGET_ANY | MSI_TARGET_PLATFORM_CPU
        )
    {
        return DriverStep::complete(DriverStatus::InvalidParameter);
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

    let msi_request =
        msi_request.with_requester(MsiRequester::pci(ext.seg, ext.bus, ext.dev, ext.func));
    let message = match irq_compose_msi_message(&msi_request) {
        Some(message) => message,
        None => {
            let _ = unmap_mmio_region(table_va, table_region_size);
            return DriverStep::complete(DriverStatus::NotImplemented);
        }
    };

    let entry_offset = msi_request.table_index as u64 * 16;
    let entry_va = table_va.as_u64() + entry_offset;

    // Vector Control: bit 0 = mask (0 = masked)
    let vector_ctrl_masked: u32 = 1;
    let vector_ctrl_unmasked: u32 = 0;

    unsafe {
        // Program entry while masked to avoid spurious interrupts on picky devices.
        write_volatile((entry_va + 12) as *mut u32, vector_ctrl_masked);
        write_volatile((entry_va + 0) as *mut u32, message.address_lo());
        write_volatile((entry_va + 4) as *mut u32, message.address_hi());
        write_volatile((entry_va + 8) as *mut u32, message.data);
        write_volatile((entry_va + 12) as *mut u32, vector_ctrl_unmasked);
    }

    // Read back and verify
    let _rb_addr = unsafe { read_volatile((entry_va + 0) as *const u32) };
    let _rb_data = unsafe { read_volatile((entry_va + 8) as *const u32) };
    let _rb_ctrl = unsafe { read_volatile((entry_va + 12) as *const u32) };

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
