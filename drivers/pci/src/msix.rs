use alloc::sync::Arc;
use core::ptr::{read_volatile, write_volatile};

use kernel_api::device::DeviceObject;
use kernel_api::irq::{IrqHandleExt, bind_msi_interrupt};
use kernel_api::kernel_types::irq::{
    IrqHandle, IrqIsrFn, MSI_KIND_MSIX, MSI_TARGET_ANY, MSI_TARGET_PLATFORM_CPU, MsiBindingRequest,
    MsiRequester,
};
use kernel_api::memory::{PhysAddr, VirtAddr, map_mmio_region, unmap_mmio_region};

use crate::dev_ext::PciPdoExt;
use kernel_api::kernel_types::pci::BarKind;

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
pub extern "C" fn pci_setup_msix(
    dev: &Arc<DeviceObject>,
    request: MsiBindingRequest,
    isr: IrqIsrFn,
    context: usize,
) -> IrqHandle {
    let ext = match dev.try_devext::<PciPdoExt>() {
        Ok(e) => e,
        Err(_) => return IrqHandle::null(),
    };

    let msix = match ext.msix.as_ref() {
        Some(m) => m,
        None => return IrqHandle::null(),
    };

    if request.kind != MSI_KIND_MSIX
        || request.table_index >= msix.table_size
        || !matches!(
            request.target.mode,
            MSI_TARGET_ANY | MSI_TARGET_PLATFORM_CPU
        )
    {
        return IrqHandle::null();
    }

    let table_bar = &ext.bars[msix.table_bar as usize];
    if table_bar.kind == BarKind::None {
        return IrqHandle::null();
    }

    let table_region_size = ((msix.table_size as u64 * 16) + 0xFFF) & !0xFFF;
    let table_phys = table_bar.base + msix.table_offset as u64;

    let table_va = match map_mmio_region(PhysAddr::new(table_phys), table_region_size) {
        Ok(va) => va,
        Err(_) => return IrqHandle::null(),
    };

    let request = request.with_requester(MsiRequester::pci(ext.seg, ext.bus, ext.dev, ext.func));
    let Some(binding) = bind_msi_interrupt(&request, isr, context) else {
        let _ = unsafe { unmap_mmio_region(table_va, table_region_size) };
        return IrqHandle::null();
    };
    let entry_offset = request.table_index as u64 * 16;
    let entry_va = table_va.as_u64() + entry_offset;

    // Vector Control: bit 0 = mask (0 = masked)
    let vector_ctrl_masked: u32 = 1;
    let vector_ctrl_unmasked: u32 = 0;

    unsafe {
        // Program entry while masked to avoid spurious interrupts on picky devices.
        write_volatile((entry_va + 12) as *mut u32, vector_ctrl_masked);
        write_volatile((entry_va + 0) as *mut u32, binding.message.address_lo());
        write_volatile((entry_va + 4) as *mut u32, binding.message.address_hi());
        write_volatile((entry_va + 8) as *mut u32, binding.message.data);
        write_volatile((entry_va + 12) as *mut u32, vector_ctrl_unmasked);
    }

    // Read back and verify
    let _rb_addr = unsafe { read_volatile((entry_va + 0) as *const u32) };
    let _rb_data = unsafe { read_volatile((entry_va + 8) as *const u32) };
    let _rb_ctrl = unsafe { read_volatile((entry_va + 12) as *const u32) };

    let cfg_va = match map_mmio_region(PhysAddr::new(ext.cfg_phys), 4096) {
        Ok(va) => va,
        Err(_) => {
            let _ = unsafe { unmap_mmio_region(table_va, table_region_size) };
            binding.handle.unregister();
            return IrqHandle::null();
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

    let _ = unsafe { unmap_mmio_region(cfg_va, 4096) };
    let _ = unsafe { unmap_mmio_region(table_va, table_region_size) };

    binding.handle
}
