use crate::DriverErrorKind;
use crate::KernelError;
use alloc::sync::Arc;
use core::ptr::{read_volatile, write_volatile};
use kernel_api::device::DeviceObject;
use kernel_api::dma::open_device_handle;
use kernel_api::error::error_with_message;
use kernel_api::irq::MsiRequest;
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
    request: MsiRequest,
    isr: IrqIsrFn,
    context: usize,
) -> Result<IrqHandle, KernelError> {
    let ext = dev.try_devext::<PciPdoExt>().map_err(|err| {
        error_with_message(
            DriverErrorKind::NoSuchDevice,
            format_args!("failed to access PCI device extension while configuring MSI-X: {err:?}"),
        )
    })?;

    let msix = ext.msix.as_ref().ok_or_else(|| {
        error_with_message(
            DriverErrorKind::NotImplemented,
            format_args!(
                "PCI device {:04x}:{:02x}:{:02x}.{} does not expose an MSI-X capability",
                ext.seg, ext.bus, ext.dev, ext.func,
            ),
        )
    })?;

    if request.kind != MSI_KIND_MSIX {
        return Err(error_with_message(
            DriverErrorKind::InvalidParameter,
            format_args!(
                "invalid MSI request kind {} for PCI MSI-X setup on {:04x}:{:02x}:{:02x}.{}",
                request.kind, ext.seg, ext.bus, ext.dev, ext.func,
            ),
        ));
    }

    if request.table_index >= msix.table_size {
        return Err(error_with_message(
            DriverErrorKind::InvalidParameter,
            format_args!(
                "MSI-X table index {} is out of range for PCI device \
                 {:04x}:{:02x}:{:02x}.{}; table contains {} entries",
                request.table_index, ext.seg, ext.bus, ext.dev, ext.func, msix.table_size,
            ),
        ));
    }

    if !matches!(
        request.target.mode,
        MSI_TARGET_ANY | MSI_TARGET_PLATFORM_CPU
    ) {
        return Err(error_with_message(
            DriverErrorKind::InvalidParameter,
            format_args!(
                "unsupported MSI target mode {} for PCI device \
                 {:04x}:{:02x}:{:02x}.{}",
                request.target.mode, ext.seg, ext.bus, ext.dev, ext.func,
            ),
        ));
    }

    let dma_device = open_device_handle(dev).ok();

    let request = MsiBindingRequest::new(
        request,
        MsiRequester::pci(ext.seg, ext.bus, ext.dev, ext.func),
        dma_device,
    );

    let table_bar = ext.bars.get(msix.table_bar as usize).ok_or_else(|| {
        error_with_message(
            DriverErrorKind::DeviceError,
            format_args!(
                "MSI-X capability for PCI device {:04x}:{:02x}:{:02x}.{} \
                     references invalid BAR {}",
                ext.seg, ext.bus, ext.dev, ext.func, msix.table_bar,
            ),
        )
    })?;

    if table_bar.kind == BarKind::None {
        return Err(error_with_message(
            DriverErrorKind::DeviceError,
            format_args!(
                "MSI-X capability for PCI device {:04x}:{:02x}:{:02x}.{} \
                 references BAR {}, but that BAR is not present",
                ext.seg, ext.bus, ext.dev, ext.func, msix.table_bar,
            ),
        ));
    }

    let table_region_size = (msix.table_size as u64)
        .checked_mul(16)
        .and_then(|size| size.checked_add(0xFFF))
        .map(|size| size & !0xFFF)
        .ok_or_else(|| {
            error_with_message(
                DriverErrorKind::InvalidParameter,
                format_args!(
                    "MSI-X table size overflow for PCI device \
                     {:04x}:{:02x}:{:02x}.{} with {} entries",
                    ext.seg, ext.bus, ext.dev, ext.func, msix.table_size,
                ),
            )
        })?;

    let table_phys = table_bar
        .base
        .checked_add(msix.table_offset as u64)
        .ok_or_else(|| {
            error_with_message(
                DriverErrorKind::InvalidParameter,
                format_args!(
                    "MSI-X table physical address overflow for PCI device \
                     {:04x}:{:02x}:{:02x}.{}: BAR base {:#x}, table offset {:#x}",
                    ext.seg, ext.bus, ext.dev, ext.func, table_bar.base, msix.table_offset,
                ),
            )
        })?;

    let table_va =
        map_mmio_region(PhysAddr::new(table_phys), table_region_size).map_err(|err| {
            error_with_message(
                DriverErrorKind::InsufficientResources,
                format_args!(
                    "failed to map MSI-X table for PCI device \
                 {:04x}:{:02x}:{:02x}.{} at physical address {:#x}, \
                 size {:#x}: {err:?}",
                    ext.seg, ext.bus, ext.dev, ext.func, table_phys, table_region_size,
                ),
            )
        })?;

    let binding = match bind_msi_interrupt(&request, isr, context) {
        Some(binding) => binding,

        None => {
            let unmap_result = unsafe { unmap_mmio_region(table_va, table_region_size) };

            let mut error = error_with_message(
                DriverErrorKind::InsufficientResources,
                format_args!(
                    "failed to bind MSI-X interrupt for PCI device \
                     {:04x}:{:02x}:{:02x}.{}, table index {}, target mode {}, target CPU {}",
                    ext.seg,
                    ext.bus,
                    ext.dev,
                    ext.func,
                    request.table_index,
                    request.target.mode,
                    request.target.platform_cpu_id,
                ),
            );

            if let Err(unmap_err) = unmap_result {
                error = error.with_context(format_args!(
                    "additionally failed to unmap MSI-X table VA {:#x}, size {:#x}: {unmap_err:?}",
                    table_va.as_u64(),
                    table_region_size,
                ));
            }

            return Err(error);
        }
    };

    let entry_offset = (request.table_index as u64)
        .checked_mul(16)
        .ok_or_else(|| {
            binding.handle.unregister();

            let _ = unsafe { unmap_mmio_region(table_va, table_region_size) };

            error_with_message(
                DriverErrorKind::InvalidParameter,
                format_args!(
                    "MSI-X table entry offset overflow for table index {}",
                    request.table_index,
                ),
            )
        })?;

    let entry_va = table_va.as_u64().checked_add(entry_offset).ok_or_else(|| {
        binding.handle.unregister();

        let _ = unsafe { unmap_mmio_region(table_va, table_region_size) };

        error_with_message(
            DriverErrorKind::InvalidParameter,
            format_args!(
                "MSI-X table virtual address overflow: table VA {:#x}, entry offset {:#x}",
                table_va.as_u64(),
                entry_offset,
            ),
        )
    })?;

    const VECTOR_CTRL_MASKED: u32 = 1;
    const VECTOR_CTRL_UNMASKED: u32 = 0;

    unsafe {
        write_volatile((entry_va + 12) as *mut u32, VECTOR_CTRL_MASKED);

        write_volatile(entry_va as *mut u32, binding.message.address_lo());

        write_volatile((entry_va + 4) as *mut u32, binding.message.address_hi());

        write_volatile((entry_va + 8) as *mut u32, binding.message.data);

        write_volatile((entry_va + 12) as *mut u32, VECTOR_CTRL_UNMASKED);
    }

    let cfg_va = match map_mmio_region(PhysAddr::new(ext.cfg_phys), 4096) {
        Ok(va) => va,

        Err(map_err) => {
            unsafe {
                write_volatile((entry_va + 12) as *mut u32, VECTOR_CTRL_MASKED);
            }

            binding.handle.unregister();

            let unmap_result = unsafe { unmap_mmio_region(table_va, table_region_size) };

            let mut error = error_with_message(
                DriverErrorKind::InsufficientResources,
                format_args!(
                    "failed to map PCI configuration space while enabling MSI-X for \
                     {:04x}:{:02x}:{:02x}.{} at physical address {:#x}: {map_err:?}",
                    ext.seg, ext.bus, ext.dev, ext.func, ext.cfg_phys,
                ),
            );

            if let Err(unmap_err) = unmap_result {
                error = error.with_context(format_args!(
                    "additionally failed to unmap MSI-X table VA {:#x}, size {:#x}: {unmap_err:?}",
                    table_va.as_u64(),
                    table_region_size,
                ));
            }

            return Err(error);
        }
    };

    let cmd = unsafe { cfg_read16(cfg_va, 0x04) };

    unsafe {
        cfg_write16(cfg_va, 0x04, cmd | 0x06);
    }

    let msg_ctrl_offset = msix.cap_offset + 2;

    let msg_ctrl = unsafe { cfg_read16(cfg_va, msg_ctrl_offset) };
    let new_msg_ctrl = (msg_ctrl | (1 << 15)) & !(1 << 14);

    unsafe {
        cfg_write16(cfg_va, msg_ctrl_offset, new_msg_ctrl);
    }

    if let Err(err) = unsafe { unmap_mmio_region(cfg_va, 4096) } {
        let _ = unsafe { unmap_mmio_region(table_va, table_region_size) };

        return Err(error_with_message(
            DriverErrorKind::DeviceError,
            format_args!(
                "MSI-X was enabled for PCI device {:04x}:{:02x}:{:02x}.{}, \
                 but unmapping its temporary configuration-space mapping \
                 at VA {:#x} failed: {err:?}",
                ext.seg,
                ext.bus,
                ext.dev,
                ext.func,
                cfg_va.as_u64(),
            ),
        ));
    }

    if let Err(err) = unsafe { unmap_mmio_region(table_va, table_region_size) } {
        return Err(error_with_message(
            DriverErrorKind::DeviceError,
            format_args!(
                "MSI-X was enabled for PCI device {:04x}:{:02x}:{:02x}.{}, \
                 but unmapping its temporary MSI-X table mapping at VA {:#x}, \
                 size {:#x} failed: {err:?}",
                ext.seg,
                ext.bus,
                ext.dev,
                ext.func,
                table_va.as_u64(),
                table_region_size,
            ),
        ));
    }

    Ok(binding.handle)
}
