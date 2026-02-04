use kernel_api::memory::{
    PageTableFlags, allocate_auto_kernel_range_mapped, deallocate_kernel_range, virt_to_phys,
};
use kernel_api::x86_64::{PhysAddr, VirtAddr};

use crate::pci;
use crate::virtqueue::{VRING_DESC_F_NEXT, VRING_DESC_F_WRITE, Virtqueue};

pub const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;
pub const VIRTIO_STATUS_DRIVER: u8 = 2;
pub const VIRTIO_STATUS_FEATURES_OK: u8 = 8;
pub const VIRTIO_STATUS_DRIVER_OK: u8 = 4;
pub const VIRTIO_STATUS_FAILED: u8 = 128;

pub const VIRTIO_BLK_T_IN: u32 = 0;
pub const VIRTIO_BLK_T_OUT: u32 = 1;

#[repr(C)]
pub struct VirtioBlkReqHeader {
    pub req_type: u32,
    pub reserved: u32,
    pub sector: u64,
}

pub const VIRTIO_BLK_S_OK: u8 = 0;
pub const VIRTIO_BLK_S_IOERR: u8 = 1;
pub const VIRTIO_BLK_S_UNSUPP: u8 = 2;

pub const VIRTIO_BLK_F_SIZE_MAX: u32 = 1;
pub const VIRTIO_BLK_F_SEG_MAX: u32 = 2;
pub const VIRTIO_BLK_F_BLK_SIZE: u32 = 6;

const DEVCFG_CAPACITY: usize = 0x00; // u64 — capacity in 512-byte sectors

/// Negotiate features and read device configuration.
/// Returns the disk capacity in 512-byte sectors.
pub fn init_device(common_cfg: VirtAddr, device_cfg: VirtAddr) -> Option<u64> {
    unsafe { pci::common_write_u8(common_cfg, pci::COMMON_DEVICE_STATUS, 0) };

    unsafe {
        pci::common_write_u8(
            common_cfg,
            pci::COMMON_DEVICE_STATUS,
            VIRTIO_STATUS_ACKNOWLEDGE,
        )
    };

    unsafe {
        pci::common_write_u8(
            common_cfg,
            pci::COMMON_DEVICE_STATUS,
            VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER,
        )
    };

    unsafe { pci::common_write_u32(common_cfg, pci::COMMON_DEVICE_FEATURE_SELECT, 0) };
    let _dev_features = unsafe { pci::common_read_u32(common_cfg, pci::COMMON_DEVICE_FEATURE) };

    unsafe { pci::common_write_u32(common_cfg, pci::COMMON_DRIVER_FEATURE_SELECT, 0) };
    unsafe { pci::common_write_u32(common_cfg, pci::COMMON_DRIVER_FEATURE, 0) };

    unsafe {
        pci::common_write_u8(
            common_cfg,
            pci::COMMON_DEVICE_STATUS,
            VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK,
        )
    };

    let status = unsafe { pci::common_read_u8(common_cfg, pci::COMMON_DEVICE_STATUS) };
    if status & VIRTIO_STATUS_FEATURES_OK == 0 {
        unsafe {
            pci::common_write_u8(common_cfg, pci::COMMON_DEVICE_STATUS, VIRTIO_STATUS_FAILED)
        };
        return None;
    }

    let capacity = unsafe {
        core::ptr::read_volatile(
            (device_cfg.as_u64() as *const u8).add(DEVCFG_CAPACITY) as *const u64
        )
    };

    Some(capacity)
}

/// Set the DRIVER_OK status bit, completing device initialization.
pub fn set_driver_ok(common_cfg: VirtAddr) {
    unsafe {
        pci::common_write_u8(
            common_cfg,
            pci::COMMON_DEVICE_STATUS,
            VIRTIO_STATUS_ACKNOWLEDGE
                | VIRTIO_STATUS_DRIVER
                | VIRTIO_STATUS_FEATURES_OK
                | VIRTIO_STATUS_DRIVER_OK,
        )
    };
}

/// Reset the device by writing 0 to device_status.
pub fn reset_device(common_cfg: VirtAddr) {
    unsafe { pci::common_write_u8(common_cfg, pci::COMMON_DEVICE_STATUS, 0) };
}


/// A prepared block I/O request with DMA buffers allocated.
pub struct BlkIoRequest {
    /// DMA buffer containing the 16-byte request header.
    pub header_va: VirtAddr,
    pub header_phys: PhysAddr,
    /// DMA buffer for data transfer.
    pub data_va: VirtAddr,
    pub data_phys: PhysAddr,
    pub data_len: u32,
    /// DMA buffer for the 1-byte status response.
    pub status_va: VirtAddr,
    pub status_phys: PhysAddr,
}

impl BlkIoRequest {
    /// Allocate DMA buffers and prepare a block I/O request.
    /// `req_type` is VIRTIO_BLK_T_IN (read) or VIRTIO_BLK_T_OUT (write).
    /// `sector` is the starting 512-byte sector.
    /// `data_len` is the number of bytes to transfer (must be sector-aligned).
    pub fn new(req_type: u32, sector: u64, data_len: u32) -> Option<Self> {
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_CACHE;

        let header_va = allocate_auto_kernel_range_mapped(4096, flags).ok()?;
        let header_phys = virt_to_phys(header_va);
        unsafe {
            let hdr = header_va.as_u64() as *mut VirtioBlkReqHeader;
            core::ptr::write_volatile(
                hdr,
                VirtioBlkReqHeader {
                    req_type,
                    reserved: 0,
                    sector,
                },
            );
        }

        let data_pages = ((data_len as u64) + 4095) & !4095;
        let data_va = allocate_auto_kernel_range_mapped(data_pages.max(4096), flags).ok()?;
        let data_phys = virt_to_phys(data_va);
        unsafe { core::ptr::write_bytes(data_va.as_u64() as *mut u8, 0, data_len as usize) };

        let status_va = allocate_auto_kernel_range_mapped(4096, flags).ok()?;
        let status_phys = virt_to_phys(status_va);
        unsafe { core::ptr::write_volatile(status_va.as_u64() as *mut u8, 0xFF) }; // sentinel

        Some(Self {
            header_va,
            header_phys,
            data_va,
            data_phys,
            data_len,
            status_va,
            status_phys,
        })
    }

    /// Build the 3-descriptor chain for this request and push it to the virtqueue.
    /// Returns the head descriptor index.
    pub fn submit(&self, vq: &mut Virtqueue, is_write: bool) -> Option<u16> {
        let data_flags = if is_write { 0 } else { VRING_DESC_F_WRITE };
        let bufs = [
            (self.header_phys, 16, 0u16),
            (self.data_phys, self.data_len, data_flags),
            (self.status_phys, 1, VRING_DESC_F_WRITE),
        ];
        vq.push_chain(&bufs)
    }

    /// Read the status byte from the DMA buffer.
    pub fn status(&self) -> u8 {
        unsafe { core::ptr::read_volatile(self.status_va.as_u64() as *const u8) }
    }

    /// Get a slice view of the data buffer.
    pub fn data_slice(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(self.data_va.as_u64() as *const u8, self.data_len as usize)
        }
    }

    /// Get a mutable slice view of the data buffer (for writing data before an OUT request).
    pub fn data_slice_mut(&mut self) -> &mut [u8] {
        unsafe {
            core::slice::from_raw_parts_mut(
                self.data_va.as_u64() as *mut u8,
                self.data_len as usize,
            )
        }
    }

    /// Free all DMA buffers.
    pub fn destroy(self) {
        deallocate_kernel_range(self.header_va, 4096);
        let data_pages = ((self.data_len as u64) + 4095) & !4095;
        deallocate_kernel_range(self.data_va, data_pages.max(4096));
        deallocate_kernel_range(self.status_va, 4096);
    }
}
