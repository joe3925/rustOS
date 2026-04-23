use kernel_api::memory::{
    PageTableFlags, allocate_auto_kernel_range_mapped_contiguous, deallocate_kernel_range,
    unmap_range, virt_to_phys,
};
use kernel_api::x86_64::{PhysAddr, VirtAddr};

use crate::pci;
use crate::virtqueue::{VRING_DESC_F_NEXT, VRING_DESC_F_WRITE, VirtqDesc, Virtqueue};

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

pub const VIRTIO_BLK_F_SIZE_MAX: u64 = 1 << 1;
pub const VIRTIO_BLK_F_SEG_MAX: u64 = 1 << 2;
pub const VIRTIO_BLK_F_BLK_SIZE: u64 = 1 << 6;
/// Mandatory for modern virtio-pci devices.
pub const VIRTIO_F_VERSION_1: u64 = 1u64 << 32;

/// Multiqueue feature bit - device supports multiple request queues.
pub const VIRTIO_BLK_F_MQ: u64 = 1 << 12;

/// Indirect descriptors feature bit - allows chaining descriptors via a table.
pub const VIRTIO_F_INDIRECT_DESC: u64 = 1u64 << 28;

const DEVCFG_CAPACITY: usize = 0x00; // u64 — capacity in 512-byte sectors
const DEVCFG_NUM_QUEUES: usize = 0x08; // u16 — number of request queues (if VIRTIO_BLK_F_MQ)

/// Result of device initialization containing capacity and multiqueue info.
pub struct DeviceInitResult {
    /// Disk capacity in 512-byte sectors.
    pub capacity: u64,
    /// Number of request queues supported by device (1 if MQ not supported).
    pub num_queues: u16,
    /// Whether multiqueue feature was successfully negotiated.
    pub mq_negotiated: bool,
    /// Whether indirect descriptors were successfully negotiated.
    pub indirect_desc_supported: bool,
}

/// Negotiate features and read device configuration.
/// Returns DeviceInitResult with capacity and multiqueue information.
pub fn init_device(common_cfg: VirtAddr, device_cfg: VirtAddr) -> Option<DeviceInitResult> {
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

    // Read 64-bit device feature set.
    unsafe { pci::common_write_u32(common_cfg, pci::COMMON_DEVICE_FEATURE_SELECT, 0) };
    let dev_features_lo = unsafe { pci::common_read_u32(common_cfg, pci::COMMON_DEVICE_FEATURE) };
    unsafe { pci::common_write_u32(common_cfg, pci::COMMON_DEVICE_FEATURE_SELECT, 1) };
    let dev_features_hi = unsafe { pci::common_read_u32(common_cfg, pci::COMMON_DEVICE_FEATURE) };
    let dev_features = (dev_features_hi as u64) << 32 | dev_features_lo as u64;

    // Modern virtio-pci requires VERSION_1; fail early if missing.
    if dev_features & VIRTIO_F_VERSION_1 == 0 {
        unsafe {
            pci::common_write_u8(common_cfg, pci::COMMON_DEVICE_STATUS, VIRTIO_STATUS_FAILED)
        };
        return None;
    }

    // Check for feature support
    let mq_supported = (dev_features & VIRTIO_BLK_F_MQ) != 0;
    let indirect_supported = (dev_features & VIRTIO_F_INDIRECT_DESC) != 0;

    // Negotiate VERSION_1 and other supported features
    let mut supported_features = VIRTIO_F_VERSION_1;
    if mq_supported {
        supported_features |= VIRTIO_BLK_F_MQ;
    }
    if indirect_supported {
        supported_features |= VIRTIO_F_INDIRECT_DESC;
    }
    let driver_features = dev_features & supported_features;

    unsafe { pci::common_write_u32(common_cfg, pci::COMMON_DRIVER_FEATURE_SELECT, 0) };
    unsafe {
        pci::common_write_u32(
            common_cfg,
            pci::COMMON_DRIVER_FEATURE,
            driver_features as u32,
        )
    };
    unsafe { pci::common_write_u32(common_cfg, pci::COMMON_DRIVER_FEATURE_SELECT, 1) };
    unsafe {
        pci::common_write_u32(
            common_cfg,
            pci::COMMON_DRIVER_FEATURE,
            (driver_features >> 32) as u32,
        )
    };

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

    // Check if features were actually negotiated
    let mq_negotiated = mq_supported && (driver_features & VIRTIO_BLK_F_MQ) != 0;
    let indirect_negotiated = indirect_supported && (driver_features & VIRTIO_F_INDIRECT_DESC) != 0;

    let capacity = unsafe {
        core::ptr::read_volatile(
            (device_cfg.as_u64() as *const u8).add(DEVCFG_CAPACITY) as *const u64
        )
    };

    // Read num_queues if MQ was negotiated, otherwise default to 1
    let num_queues = if mq_negotiated {
        let nq = unsafe {
            core::ptr::read_volatile(
                (device_cfg.as_u64() as *const u8).add(DEVCFG_NUM_QUEUES) as *const u16
            )
        };
        nq.max(1)
    } else {
        1
    };

    Some(DeviceInitResult {
        capacity,
        num_queues,
        mq_negotiated,
        indirect_desc_supported: indirect_negotiated,
    })
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

/// Maximum descriptors in an indirect table.
/// 1 for header + up to 32 for data (from `IoBufferDmaSegment`) + 1 for status = 34.
pub const MAX_INDIRECT_DESCRIPTORS: usize = 34;

#[repr(C)]
pub struct BlkSlot {
    pub header: VirtioBlkReqHeader, // 16 bytes
    pub status: u8,                 // 1 byte
    pub padding: [u8; 15],          // padding to keep array aligned
    pub indirect_table: [VirtqDesc; MAX_INDIRECT_DESCRIPTORS],
}

pub struct BlkIoSlots {
    pub pool_va: VirtAddr,
    pub pool_phys: PhysAddr,
    pub pool_pages: usize,
    pub slot_count: usize,
}

unsafe impl Send for BlkIoSlots {}
unsafe impl Sync for BlkIoSlots {}

impl BlkIoSlots {
    pub fn new(slot_count: usize) -> Option<Self> {
        let bytes = slot_count * core::mem::size_of::<BlkSlot>();
        let pool_pages = (bytes + 4095) / 4096;
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        let pool_va =
            allocate_auto_kernel_range_mapped_contiguous((pool_pages * 4096) as u64, flags).ok()?;
        let pool_phys = virt_to_phys(pool_va)?;

        // initialize statuses to 0xFF (sentinel)
        unsafe {
            core::ptr::write_bytes(pool_va.as_u64() as *mut u8, 0, pool_pages * 4096);
            for i in 0..slot_count {
                let slot = (pool_va.as_u64() as *mut BlkSlot).add(i);
                (*slot).status = 0xFF;
            }
        }

        Some(Self {
            pool_va,
            pool_phys,
            pool_pages,
            slot_count,
        })
    }

    #[inline]
    pub fn get_slot_ptr(&self, idx: u16) -> *mut BlkSlot {
        debug_assert!((idx as usize) < self.slot_count);
        (self.pool_va.as_u64() as *mut BlkSlot).wrapping_add(idx as usize)
    }

    pub fn submit_request(
        &self,
        vq: &mut Virtqueue,
        req_type: u32,
        sector: u64,
        data_segments: &[kernel_api::kernel_types::dma::IoBufferDmaSegment],
        is_write: bool,
    ) -> Option<u16> {
        let head = vq.alloc_desc()?;
        let slot_ptr = self.get_slot_ptr(head);

        let pool_phys_base = self.pool_phys.as_u64();
        let slot_phys_base =
            pool_phys_base + (head as u64) * (core::mem::size_of::<BlkSlot>() as u64);

        let header_phys = slot_phys_base + core::mem::offset_of!(BlkSlot, header) as u64;
        let status_phys = slot_phys_base + core::mem::offset_of!(BlkSlot, status) as u64;
        let indirect_phys = slot_phys_base + core::mem::offset_of!(BlkSlot, indirect_table) as u64;

        unsafe {
            (*slot_ptr).header.req_type = req_type;
            (*slot_ptr).header.reserved = 0;
            (*slot_ptr).header.sector = sector;

            core::ptr::write_volatile(&mut (*slot_ptr).status, 0xFF);

            let mut desc_count = 0;
            let table = (*slot_ptr).indirect_table.as_mut_ptr();

            // Header
            (*table.add(desc_count)).addr = header_phys;
            (*table.add(desc_count)).len = 16;
            (*table.add(desc_count)).flags = VRING_DESC_F_NEXT;
            (*table.add(desc_count)).next = (desc_count + 1) as u16;
            desc_count += 1;

            let data_flags = if is_write { 0 } else { VRING_DESC_F_WRITE };
            for seg in data_segments {
                (*table.add(desc_count)).addr = seg.dma_addr;
                (*table.add(desc_count)).len = seg.byte_len as u32;
                (*table.add(desc_count)).flags = data_flags | VRING_DESC_F_NEXT;
                (*table.add(desc_count)).next = (desc_count + 1) as u16;
                desc_count += 1;
            }

            // Status
            (*table.add(desc_count)).addr = status_phys;
            (*table.add(desc_count)).len = 1;
            (*table.add(desc_count)).flags = VRING_DESC_F_WRITE;
            // no next for the last descriptor
            desc_count += 1;

            let total_table_len = (desc_count * 16) as u32;
            vq.push_allocated_indirect(head, PhysAddr::new(indirect_phys), total_table_len);
        }

        Some(head)
    }

    pub fn get_status(&self, head: u16) -> u8 {
        let slot_ptr = self.get_slot_ptr(head);
        unsafe { core::ptr::read_volatile(&(*slot_ptr).status) }
    }
}

impl Drop for BlkIoSlots {
    fn drop(&mut self) {
        let bytes = (self.pool_pages * 4096) as u64;
        unsafe { unmap_range(self.pool_va, bytes) };
        deallocate_kernel_range(self.pool_va, bytes);
    }
}
