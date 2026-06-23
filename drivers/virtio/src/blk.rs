use alloc::sync::Arc;
use core::hint::{cold_path, unlikely};
use kernel_api::device::DeviceObject;
use kernel_api::disk_profile as dp;
use kernel_api::kernel_types::disk_profile::{
    B_VIRTIO_DESCRIPTOR_SETUP, C_SCATTER_GATHER_SEGMENTS, C_VIRTIO_SUBMISSION_BYTES,
    C_VIRTIO_SUBMISSIONS,
};
use kernel_api::kernel_types::dma::IoBufferDmaSegment;
use kernel_api::memory::VirtAddr;

use crate::dma_region::ContiguousDmaRegion;
use crate::pci;
use crate::virtqueue::{VRING_DESC_F_NEXT, VRING_DESC_F_WRITE, VirtqDesc, Virtqueue};

pub const BLK_INDIRECT_DESC_CAPACITY: usize = 256;
pub const BLK_MAX_DATA_SEGMENTS_PER_REQUEST: usize = BLK_INDIRECT_DESC_CAPACITY - 2;

pub const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;
pub const VIRTIO_STATUS_DRIVER: u8 = 2;
pub const VIRTIO_STATUS_FEATURES_OK: u8 = 8;
pub const VIRTIO_STATUS_DRIVER_OK: u8 = 4;
pub const VIRTIO_STATUS_FAILED: u8 = 128;

pub const VIRTIO_BLK_T_IN: u32 = 0;
pub const VIRTIO_BLK_T_OUT: u32 = 1;
pub const VIRTIO_BLK_T_FLUSH: u32 = 4;

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
pub const VIRTIO_BLK_F_FLUSH: u64 = 1 << 9;
/// Mandatory for modern virtio-pci devices.
pub const VIRTIO_F_VERSION_1: u64 = 1u64 << 32;

/// Device can operate with platform-mediated DMA addresses (for example IOVA).
pub const VIRTIO_F_ACCESS_PLATFORM: u64 = 1u64 << 33;

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
    /// Whether device cache flush requests were successfully negotiated.
    pub flush_supported: bool,
}

/// Negotiate features and read device configuration.
/// Returns DeviceInitResult with capacity and multiqueue information.
pub fn init_device(
    common_cfg: VirtAddr,
    device_cfg: VirtAddr,
) -> Result<DeviceInitResult, &'static str> {
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
    if unlikely(dev_features & VIRTIO_F_VERSION_1 == 0) {
        cold_path();
        unsafe {
            pci::common_write_u8(common_cfg, pci::COMMON_DEVICE_STATUS, VIRTIO_STATUS_FAILED)
        };
        return Err("device does not advertise VIRTIO_F_VERSION_1");
    }

    // Check for feature support
    let mq_supported = (dev_features & VIRTIO_BLK_F_MQ) != 0;
    let indirect_supported = (dev_features & VIRTIO_F_INDIRECT_DESC) != 0;
    let flush_supported = (dev_features & VIRTIO_BLK_F_FLUSH) != 0;
    let access_platform_supported = (dev_features & VIRTIO_F_ACCESS_PLATFORM) != 0;

    if unlikely(!access_platform_supported) {
        cold_path();
        unsafe {
            pci::common_write_u8(common_cfg, pci::COMMON_DEVICE_STATUS, VIRTIO_STATUS_FAILED)
        };
        return Err("device does not advertise VIRTIO_F_ACCESS_PLATFORM");
    }

    // Negotiate VERSION_1 and other supported features
    let mut supported_features = VIRTIO_F_VERSION_1 | VIRTIO_F_ACCESS_PLATFORM;
    if mq_supported {
        supported_features |= VIRTIO_BLK_F_MQ;
    }
    if indirect_supported {
        supported_features |= VIRTIO_F_INDIRECT_DESC;
    }
    if flush_supported {
        supported_features |= VIRTIO_BLK_F_FLUSH;
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
    if unlikely(status & VIRTIO_STATUS_FEATURES_OK == 0) {
        cold_path();
        unsafe {
            pci::common_write_u8(common_cfg, pci::COMMON_DEVICE_STATUS, VIRTIO_STATUS_FAILED)
        };
        return Err("device rejected negotiated feature set");
    }

    // Check if features were actually negotiated
    let mq_negotiated = mq_supported && (driver_features & VIRTIO_BLK_F_MQ) != 0;
    let indirect_negotiated = indirect_supported && (driver_features & VIRTIO_F_INDIRECT_DESC) != 0;
    let flush_negotiated = flush_supported && (driver_features & VIRTIO_BLK_F_FLUSH) != 0;

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

    Ok(DeviceInitResult {
        capacity,
        num_queues,
        mq_negotiated,
        indirect_desc_supported: indirect_negotiated,
        flush_supported: flush_negotiated,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmitRequestError {
    QueueFull,
    TooManyDataSegments,
}

#[repr(C)]
pub struct BlkSlot {
    pub header: VirtioBlkReqHeader,
    pub status: u8,
    pub padding: [u8; 15],
    pub indirect_table: [VirtqDesc; BLK_INDIRECT_DESC_CAPACITY],
}

pub struct BlkIoSlots {
    pub pool: ContiguousDmaRegion,
    pub slot_count: usize,
}

unsafe impl Send for BlkIoSlots {}
unsafe impl Sync for BlkIoSlots {}

impl BlkIoSlots {
    pub fn new(slot_count: usize, device: &Arc<DeviceObject>) -> Option<Self> {
        let slot_bytes = core::mem::size_of::<BlkSlot>();
        let mapped_bytes = slot_count * slot_bytes;
        let alloc_bytes = mapped_bytes.div_ceil(4096) * 4096;
        let pool =
            ContiguousDmaRegion::new_with_alloc(device, mapped_bytes, alloc_bytes, slot_bytes)?;

        // initialize statuses to 0xFF (sentinel)
        unsafe {
            for i in 0..slot_count {
                let slot = pool.as_ptr::<BlkSlot>().add(i);
                (*slot).status = 0xFF;
            }
        }

        Some(Self { pool, slot_count })
    }

    #[inline]
    pub fn get_slot_ptr(&self, idx: u16) -> *mut BlkSlot {
        debug_assert!((idx as usize) < self.slot_count);
        self.pool.as_ptr::<BlkSlot>().wrapping_add(idx as usize)
    }

    pub fn submit_request(
        &self,
        vq: &mut Virtqueue,
        req_type: u32,
        sector: u64,
        data_segments: impl IntoIterator<Item = IoBufferDmaSegment>,
        is_write: bool,
    ) -> Result<u16, SubmitRequestError> {
        let profile_start = dp::timestamp_ns();

        let Some(head) = vq.alloc_desc() else {
            cold_path();
            return Err(SubmitRequestError::QueueFull);
        };

        let slot_ptr = self.get_slot_ptr(head);

        let slot_dma_base = self
            .pool
            .dma_addr_at(head as usize * core::mem::size_of::<BlkSlot>())
            .expect("virtio-blk: slot offset fell outside mapped DMA pool");

        let header_phys = slot_dma_base + core::mem::offset_of!(BlkSlot, header) as u64;
        let status_phys = slot_dma_base + core::mem::offset_of!(BlkSlot, status) as u64;
        let indirect_phys = slot_dma_base + core::mem::offset_of!(BlkSlot, indirect_table) as u64;

        unsafe {
            (*slot_ptr).header.req_type = req_type;
            (*slot_ptr).header.reserved = 0;
            (*slot_ptr).header.sector = sector;

            core::ptr::write_volatile(&mut (*slot_ptr).status, 0xFF);

            let mut desc_count = 0usize;
            let table_ptr = (*slot_ptr).indirect_table.as_mut_ptr();

            (*table_ptr.add(desc_count)).addr = header_phys;
            (*table_ptr.add(desc_count)).len = core::mem::size_of::<VirtioBlkReqHeader>() as u32;
            (*table_ptr.add(desc_count)).flags = VRING_DESC_F_NEXT;
            (*table_ptr.add(desc_count)).next = (desc_count + 1) as u16;
            desc_count += 1;

            let data_flags = if is_write { 0 } else { VRING_DESC_F_WRITE };
            let mut segment_count = 0usize;
            let mut segment_bytes = 0u64;

            for seg in data_segments {
                if unlikely(seg.byte_len == 0) {
                    cold_path();
                    continue;
                }

                if unlikely(desc_count + 2 > BLK_INDIRECT_DESC_CAPACITY) {
                    cold_path();
                    vq.free_desc(head);
                    dp::add_elapsed(B_VIRTIO_DESCRIPTOR_SETUP, profile_start);
                    return Err(SubmitRequestError::TooManyDataSegments);
                }

                (*table_ptr.add(desc_count)).addr = seg.dma_addr;
                (*table_ptr.add(desc_count)).len = seg.byte_len;
                (*table_ptr.add(desc_count)).flags = data_flags | VRING_DESC_F_NEXT;
                (*table_ptr.add(desc_count)).next = (desc_count + 1) as u16;

                desc_count += 1;
                segment_count += 1;
                segment_bytes = segment_bytes.saturating_add(seg.byte_len as u64);
            }

            if unlikely(desc_count + 1 > BLK_INDIRECT_DESC_CAPACITY) {
                cold_path();
                vq.free_desc(head);
                dp::add_elapsed(B_VIRTIO_DESCRIPTOR_SETUP, profile_start);
                return Err(SubmitRequestError::TooManyDataSegments);
            }

            (*table_ptr.add(desc_count)).addr = status_phys;
            (*table_ptr.add(desc_count)).len = 1;
            (*table_ptr.add(desc_count)).flags = VRING_DESC_F_WRITE;
            (*table_ptr.add(desc_count)).next = 0;
            desc_count += 1;

            let total_table_len = (desc_count * core::mem::size_of::<VirtqDesc>()) as u32;
            vq.push_allocated_indirect(head, indirect_phys, total_table_len);

            dp::add_counter(C_VIRTIO_SUBMISSIONS, 1);
            dp::add_counter(C_SCATTER_GATHER_SEGMENTS, segment_count as u64);
            dp::add_counter(C_VIRTIO_SUBMISSION_BYTES, segment_bytes);
        }

        dp::add_elapsed(B_VIRTIO_DESCRIPTOR_SETUP, profile_start);

        Ok(head)
    }

    pub fn destroy(&mut self) {
        self.pool.destroy();
    }

    pub fn get_status(&self, head: u16) -> u8 {
        let slot_ptr = self.get_slot_ptr(head);
        unsafe { core::ptr::read_volatile(&(*slot_ptr).status) }
    }
}

impl Drop for BlkIoSlots {
    fn drop(&mut self) {
        self.destroy();
    }
}
