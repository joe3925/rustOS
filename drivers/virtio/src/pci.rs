use alloc::vec::Vec;
use kernel_api::memory::{map_mmio_region, virt_to_phys};
use kernel_api::pnp::ResourceKind;
use kernel_api::x86_64::{PhysAddr, VirtAddr};

/// Parsed virtio PCI capability pointers (virtual addresses into mapped BARs).
pub struct VirtioPciCaps {
    pub common_cfg: VirtAddr,
    pub notify_base: VirtAddr,
    pub notify_off_multiplier: u32,
    pub isr_cfg: VirtAddr,
    pub device_cfg: VirtAddr,
}

/// A parsed resource entry from the PCI RSRC blob.
#[derive(Clone, Copy)]
pub struct PciResource {
    pub kind: u32,
    pub index: u32,
    pub start: u64,
    pub length: u64,
}

/// Parse the RSRC blob returned by QueryResources into individual resource entries.
pub fn parse_resources(blob: &[u8]) -> Vec<PciResource> {
    let mut out = Vec::new();
    if blob.len() < 12 || &blob[0..4] != b"RSRC" {
        return out;
    }
    let mut off = 12usize;
    while off + 24 <= blob.len() {
        let kind = u32::from_le_bytes([blob[off], blob[off + 1], blob[off + 2], blob[off + 3]]);
        let index =
            u32::from_le_bytes([blob[off + 4], blob[off + 5], blob[off + 6], blob[off + 7]]);
        let start = u64::from_le_bytes([
            blob[off + 8],
            blob[off + 9],
            blob[off + 10],
            blob[off + 11],
            blob[off + 12],
            blob[off + 13],
            blob[off + 14],
            blob[off + 15],
        ]);
        let length = u64::from_le_bytes([
            blob[off + 16],
            blob[off + 17],
            blob[off + 18],
            blob[off + 19],
            blob[off + 20],
            blob[off + 21],
            blob[off + 22],
            blob[off + 23],
        ]);
        off += 24;
        out.push(PciResource {
            kind,
            index,
            start,
            length,
        });
    }
    out
}

/// Find the PCI configuration space physical address from the resource blob.
pub fn find_config_space(resources: &[PciResource]) -> Option<(u64, u64)> {
    for r in resources {
        if r.kind == ResourceKind::ConfigSpace as u32 {
            return Some((r.start, r.length));
        }
    }
    None
}

/// Find a GSI from the resource blob (preferred over legacy IRQ lines).
pub fn find_gsi(resources: &[PciResource]) -> Option<u16> {
    for r in resources {
        if r.kind == ResourceKind::Gsi as u32 {
            return Some(r.start as u16);
        }
    }
    None
}

/// Find the legacy IRQ line from the resource blob.
pub fn find_legacy_irq_line(resources: &[PciResource]) -> Option<u8> {
    for r in resources {
        if r.kind == ResourceKind::Interrupt as u32 {
            return Some(r.start as u8);
        }
    }
    None
}

/// Map all memory BARs from the resource list.
/// Returns (bar_index, virt_addr, size) tuples. The caller must track these for cleanup.
pub fn map_memory_bars(resources: &[PciResource]) -> Vec<(u32, VirtAddr, u64)> {
    let mut mapped = Vec::new();
    for r in resources {
        if r.kind == ResourceKind::Memory as u32 && r.length > 0 {
            if let Ok(va) = map_mmio_region(PhysAddr::new(r.start), r.length) {
                mapped.push((r.index, va, r.length));
            }
        }
    }
    mapped
}

/// Virtio PCI capability structure layout (from PCI config space).
/// cfg_type values:
///   1 = Common configuration
///   2 = Notifications
///   3 = ISR status
///   4 = Device-specific configuration
///   5 = PCI configuration access
#[repr(C)]
struct VirtioPciCap {
    cap_vndr: u8, // 0x09 for virtio
    cap_next: u8,
    cap_len: u8,
    cfg_type: u8,
    bar: u8,
    _padding: [u8; 3],
    offset: u32,
    length: u32,
}

/// Walk the PCI capability list in config space (mapped via BAR 0 or ECAM)
/// to find virtio-specific capabilities.
///
/// `cfg_base` is the mapped virtual address of the PCI configuration space for this device.
/// `mapped_bars` provides (bar_index, virtual_addr, size) for each mapped BAR.
///
/// For virtio-pci modern devices, the capabilities are found in PCI config space
/// starting at the capability pointer (offset 0x34). Each capability is a linked list entry.
pub fn parse_virtio_caps(
    cfg_base: VirtAddr,
    mapped_bars: &[(u32, VirtAddr, u64)],
) -> Option<VirtioPciCaps> {
    let base = cfg_base.as_u64() as *const u8;

    // Read capability pointer from PCI config offset 0x34
    let cap_ptr = unsafe { core::ptr::read_volatile(base.add(0x34)) };
    if cap_ptr == 0 {
        return None;
    }

    let mut common_cfg = None;
    let mut notify_base = None;
    let mut notify_off_multiplier = 0u32;
    let mut isr_cfg = None;
    let mut device_cfg = None;

    let mut ptr = cap_ptr as usize;
    let mut iterations = 0u32;

    while ptr != 0 && iterations < 64 {
        iterations += 1;
        let vndr = unsafe { core::ptr::read_volatile(base.add(ptr)) };

        if vndr == 0x09 {
            // This is a virtio capability
            let cfg_type = unsafe { core::ptr::read_volatile(base.add(ptr + 3)) };
            let bar = unsafe { core::ptr::read_volatile(base.add(ptr + 4)) };
            let offset = unsafe { core::ptr::read_volatile(base.add(ptr + 8) as *const u32) };
            let length = unsafe { core::ptr::read_volatile(base.add(ptr + 12) as *const u32) };

            // Find the mapped BAR
            if let Some((_idx, bar_va, _sz)) =
                mapped_bars.iter().find(|(idx, _, _)| *idx == bar as u32)
            {
                let region_va = VirtAddr::new(bar_va.as_u64() + offset as u64);
                match cfg_type {
                    1 => common_cfg = Some(region_va),
                    2 => {
                        notify_base = Some(region_va);
                        // The notify_off_multiplier is at cap offset 16 (after the standard cap fields)
                        notify_off_multiplier =
                            unsafe { core::ptr::read_volatile(base.add(ptr + 16) as *const u32) };
                    }
                    3 => isr_cfg = Some(region_va),
                    4 => device_cfg = Some(region_va),
                    _ => {}
                }
            }
        }

        // Follow the linked list
        ptr = unsafe { core::ptr::read_volatile(base.add(ptr + 1)) } as usize;
    }

    Some(VirtioPciCaps {
        common_cfg: common_cfg?,
        notify_base: notify_base?,
        notify_off_multiplier,
        isr_cfg: isr_cfg?,
        device_cfg: device_cfg?,
    })
}

// ---------------------------------------------------------------------------
// Volatile accessors for the common configuration structure
// ---------------------------------------------------------------------------
// Layout of virtio_pci_common_cfg (offsets from common_cfg base):
//   0x00  u32  device_feature_select
//   0x04  u32  device_feature
//   0x08  u32  driver_feature_select
//   0x0C  u32  driver_feature
//   0x10  u16  msix_config
//   0x12  u16  num_queues
//   0x14  u8   device_status
//   0x15  u8   config_generation
//   0x16  u16  queue_select
//   0x18  u16  queue_size
//   0x1A  u16  queue_msix_vector
//   0x1C  u16  queue_enable
//   0x1E  u16  queue_notify_off
//   0x20  u64  queue_desc
//   0x28  u64  queue_driver   (avail)
//   0x30  u64  queue_device   (used)

pub unsafe fn common_read_u8(common: VirtAddr, offset: usize) -> u8 {
    unsafe { core::ptr::read_volatile((common.as_u64() as *const u8).add(offset)) }
}

pub unsafe fn common_write_u8(common: VirtAddr, offset: usize, val: u8) {
    unsafe { core::ptr::write_volatile((common.as_u64() as *mut u8).add(offset), val) }
}

pub unsafe fn common_read_u16(common: VirtAddr, offset: usize) -> u16 {
    unsafe { core::ptr::read_volatile((common.as_u64() as *const u8).add(offset) as *const u16) }
}

pub unsafe fn common_write_u16(common: VirtAddr, offset: usize, val: u16) {
    unsafe { core::ptr::write_volatile((common.as_u64() as *mut u8).add(offset) as *mut u16, val) }
}

pub unsafe fn common_read_u32(common: VirtAddr, offset: usize) -> u32 {
    unsafe { core::ptr::read_volatile((common.as_u64() as *const u8).add(offset) as *const u32) }
}

pub unsafe fn common_write_u32(common: VirtAddr, offset: usize, val: u32) {
    unsafe { core::ptr::write_volatile((common.as_u64() as *mut u8).add(offset) as *mut u32, val) }
}

pub unsafe fn common_read_u64(common: VirtAddr, offset: usize) -> u64 {
    unsafe { core::ptr::read_volatile((common.as_u64() as *const u8).add(offset) as *const u64) }
}

pub unsafe fn common_write_u64(common: VirtAddr, offset: usize, val: u64) {
    unsafe { core::ptr::write_volatile((common.as_u64() as *mut u8).add(offset) as *mut u64, val) }
}

// Named offsets
pub const COMMON_DEVICE_FEATURE_SELECT: usize = 0x00;
pub const COMMON_DEVICE_FEATURE: usize = 0x04;
pub const COMMON_DRIVER_FEATURE_SELECT: usize = 0x08;
pub const COMMON_DRIVER_FEATURE: usize = 0x0C;
pub const COMMON_NUM_QUEUES: usize = 0x12;
pub const COMMON_DEVICE_STATUS: usize = 0x14;
pub const COMMON_QUEUE_SELECT: usize = 0x16;
pub const COMMON_QUEUE_SIZE: usize = 0x18;
pub const COMMON_QUEUE_ENABLE: usize = 0x1C;
pub const COMMON_QUEUE_NOTIFY_OFF: usize = 0x1E;
pub const COMMON_QUEUE_DESC: usize = 0x20;
pub const COMMON_QUEUE_DRIVER: usize = 0x28;
pub const COMMON_QUEUE_DEVICE: usize = 0x30;
