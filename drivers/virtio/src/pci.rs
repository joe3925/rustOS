use alloc::vec::Vec;
use core::mem::MaybeUninit;
use kernel_api::memory::{PhysAddr, VirtAddr, map_mmio_region};
use kernel_api::pnp::{ResourceKind, ResourceDescriptor};

/// Volatile reads/writes that remain defined on unaligned PCI/virtio registers.
#[repr(C, packed)]
struct VolatileUnaligned<T>(T);

#[inline]
unsafe fn read_volatile_unaligned<T: Copy>(ptr: *const u8) -> T {
    unsafe { core::ptr::read_volatile(ptr as *const VolatileUnaligned<T>).0 }
}

#[inline]
unsafe fn write_volatile_unaligned<T: Copy>(ptr: *mut u8, val: T) {
    unsafe { core::ptr::write_volatile(ptr as *mut VolatileUnaligned<T>, VolatileUnaligned(val)) };
}

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



/// Find the PCI configuration space physical address from the resource blob.




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
pub(crate) unsafe fn parse_virtio_caps(
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
            let offset = unsafe { read_volatile_unaligned::<u32>(base.add(ptr + 8)) };
            let _length = unsafe { read_volatile_unaligned::<u32>(base.add(ptr + 12)) };

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
                            unsafe { read_volatile_unaligned::<u32>(base.add(ptr + 16)) };
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

pub unsafe fn common_read_u8(common: VirtAddr, offset: usize) -> u8 {
    unsafe { core::ptr::read_volatile((common.as_u64() as *const u8).add(offset)) }
}

pub unsafe fn common_write_u8(common: VirtAddr, offset: usize, val: u8) {
    unsafe { core::ptr::write_volatile((common.as_u64() as *mut u8).add(offset), val) }
}

pub unsafe fn common_read_u16(common: VirtAddr, offset: usize) -> u16 {
    unsafe { read_volatile_unaligned::<u16>((common.as_u64() as *const u8).add(offset)) }
}

pub unsafe fn common_write_u16(common: VirtAddr, offset: usize, val: u16) {
    unsafe { write_volatile_unaligned::<u16>((common.as_u64() as *mut u8).add(offset), val) }
}

pub unsafe fn common_read_u32(common: VirtAddr, offset: usize) -> u32 {
    unsafe { read_volatile_unaligned::<u32>((common.as_u64() as *const u8).add(offset)) }
}

pub unsafe fn common_write_u32(common: VirtAddr, offset: usize, val: u32) {
    unsafe { write_volatile_unaligned::<u32>((common.as_u64() as *mut u8).add(offset), val) }
}

pub unsafe fn common_read_u64(common: VirtAddr, offset: usize) -> u64 {
    unsafe { read_volatile_unaligned::<u64>((common.as_u64() as *const u8).add(offset)) }
}

pub unsafe fn common_write_u64(common: VirtAddr, offset: usize, val: u64) {
    unsafe { write_volatile_unaligned::<u64>((common.as_u64() as *mut u8).add(offset), val) }
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
pub const COMMON_MSIX_CONFIG: usize = 0x10;
pub const COMMON_QUEUE_MSIX_VECTOR: usize = 0x1A;


