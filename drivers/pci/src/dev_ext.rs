use alloc::sync::Arc;
use alloc::vec::Vec;
use kernel_api::device::DeviceObject;
use kernel_api::kernel_types::pci::{Bar, BarKind, EcamSegment, MsixInfo, PciConfigAddress};
use kernel_api::memory::{PhysAddr, VirtAddr, map_mmio_region};
use kernel_api::pci::{pci_read_config_u32, pci_write_config_u32};
use kernel_api::pnp::{QueryResources, ResourceSet};
use kernel_api::status::PageMapError;

use kernel_api::pnp::pnp;

use spin::Once;

pub type McfgSegment = EcamSegment;

#[derive(Clone, Copy, Debug)]
pub struct PrtEntry {
    pub device: u8,
    pub pin: u8,
    pub gsi: u16,
}

#[repr(C)]
pub struct DevExt {
    pub segments: Once<Vec<McfgSegment>>,
    pub prt: Once<Vec<PrtEntry>>,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PciPdoExt {
    pub seg: u16,
    pub bus: u8,
    pub dev: u8,
    pub func: u8,

    pub vendor_id: u16,
    pub device_id: u16,
    pub command: u16,

    pub class: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub revision: u8,

    pub ss_vid: u16,
    pub ss_id: u16,

    pub irq_pin: u8,
    pub irq_line: u8,
    pub irq_gsi: Option<u16>,

    pub cfg_phys: u64,

    pub bars: [Bar; 6],

    pub msix: Option<MsixInfo>,
}

#[derive(Clone, Copy, Debug)]
pub struct EcamSegmentMap {
    pub base: VirtAddr,
    pub size: u64,
    pub start_bus: u8,
}

#[inline]
fn ecam_phys_addr(seg: &McfgSegment, bus: u8, dev: u8, func: u8, offset: u16) -> u64 {
    seg.config_space_phys_addr(bus, dev, func, offset)
}

trait ConfigAccess {
    fn read32(&self, offset: u16) -> Option<u32>;
    fn write32(&self, offset: u16, value: u32) -> Option<()>;
}

struct MappedConfig {
    base: VirtAddr,
}

impl ConfigAccess for MappedConfig {
    #[inline]
    fn read32(&self, offset: u16) -> Option<u32> {
        Some(unsafe { cfg_read32(self.base, offset) })
    }

    #[inline]
    fn write32(&self, offset: u16, value: u32) -> Option<()> {
        unsafe { cfg_write32(self.base, offset, value) };
        Some(())
    }
}

fn probe_msix_capability(config: &impl ConfigAccess) -> Option<MsixInfo> {
    let status = (config.read32(0x04)? >> 16) as u16;
    if (status & (1 << 4)) == 0 {
        return None;
    }

    let mut cap_ptr = (config.read32(0x34)? & 0xFF) as u16;

    while cap_ptr != 0 && cap_ptr < 0x100 {
        let cap_header = config.read32(cap_ptr)?;
        let cap_id = (cap_header & 0xFF) as u8;
        let next_ptr = ((cap_header >> 8) & 0xFF) as u16;

        if cap_id == 0x11 {
            let msg_ctrl = (cap_header >> 16) as u16;
            let table_size = (msg_ctrl & 0x7FF) + 1;

            let table_reg = config.read32(cap_ptr + 4)?;
            let table_bar = (table_reg & 0x7) as u8;
            let table_offset = table_reg & !0x7;

            let pba_reg = config.read32(cap_ptr + 8)?;
            let pba_bar = (pba_reg & 0x7) as u8;
            let pba_offset = pba_reg & !0x7;

            return Some(MsixInfo {
                cap_offset: cap_ptr,
                table_bar,
                table_offset,
                table_size,
                pba_bar,
                pba_offset,
            });
        }
        cap_ptr = next_ptr;
    }
    None
}

#[inline]
fn function_base(bus_base: VirtAddr, dev: u8, func: u8) -> VirtAddr {
    VirtAddr::new(bus_base.as_u64() + ((dev as u64) << 15) + ((func as u64) << 12))
}

#[inline]
unsafe fn cfg_read32(base: VirtAddr, off: u16) -> u32 {
    unsafe {
        let p = (base.as_u64() + off as u64) as *const u32;
        core::ptr::read_volatile(p)
    }
}

#[inline]
unsafe fn cfg_write32(base: VirtAddr, off: u16, v: u32) {
    unsafe {
        let p = (base.as_u64() + off as u64) as *mut u32;
        core::ptr::write_volatile(p, v);
    }
}

#[inline]
pub fn map_ecam_bus(seg: &McfgSegment, bus: u8) -> Result<(VirtAddr, u64), PageMapError> {
    let pa = PhysAddr::new(seg.base + ((bus as u64) << 20));
    let sz = 1u64 << 20;
    map_mmio_region(pa, sz).map(|va| (va, sz))
}

pub fn map_ecam_segment_range(seg: &McfgSegment) -> Result<EcamSegmentMap, PageMapError> {
    let start = seg.start_bus as u64;
    let end = seg.end_bus as u64;
    if end < start {
        return Err(PageMapError::TranslationFailed());
    }
    let bus_count = (end - start) + 1;
    let sz = bus_count << 20;

    let pa = PhysAddr::new(seg.base + (start << 20));
    let base = map_mmio_region(pa, sz)?;
    Ok(EcamSegmentMap {
        base,
        size: sz,
        start_bus: seg.start_bus,
    })
}

#[inline]
pub fn ecam_bus_base_from_segment(map: EcamSegmentMap, bus: u8) -> VirtAddr {
    let delta = (bus.wrapping_sub(map.start_bus)) as u64;
    VirtAddr::new(map.base.as_u64() + (delta << 20))
}

#[inline]
fn probe_function_mapped(
    seg: &McfgSegment,
    bus: u8,
    dev: u8,
    func: u8,
    func_base: VirtAddr,
) -> Option<PciPdoExt> {
    let config = MappedConfig { base: func_base };
    probe_function_with(
        &config,
        seg.seg,
        bus,
        dev,
        func,
        ecam_phys_addr(seg, bus, dev, func, 0),
    )
}

fn probe_function_with(
    config: &impl ConfigAccess,
    seg: u16,
    bus: u8,
    dev: u8,
    func: u8,
    cfg_phys: u64,
) -> Option<PciPdoExt> {
    let vendor = config.read32(0x00)? & 0xFFFF;
    if vendor == 0xFFFF {
        return None;
    }

    let did_vid = config.read32(0x00)?;
    let device_id = ((did_vid >> 16) & 0xFFFF) as u16;
    let vendor_id = (did_vid & 0xFFFF) as u16;
    let command = (config.read32(0x04)? & 0xFFFF) as u16;

    let class_rev = config.read32(0x08)?;
    let revision = (class_rev & 0xFF) as u8;
    let prog_if = ((class_rev >> 8) & 0xFF) as u8;
    let subclass = ((class_rev >> 16) & 0xFF) as u8;
    let class = ((class_rev >> 24) & 0xFF) as u8;

    let hdr_type = ((config.read32(0x0C)? >> 16) & 0xFF) as u8;
    let hdr_kind = hdr_type & 0x7F;

    let (ss_vid, ss_id) = if hdr_kind == 0x00 {
        let ss = config.read32(0x2C)?;
        ((ss & 0xFFFF) as u16, ((ss >> 16) & 0xFFFF) as u16)
    } else {
        (0, 0)
    };

    let intr = config.read32(0x3C)?;
    let irq_line = (intr & 0xFF) as u8;
    let irq_pin = ((intr >> 8) & 0xFF) as u8;

    let mut bars = [Bar::default(); 6];
    let max_bars = if hdr_kind == 0x00 {
        6
    } else if hdr_kind == 0x01 {
        2
    } else {
        0
    };

    let mut i = 0;
    while i < max_bars {
        let off = 0x10 + (i as u16) * 4;
        let orig = config.read32(off)?;
        if orig == 0 {
            i += 1;
            continue;
        }

        if (orig & 0x1) == 0x1 {
            let base = (orig & 0xFFFFFFFC) as u64;
            config.write32(off, 0xFFFF_FFFF)?;
            let sz_mask = config.read32(off)? & 0xFFFFFFFC;
            config.write32(off, orig)?;
            let size = ((!sz_mask).wrapping_add(1)) as u64;

            bars[i] = Bar {
                kind: BarKind::Io,
                base,
                size,
                prefetch: false,
            };
            i += 1;
        } else {
            let prefetch = (orig & (1 << 3)) != 0;
            let mem_type = (orig >> 1) & 0x3;

            match mem_type {
                0b00 => {
                    let base = (orig & 0xFFFF_FFF0) as u64;
                    config.write32(off, 0xFFFF_FFF0)?;
                    let mask = config.read32(off)? & 0xFFFF_FFF0;
                    config.write32(off, orig)?;
                    let size = ((!mask).wrapping_add(1)) as u64;

                    bars[i] = Bar {
                        kind: BarKind::Mem32,
                        base,
                        size,
                        prefetch,
                    };
                    i += 1;
                }
                0b10 => {
                    let orig_hi = config.read32(off + 4)?;
                    let base = ((orig_hi as u64) << 32) | ((orig as u64) & 0xFFFF_FFF0);

                    config.write32(off, 0xFFFF_FFF0)?;
                    config.write32(off + 4, 0xFFFF_FFFF)?;
                    let mask_lo = config.read32(off)? & 0xFFFF_FFF0;
                    let mask_hi = config.read32(off + 4)?;
                    config.write32(off, orig)?;
                    config.write32(off + 4, orig_hi)?;
                    let mask = ((mask_hi as u64) << 32) | (mask_lo as u64);
                    let size = ((!mask).wrapping_add(1)) as u64;

                    bars[i] = Bar {
                        kind: BarKind::Mem64,
                        base,
                        size,
                        prefetch,
                    };
                    i += 2;
                }
                _ => {
                    i += 1;
                }
            }
        }
    }

    let msix = probe_msix_capability(config);

    Some(PciPdoExt {
        seg,
        bus,
        dev,
        func,
        vendor_id,
        device_id,
        command,
        class,
        subclass,
        prog_if,
        revision,
        ss_vid,
        ss_id,
        irq_pin,
        irq_line,
        irq_gsi: None,
        cfg_phys,
        bars,
        msix,
    })
}

pub(crate) unsafe fn scan_ecam_bus_mapped(
    seg: &McfgSegment,
    bus: u8,
    bus_base: VirtAddr,
) -> Vec<PciPdoExt> {
    let mut out = Vec::new();

    for dev in 0u8..32 {
        let func0_base = function_base(bus_base, dev, 0);
        let vid = unsafe { cfg_read32(func0_base, 0x00) } & 0xFFFF;
        if vid == 0xFFFF {
            continue;
        }

        let ht = ((unsafe { cfg_read32(func0_base, 0x0C) } >> 16) & 0xFF) as u8;
        let multi = (ht & 0x80) != 0;
        let func_span = if multi { 0u8..8 } else { 0u8..1 };
        for func in func_span {
            let fbase = function_base(bus_base, dev, func);
            if let Some(p) = probe_function_mapped(seg, bus, dev, func, fbase) {
                out.push(p);
            }
        }
    }

    out
}

#[inline]
pub fn hwids_for(
    p: &PciPdoExt,
) -> (
    alloc::vec::Vec<alloc::string::String>,
    alloc::vec::Vec<alloc::string::String>,
    alloc::string::String,
) {
    let ven = p.vendor_id as u32;
    let dev = p.device_id as u32;
    let rev = p.revision as u32;
    let ss = ((p.ss_id as u32) << 16) | (p.ss_vid as u32);
    let cc_full = alloc::format!("{:02X}{:02X}{:02X}", p.class, p.subclass, p.prog_if);
    let cc_nopi = alloc::format!("{:02X}{:02X}00", p.class, p.subclass);

    let mut hardware = alloc::vec::Vec::new();
    hardware.push(alloc::format!(
        "PCI\\VEN_{:04X}&DEV_{:04X}&SUBSYS_{:08X}&REV_{:02X}",
        ven,
        dev,
        ss,
        rev
    ));
    hardware.push(alloc::format!(
        "PCI\\VEN_{:04X}&DEV_{:04X}&SUBSYS_{:08X}",
        ven,
        dev,
        ss
    ));
    hardware.push(alloc::format!(
        "PCI\\VEN_{:04X}&DEV_{:04X}&REV_{:02X}",
        ven,
        dev,
        rev
    ));
    hardware.push(alloc::format!("PCI\\VEN_{:04X}&DEV_{:04X}", ven, dev));

    let mut compatible = alloc::vec::Vec::new();
    compatible.push(alloc::format!(
        "PCI\\VEN_{:04X}&DEV_{:04X}&CC_{}",
        ven,
        dev,
        cc_full
    ));
    compatible.push(alloc::format!(
        "PCI\\VEN_{:04X}&DEV_{:04X}&CC_{}",
        ven,
        dev,
        cc_nopi
    ));
    compatible.push(alloc::format!("PCI\\CC_{}", cc_full));
    compatible.push(alloc::format!("PCI\\CC_{}", cc_nopi));

    let class_tag = alloc::format!("CC_{}", &cc_nopi);

    (hardware, compatible, class_tag)
}

#[inline]
pub fn instance_path_for(p: &PciPdoExt) -> alloc::string::String {
    alloc::format!(
        "PCI\\SEG_{:04X}&BUS_{:02X}&DEV_{:02X}&FUNC_{:02X}",
        p.seg,
        p.bus,
        p.dev,
        p.func
    )
}

#[inline]
pub fn name_for(p: &PciPdoExt) -> alloc::string::String {
    alloc::format!("PCI_{}_{}_{}", p.bus, p.dev, p.func)
}

pub fn parse_ecam_segments_from_blob(blob: &[u8]) -> Vec<McfgSegment> {
    let mut segs = Vec::new();
    let mut i = 0usize;
    while i + 8 <= blob.len() {
        if &blob[i..i + 4] == b"ECAM" {
            let cnt =
                u32::from_le_bytes([blob[i + 4], blob[i + 5], blob[i + 6], blob[i + 7]]) as usize;
            let mut off = i + 8;
            for _ in 0..cnt {
                if off + 12 > blob.len() {
                    break;
                }
                let base = u64::from_le_bytes([
                    blob[off],
                    blob[off + 1],
                    blob[off + 2],
                    blob[off + 3],
                    blob[off + 4],
                    blob[off + 5],
                    blob[off + 6],
                    blob[off + 7],
                ]);
                let seg = u16::from_le_bytes([blob[off + 8], blob[off + 9]]);
                let sb = blob[off + 10];
                let eb = blob[off + 11];
                segs.push(McfgSegment::new(base, seg, sb, eb));
                off += 12;
            }
            break;
        }
        i += 1;
    }
    segs
}

pub fn parse_prt_from_blob(blob: &[u8]) -> Vec<PrtEntry> {
    let mut entries = Vec::new();
    let mut i = 0usize;
    while i + 8 <= blob.len() {
        if &blob[i..i + 4] == b"PIRT" {
            let cnt =
                u32::from_le_bytes([blob[i + 4], blob[i + 5], blob[i + 6], blob[i + 7]]) as usize;
            let mut off = i + 8;
            for _ in 0..cnt {
                if off + 4 > blob.len() {
                    break;
                }
                let device = blob[off];
                let pin = blob[off + 1];
                let gsi = u16::from_le_bytes([blob[off + 2], blob[off + 3]]);
                entries.push(PrtEntry { device, pin, gsi });
                off += 4;
            }
            break;
        }
        i += 1;
    }
    entries
}

pub async fn load_segments_from_parent(
    device: &Arc<DeviceObject>,
) -> Result<Vec<McfgSegment>, kernel_api::error::KernelError> {
    let mut handle = QueryResources {
        resources: ResourceSet::default(),
    };
    pnp::send_next_lower(device.clone(), &mut handle)
        .await
        .map_err(|error| error.with_context("querying parent PCI resources"))?;

    let blob = match handle.resources {
        ResourceSet::Encoded(blob) => blob,
        _ => Vec::new(),
    };

    let segs: Vec<McfgSegment> = parse_ecam_segments_from_blob(&blob);
    if segs.is_empty() {
        kernel_api::println!("[PCI] no ECAM block found in parent resources");
    }
    Ok(segs)
}

#[inline]
fn platform_config_address(bus: u8, dev: u8, func: u8, offset: u16) -> PciConfigAddress {
    PciConfigAddress::new(0, bus, dev, func, offset)
}

#[inline]
fn platform_config_read32(bus: u8, dev: u8, func: u8, offset: u16) -> Option<u32> {
    pci_read_config_u32(platform_config_address(bus, dev, func, offset))
}

#[inline]
fn platform_config_write32(bus: u8, dev: u8, func: u8, offset: u16, val: u32) -> Option<()> {
    pci_write_config_u32(platform_config_address(bus, dev, func, offset), val).then_some(())
}

struct PlatformConfig {
    bus: u8,
    dev: u8,
    func: u8,
}

impl ConfigAccess for PlatformConfig {
    #[inline]
    fn read32(&self, offset: u16) -> Option<u32> {
        platform_config_read32(self.bus, self.dev, self.func, offset)
    }

    #[inline]
    fn write32(&self, offset: u16, value: u32) -> Option<()> {
        platform_config_write32(self.bus, self.dev, self.func, offset, value)
    }
}

pub fn platform_config_access_available() -> bool {
    platform_config_read32(0, 0, 0, 0x00).is_some()
}

pub fn header_type_config(bus: u8, dev: u8) -> Option<u8> {
    let config = PlatformConfig { bus, dev, func: 0 };
    let vid = config.read32(0x00)? & 0xFFFF;
    if vid == 0xFFFF {
        return None;
    }
    Some(((config.read32(0x0C)? >> 16) & 0xFF) as u8)
}

pub fn probe_function_config(bus: u8, dev: u8, func: u8) -> Option<PciPdoExt> {
    let config = PlatformConfig { bus, dev, func };
    probe_function_with(&config, 0, bus, dev, func, 0)
}
