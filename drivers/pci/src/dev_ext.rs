#![allow(dead_code)]

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::arch::asm;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};
use kernel_api::RequestExt;
use kernel_api::device::DeviceObject;
use kernel_api::memory::{map_mmio_region, unmap_mmio_region, unmap_range};
use kernel_api::request::{Request, RequestData};
use kernel_api::status::{DriverStatus, PageMapError};

use kernel_api::pnp::{
    DeviceRelationType, PnpMinorFunction, PnpRequest, QueryIdType, ResourceKind,
    pnp_forward_request_to_next_lower,
};

use kernel_api::{
    println,
    x86_64::{PhysAddr, VirtAddr},
};
use spin::{Mutex, Once, RwLock};

const PCI_CFG1_ADDR: u16 = 0xCF8;
const PCI_CFG1_DATA: u16 = 0xCFC;
static CFG1_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy, Debug)]
pub struct McfgSegment {
    pub base: u64,
    pub seg: u16,
    pub start_bus: u8,
    pub end_bus: u8,
}

#[repr(C)]
pub struct DevExt {
    pub segments: Once<Vec<McfgSegment>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BarKind {
    None,
    Io,
    Mem32,
    Mem64,
}

#[derive(Clone, Copy, Debug)]
pub struct Bar {
    pub kind: BarKind,
    pub base: u64,
    pub size: u64,
    pub prefetch: bool,
}

impl Default for Bar {
    fn default() -> Self {
        Bar {
            kind: BarKind::None,
            base: 0,
            size: 0,
            prefetch: false,
        }
    }
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

    pub class: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub revision: u8,

    pub ss_vid: u16,
    pub ss_id: u16,

    pub irq_pin: u8,
    pub irq_line: u8,

    pub bars: [Bar; 6],
}

#[repr(C)]
pub struct PrepareHardwareCtx {
    pub(crate) original_device: Arc<DeviceObject>,
    pub(crate) original_request: Arc<RwLock<Request>>,
}

#[inline]
fn ecam_phys_addr(seg: &McfgSegment, bus: u8, dev: u8, func: u8, offset: u16) -> u64 {
    seg.base + ((bus as u64) << 20) + ((dev as u64) << 15) + ((func as u64) << 12) + (offset as u64)
}

#[inline]
fn map_cfg_page(
    seg: &McfgSegment,
    bus: u8,
    dev: u8,
    func: u8,
) -> Result<(VirtAddr, u64), PageMapError> {
    let pa = PhysAddr::new(ecam_phys_addr(seg, bus, dev, func, 0));
    let sz = 4096u64;
    map_mmio_region(pa, sz).map(|va| (va, sz))
}

#[inline]
unsafe fn unmap_cfg_page(va: VirtAddr, size: u64) {
    unsafe { unmap_mmio_region(va, size) };
}

#[inline]
unsafe fn cfg_read32(base: VirtAddr, off: u16) -> u32 {
    let p = (base.as_u64() + off as u64) as *const u32;
    unsafe { core::ptr::read_volatile(p) }
}

#[inline]
unsafe fn cfg_write32(base: VirtAddr, off: u16, v: u32) {
    let p = (base.as_u64() + off as u64) as *mut u32;
    unsafe {
        core::ptr::write_volatile(p, v);
    }
}

pub fn probe_function(seg: &McfgSegment, bus: u8, dev: u8, func: u8) -> Option<PciPdoExt> {
    let (va, sz) = map_cfg_page(seg, bus, dev, func).ok()?;

    let vendor = unsafe { cfg_read32(va, 0x00) } & 0xFFFF;
    if vendor == 0xFFFF {
        unsafe { unmap_cfg_page(va, sz) };
        return None;
    }

    let did_vid = unsafe { cfg_read32(va, 0x00) };
    let device_id = ((did_vid >> 16) & 0xFFFF) as u16;
    let vendor_id = (did_vid & 0xFFFF) as u16;

    let class_rev = unsafe { cfg_read32(va, 0x08) };
    let revision = (class_rev & 0xFF) as u8;
    let prog_if = ((class_rev >> 8) & 0xFF) as u8;
    let subclass = ((class_rev >> 16) & 0xFF) as u8;
    let class = ((class_rev >> 24) & 0xFF) as u8;

    let hdr_type = ((unsafe { cfg_read32(va, 0x0C) } >> 16) & 0xFF) as u8;
    let hdr_kind = hdr_type & 0x7F;

    let (ss_vid, ss_id) = if hdr_kind == 0x00 {
        let ss = unsafe { cfg_read32(va, 0x2C) };
        ((ss & 0xFFFF) as u16, ((ss >> 16) & 0xFFFF) as u16)
    } else {
        (0, 0)
    };

    let intr = unsafe { cfg_read32(va, 0x3C) };
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
        let orig = unsafe { cfg_read32(va, off) };
        if orig == 0 {
            i += 1;
            continue;
        }

        if (orig & 0x1) == 0x1 {
            let base = (orig & 0xFFFFFFFC) as u64;
            unsafe { cfg_write32(va, off, 0xFFFF_FFFF) };
            let sz_mask = unsafe { cfg_read32(va, off) } & 0xFFFFFFFC;
            unsafe { cfg_write32(va, off, orig) };
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
                    unsafe { cfg_write32(va, off, 0xFFFF_FFF0) };
                    let mask = unsafe { cfg_read32(va, off) } & 0xFFFF_FFF0;
                    unsafe { cfg_write32(va, off, orig) };
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
                    let orig_hi = unsafe { cfg_read32(va, off + 4) };
                    let base = ((orig_hi as u64) << 32) | ((orig as u64) & 0xFFFF_FFF0);

                    unsafe { cfg_write32(va, off, 0xFFFF_FFF0) };
                    unsafe { cfg_write32(va, off + 4, 0xFFFF_FFFF) };
                    let mask_lo = unsafe { cfg_read32(va, off) } & 0xFFFF_FFF0;
                    let mask_hi = unsafe { cfg_read32(va, off + 4) };
                    unsafe { cfg_write32(va, off, orig) };
                    unsafe { cfg_write32(va, off + 4, orig_hi) };
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

    unsafe { unmap_cfg_page(va, sz) };
    Some(PciPdoExt {
        seg: seg.seg,
        bus,
        dev,
        func,
        vendor_id,
        device_id,
        class,
        subclass,
        prog_if,
        revision,
        ss_vid,
        ss_id,
        irq_pin,
        irq_line,
        bars,
    })
}

pub fn header_type(seg: &McfgSegment, bus: u8, dev: u8) -> Option<u8> {
    let (va, sz) = unsafe { map_cfg_page(seg, bus, dev, 0).ok()? };
    let vid = unsafe { cfg_read32(va, 0x00) } & 0xFFFF;
    if vid == 0xFFFF {
        unsafe { unmap_cfg_page(va, sz) };
        return None;
    }
    let ht = ((unsafe { cfg_read32(va, 0x0C) } >> 16) & 0xFF) as u8;
    unsafe { unmap_cfg_page(va, sz) };
    Some(ht)
}

pub fn build_resources_blob(p: &PciPdoExt) -> alloc::vec::Vec<u8> {
    let mut items: alloc::vec::Vec<(u32, u32, u64, u64)> = alloc::vec::Vec::new();

    for (i, b) in p.bars.iter().enumerate() {
        match b.kind {
            BarKind::None => {}
            BarKind::Io => {
                // write BAR index in the second u32
                items.push((ResourceKind::Port as u32, i as u32, b.base, b.size));
            }
            BarKind::Mem32 | BarKind::Mem64 => {
                items.push((ResourceKind::Memory as u32, i as u32, b.base, b.size));
            }
        }
    }

    if p.irq_pin != 0 {
        let flags = (p.irq_pin as u32) & 0xFF;
        items.push((ResourceKind::Interrupt as u32, flags, p.irq_line as u64, 0));
    }

    let mut out = alloc::vec::Vec::with_capacity(12 + items.len() * 24);
    out.extend_from_slice(b"RSRC");
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&(items.len() as u32).to_le_bytes());
    for (k, idx, s, l) in items {
        out.extend_from_slice(&k.to_le_bytes());
        out.extend_from_slice(&idx.to_le_bytes());
        out.extend_from_slice(&s.to_le_bytes());
        out.extend_from_slice(&l.to_le_bytes());
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
    use alloc::format;
    let ven = p.vendor_id as u32;
    let dev = p.device_id as u32;
    let rev = p.revision as u32;
    let ss = ((p.ss_id as u32) << 16) | (p.ss_vid as u32);
    let cc_full = format!("{:02X}{:02X}{:02X}", p.class, p.subclass, p.prog_if);
    let cc_nopi = format!("{:02X}{:02X}00", p.class, p.subclass);

    let mut hardware = alloc::vec::Vec::new();
    hardware.push(format!(
        "PCI\\VEN_{:04X}&DEV_{:04X}&SUBSYS_{:08X}&REV_{:02X}",
        ven, dev, ss, rev
    ));
    hardware.push(format!(
        "PCI\\VEN_{:04X}&DEV_{:04X}&SUBSYS_{:08X}",
        ven, dev, ss
    ));
    hardware.push(format!(
        "PCI\\VEN_{:04X}&DEV_{:04X}&REV_{:02X}",
        ven, dev, rev
    ));
    hardware.push(format!("PCI\\VEN_{:04X}&DEV_{:04X}", ven, dev));

    let mut compatible = alloc::vec::Vec::new();
    compatible.push(format!(
        "PCI\\VEN_{:04X}&DEV_{:04X}&CC_{}",
        ven, dev, cc_full
    ));
    compatible.push(format!(
        "PCI\\VEN_{:04X}&DEV_{:04X}&CC_{}",
        ven, dev, cc_nopi
    ));
    compatible.push(format!("PCI\\CC_{}", cc_full));
    compatible.push(format!("PCI\\CC_{}", cc_nopi));

    let class_tag = format!("CC_{}", &cc_nopi);

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

struct WaitCtx {
    done: AtomicBool,
    status: UnsafeCell<DriverStatus>,
    blob: UnsafeCell<Vec<u8>>,
}

extern "win64" fn on_complete(req: &mut Request, ctx: usize) -> DriverStatus {
    let w = unsafe { &*(ctx as *const WaitCtx) };
    let mut out = Vec::new();
    if let Some(p) = req.pnp.as_ref() {
        out.extend_from_slice(&p.blob_out);
    }
    unsafe {
        *w.status.get() = req.status;
    }
    unsafe {
        *w.blob.get() = out;
    }
    w.done.store(true, Ordering::Release);
    return DriverStatus::Success;
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
                    blob[off + 0],
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
                segs.push(McfgSegment {
                    base,
                    seg,
                    start_bus: sb,
                    end_bus: eb,
                });
                off += 12;
            }
            break;
        }
        i += 1;
    }
    segs
}

pub fn load_segments_from_parent(device: &Arc<DeviceObject>) -> Vec<McfgSegment> {
    let pnp = PnpRequest {
        minor_function: PnpMinorFunction::QueryResources,
        relation: DeviceRelationType::TargetDeviceRelation,
        id_type: QueryIdType::CompatibleIds,
        ids_out: alloc::vec::Vec::new(),
        blob_out: alloc::vec::Vec::new(),
    };

    let req = Request::new_pnp(pnp, RequestData::empty());

    let req_arc = alloc::sync::Arc::new(spin::RwLock::new(req));
    let down = pnp_forward_request_to_next_lower(device.clone(), req_arc.clone());

    let st = { req_arc.read().status };
    if st != DriverStatus::Success {
        println!("[PCI] parent QueryResources failed; no ECAM");
        return alloc::vec::Vec::new();
    }

    let blob = {
        let g = req_arc.read();
        g.pnp
            .as_ref()
            .map(|p| p.blob_out.clone())
            .unwrap_or_default()
    };

    let segs: Vec<McfgSegment> = parse_ecam_segments_from_blob(&blob);
    if segs.is_empty() {
        kernel_api::println!("[PCI] no ECAM block found in parent resources");
    }
    segs
}

#[inline]
fn cfg1_addr(bus: u8, dev: u8, func: u8, offset: u16) -> u32 {
    0x8000_0000
        | ((bus as u32) << 16)
        | ((dev as u32) << 11)
        | ((func as u32) << 8)
        | (((offset as u32) & !3) as u32)
}

#[inline]
unsafe fn outl(port: u16, val: u32) {
    unsafe { asm!("out dx, eax", in("dx") port, in("eax") val, options(nostack, preserves_flags)) };
}

#[inline]
unsafe fn inl(port: u16) -> u32 {
    let v: u32;
    unsafe { asm!("in eax, dx", in("dx") port, out("eax") v, options(nostack, preserves_flags)) };
    v
}

#[inline]
unsafe fn cfg1_read32_unlocked(bus: u8, dev: u8, func: u8, offset: u16) -> u32 {
    unsafe { outl(PCI_CFG1_ADDR, cfg1_addr(bus, dev, func, offset)) };
    unsafe { inl(PCI_CFG1_DATA) }
}

#[inline]
unsafe fn cfg1_write32_unlocked(bus: u8, dev: u8, func: u8, offset: u16, val: u32) {
    unsafe { outl(PCI_CFG1_ADDR, cfg1_addr(bus, dev, func, offset)) };
    unsafe { outl(PCI_CFG1_DATA, val) };
}

#[inline]
fn cfg1_read32(bus: u8, dev: u8, func: u8, offset: u16) -> u32 {
    let _g = CFG1_LOCK.lock();
    unsafe { cfg1_read32_unlocked(bus, dev, func, offset) }
}

#[inline]
fn cfg1_write32(bus: u8, dev: u8, func: u8, offset: u16, val: u32) -> u32 {
    let _g = CFG1_LOCK.lock();
    unsafe {
        cfg1_write32_unlocked(bus, dev, func, offset, val);
        val
    }
}

pub fn header_type_legacy(bus: u8, dev: u8) -> Option<u8> {
    let vid = cfg1_read32(bus, dev, 0, 0x00) & 0xFFFF;
    if vid == 0xFFFF {
        return None;
    }
    Some(((cfg1_read32(bus, dev, 0, 0x0C) >> 16) & 0xFF) as u8)
}

pub fn probe_function_legacy(bus: u8, dev: u8, func: u8) -> Option<PciPdoExt> {
    let _g = CFG1_LOCK.lock();

    let did_vid = unsafe { cfg1_read32_unlocked(bus, dev, func, 0x00) };
    let vendor = did_vid & 0xFFFF;
    if vendor == 0xFFFF {
        return None;
    }

    let device_id = ((did_vid >> 16) & 0xFFFF) as u16;
    let vendor_id = (did_vid & 0xFFFF) as u16;

    let class_rev = unsafe { cfg1_read32_unlocked(bus, dev, func, 0x08) };
    let revision = (class_rev & 0xFF) as u8;
    let prog_if = ((class_rev >> 8) & 0xFF) as u8;
    let subclass = ((class_rev >> 16) & 0xFF) as u8;
    let class = ((class_rev >> 24) & 0xFF) as u8;

    let hdr_type = ((unsafe { cfg1_read32_unlocked(bus, dev, func, 0x0C) } >> 16) & 0xFF) as u8;
    let hdr_kind = hdr_type & 0x7F;

    let (ss_vid, ss_id) = if hdr_kind == 0x00 {
        let ss = unsafe { cfg1_read32_unlocked(bus, dev, func, 0x2C) };
        ((ss & 0xFFFF) as u16, ((ss >> 16) & 0xFFFF) as u16)
    } else {
        (0, 0)
    };

    let intr = unsafe { cfg1_read32_unlocked(bus, dev, func, 0x3C) };
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
        let orig = unsafe { cfg1_read32_unlocked(bus, dev, func, off) };
        if orig == 0 {
            i += 1;
            continue;
        }

        if (orig & 0x1) == 0x1 {
            let base: u64 = (orig & 0xFFFF_FFFC) as u64;
            unsafe { cfg1_write32_unlocked(bus, dev, func, off, 0xFFFF_FFFF) };
            let mask = unsafe { cfg1_read32_unlocked(bus, dev, func, off) } & 0xFFFF_FFFC;
            unsafe { cfg1_write32_unlocked(bus, dev, func, off, orig) };
            let size = ((!mask).wrapping_add(1)) as u64;
            bars[i] = Bar {
                kind: BarKind::Io,
                base,
                size,
                prefetch: false,
            };
            i += 1;
        } else {
            let prefetch = (orig & (1 << 3)) != 0;
            let mem_ty = (orig >> 1) & 0x3;
            match mem_ty {
                0b00 => {
                    let base = (orig & 0xFFFF_FFF0) as u64;
                    unsafe { cfg1_write32_unlocked(bus, dev, func, off, 0xFFFF_FFF0) };
                    let mask = unsafe { cfg1_read32_unlocked(bus, dev, func, off) } & 0xFFFF_FFF0;
                    unsafe { cfg1_write32_unlocked(bus, dev, func, off, orig) };
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
                    let orig_hi = unsafe { cfg1_read32_unlocked(bus, dev, func, off + 4) };
                    let base = ((orig_hi as u64) << 32) | ((orig as u64) & 0xFFFF_FFF0);
                    unsafe { cfg1_write32_unlocked(bus, dev, func, off, 0xFFFF_FFF0) };
                    unsafe { cfg1_write32_unlocked(bus, dev, func, off + 4, 0xFFFF_FFFF) };
                    let mask_lo =
                        unsafe { cfg1_read32_unlocked(bus, dev, func, off) } & 0xFFFF_FFF0;
                    let mask_hi = unsafe { cfg1_read32_unlocked(bus, dev, func, off + 4) };
                    unsafe { cfg1_write32_unlocked(bus, dev, func, off, orig) };
                    unsafe { cfg1_write32_unlocked(bus, dev, func, off + 4, orig_hi) };
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

    Some(PciPdoExt {
        seg: 0,
        bus,
        dev,
        func,
        vendor_id,
        device_id,
        class,
        subclass,
        prog_if,
        revision,
        ss_vid,
        ss_id,
        irq_pin,
        irq_line,
        bars,
    })
}
