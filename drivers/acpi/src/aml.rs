use crate::alloc::format;
use crate::alloc::vec;
use crate::map_aml;
use crate::pdo::AcpiPdoExt;
use alloc::{
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use aml::value::Args;
use aml::{AmlContext, AmlName, AmlValue, Handler};
use core::ptr::{read_volatile, write_volatile};
use kernel_api::acpi::mcfg::Mcfg;
use kernel_api::device::DevNode;
use kernel_api::device::DeviceInit;
use kernel_api::device::DeviceObject;
use kernel_api::kernel_types::io::IoVtable;
use kernel_api::kernel_types::pnp::DeviceIds;
use kernel_api::memory::map_mmio_region;
use kernel_api::memory::unmap_mmio_region;
use kernel_api::memory::unmap_range;
use kernel_api::pnp::DriverStep;
use kernel_api::pnp::PnpMinorFunction;
use kernel_api::pnp::PnpVtable;
use kernel_api::pnp::QueryIdType;
use kernel_api::pnp::ResourceKind;
use kernel_api::pnp::get_acpi_tables;
use kernel_api::pnp::pnp_create_child_devnode_and_pdo_with_init;
use kernel_api::println;
use kernel_api::request::Request;
use kernel_api::request_handler;
use kernel_api::status::DriverStatus;
use kernel_api::x86_64::PhysAddr;
use kernel_api::x86_64::VirtAddr;
use kernel_api::x86_64::instructions::port::Port;
use spin::{Mutex, RwLock};
pub const PAGE_SIZE: usize = 4096;
#[repr(C)]
pub struct KernelAmlHandler;

#[repr(C)]
pub struct McfgSeg {
    pub base: u64,
    pub seg: u16,
    pub sb: u8,
    pub eb: u8,
}

#[inline]
fn round_up(n: usize, align: usize) -> usize {
    (n + align - 1) & !(align - 1)
}

#[inline]
unsafe fn map_phys_window(paddr: usize, bytes: usize) -> (VirtAddr, usize, usize) {
    let off = paddr & (PAGE_SIZE - 1);
    let base = paddr - off;
    let size = round_up(off + bytes, PAGE_SIZE);
    let va = map_mmio_region(PhysAddr::new(base as u64), size as u64).unwrap_or_else(|e| {
        kernel_api::println!("[ACPI] map_phys_window failed: {:?}", e);
        core::intrinsics::abort();
    });

    (va, off, size)
}

#[inline]
unsafe fn unmap_phys_window(va: VirtAddr, size: usize) {
    unsafe { unmap_mmio_region(va, size as u64) };
}

#[inline]
unsafe fn mmio_read<T: Copy>(paddr: usize) -> T {
    let (va, off, size) = unsafe { map_phys_window(paddr, core::mem::size_of::<T>()) };
    let ptr = (va.as_u64() as usize + off) as *const T;
    let v = unsafe { read_volatile(ptr) };
    unsafe { unmap_phys_window(va, size) };
    v
}

#[inline]
unsafe fn mmio_write<T: Copy>(paddr: usize, val: T) {
    let (va, off, size) = unsafe { map_phys_window(paddr, core::mem::size_of::<T>()) };
    let ptr = (va.as_u64() as usize + off) as *mut T;
    unsafe { write_volatile(ptr, val) };
    unsafe { unmap_phys_window(va, size) };
}

static PCI_CFG_LOCK: Mutex<()> = Mutex::new(());

#[inline]
fn pci_cfg_addr(bus: u8, dev: u8, func: u8, off: u16) -> u32 {
    0x8000_0000u32
        | ((bus as u32) << 16)
        | ((dev as u32) << 11)
        | ((func as u32) << 8)
        | ((off as u32) & 0xFC)
}

impl Handler for KernelAmlHandler {
    #[inline]
    fn read_u8(&self, address: usize) -> u8 {
        unsafe { mmio_read::<u8>(address) }
    }
    #[inline]
    fn read_u16(&self, address: usize) -> u16 {
        unsafe { mmio_read::<u16>(address) }
    }
    #[inline]
    fn read_u32(&self, address: usize) -> u32 {
        unsafe { mmio_read::<u32>(address) }
    }
    #[inline]
    fn read_u64(&self, address: usize) -> u64 {
        unsafe { mmio_read::<u64>(address) }
    }

    #[inline]
    fn write_u8(&mut self, address: usize, value: u8) {
        unsafe { mmio_write::<u8>(address, value) }
    }
    #[inline]
    fn write_u16(&mut self, address: usize, value: u16) {
        unsafe { mmio_write::<u16>(address, value) }
    }
    #[inline]
    fn write_u32(&mut self, address: usize, value: u32) {
        unsafe { mmio_write::<u32>(address, value) }
    }
    #[inline]
    fn write_u64(&mut self, address: usize, value: u64) {
        unsafe { mmio_write::<u64>(address, value) }
    }

    #[inline]
    fn read_io_u8(&self, port: u16) -> u8 {
        unsafe {
            let mut p = Port::<u8>::new(port);
            p.read()
        }
    }
    #[inline]
    fn read_io_u16(&self, port: u16) -> u16 {
        unsafe {
            let mut p = Port::<u16>::new(port);
            p.read()
        }
    }
    #[inline]
    fn read_io_u32(&self, port: u16) -> u32 {
        unsafe {
            let mut p = Port::<u32>::new(port);
            p.read()
        }
    }

    #[inline]
    fn write_io_u8(&self, port: u16, v: u8) {
        unsafe {
            let mut p = Port::<u8>::new(port);
            p.write(v)
        }
    }
    #[inline]
    fn write_io_u16(&self, port: u16, v: u16) {
        unsafe {
            let mut p = Port::<u16>::new(port);
            p.write(v)
        }
    }
    #[inline]
    fn write_io_u32(&self, port: u16, v: u32) {
        unsafe {
            let mut p = Port::<u32>::new(port);
            p.write(v)
        }
    }

    #[inline]
    fn read_pci_u32(&self, _seg: u16, bus: u8, dev: u8, func: u8, off: u16) -> u32 {
        let _g = PCI_CFG_LOCK.lock();
        let addr = pci_cfg_addr(bus, dev, func, off);
        unsafe {
            let mut cf8 = Port::<u32>::new(0xCF8);
            let mut cfc = Port::<u32>::new(0xCFC);
            cf8.write(addr);
            cfc.read()
        }
    }

    #[inline]
    fn read_pci_u16(&self, seg: u16, bus: u8, dev: u8, func: u8, off: u16) -> u16 {
        let d = self.read_pci_u32(seg, bus, dev, func, off & !3);
        let sh = (off & 2) * 8;
        ((d >> sh) & 0xFFFF) as u16
    }

    #[inline]
    fn read_pci_u8(&self, seg: u16, bus: u8, dev: u8, func: u8, off: u16) -> u8 {
        let d = self.read_pci_u32(seg, bus, dev, func, off & !3);
        let sh = (off & 3) * 8;
        ((d >> sh) & 0xFF) as u8
    }

    #[inline]
    fn write_pci_u32(&self, _seg: u16, bus: u8, dev: u8, func: u8, off: u16, val: u32) {
        let _g = PCI_CFG_LOCK.lock();
        let addr = pci_cfg_addr(bus, dev, func, off);
        unsafe {
            let mut cf8 = Port::<u32>::new(0xCF8);
            let mut cfc = Port::<u32>::new(0xCFC);
            cf8.write(addr);
            cfc.write(val);
        }
    }

    #[inline]
    fn write_pci_u16(&self, seg: u16, bus: u8, dev: u8, func: u8, off: u16, val: u16) {
        let mut d = self.read_pci_u32(seg, bus, dev, func, off & !3);
        let sh = (off & 2) * 8;
        let mask = !(0xFFFFu32 << sh);
        d = (d & mask) | ((val as u32) << sh);
        self.write_pci_u32(seg, bus, dev, func, off & !3, d);
    }

    #[inline]
    fn write_pci_u8(&self, seg: u16, bus: u8, dev: u8, func: u8, off: u16, val: u8) {
        let mut d = self.read_pci_u32(seg, bus, dev, func, off & !3);
        let sh = (off & 3) * 8;
        let mask = !(0xFFu32 << sh);
        d = (d & mask) | ((val as u32) << sh);
        self.write_pci_u32(seg, bus, dev, func, off & !3, d);
    }
}

fn sta_present(ctx: &mut AmlContext, dev: &AmlName) -> bool {
    let path = match AmlName::from_str(&(dev.as_string() + "._STA")) {
        Ok(p) => p,
        Err(_) => return true,
    };
    let val = match ctx.namespace.get_by_path(&path) {
        Ok(aml::AmlValue::Integer(x)) => *x as u32,
        Ok(aml::AmlValue::Method { .. }) => {
            match ctx.invoke_method(&path, aml::value::Args::EMPTY) {
                Ok(aml::AmlValue::Integer(x)) => x as u32,
                _ => 0x0F,
            }
        }
        _ => 0x0F,
    };
    (val & 0x1) != 0
}

pub fn read_ids(ctx: &mut AmlContext, dev: &AmlName) -> (Option<String>, Vec<String>) {
    use aml::AmlValue;

    fn read_obj(ctx: &mut AmlContext, p: &AmlName) -> Option<AmlValue> {
        match ctx.namespace.get_by_path(p) {
            Ok(AmlValue::Method { .. }) => ctx.invoke_method(p, aml::value::Args::EMPTY).ok(),
            Ok(v) => Some(v.clone()),
            Err(_) => None,
        }
    }

    let mut hid: Option<String> = None;
    if let Ok(hid_path) = AmlName::from_str(&(dev.as_string() + "._HID")) {
        if let Some(v) = read_obj(ctx, &hid_path) {
            match v {
                AmlValue::String(s) => hid = Some(format!("ACPI\\{}", s)),
                AmlValue::Integer(i) => hid = Some(format!("ACPI\\{}", pnp_id_from_u32(i as u32))),
                _ => {}
            }
        }
    }

    let mut cids: Vec<String> = Vec::new();
    if let Ok(cid_path) = AmlName::from_str(&(dev.as_string() + "._CID")) {
        if let Some(v) = read_obj(ctx, &cid_path) {
            match v {
                AmlValue::String(s) => cids.push(format!("ACPI\\{}", s)),
                AmlValue::Integer(i) => cids.push(format!("ACPI\\{}", pnp_id_from_u32(i as u32))),
                AmlValue::Package(pk) => {
                    for it in pk.iter() {
                        match it {
                            AmlValue::String(s) => cids.push(format!("ACPI\\{}", s.clone())),
                            AmlValue::Integer(i) => {
                                cids.push(format!("ACPI\\{}", pnp_id_from_u32(*i as u32)))
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
    }

    if let Some(h) = &hid {
        cids.retain(|x| x != h);
    }
    cids.sort_unstable();
    cids.dedup();
    (hid, cids)
}

const BUS_HIDS: &[&str] = &["ACPI\\PNP0A03", "ACPI\\PNP0A08"];

fn read_uid(ctx: &mut AmlContext, dev: &AmlName) -> Option<String> {
    let path = AmlName::from_str(&(dev.as_string() + "._UID")).ok()?;
    match ctx.namespace.get_by_path(&path).ok() {
        Some(aml::AmlValue::String(s)) => Some(s.to_string()),
        Some(aml::AmlValue::Integer(i)) => Some(format!("{}", i)),
        Some(aml::AmlValue::Method { .. }) => {
            match ctx.invoke_method(&path, aml::value::Args::EMPTY).ok()? {
                aml::AmlValue::String(s) => Some(s),
                aml::AmlValue::Integer(i) => Some(format!("{}", i)),
                _ => None,
            }
        }
        _ => None,
    }
}

pub fn create_pnp_bus_from_acpi(
    ctx_lock: &Arc<spin::RwLock<aml::AmlContext>>,
    parent_dev_node: &Arc<DevNode>,
    dev_name: AmlName,
) -> bool {
    let mut ctx = ctx_lock.write();
    if !sta_present(&mut ctx, &dev_name) {
        return false;
    }

    let (hid_opt, mut cids) = read_ids(&mut ctx, &dev_name);
    let Some(hid_raw) = hid_opt else {
        return false;
    };
    let hid = hid_raw.to_ascii_uppercase();

    let mut hardware_ids = alloc::vec::Vec::new();
    hardware_ids.push(hid.clone());

    for cid in cids.iter_mut() {
        *cid = cid.to_ascii_uppercase();
    }
    if !BUS_HIDS.contains(&hid.as_str()) && !cids.iter().any(|c| BUS_HIDS.contains(&c.as_str())) {
        return false;
    }

    let device_ids = DeviceIds {
        hardware: hardware_ids,
        compatible: cids,
    };

    let short_name = dev_name
        .as_string()
        .rsplit_once('.')
        .map_or(dev_name.as_string(), |(_, n)| n.to_string());

    let instance_path = if let Some(uid) = read_uid(&mut ctx, &dev_name) {
        alloc::format!("{}#{}", dev_name.as_string(), uid)
    } else {
        dev_name.as_string()
    };

    let mut vt = PnpVtable::new();
    vt.set(PnpMinorFunction::QueryResources, acpi_pdo_query_resources);
    vt.set(PnpMinorFunction::QueryId, acpi_pdo_query_id);
    vt.set(PnpMinorFunction::StartDevice, acpi_pdo_start);

    let mut init = DeviceInit::new(IoVtable::new(), Some(vt));
    let mut ext = AcpiPdoExt {
        acpi_path: dev_name.clone(),
        ctx: ctx_lock.clone(),
        ecam: alloc::vec::Vec::new(),
        prt: alloc::vec::Vec::new(),
    };

    // Compute ECAM coverage, then write into the dev-ext
    let seg = read_int_method(&mut ctx, &dev_name, "_SEG").unwrap_or(0) as u16;
    let bbn = read_int_method(&mut ctx, &dev_name, "_BBN").unwrap_or(0) as u8;
    let (sb, eb) = bus_range_from_crs(&mut ctx, &dev_name).unwrap_or((bbn, 0xFF));

    let tables = get_acpi_tables();
    let mut ecam = alloc::vec::Vec::new();
    if let Ok(map) = tables.find_table::<Mcfg>() {
        let raw = unsafe {
            core::slice::from_raw_parts(
                map.virtual_start().as_ptr() as *const u8,
                map.region_length(),
            )
        };
        for e in parse_mcfg(raw) {
            if e.seg == seg && !(e.eb < sb || e.sb > eb) {
                let csb = sb.max(e.sb);
                let ceb = eb.min(e.eb);
                ecam.push(McfgSeg {
                    base: e.base,
                    seg: e.seg,
                    sb: csb,
                    eb: ceb,
                });
            }
        }
    }
    ext.ecam = ecam;
    ext.prt = evaluate_prt(&mut ctx, &dev_name);
    init.set_dev_ext_from(ext);

    let (_dn, mut pdo) = pnp_create_child_devnode_and_pdo_with_init(
        parent_dev_node,
        short_name,
        instance_path,
        device_ids,
        None,
        init,
    );

    drop(ctx);
    true
}

pub fn pnp_id_from_u32(id: u32) -> String {
    let x = id.swap_bytes();

    let mut s = String::with_capacity(7);
    let a = ((x >> 26) & 0x1F) as u8;
    let b = ((x >> 21) & 0x1F) as u8;
    let c = ((x >> 16) & 0x1F) as u8;
    s.push((0x40 + a) as char);
    s.push((0x40 + b) as char);
    s.push((0x40 + c) as char);

    for shift in [12, 8, 4, 0] {
        let nib = ((x >> shift) & 0xF) as usize;
        s.push("0123456789ABCDEF".as_bytes()[nib] as char);
    }
    s
}

#[inline]
fn le32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn tlv(out: &mut Vec<u8>, kind: ResourceKind, payload: impl AsRef<[u8]>) {
    let p = payload.as_ref();
    le32(out, kind as u32);
    le32(out, p.len() as u32);
    out.extend_from_slice(p);
}

fn ser_mem_port(start: u64, length: u64, flags: u32) -> [u8; 20] {
    let mut buf = [0u8; 20];
    buf[0..8].copy_from_slice(&start.to_le_bytes());
    buf[8..16].copy_from_slice(&length.to_le_bytes());
    buf[16..20].copy_from_slice(&flags.to_le_bytes());
    buf
}

fn ser_irq(vector: u32, level: bool, sharable: bool) -> [u8; 12] {
    let mut buf = [0u8; 12];
    buf[0..4].copy_from_slice(&vector.to_le_bytes());
    buf[4..8].copy_from_slice(&(level as u32).to_le_bytes());
    buf[8..12].copy_from_slice(&(sharable as u32).to_le_bytes());
    buf
}

#[inline]
fn read_int_method(ctx: &mut AmlContext, dev: &AmlName, suffix: &str) -> Option<u64> {
    let p = AmlName::from_str(&(dev.as_string() + "." + suffix)).ok()?;
    match ctx.namespace.get_by_path(&p).ok()? {
        AmlValue::Integer(n) => Some(*n as u64),
        AmlValue::Method { .. } => match ctx.invoke_method(&p, Args::EMPTY).ok()? {
            AmlValue::Integer(n) => Some(n as u64),
            _ => None,
        },
        _ => None,
    }
}

#[inline]
fn append_ecam(out: &mut Vec<u8>, base: u64, seg: u16, sb: u8, eb: u8) {
    out.extend_from_slice(b"ECAM");
    out.extend_from_slice(&1u32.to_le_bytes()); // count
    out.extend_from_slice(&base.to_le_bytes());
    out.extend_from_slice(&seg.to_le_bytes());
    out.push(sb);
    out.push(eb);
}

fn irqs_from_crs(ctx: &mut AmlContext, link: &AmlName) -> Option<Vec<u32>> {
    let crs_path = AmlName::from_str(&(link.as_string() + "._CRS")).ok()?;
    let crs_val = match ctx.namespace.get_by_path(&crs_path) {
        Ok(AmlValue::Method { .. }) => ctx.invoke_method(&crs_path, Args::EMPTY).ok(),
        Ok(v) => Some(v.clone()),
        Err(_) => None,
    }?;

    let AmlValue::Buffer(buf) = crs_val else {
        return None;
    };

    let data = buf.lock();
    let mut bytes = data.as_slice();
    let mut irqs = Vec::new();

    while !bytes.is_empty() {
        let b0 = bytes[0];

        if (b0 & 0x80) != 0 {
            if bytes.len() < 3 {
                break;
            }
            let len = u16::from_le_bytes([bytes[1], bytes[2]]) as usize;
            if bytes.len() < 3 + len {
                break;
            }

            let body = &bytes[3..3 + len];
            let typ = b0 & 0x7F;

            if typ == 0x09 && body.len() >= 2 {
                let count = body[1] as usize;
                let mut off = 2;
                for _ in 0..count {
                    if off + 4 > body.len() {
                        break;
                    }
                    let irq = u32::from_le_bytes([
                        body[off],
                        body[off + 1],
                        body[off + 2],
                        body[off + 3],
                    ]);
                    irqs.push(irq);
                    off += 4;
                }
            }

            bytes = &bytes[3 + len..];
        } else {
            let typ = (b0 >> 3) & 0x0F;
            let len = (b0 & 0x07) as usize;
            if bytes.len() < 1 + len {
                break;
            }
            if typ == 0x0F {
                break;
            }

            let body = &bytes[1..1 + len];
            if typ == 0x04 && len >= 2 {
                let mask = u16::from_le_bytes([body[0], body[1]]);
                for bit in 0..16 {
                    if (mask & (1 << bit)) != 0 {
                        irqs.push(bit as u32);
                    }
                }
            }

            bytes = &bytes[1 + len..];
        }
    }

    Some(irqs)
}

/// A single PCI interrupt routing entry from _PRT.
#[derive(Clone, Copy, Debug)]
pub struct PrtEntry {
    pub device: u8,
    pub pin: u8,
    pub gsi: u16,
}

/// Evaluate the _PRT method for a PCI host bridge and return routing entries.
/// Hardwired GSIs (Source == 0) are used directly; link devices are resolved via their _CRS.
pub fn evaluate_prt(ctx: &mut AmlContext, dev: &AmlName) -> Vec<PrtEntry> {
    use aml::value::{AmlValue, Args};
    let mut out = Vec::new();

    let prt_path = match AmlName::from_str(&(dev.as_string() + "._PRT")) {
        Ok(p) => p,
        Err(_) => return out,
    };

    let val = match ctx.namespace.get_by_path(&prt_path) {
        Ok(AmlValue::Method { .. }) => match ctx.invoke_method(&prt_path, Args::EMPTY) {
            Ok(v) => v,
            Err(_) => return out,
        },
        Ok(AmlValue::Package(elems)) => AmlValue::Package(elems.clone()),
        _ => return out,
    };

    let AmlValue::Package(entries) = val else {
        return out;
    };

    for entry in entries.iter() {
        let AmlValue::Package(fields) = entry else {
            continue;
        };
        if fields.len() < 4 {
            continue;
        }

        // Field 0: Address - device in high word, 0xFFFF in low word
        let address = match &fields[0] {
            AmlValue::Integer(n) => *n,
            _ => continue,
        };
        let device = ((address >> 16) & 0xFF) as u8;

        // Field 1: Pin (0=INTA, 1=INTB, 2=INTC, 3=INTD)
        let pin = match &fields[1] {
            AmlValue::Integer(n) => *n as u8,
            _ => continue,
        };

        let source_index = match &fields[3] {
            AmlValue::Integer(n) => *n as usize,
            _ => continue,
        };

        // Field 2: Source - 0/"" means hardwired GSI, otherwise link device name
        let gsi = match &fields[2] {
            AmlValue::Integer(0) => u16::try_from(source_index).ok(),
            AmlValue::String(s) if s.is_empty() => u16::try_from(source_index).ok(),
            AmlValue::String(source) => {
                let link = AmlName::from_str(source).ok();
                let irqs = link
                    .as_ref()
                    .and_then(|l| irqs_from_crs(ctx, l))
                    .unwrap_or_default();
                irqs.get(source_index)
                    .and_then(|irq| u16::try_from(*irq).ok())
            }
            _ => None,
        };

        if let Some(gsi) = gsi {
            out.push(PrtEntry { device, pin, gsi });
        }
    }

    out
}

/// Serialize PRT entries into a blob section with magic "PIRT".
pub fn append_prt_list(out: &mut Vec<u8>, entries: &[PrtEntry]) {
    if entries.is_empty() {
        return;
    }
    out.extend_from_slice(b"PIRT");
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for e in entries {
        out.push(e.device);
        out.push(e.pin);
        out.extend_from_slice(&e.gsi.to_le_bytes());
    }
}

fn bus_range_from_crs(ctx: &mut AmlContext, dev: &AmlName) -> Option<(u8, u8)> {
    use aml::value::Args;
    let crs = AmlName::from_str(&(dev.as_string() + "._CRS")).ok()?;
    let aml::AmlValue::Buffer(b) = ctx.invoke_method(&crs, Args::EMPTY).ok()? else {
        return None;
    };
    let data = b.lock();
    let mut bytes = data.as_slice();
    let mut lo = None;
    let mut hi = None;

    while !bytes.is_empty() {
        let b0 = bytes[0];
        if (b0 & 0x80) != 0 {
            if bytes.len() < 3 {
                break;
            }
            let len = u16::from_le_bytes([bytes[1], bytes[2]]) as usize;
            if bytes.len() < 3 + len {
                break;
            }
            let body = &bytes[3..3 + len];
            let typ = b0 & 0x7F;

            if matches!(typ, 0x07 | 0x08 | 0x0A) {
                if body.len() >= 6 + 2 * 5 {
                    let res_ty = body[0];
                    let mut off = 3;
                    let mut rd = |n: usize| {
                        let mut t = [0u8; 8];
                        t[..n].copy_from_slice(&body[off..off + n]);
                        off += n;
                        u64::from_le_bytes(t)
                    };
                    let _gran = rd(2);
                    let min = rd(2);
                    let max = rd(2);
                    let tra = rd(2);
                    let lenv = rd(2);
                    if res_ty == 2 {
                        let sb = (min + tra) as u8;
                        let eb = if lenv == 0 {
                            max as u8
                        } else {
                            (min + tra + lenv - 1) as u8
                        };
                        lo = Some(sb);
                        hi = Some(eb);
                    }
                }
            }
            bytes = &bytes[3 + len..];
        } else {
            let len = (b0 & 0x07) as usize;
            if bytes.len() < 1 + len {
                break;
            }
            bytes = &bytes[1 + len..];
        }
    }
    Some((lo?, hi?))
}

fn parse_mcfg(raw: &[u8]) -> alloc::vec::Vec<McfgSeg> {
    let mut v = alloc::vec::Vec::new();
    if raw.len() < 44 {
        return v;
    }
    let mut off = 44;
    while off + 16 <= raw.len() {
        let base = u64::from_le_bytes(raw[off..off + 8].try_into().unwrap());
        let seg = u16::from_le_bytes(raw[off + 8..off + 10].try_into().unwrap());
        let sb = raw[off + 10];
        let eb = raw[off + 11];
        v.push(McfgSeg { base, seg, sb, eb });
        off += 16;
    }
    v
}

pub fn append_ecam_list(out: &mut Vec<u8>, segs: &[McfgSeg]) {
    out.extend_from_slice(b"ECAM");
    out.extend_from_slice(&(segs.len() as u32).to_le_bytes());
    for s in segs {
        out.extend_from_slice(&s.base.to_le_bytes());
        out.extend_from_slice(&s.seg.to_le_bytes());
        out.push(s.sb);
        out.push(s.eb);
    }
}

pub(crate) fn build_query_resources_blob(ctx: &mut AmlContext, dev: &AmlName) -> Option<Vec<u8>> {
    use aml::value::AmlValue;

    let crs_path = AmlName::from_str(&(dev.as_string() + "._CRS")).ok()?;
    let val = ctx.invoke_method(&crs_path, Args::EMPTY).ok()?;
    let buf = match val {
        AmlValue::Buffer(b) => b,
        _ => return None,
    };

    let data = buf.lock();
    let mut bytes = data.as_slice();
    let mut out = Vec::new();

    let mut bus_lo: Option<u8> = None;
    let mut bus_hi: Option<u8> = None;

    while !bytes.is_empty() {
        let b0 = bytes[0];

        if (b0 & 0x80) != 0 {
            if bytes.len() < 3 {
                break;
            }
            let len = u16::from_le_bytes([bytes[1], bytes[2]]) as usize;
            if bytes.len() < 3 + len {
                break;
            }

            let body = &bytes[3..3 + len];
            let typ = b0 & 0x7F;

            match typ {
                0x06 => {
                    if body.len() >= 9 {
                        let info = body[0];
                        let base = u32::from_le_bytes([body[1], body[2], body[3], body[4]]) as u64;
                        let length =
                            u32::from_le_bytes([body[5], body[6], body[7], body[8]]) as u64;
                        let mut flags = 0u32;
                        if (info & 0x1) != 0 {
                            flags |= 1;
                        }
                        tlv(
                            &mut out,
                            ResourceKind::Memory,
                            ser_mem_port(base, length, flags),
                        );
                    }
                }
                0x07 | 0x08 | 0x0A => {
                    let w = match typ {
                        0x08 => 2,
                        0x07 => 4,
                        _ => 8,
                    };
                    if body.len() >= 6 + w * 5 {
                        let res_type = body[0];
                        let general = body[1];
                        let mut off = 3;

                        let mut read_u = |n: usize| {
                            let mut tmp = [0u8; 8];
                            tmp[..n].copy_from_slice(&body[off..off + n]);
                            off += n;
                            u64::from_le_bytes(tmp)
                        };

                        let _gran = read_u(w);
                        let min = read_u(w);
                        let max = read_u(w);
                        let tra = read_u(w);
                        let lenv = read_u(w);

                        let start = min.wrapping_add(tra);
                        let mut flags = 0u32;
                        if (general & 0b10) != 0 {
                            flags |= 1 << 1;
                        }

                        match res_type {
                            0 => tlv(
                                &mut out,
                                ResourceKind::Memory,
                                ser_mem_port(start, lenv, flags),
                            ),
                            1 => tlv(
                                &mut out,
                                ResourceKind::Port,
                                ser_mem_port(start, lenv, flags),
                            ),
                            2 => {
                                let sb = start as u8;
                                let eb = if lenv == 0 {
                                    max as u8
                                } else {
                                    (start + lenv - 1) as u8
                                };
                                bus_lo = Some(sb);
                                bus_hi = Some(eb);
                            }
                            _ => {}
                        }
                    }
                }
                0x09 => {
                    if body.len() >= 2 + 4 {
                        let flags = body[0];
                        let count = body[1] as usize;
                        if count >= 1 && body.len() >= 2 + 4 * count {
                            let vec0 = u32::from_le_bytes([body[2], body[3], body[4], body[5]]);
                            let level = (flags & (1 << 1)) == 0;
                            let sharable = (flags & (1 << 3)) != 0;
                            tlv(
                                &mut out,
                                ResourceKind::Interrupt,
                                ser_irq(vec0, level, sharable),
                            );
                        }
                    }
                }
                _ => {}
            }

            bytes = &bytes[3 + len..];
        } else {
            let typ = (b0 >> 3) & 0x0F;
            let len = (b0 & 0x07) as usize;
            if bytes.len() < 1 + len {
                break;
            }
            let body = &bytes[1..1 + len];

            match typ {
                0x04 => {
                    if len >= 2 {
                        let mask = u16::from_le_bytes([body[0], body[1]]);
                        if mask != 0 {
                            let info = if len >= 3 { Some(body[2]) } else { None };
                            let vector = mask.trailing_zeros().min(15) as u32;
                            let level = info.map(|i| (i & 0x01) == 0).unwrap_or(false);
                            let sharable = info.map(|i| (i & (1 << 4)) != 0).unwrap_or(false);
                            tlv(
                                &mut out,
                                ResourceKind::Interrupt,
                                ser_irq(vector, level, sharable),
                            );
                        }
                    }
                }
                0x08 => {
                    if len >= 7 {
                        let decodes_full = (body[0] & 1) != 0;
                        let min = u16::from_le_bytes([body[1], body[2]]) as u64;
                        let _max = u16::from_le_bytes([body[3], body[4]]) as u64;
                        let _aln = body[5];
                        let rng_len = body[6] as u64;
                        let mut flags = 0u32;
                        if decodes_full {
                            flags |= 1;
                        }
                        tlv(
                            &mut out,
                            ResourceKind::Port,
                            ser_mem_port(min, rng_len, flags),
                        );
                    }
                }
                // EndTag
                0x0F => break,
                _ => {}
            }

            bytes = &bytes[1 + len..];
        }
    }

    let seg = read_int_method(ctx, dev, "_SEG").unwrap_or(0) as u16;
    let bbn = read_int_method(ctx, dev, "_BBN").unwrap_or(0) as u8;
    let base = read_int_method(ctx, dev, "_CBA");

    if let Some(cba) = base {
        let (sb, eb) = match (bus_lo, bus_hi) {
            (Some(lo), Some(hi)) => (lo, hi),
            _ => (bbn, 0xFF),
        };
        append_ecam(&mut out, cba, seg, sb, eb);
    }

    Some(out)
}

#[request_handler]
pub async fn acpi_pdo_query_resources(
    dev: Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
) -> DriverStep {
    let pext: &AcpiPdoExt = &dev.try_devext().expect("Failed to get devext");

    let ctx_lock = &pext.ctx;

    let mut guard = ctx_lock.write();
    let mut blob = build_query_resources_blob(&mut *guard, &pext.acpi_path).unwrap_or_default();
    drop(guard);

    if !pext.ecam.is_empty() {
        append_ecam_list(&mut blob, &pext.ecam);
    }

    if !pext.prt.is_empty() {
        append_prt_list(&mut blob, &pext.prt);
    }

    let mut w = req.write();
    if let Some(p) = w.pnp.as_mut() {
        p.blob_out = blob;
    }
    DriverStep::complete(DriverStatus::Success)
}

#[request_handler]
pub async fn acpi_pdo_query_id(dev: Arc<DeviceObject>, req: Arc<RwLock<Request>>) -> DriverStep {
    let pext: &AcpiPdoExt = &dev.try_devext().expect("Failed to get devext");

    let ty = { req.read().pnp.as_ref().unwrap().id_type };

    let ctx_lock = &pext.ctx;
    let mut guard = ctx_lock.write();
    let (hid_opt, mut cids) = read_ids(&mut *guard, &pext.acpi_path);
    drop(guard);

    let mut w = req.write();
    let p = w.pnp.as_mut().unwrap();

    match ty {
        QueryIdType::HardwareIds => {
            if let Some(h) = hid_opt {
                p.ids_out.push(h);
            }
        }
        QueryIdType::CompatibleIds => {
            p.ids_out.append(&mut cids);
        }
        QueryIdType::DeviceId => {
            if let Some(h) = hid_opt {
                p.ids_out.push(h);
            } else {
                w.status = DriverStatus::NoSuchDevice;
                return DriverStep::complete(DriverStatus::NoSuchDevice);
            }
        }
        QueryIdType::InstanceId => {
            if let Some(dn) = dev.dev_node.get().unwrap().upgrade() {
                p.ids_out.push(dn.instance_path.clone());
            } else {
                w.status = DriverStatus::NoSuchDevice;
                return DriverStep::complete(DriverStatus::NoSuchDevice);
            }
        }
    }

    DriverStep::complete(DriverStatus::Success)
}

#[request_handler]
pub async fn acpi_pdo_start(_dev: Arc<DeviceObject>, req: Arc<RwLock<Request>>) -> DriverStep {
    DriverStep::complete(DriverStatus::Success)
}
