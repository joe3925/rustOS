use crate::alloc::format;
use crate::alloc::vec;
use crate::pdo::AcpiPdoExt;
use crate::pdo::acpi_pdo_pnp_dispatch;
use alloc::{
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use aml::Handler;
use aml::resource::AddressSpaceDescriptor;

use crate::aml::acpi::address::AddressSpace as AmlAddressSpace;
use aml::resource::{Resource as AmlResource, Resource};
use aml::{AmlContext, AmlName, AmlValue};
use core::ptr::{read_volatile, write_volatile};
use kernel_api::ResourceKind;
use kernel_api::{
    DevNode, DeviceObject, acpi, ffi, println,
    x86_64::{PhysAddr, VirtAddr, instructions::port::Port},
};
use spin::Mutex;
use spin::RwLock;
pub const PAGE_SIZE: usize = 4096;

pub struct KernelAmlHandler;

#[inline]
fn round_up(n: usize, align: usize) -> usize {
    (n + align - 1) & !(align - 1)
}

#[inline]
unsafe fn map_phys_window(paddr: usize, bytes: usize) -> (VirtAddr, usize, usize) {
    let off = paddr & (PAGE_SIZE - 1);
    let base = paddr - off;
    let size = round_up(off + bytes, PAGE_SIZE);
    let va = unsafe {
        ffi::map_mmio_region(PhysAddr::new(base as u64), size as u64).unwrap_or_else(|e| {
            kernel_api::println!("[ACPI] map_phys_window failed: {:?}", e);
            core::intrinsics::abort();
        })
    };
    (va, off, size)
}

#[inline]
unsafe fn unmap_phys_window(va: VirtAddr, size: usize) {
    unsafe { ffi::unmap_range(va, size as u64) };
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
    ctx_lock: &spin::RwLock<aml::AmlContext>,
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
    hardware_ids.push(alloc::format!("ACPI\\{}", hid));

    for cid in cids.iter_mut() {
        *cid = cid.to_ascii_uppercase();
    }
    if !BUS_HIDS.contains(&hid.as_str()) && !cids.iter().any(|c| BUS_HIDS.contains(&c.as_str())) {
        return false;
    }

    let device_ids = kernel_api::alloc_api::DeviceIds {
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
    let init = kernel_api::alloc_api::DeviceInit {
        dev_ext_size: core::mem::size_of::<AcpiPdoExt>(),
        io_read: None,
        io_write: None,
        io_device_control: None,
        evt_device_prepare_hardware: None,
        evt_bus_enumerate_devices: None,
        evt_pnp: Some(acpi_pdo_pnp_dispatch),
    };

    let (_dn, pdo) = unsafe {
        kernel_api::alloc_api::ffi::pnp_create_child_devnode_and_pdo_with_init(
            parent_dev_node,
            short_name,
            instance_path,
            device_ids,
            None,
            init,
        )
    };

    let pext: &mut AcpiPdoExt = unsafe { &mut *((&*pdo.dev_ext).as_ptr() as *mut AcpiPdoExt) };
    pext.acpi_path = dev_name;
    drop(ctx);
    pext.ctx = ctx_lock;
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

pub(crate) fn build_query_resources_blob(ctx: &mut AmlContext, dev: &AmlName) -> Option<Vec<u8>> {
    use aml::value::AmlValue;
    let crs_path = AmlName::from_str(&(dev.as_string() + "._CRS")).ok()?;
    let val = ctx.invoke_method(&crs_path, aml::value::Args::EMPTY).ok()?;
    let buf = match val {
        AmlValue::Buffer(b) => b,
        _ => return None,
    };

    let data = buf.lock();
    let mut bytes = data.as_slice();
    let mut out = Vec::new();

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
                        let _max = read_u(w);
                        let tra = read_u(w);
                        let lenv = read_u(w);

                        let start = min + tra;
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
                            let level = match info {
                                Some(i) => (i & 0x01) == 0,
                                None => false,
                            };
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
                0x0F => break,
                _ => {}
            }

            bytes = &bytes[1 + len..];
        }
    }

    Some(out)
}
