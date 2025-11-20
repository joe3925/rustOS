#![no_std]
#![no_main]
#![feature(const_option_ops)]
#![feature(const_trait_impl)]
extern crate alloc;

mod dev_ext;
mod msvc_shims;

use alloc::sync::Weak;
use alloc::vec;
use alloc::{
    boxed::Box,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use core::{mem::size_of, panic::PanicInfo};
use kernel_api::alloc_api::{IoType, IoVtable, PnpVtable, Synchronization};
use kernel_api::{DiskInfo, PnpMinorFunction, QueryIdType};
use spin::Mutex;
use spin::rwlock::RwLock;

use dev_ext::{DevExt, Ports};
use kernel_api::{
    DeviceObject, DeviceRelationType, DriverObject, DriverStatus, KernelAllocator, Request,
    RequestType, ResourceKind,
    alloc_api::{
        DeviceIds, DeviceInit, PnpRequest,
        ffi::{
            InvalidateDeviceRelations, driver_set_evt_device_add, pnp_complete_request,
            pnp_create_child_devnode_and_pdo_with_init, pnp_forward_request_to_next_lower,
        },
    },
    ffi::wait_ms,
    println,
    x86_64::instructions::port::Port,
};
static MOD_NAME: &str = option_env!("CARGO_PKG_NAME").unwrap_or(module_path!());

#[global_allocator]
static ALLOCATOR: KernelAllocator = KernelAllocator;

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    use kernel_api::alloc_api::ffi::panic_common;

    unsafe { panic_common(MOD_NAME, info) }
}

const IOCTL_BLOCK_QUERY: u32 = 0xB000_0001;
const IOCTL_BLOCK_RW: u32 = 0xB000_0002;
const IOCTL_BLOCK_FLUSH: u32 = 0xB000_0003;

const BLOCK_RW_READ: u32 = 0;
const BLOCK_RW_WRITE: u32 = 1;

const FEAT_FLUSH: u64 = 1 << 0;

#[repr(C)]
pub struct BlockQueryOut {
    pub block_size: u32,
    pub max_blocks: u32,
    pub alignment_mask: u32,
    pub features: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BlockRwIn {
    pub op: u32,
    pub _rsvd: u32,
    pub lba: u64,
    pub blocks: u32,
    pub buf_off: u32,
}

const ATA_CMD_IDENTIFY: u8 = 0xEC;
const ATA_CMD_READ_SECTORS: u8 = 0x20;
const ATA_CMD_WRITE_SECTORS: u8 = 0x30;
const ATA_CMD_FLUSH_CACHE: u8 = 0xE7;

const ATA_SR_BSY: u8 = 1 << 7;
const ATA_SR_DRDY: u8 = 1 << 6;
const ATA_SR_DRQ: u8 = 1 << 3;
const ATA_SR_ERR: u8 = 1 << 0;

const TIMEOUT_MS: u64 = 1000;
pub static LOCK: Mutex<u64> = Mutex::new(0);

#[repr(C)]
pub struct ChildExt {
    pub parent_device: Weak<DeviceObject>,
    pub dh: AtomicU8,
    pub present: AtomicBool,
    pub disk_info: Option<Arc<DiskInfo>>,
}

#[unsafe(no_mangle)]
pub extern "win64" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    unsafe { driver_set_evt_device_add(driver, ide_device_add) };
    DriverStatus::Success
}

pub extern "win64" fn ide_device_add(
    _driver: &Arc<DriverObject>,
    dev_init: &mut DeviceInit,
) -> DriverStatus {
    let mut vt = PnpVtable::new();
    vt.set(PnpMinorFunction::StartDevice, ide_pnp_start);
    vt.set(
        PnpMinorFunction::QueryDeviceRelations,
        ide_pnp_query_devrels,
    );

    let init = DeviceInit::new(IoVtable::new(), Some(vt));
    *dev_init = init;
    dev_init.set_dev_ext_from(DevExt::new(0x1F0, 0x3F4));

    DriverStatus::Success
}

extern "win64" fn ide_pnp_start(
    dev: &Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
) -> DriverStatus {
    let _guard = LOCK.lock();

    let mut child = Request::new_pnp(
        PnpRequest {
            minor_function: PnpMinorFunction::QueryResources,
            relation: DeviceRelationType::TargetDeviceRelation,
            id_type: QueryIdType::CompatibleIds,
            ids_out: Vec::new(),
            blob_out: Vec::new(),
        },
        Box::new([]),
    );
    let child = Arc::new(RwLock::new(child));
    let st = unsafe { pnp_forward_request_to_next_lower(dev, child.clone()) };
    if st != DriverStatus::NoSuchDevice {
        unsafe { kernel_api::alloc_api::ffi::pnp_wait_for_request(&child) };
        let qst = { child.read().status };
        if qst != DriverStatus::Success {
            return qst;
        }

        let bars = {
            let g = child.read();
            parse_ide_bars(&g.pnp.as_ref().unwrap().blob_out)
        };

        let dx = dev.try_devext::<DevExt>().expect("ide: FDO DevExt missing");

        let cb = bars.cmd as u16;
        let ctl = bars.ctl as u16;
        let alt = ctl.wrapping_add(2);

        {
            let mut p = dx.ports.lock();
            *p = Ports::new(cb, alt);
            unsafe { p.control.write(0u8) };
        }

        dx.present.store(true, Ordering::Release);
        dx.enumerated.store(false, Ordering::Release);
    } else {
        let dx = dev.try_devext::<DevExt>().expect("ide: FDO DevExt missing");
        dx.present.store(true, Ordering::Release);
        dx.enumerated.store(false, Ordering::Release);
    }

    DriverStatus::Continue
}

extern "win64" fn ide_pnp_query_devrels(
    dev: &Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
) -> DriverStatus {
    let relation = { req.read().pnp.as_ref().unwrap().relation };
    if relation == DeviceRelationType::BusRelations {
        ide_enumerate_bus(dev);
        // We are the only ones to enum this bus, prevent lower drivers from adding new drives
        return DriverStatus::Success;
    }
    DriverStatus::Continue
}

fn ide_enumerate_bus(parent: &Arc<DeviceObject>) {
    let dx = parent
        .try_devext::<DevExt>()
        .expect("ide: FDO DevExt missing");
    if dx.enumerated.load(Ordering::Acquire) || !dx.present.load(Ordering::Acquire) {
        return;
    }

    if ata_probe_drive(&dx, 0xE0) {
        create_child_pdo(parent, 0, 0);
    }
    if ata_probe_drive(&dx, 0xF0) {
        create_child_pdo(parent, 0, 1);
    }

    dx.enumerated.store(true, Ordering::Release);
}

fn create_child_pdo(parent: &Arc<DeviceObject>, channel: u8, drive: u8) {
    let dx = parent
        .try_devext::<DevExt>()
        .expect("ide: FDO DevExt missing");

    let dh = if drive == 0 { 0xE0 } else { 0xF0 };
    let id_words_opt = ata_identify_words(&dx, dh);

    let (hardware, compatible) = if let Some(words) = id_words_opt {
        let model = id_string(&words[27..=46]);
        let fw = id_string(&words[23..=26]);
        let mut hw = vec![];
        if !model.is_empty() && !fw.is_empty() {
            hw.push(alloc::format!("IDE\\Disk{model}_{fw}"));
        } else if !model.is_empty() {
            hw.push(alloc::format!("IDE\\Disk{model}"));
        }
        hw.push(alloc::format!("IDE\\Disk&DRV_{:02}", drive));
        (hw, vec!["IDE\\Disk".into(), "GenDisk".into()])
    } else {
        (
            vec![alloc::format!("IDE\\Disk&DRV_{:02}", drive)],
            vec!["IDE\\Disk".into(), "GenDisk".into()],
        )
    };

    let class = Some("disk".to_string());

    let parent_dn = parent.dev_node.get().unwrap().upgrade().unwrap();

    let ids = DeviceIds {
        hardware,
        compatible,
    };

    let mut io_vtable = IoVtable::new();
    io_vtable.set(
        IoType::DeviceControl(ide_pdo_internal_ioctl),
        Synchronization::Sync,
        0,
    );

    let mut pvt = PnpVtable::new();
    pvt.set(PnpMinorFunction::QueryId, ide_pdo_query_id);
    pvt.set(PnpMinorFunction::QueryResources, ide_pdo_query_resources);
    pvt.set(PnpMinorFunction::StartDevice, ide_pdo_start);

    let mut child_init = DeviceInit::new(io_vtable, Some(pvt));
    child_init.set_dev_ext_from(ChildExt {
        parent_device: Arc::downgrade(parent),
        dh: AtomicU8::new(dh),
        present: AtomicBool::new(true),
        disk_info: if let Some(words) = id_words_opt {
            Some(Arc::new(disk_info_from_identify(&words)))
        } else {
            Some(Arc::new(DiskInfo {
                logical_block_size: 512,
                physical_block_size: 0,
                total_logical_blocks: 0,
                total_bytes_low: 0,
                total_bytes_high: 0,
            }))
        },
    });

    let short_name = alloc::format!("IDE_Disk_{}_{}", channel, drive);
    let instance = alloc::format!("IDE\\DRV_{:02}", drive);

    let (_dn, pdo) = unsafe {
        pnp_create_child_devnode_and_pdo_with_init(
            &parent_dn, short_name, instance, ids, class, child_init,
        )
    };

    let _cdx = pdo
        .try_devext::<ChildExt>()
        .expect("ide: PDO ChildExt missing");
}

pub extern "win64" fn ide_pdo_internal_ioctl(
    pdo: &Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
) -> DriverStatus {
    let _guard = LOCK.lock();

    let cdx = pdo
        .try_devext::<ChildExt>()
        .expect("ide: PDO ChildExt missing");

    if !cdx.present.load(Ordering::Acquire) {
        return DriverStatus::NoSuchDevice;
    }

    let parent: Arc<DeviceObject> = cdx.parent_device.upgrade().expect("parent device gone");

    let dx = parent
        .try_devext::<DevExt>()
        .expect("No parent IDE dev ext");

    // OPTIMIZATION: Use read lock to get the code
    let code = {
        let r = req.read();
        match r.kind {
            RequestType::DeviceControl(c) => c,
            _ => return DriverStatus::InvalidParameter,
        }
    };

    match code {
        IOCTL_BLOCK_QUERY => {
            let mut w = req.write();
            if w.data.len() < size_of::<BlockQueryOut>() {
                return DriverStatus::InsufficientResources;
            }
            let out = unsafe { &mut *(w.data.as_mut_ptr() as *mut BlockQueryOut) };
            out.block_size = 512;
            out.max_blocks = 256;
            out.alignment_mask = 0;
            out.features = FEAT_FLUSH;
            DriverStatus::Success
        }

        IOCTL_BLOCK_RW => {
            let (hdr, need, off) = {
                let r = req.read();
                if r.data.len() < size_of::<BlockRwIn>() {
                    return DriverStatus::InvalidParameter;
                }
                let hdr = unsafe { *(r.data.as_ptr() as *const BlockRwIn) };
                let need = (hdr.blocks as usize) * 512;
                let off = hdr.buf_off as usize;

                let bounds_check = off
                    .checked_add(need)
                    .map(|e| e <= r.data.len())
                    .unwrap_or(false);

                if hdr.blocks == 0 || !bounds_check || (hdr.lba >> 28) != 0 {
                    return DriverStatus::InvalidParameter;
                }
                (hdr, need, off)
            };

            let mut w = req.write();
            let ok = match hdr.op {
                BLOCK_RW_READ => ata_pio_read(
                    &dx,
                    cdx.dh.load(Ordering::Acquire),
                    hdr.lba as u32,
                    hdr.blocks as u32,
                    &mut w.data[off..off + need],
                ),
                BLOCK_RW_WRITE => ata_pio_write(
                    &dx,
                    cdx.dh.load(Ordering::Acquire),
                    hdr.lba as u32,
                    hdr.blocks as u32,
                    &w.data[off..off + need],
                ),
                _ => return DriverStatus::InvalidParameter,
            };

            if ok {
                DriverStatus::Success
            } else {
                DriverStatus::Unsuccessful
            }
        }

        IOCTL_BLOCK_FLUSH => {
            {
                let mut p = dx.ports.lock();
                unsafe { p.command.write(ATA_CMD_FLUSH_CACHE) };
            }

            let ok = {
                let mut p = dx.ports.lock();
                wait_not_busy(&mut p.control, TIMEOUT_MS)
            };

            if ok {
                DriverStatus::Success
            } else {
                DriverStatus::Unsuccessful
            }
        }

        _ => DriverStatus::NotImplemented,
    }
}
#[derive(Default, Clone, Copy)]
struct IdeBars {
    cmd: u16,
    ctl: u16,
    bm: u16,
}

fn parse_ide_bars(blob: &[u8]) -> IdeBars {
    let mut bars = IdeBars::default();

    if blob.len() < 12 || &blob[0..4] != b"RSRC" {
        bars.cmd = 0x1F0;
        bars.ctl = 0x3F4;
        return bars;
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
        let len = u64::from_le_bytes([
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

        if kind != ResourceKind::Port as u32 {
            continue;
        }

        match index {
            0 => bars.cmd = start as u16,
            1 => bars.ctl = start as u16,
            4 => bars.bm = start as u16,
            _ => {
                let l = len as u16;
                if bars.cmd == 0 && (l == 8 || l == 16) {
                    bars.cmd = start as u16;
                } else if bars.ctl == 0 && (l == 4 || l == 2) {
                    bars.ctl = start as u16;
                } else if bars.bm == 0 && (l == 0x10 || l == 0x08) {
                    bars.bm = start as u16;
                }
            }
        }
    }

    if bars.cmd == 0 {
        bars.cmd = 0x1F0;
    }
    if bars.ctl == 0 {
        bars.ctl = match bars.cmd {
            0x1F0 => 0x3F4,
            0x170 => 0x374,
            v => v.wrapping_add(2),
        };
    }

    bars
}

fn id_string(words: &[u16]) -> String {
    let mut bytes: Vec<u8> = Vec::with_capacity(words.len() * 2);
    for &w in words {
        bytes.push((w >> 8) as u8);
        bytes.push((w & 0xFF) as u8);
    }
    let s = core::str::from_utf8(&bytes)
        .unwrap_or("")
        .trim_matches(|c| c == '\0' || c == ' ');
    let mut out = String::with_capacity(s.len());
    let mut last_ws = false;
    for ch in s.chars() {
        let ws = ch.is_ascii_whitespace();
        if ws {
            if !last_ws {
                out.push('_');
            }
        } else if ch.is_ascii_graphic() {
            out.push(ch);
        }
        last_ws = ws;
    }
    while out.starts_with('_') {
        out.remove(0);
    }
    while out.ends_with('_') {
        out.pop();
    }
    out
}

fn ata_identify_words(dx: &DevExt, dh: u8) -> Option<[u16; 256]> {
    let _guard = LOCK.lock();
    {
        let mut p = dx.ports.lock();
        unsafe { p.drive_head.write(dh) };
        io_wait_400ns(&mut p.control);
        unsafe { p.command.write(ATA_CMD_IDENTIFY) };
        let st: u8 = unsafe { p.command.read() };
        if st == 0 || (st & ATA_SR_ERR) != 0 {
            return None;
        }

        let mut words = [0u16; 256];
        for i in 0..256 {
            words[i] = unsafe { p.data.read() };
        }
        return Some(words);
    }
}

fn ata_probe_drive(dx: &DevExt, dh: u8) -> bool {
    ata_identify_words(dx, dh).is_some()
}

fn ata_pio_read(dx: &DevExt, dh: u8, mut lba: u32, mut sectors: u32, out: &mut [u8]) -> bool {
    let mut off = 0usize;
    while sectors > 0 {
        let chunk = core::cmp::min(sectors, 256);
        let sc = if chunk == 256 { 0u8 } else { chunk as u8 };

        {
            let mut p = dx.ports.lock();
            if !wait_ready(&mut p.command, TIMEOUT_MS) {
                return false;
            }
            let devsel = 0xE0 | (dh & 0x10) | ((lba >> 24) as u8 & 0x0F);
            unsafe { p.drive_head.write(devsel) };
            io_wait_400ns(&mut p.control);
            if !wait_ready(&mut p.command, TIMEOUT_MS) {
                return false;
            }
            unsafe {
                p.sector_count.write(sc);
                p.lba_lo.write((lba & 0xFF) as u8);
                p.lba_mid.write(((lba >> 8) & 0xFF) as u8);
                p.lba_hi.write(((lba >> 16) & 0xFF) as u8);
                p.command.write(ATA_CMD_READ_SECTORS);
            }

            for _ in 0..chunk {
                if !wait_drq_set(&mut p.command, TIMEOUT_MS) {
                    return false;
                }
                if off + 512 > out.len() {
                    return false;
                }
                for _ in 0..256 {
                    let w: u16 = unsafe { p.data.read() };
                    out[off] = (w & 0xFF) as u8;
                    out[off + 1] = (w >> 8) as u8;
                    off += 2;
                }
                let _ = unsafe { p.command.read() };
            }
        }

        lba = lba.wrapping_add(chunk);
        sectors -= chunk;
    }
    true
}

fn ata_pio_write(dx: &DevExt, dh: u8, mut lba: u32, mut sectors: u32, data: &[u8]) -> bool {
    let mut off = 0usize;
    while sectors > 0 {
        let chunk = core::cmp::min(sectors, 256);
        let sc = if chunk == 256 { 0u8 } else { chunk as u8 };

        {
            let mut p = dx.ports.lock();
            unsafe { p.drive_head.write((dh & 0xF0) | ((lba >> 24) as u8 & 0x0F)) };
            io_wait_400ns(&mut p.command);
            if !wait_ready(&mut p.command, TIMEOUT_MS) {
                return false;
            }

            unsafe {
                p.sector_count.write(sc);
                p.lba_lo.write((lba & 0xFF) as u8);
                p.lba_mid.write(((lba >> 8) & 0xFF) as u8);
                p.lba_hi.write(((lba >> 16) & 0xFF) as u8);
                p.command.write(ATA_CMD_WRITE_SECTORS);
            }

            for _ in 0..chunk {
                if !wait_drq_set(&mut p.command, TIMEOUT_MS) {
                    return false;
                }
                for _ in 0..256 {
                    let lo = data[off] as u16;
                    let hi = data[off + 1] as u16;
                    unsafe { p.data.write(lo | (hi << 8)) };
                    off += 2;
                }
            }
        }

        lba = lba.wrapping_add(chunk);
        sectors -= chunk;
    }

    {
        let mut p = dx.ports.lock();
        unsafe { p.command.write(ATA_CMD_FLUSH_CACHE) };
        wait_not_busy(&mut p.control, TIMEOUT_MS)
    }
}

fn disk_info_from_identify(words: &[u16; 256]) -> DiskInfo {
    let lba48: u64 = ((words[103] as u64) << 48)
        | ((words[102] as u64) << 32)
        | ((words[101] as u64) << 16)
        | (words[100] as u64);
    let lba28: u64 = ((words[61] as u64) << 16) | (words[60] as u64);
    let total_lbas = if lba48 != 0 { lba48 } else { lba28 };
    let logical = 512u32;
    let total_bytes = total_lbas.saturating_mul(logical as u64);

    DiskInfo {
        logical_block_size: logical,
        physical_block_size: 0,
        total_logical_blocks: total_lbas,
        total_bytes_low: total_bytes,
        total_bytes_high: 0,
    }
}

fn io_wait_400ns(alt: &mut Port<u8>) {
    unsafe {
        let _ = alt.read();
        let _ = alt.read();
        let _ = alt.read();
        let _ = alt.read();
    }
}

fn wait_not_busy(st: &mut Port<u8>, timeout_ms: u64) -> bool {
    for _ in 0..timeout_ms {
        let s = unsafe { st.read() };
        if (s & ATA_SR_BSY) == 0 {
            return true;
        }
        unsafe { wait_ms(1) };
    }
    false
}

fn wait_ready(st: &mut Port<u8>, timeout_ms: u64) -> bool {
    for _ in 0..timeout_ms {
        let s = unsafe { st.read() };
        if (s & ATA_SR_BSY) == 0 && (s & ATA_SR_DRDY) != 0 {
            return true;
        }
        unsafe { wait_ms(1) };
    }
    false
}

fn wait_drq_set(st: &mut Port<u8>, timeout_ms: u64) -> bool {
    for _ in 0..timeout_ms {
        let s = unsafe { st.read() };
        if (s & ATA_SR_BSY) != 0 {
            unsafe { wait_ms(1) };
            continue;
        }
        if (s & ATA_SR_ERR) != 0 {
            return false;
        }
        if (s & ATA_SR_DRQ) != 0 {
            return true;
        }
        unsafe { wait_ms(1) };
    }
    false
}

extern "win64" fn ide_pdo_query_id(
    pdo: &Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
) -> DriverStatus {
    use QueryIdType::*;
    let ty = { req.read().pnp.as_ref().unwrap().id_type };
    let mut w = req.write();
    let p = w.pnp.as_mut().unwrap();
    match ty {
        HardwareIds => {
            p.ids_out.push("IDE\\Disk".into());
            p.ids_out.push("GenDisk".into());
        }
        CompatibleIds => {
            p.ids_out.push("IDE\\Disk".into());
            p.ids_out.push("GenDisk".into());
        }
        DeviceId => {
            p.ids_out.push("IDE\\Disk".into());
        }
        InstanceId => {
            p.ids_out.push(
                pdo.dev_node
                    .get()
                    .unwrap()
                    .upgrade()
                    .unwrap()
                    .instance_path
                    .clone(),
            );
        }
    }
    DriverStatus::Success
}

extern "win64" fn ide_pdo_query_resources(
    pdo: &Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
) -> DriverStatus {
    let cdx = match pdo.try_devext::<ChildExt>() {
        Ok(x) => x,
        Err(_) => {
            return DriverStatus::NoSuchDevice;
        }
    };

    let mut w = req.write();
    let Some(p) = w.pnp.as_mut() else {
        return DriverStatus::InvalidParameter;
    };

    let Some(di) = cdx.disk_info.as_ref() else {
        return DriverStatus::DeviceNotReady;
    };
    let di_ptr = di.as_ref() as *const DiskInfo as *const u8;
    let n = core::mem::size_of::<DiskInfo>();
    let bytes = unsafe { core::slice::from_raw_parts(di_ptr, n) };
    p.blob_out = bytes.to_vec();

    DriverStatus::Success
}

extern "win64" fn ide_pdo_start(
    _pdo: &Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
) -> DriverStatus {
    DriverStatus::Success
}
