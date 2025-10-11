#![no_std]
#![no_main]

extern crate alloc;

mod dev_ext;
mod msvc_shims;

use alloc::vec;
use alloc::{
    boxed::Box,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::{mem::size_of, panic::PanicInfo};
use kernel_api::alloc_api::{IoType, IoVtable, PnpVtable, Synchronization};
use kernel_api::{PnpMinorFunction, QueryIdType};
use spin::{Mutex, RwLock};

use dev_ext::DevExt;
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

#[global_allocator]
static ALLOCATOR: KernelAllocator = KernelAllocator;

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("{}", info);
    loop {}
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
struct ChildExt {
    parent_dx: *mut DevExt,
    dh: u8,
    present: bool,
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
    dev_init.dev_ext_size = core::mem::size_of::<DevExt>();

    let mut vt = PnpVtable::new();
    vt.set(PnpMinorFunction::StartDevice, ide_pnp_start);
    vt.set(
        PnpMinorFunction::QueryDeviceRelations,
        ide_pnp_query_devrels,
    );
    dev_init.pnp_vtable = Some(vt);
    DriverStatus::Success
}

extern "win64" fn ide_pnp_start(
    dev: &Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
) -> DriverStatus {
    let guard = LOCK.lock();
    // sync QueryResources to parent/lower
    let mut child = Request::new(RequestType::Pnp, Box::new([]));
    child.pnp = Some(PnpRequest {
        minor_function: PnpMinorFunction::QueryResources,
        relation: DeviceRelationType::TargetDeviceRelation,
        id_type: QueryIdType::CompatibleIds,
        ids_out: Vec::new(),
        blob_out: Vec::new(),
    });
    let child = Arc::new(RwLock::new(child));
    let st = unsafe { pnp_forward_request_to_next_lower(dev, child.clone()) };
    if st != DriverStatus::NoSuchDevice {
        unsafe { kernel_api::alloc_api::ffi::pnp_wait_for_request(&child) };
        let qst = { child.read().status };
        if qst != DriverStatus::Success {
            let mut pg = req.write();
            pg.status = qst;
            unsafe { pnp_complete_request(&mut *pg) };
            return DriverStatus::Success;
        }
        let bars = {
            let g = child.read();
            parse_ide_bars(&g.pnp.as_ref().unwrap().blob_out)
        };

        let dx: &mut DevExt =
            unsafe { &mut *((&*dev.dev_ext).as_ptr() as *const DevExt as *mut DevExt) };

        let cb = bars.cmd as u16;
        let ctl = bars.ctl as u16;
        let alt = ctl.wrapping_add(2);

        dx.data_port = Port::new(cb + 0);
        dx.error_port = Port::new(cb + 1);
        dx.sector_count_port = Port::new(cb + 2);
        dx.lba_lo_port = Port::new(cb + 3);
        dx.lba_mid_port = Port::new(cb + 4);
        dx.lba_hi_port = Port::new(cb + 5);
        dx.drive_head_port = Port::new(cb + 6);
        dx.command_port = Port::new(cb + 7);
        dx.alternative_command_port = Port::new(alt);
        dx.control_port = Port::new(alt);

        unsafe { dx.control_port.write(0u8) };

        dx.present = true;
        dx.enumerated = false;
    } else {
        let dx: &mut DevExt =
            unsafe { &mut *((&*dev.dev_ext).as_ptr() as *const DevExt as *mut DevExt) };
        dx.present = true;
        dx.enumerated = false;
    }

    req.write().status = DriverStatus::Pending;
    DriverStatus::Pending
}

extern "win64" fn ide_pnp_query_devrels(
    dev: &Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
) -> DriverStatus {
    let relation = { req.read().pnp.as_ref().unwrap().relation };
    if relation == DeviceRelationType::BusRelations {
        ide_enumerate_bus(dev);
        req.write().status = DriverStatus::Success;
        return DriverStatus::Success;
    }
    DriverStatus::Pending
}

fn ide_enumerate_bus(parent: &Arc<DeviceObject>) {
    let dx: &mut DevExt =
        unsafe { &mut *((&*parent.dev_ext).as_ptr() as *const DevExt as *mut DevExt) };
    if dx.enumerated || !dx.present {
        return;
    }

    if ata_probe_drive(dx, 0xE0) {
        create_child_pdo(parent, 0, 0);
    }
    if ata_probe_drive(dx, 0xF0) {
        create_child_pdo(parent, 0, 1);
    }

    dx.enumerated = true;
}

fn create_child_pdo(parent: &Arc<DeviceObject>, channel: u8, drive: u8) {
    let dx: &mut DevExt =
        unsafe { &mut *((&*parent.dev_ext).as_ptr() as *const DevExt as *mut DevExt) };

    let dh = if drive == 0 { 0xE0 } else { 0xF0 };
    let id_words_opt = ata_identify_words(dx, dh);

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

    let parent_dn = unsafe {
        (*(Arc::as_ptr(parent) as *const DeviceObject))
            .dev_node
            .upgrade()
            .expect("IDE FDO has no DevNode")
    };

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
    let mut child_init = DeviceInit {
        dev_ext_size: size_of::<ChildExt>(),
        io_vtable,
        pnp_vtable: None,
    };
    let mut pvt = PnpVtable::new();
    pvt.set(PnpMinorFunction::QueryId, ide_pdo_query_id);
    pvt.set(PnpMinorFunction::QueryResources, ide_pdo_query_resources);
    pvt.set(PnpMinorFunction::StartDevice, ide_pdo_start);
    child_init.pnp_vtable = Some(pvt);

    let short_name = alloc::format!("IDE_Disk_{}_{}", channel, drive);
    let instance = alloc::format!("IDE\\DRV_{:02}", drive);

    let (_dn, pdo) = unsafe {
        pnp_create_child_devnode_and_pdo_with_init(
            &parent_dn, short_name, instance, ids, class, child_init,
        )
    };

    let cdx: &mut ChildExt =
        unsafe { &mut *((&*pdo.dev_ext).as_ptr() as *const ChildExt as *mut ChildExt) };
    cdx.parent_dx = unsafe { (&*parent.dev_ext).as_ptr() as *const DevExt as *mut DevExt };
    cdx.dh = if drive == 0 { 0xE0 } else { 0xF0 };
    cdx.present = true;
}
pub extern "win64" fn ide_pdo_internal_ioctl(pdo: &Arc<DeviceObject>, req: Arc<RwLock<Request>>) {
    let guard = LOCK.lock();
    // Validate child state
    let cdx: &mut ChildExt =
        unsafe { &mut *((&*pdo.dev_ext).as_ptr() as *const ChildExt as *mut ChildExt) };
    if !cdx.present || cdx.parent_dx.is_null() {
        req.write().status = DriverStatus::NoSuchDevice;
        return;
    }
    let dx: &mut DevExt = unsafe { &mut *cdx.parent_dx };

    // Pull IOCTL code
    let code = {
        let mut w = req.write();
        match w.kind {
            RequestType::DeviceControl(c) => c,
            _ => {
                w.status = DriverStatus::InvalidParameter;
                return;
            }
        }
    };

    match code {
        IOCTL_BLOCK_QUERY => {
            let mut w = req.write();
            if w.data.len() < size_of::<BlockQueryOut>() {
                w.status = DriverStatus::InsufficientResources;
                return;
            }
            let out = unsafe { &mut *(w.data.as_mut_ptr() as *mut BlockQueryOut) };
            out.block_size = 512;
            out.max_blocks = 256;
            out.alignment_mask = 0;
            out.features = FEAT_FLUSH;
            w.status = DriverStatus::Success;
        }

        IOCTL_BLOCK_RW => {
            // Read header first
            let (hdr, need, off) = {
                let w = req.read();
                if w.data.len() < size_of::<BlockRwIn>() {
                    drop(w);
                    req.write().status = DriverStatus::InvalidParameter;
                    return;
                }
                let hdr = unsafe { *(w.data.as_ptr() as *const BlockRwIn) };
                let need = (hdr.blocks as usize) * 512;
                let off = hdr.buf_off as usize;
                if hdr.blocks == 0
                    || off
                        .checked_add(need)
                        .map(|e| e <= w.data.len())
                        .unwrap_or(false)
                        == false
                    || (hdr.lba >> 28) != 0
                {
                    drop(w);
                    req.write().status = DriverStatus::InvalidParameter;
                    return;
                }
                (hdr, need, off)
            };

            // Perform I/O and set status
            let mut w = req.write();
            let ok = match hdr.op {
                BLOCK_RW_READ => ata_pio_read(
                    dx,
                    cdx.dh,
                    hdr.lba as u32,
                    hdr.blocks as u32,
                    &mut w.data[off..off + need],
                ),
                BLOCK_RW_WRITE => ata_pio_write(
                    dx,
                    cdx.dh,
                    hdr.lba as u32,
                    hdr.blocks as u32,
                    &w.data[off..off + need],
                ),
                _ => {
                    w.status = DriverStatus::InvalidParameter;
                    return;
                }
            };
            w.status = if ok {
                DriverStatus::Success
            } else {
                DriverStatus::Unsuccessful
            };
        }

        IOCTL_BLOCK_FLUSH => {
            unsafe { dx.command_port.write(ATA_CMD_FLUSH_CACHE) };
            let mut w = req.write();
            w.status = if wait_not_busy(&mut dx.alternative_command_port, TIMEOUT_MS) {
                DriverStatus::Success
            } else {
                DriverStatus::Unsuccessful
            };
        }

        _ => {
            req.write().status = DriverStatus::NotImplemented;
        }
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

fn ata_identify_words(dx: &mut DevExt, dh: u8) -> Option<[u16; 256]> {
    let guard = LOCK.lock();
    unsafe {
        dx.drive_head_port.write(dh);
    }
    io_wait_400ns(&mut dx.alternative_command_port);

    unsafe { dx.command_port.write(ATA_CMD_IDENTIFY) };
    let st: u8 = unsafe { dx.command_port.read() };
    if st == 0 || (st & ATA_SR_ERR) != 0 {
        return None;
    }

    let mut words = [0u16; 256];
    for i in 0..256 {
        words[i] = unsafe { dx.data_port.read() };
    }
    Some(words)
}

fn ata_probe_drive(dx: &mut DevExt, dh: u8) -> bool {
    ata_identify_words(dx, dh).is_some()
}

fn ata_pio_read(dx: &mut DevExt, dh: u8, mut lba: u32, mut sectors: u32, out: &mut [u8]) -> bool {
    let mut off = 0usize;
    while sectors > 0 {
        let chunk = core::cmp::min(sectors, 256);
        let sc = if chunk == 256 { 0u8 } else { chunk as u8 };

        if !wait_ready(&mut dx.command_port, TIMEOUT_MS) {
            return false;
        }

        let devsel = 0xE0 | (dh & 0x10) | ((lba >> 24) as u8 & 0x0F);
        unsafe { dx.drive_head_port.write(devsel) };
        io_wait_400ns(&mut dx.alternative_command_port);

        if !wait_ready(&mut dx.command_port, TIMEOUT_MS) {
            return false;
        }

        unsafe {
            dx.sector_count_port.write(sc);
            dx.lba_lo_port.write((lba & 0xFF) as u8);
            dx.lba_mid_port.write(((lba >> 8) & 0xFF) as u8);
            dx.lba_hi_port.write(((lba >> 16) & 0xFF) as u8);
            dx.command_port.write(ATA_CMD_READ_SECTORS);
        }

        for _ in 0..chunk {
            if !wait_drq_set(&mut dx.command_port, TIMEOUT_MS) {
                return false;
            }
            if off + 512 > out.len() {
                return false;
            }

            for _ in 0..256 {
                let w: u16 = unsafe { dx.data_port.read() };
                out[off] = (w & 0xFF) as u8;
                out[off + 1] = (w >> 8) as u8;
                off += 2;
            }
            let _ = unsafe { dx.command_port.read() };
        }

        lba = lba.wrapping_add(chunk);
        sectors -= chunk;
    }
    true
}

fn ata_pio_write(dx: &mut DevExt, dh: u8, mut lba: u32, mut sectors: u32, data: &[u8]) -> bool {
    let mut off = 0usize;
    while sectors > 0 {
        let chunk = core::cmp::min(sectors, 256);
        let sc = if chunk == 256 { 0u8 } else { chunk as u8 };

        unsafe {
            dx.drive_head_port
                .write((dh & 0xF0) | ((lba >> 24) as u8 & 0x0F))
        };
        io_wait_400ns(&mut dx.command_port);
        if !wait_ready(&mut dx.command_port, TIMEOUT_MS) {
            return false;
        }

        unsafe {
            dx.sector_count_port.write(sc);
            dx.lba_lo_port.write((lba & 0xFF) as u8);
            dx.lba_mid_port.write(((lba >> 8) & 0xFF) as u8);
            dx.lba_hi_port.write(((lba >> 16) & 0xFF) as u8);
            dx.command_port.write(ATA_CMD_WRITE_SECTORS);
        }

        for _ in 0..chunk {
            if !wait_drq_set(&mut dx.command_port, TIMEOUT_MS) {
                return false;
            }
            for _ in 0..256 {
                let lo = data[off] as u16;
                let hi = data[off + 1] as u16;
                unsafe { dx.data_port.write(lo | (hi << 8)) };
                off += 2;
            }
        }

        lba = lba.wrapping_add(chunk);
        sectors -= chunk;
    }

    unsafe { dx.command_port.write(ATA_CMD_FLUSH_CACHE) };
    wait_not_busy(&mut dx.alternative_command_port, TIMEOUT_MS)
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
            p.ids_out
                .push(pdo.dev_node.upgrade().unwrap().instance_path.clone());
        }
    }
    w.status = DriverStatus::Success;
    DriverStatus::Success
}

extern "win64" fn ide_pdo_query_resources(
    _pdo: &Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
) -> DriverStatus {
    req.write().status = DriverStatus::Success; // none for child PDO
    DriverStatus::Success
}

extern "win64" fn ide_pdo_start(
    _pdo: &Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
) -> DriverStatus {
    if req.read().status == DriverStatus::Pending {
        req.write().status = DriverStatus::Success;
    }
    DriverStatus::Success
}
