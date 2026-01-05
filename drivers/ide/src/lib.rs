#![no_std]
#![no_main]
#![feature(const_option_ops)]
#![feature(const_trait_impl)]
extern crate alloc;

mod dev_ext;

use alloc::sync::Weak;
use alloc::vec;
use alloc::{
    boxed::Box,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use core::time::Duration;
use kernel_api::device::{DeviceInit, DeviceObject, DriverObject};
use kernel_api::kernel_types::io::{DiskInfo, IoType, IoVtable, Synchronization};
use kernel_api::kernel_types::pnp::DeviceIds;
use kernel_api::kernel_types::request::RequestData;
use kernel_api::pnp::{
    DeviceRelationType, DriverStep, PnpMinorFunction, PnpRequest, PnpVtable, QueryIdType,
    ResourceKind, driver_set_evt_device_add, pnp_create_child_devnode_and_pdo_with_init,
    pnp_forward_request_to_next_lower,
};
use kernel_api::request::{Request, RequestType};
use kernel_api::runtime::spawn_blocking;
use kernel_api::status::DriverStatus;
use kernel_api::util::wait_duration;
use kernel_api::x86_64::instructions::port::Port;
use kernel_api::{RequestExt, println, request_handler};
use spin::Mutex;
use spin::rwlock::RwLock;

use dev_ext::{DevExt, Ports};

static MOD_NAME: &str = option_env!("CARGO_PKG_NAME").unwrap_or(module_path!());

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    unsafe {
        use kernel_api::util::panic_common;
        panic_common(MOD_NAME, info)
    }
}

const IOCTL_BLOCK_FLUSH: u32 = 0xB000_0003;

const ATA_CMD_IDENTIFY: u8 = 0xEC;
const ATA_CMD_READ_SECTORS: u8 = 0x20;
const ATA_CMD_WRITE_SECTORS: u8 = 0x30;
const ATA_CMD_FLUSH_CACHE: u8 = 0xE7;

const ATA_SR_BSY: u8 = 1 << 7;
const ATA_SR_DRDY: u8 = 1 << 6;
const ATA_SR_DRQ: u8 = 1 << 3;
const ATA_SR_ERR: u8 = 1 << 0;

const TIMEOUT_MS: u64 = 10000;

#[repr(C)]
pub struct ChildExt {
    pub parent_device: Weak<DeviceObject>,
    pub dh: AtomicU8,
    pub present: AtomicBool,
    pub disk_info: Option<Arc<DiskInfo>>,
}

#[unsafe(no_mangle)]
pub extern "win64" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    driver_set_evt_device_add(driver, ide_device_add);
    DriverStatus::Success
}

pub extern "win64" fn ide_device_add(
    _driver: Arc<DriverObject>,
    dev_init: &mut DeviceInit,
) -> DriverStep {
    let mut vt = PnpVtable::new();
    vt.set(PnpMinorFunction::StartDevice, ide_pnp_start);
    vt.set(
        PnpMinorFunction::QueryDeviceRelations,
        ide_pnp_query_devrels,
    );

    let init = DeviceInit::new(IoVtable::new(), Some(vt));
    *dev_init = init;
    dev_init.set_dev_ext_from(DevExt::new(0x1F0, 0x3F4));

    DriverStep::complete(DriverStatus::Success)
}

#[request_handler]
async fn ide_pnp_start(dev: Arc<DeviceObject>, _req: Arc<RwLock<Request>>) -> DriverStep {
    let mut child = Request::new_pnp(
        PnpRequest {
            minor_function: PnpMinorFunction::QueryResources,
            relation: DeviceRelationType::TargetDeviceRelation,
            id_type: QueryIdType::CompatibleIds,
            ids_out: Vec::new(),
            blob_out: Vec::new(),
        },
        RequestData::empty(),
    );
    let child = Arc::new(RwLock::new(child));
    let st = pnp_forward_request_to_next_lower(dev.clone(), child.clone()).await;
    if st != DriverStatus::NoSuchDevice {
        let qst = { child.read().status };
        if qst != DriverStatus::Success {
            return DriverStep::complete(qst);
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
            unsafe { p.control.write(0x02) };
        }

        dx.present.store(true, Ordering::Release);
        dx.enumerated.store(false, Ordering::Release);
    } else {
        let dx = dev.try_devext::<DevExt>().expect("ide: FDO DevExt missing");
        dx.present.store(true, Ordering::Release);
        dx.enumerated.store(false, Ordering::Release);
    }

    DriverStep::Continue
}

#[request_handler]
async fn ide_pnp_query_devrels(dev: Arc<DeviceObject>, req: Arc<RwLock<Request>>) -> DriverStep {
    let relation = { req.read().pnp.as_ref().unwrap().relation };
    if relation == DeviceRelationType::BusRelations {
        ide_enumerate_bus(&dev);
        return DriverStep::complete(DriverStatus::Success);
    }
    DriverStep::Continue
}

fn acquire_controller(dx: &DevExt) {
    while dx
        .busy
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        //unsafe { wait_ms(1) };
    }
}

fn release_controller(dx: &DevExt) {
    dx.busy.store(false, Ordering::Release);
}

struct ControllerGuard<'a>(&'a DevExt);

impl<'a> ControllerGuard<'a> {
    fn new(dx: &'a DevExt) -> Self {
        acquire_controller(dx);
        Self(dx)
    }
}

impl<'a> Drop for ControllerGuard<'a> {
    fn drop(&mut self) {
        release_controller(self.0);
    }
}

fn ide_enumerate_bus(parent: &Arc<DeviceObject>) {
    let dx = parent
        .try_devext::<DevExt>()
        .expect("ide: FDO DevExt missing");

    if dx.enumerated.load(Ordering::Acquire) || !dx.present.load(Ordering::Acquire) {
        return;
    }

    let _guard = ControllerGuard::new(&dx);

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
    io_vtable.set(IoType::Read(ide_pdo_read), Synchronization::Sync, 0);
    io_vtable.set(IoType::Write(ide_pdo_write), Synchronization::Sync, 0);
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

    let (_dn, _pdo) = pnp_create_child_devnode_and_pdo_with_init(
        &parent_dn, short_name, instance, ids, class, child_init,
    );
}

#[request_handler]
pub async fn ide_pdo_read(
    pdo: Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
    _buf_len: usize,
) -> DriverStep {
    let cdx = match pdo.try_devext::<ChildExt>() {
        Ok(x) => x,
        Err(_) => return DriverStep::complete(DriverStatus::NoSuchDevice),
    };

    if !cdx.present.load(Ordering::Acquire) {
        return DriverStep::complete(DriverStatus::NoSuchDevice);
    }

    let parent = match cdx.parent_device.upgrade() {
        Some(p) => p,
        None => return DriverStep::complete(DriverStatus::NoSuchDevice),
    };

    if parent.try_devext::<DevExt>().is_err() {
        return DriverStep::complete(DriverStatus::NoSuchDevice);
    }

    let (offset, len) = {
        let r = req.read();
        match r.kind {
            RequestType::Read { offset, len } => (offset, len),
            _ => return DriverStep::complete(DriverStatus::InvalidParameter),
        }
    };

    if len == 0 {
        return DriverStep::complete(DriverStatus::Success);
    }

    if (offset & 0x1FF) != 0 || (len & 0x1FF) != 0 {
        return DriverStep::complete(DriverStatus::InvalidParameter);
    }

    let lba = offset >> 9;
    let sectors = (len / 512) as u32;

    if sectors == 0 || (lba >> 28) != 0 {
        return DriverStep::complete(DriverStatus::InvalidParameter);
    }

    {
        let r = req.read();
        if r.data_len() < len {
            return DriverStep::complete(DriverStatus::InsufficientResources);
        }
    }

    let dh = cdx.dh.load(Ordering::Acquire);
    let parent_clone = parent.clone();
    let req_clone = req.clone();

    let result = (move || {
        let dx = match parent_clone.try_devext::<DevExt>() {
            Ok(dx) => dx,
            Err(_) => return Err(DriverStatus::NoSuchDevice),
        };

        let _guard = ControllerGuard::new(&dx);

        let mut w = req_clone.write();
        let buf = &mut w.data_slice_mut()[..len];

        if ata_pio_read(&dx, dh, lba as u32, sectors, buf) {
            Ok(())
        } else {
            Err(DriverStatus::Unsuccessful)
        }
    })();

    match result {
        Ok(()) => DriverStep::complete(DriverStatus::Success),
        Err(status) => DriverStep::complete(status),
    }
}

#[request_handler]
pub async fn ide_pdo_write(
    pdo: Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
    _buf_len: usize,
) -> DriverStep {
    let cdx = match pdo.try_devext::<ChildExt>() {
        Ok(x) => x,
        Err(_) => return DriverStep::complete(DriverStatus::NoSuchDevice),
    };

    if !cdx.present.load(Ordering::Acquire) {
        return DriverStep::complete(DriverStatus::NoSuchDevice);
    }

    let parent = match cdx.parent_device.upgrade() {
        Some(p) => p,
        None => return DriverStep::complete(DriverStatus::NoSuchDevice),
    };

    if parent.try_devext::<DevExt>().is_err() {
        return DriverStep::complete(DriverStatus::NoSuchDevice);
    }

    let (offset, len) = {
        let r = req.read();
        match r.kind {
            RequestType::Write { offset, len } => (offset, len),
            _ => return DriverStep::complete(DriverStatus::InvalidParameter),
        }
    };

    if len == 0 {
        return DriverStep::complete(DriverStatus::Success);
    }

    if (offset & 0x1FF) != 0 || (len & 0x1FF) != 0 {
        return DriverStep::complete(DriverStatus::InvalidParameter);
    }

    let lba = offset >> 9;
    let sectors = (len / 512) as u32;

    if sectors == 0 || (lba >> 28) != 0 {
        return DriverStep::complete(DriverStatus::InvalidParameter);
    }

    {
        let r = req.read();
        if r.data_len() < len {
            return DriverStep::complete(DriverStatus::InsufficientResources);
        }
    }

    let dh = cdx.dh.load(Ordering::Acquire);
    let parent_clone = parent.clone();
    let req_clone = req.clone();

    let result = (move || {
        let dx = match parent_clone.try_devext::<DevExt>() {
            Ok(dx) => dx,
            Err(_) => return Err(DriverStatus::NoSuchDevice),
        };

        let _guard = ControllerGuard::new(&dx);

        let r = req_clone.read();
        let buf = &r.data_slice()[..len];

        if ata_pio_write(&dx, dh, lba as u32, sectors, buf) {
            Ok(())
        } else {
            Err(DriverStatus::Unsuccessful)
        }
    })();

    match result {
        Ok(()) => DriverStep::complete(DriverStatus::Success),
        Err(status) => DriverStep::complete(status),
    }
}

#[request_handler]
pub async fn ide_pdo_internal_ioctl(
    pdo: Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
) -> DriverStep {
    let cdx = match pdo.try_devext::<ChildExt>() {
        Ok(x) => x,
        Err(_) => return DriverStep::complete(DriverStatus::NoSuchDevice),
    };

    if !cdx.present.load(Ordering::Acquire) {
        return DriverStep::complete(DriverStatus::NoSuchDevice);
    }

    let parent: Arc<DeviceObject> = match cdx.parent_device.upgrade() {
        Some(p) => p,
        None => return DriverStep::complete(DriverStatus::NoSuchDevice),
    };
    let dx = match parent.try_devext::<DevExt>() {
        Ok(dx) => dx,
        Err(_) => return DriverStep::complete(DriverStatus::NoSuchDevice),
    };

    let code = {
        let r = req.read();
        match r.kind {
            RequestType::DeviceControl(c) => c,
            _ => return DriverStep::complete(DriverStatus::InvalidParameter),
        }
    };

    match code {
        IOCTL_BLOCK_FLUSH => {
            let _guard = ControllerGuard::new(&dx);

            {
                let mut p = dx.ports.lock();
                unsafe { p.command.write(ATA_CMD_FLUSH_CACHE) };
            }

            let ok = wait_not_busy(&dx.ports, TIMEOUT_MS);

            if ok {
                DriverStep::complete(DriverStatus::Success)
            } else {
                DriverStep::complete(DriverStatus::Unsuccessful)
            }
        }
        _ => DriverStep::complete(DriverStatus::NotImplemented),
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
    if !wait_not_busy(&dx.ports, TIMEOUT_MS) {
        return None;
    }

    {
        let mut p = dx.ports.lock();
        unsafe { p.drive_head.write(dh) };
        io_wait_400ns(&mut p.control);
        unsafe { p.command.write(ATA_CMD_IDENTIFY) };
    }

    if !wait_ready(&dx.ports, TIMEOUT_MS) {
        return None;
    }

    {
        let mut p = dx.ports.lock();
        let st = unsafe { p.command.read() };
        if st == 0 || (st & ATA_SR_ERR) != 0 {
            return None;
        }

        if (st & ATA_SR_DRQ) == 0 {
            return None;
        }

        let mut words = [0u16; 256];
        for i in 0..256 {
            words[i] = unsafe { p.data.read() };
        }
        Some(words)
    }
}

fn ata_probe_drive(dx: &DevExt, dh: u8) -> bool {
    ata_identify_words(dx, dh).is_some()
}

fn ata_pio_read(dx: &DevExt, dh: u8, mut lba: u32, mut sectors: u32, out: &mut [u8]) -> bool {
    let mut off = 0usize;

    let total_sectors = sectors;
    let bps = if total_sectors != 0 {
        out.len() / total_sectors as usize
    } else {
        512
    };

    while sectors > 0 {
        let chunk = core::cmp::min(sectors, 256);
        let sc = if chunk == 256 { 0u8 } else { chunk as u8 };

        if !wait_ready(&dx.ports, TIMEOUT_MS) {
            return false;
        }

        {
            let mut p = dx.ports.lock();
            let devsel = (dh & 0xF0) | ((lba >> 24) as u8 & 0x0F);
            unsafe { p.drive_head.write(devsel) };
            io_wait_400ns(&mut p.control);
        }

        if !wait_ready(&dx.ports, TIMEOUT_MS) {
            return false;
        }

        {
            let mut p = dx.ports.lock();
            unsafe {
                p.sector_count.write(sc);
                p.lba_lo.write((lba & 0xFF) as u8);
                p.lba_mid.write(((lba >> 8) & 0xFF) as u8);
                p.lba_hi.write(((lba >> 16) & 0xFF) as u8);
                p.command.write(ATA_CMD_READ_SECTORS);
            }
        }

        for _ in 0..chunk {
            if !wait_drq_set(&dx.ports, TIMEOUT_MS) {
                return false;
            }
            {
                let mut p = dx.ports.lock();
                let st = unsafe { p.command.read() };
                if (st & ATA_SR_DRQ) == 0 {
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
            }
        }

        lba = lba.wrapping_add(chunk);
        sectors -= chunk;
    }

    true
}

fn ata_pio_write(dx: &DevExt, dh: u8, mut lba: u32, mut sectors: u32, data: &[u8]) -> bool {
    let mut off = 0usize;

    let total_sectors = sectors;
    let bps = if total_sectors != 0 {
        data.len() / total_sectors as usize
    } else {
        512
    };

    while sectors > 0 {
        let chunk = core::cmp::min(sectors, 256);
        let sc = if chunk == 256 { 0u8 } else { chunk as u8 };

        if !wait_ready(&dx.ports, TIMEOUT_MS) {
            return false;
        }

        {
            let mut p = dx.ports.lock();
            let devsel = (dh & 0xF0) | ((lba >> 24) as u8 & 0x0F);
            unsafe { p.drive_head.write(devsel) };
            io_wait_400ns(&mut p.control);
        }

        if !wait_ready(&dx.ports, TIMEOUT_MS) {
            return false;
        }

        {
            let mut p = dx.ports.lock();
            unsafe {
                p.sector_count.write(sc);
                p.lba_lo.write((lba & 0xFF) as u8);
                p.lba_mid.write(((lba >> 8) & 0xFF) as u8);
                p.lba_hi.write(((lba >> 16) & 0xFF) as u8);
                p.command.write(ATA_CMD_WRITE_SECTORS);
            }
        }

        for _ in 0..chunk {
            if !wait_drq_set(&dx.ports, TIMEOUT_MS) {
                return false;
            }
            {
                let mut p = dx.ports.lock();
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

    if !wait_not_busy(&dx.ports, TIMEOUT_MS) {
        return false;
    }

    {
        let mut p = dx.ports.lock();
        unsafe { p.command.write(ATA_CMD_FLUSH_CACHE) };
    }

    wait_not_busy(&dx.ports, TIMEOUT_MS)
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

fn wait_not_busy(ports: &Mutex<Ports>, timeout_ms: u64) -> bool {
    for _ in 0..timeout_ms {
        {
            let mut p = ports.lock();
            let s = unsafe { p.command.read() };
            if (s & ATA_SR_BSY) == 0 {
                return true;
            }
        }
        wait_duration(Duration::from_millis(1));
    }
    false
}

fn wait_ready(ports: &Mutex<Ports>, timeout_ms: u64) -> bool {
    for _ in 0..timeout_ms {
        {
            let mut p = ports.lock();
            let s = unsafe { p.command.read() };
            if (s & ATA_SR_BSY) == 0 && (s & ATA_SR_DRDY) != 0 {
                return true;
            }
        }
        wait_duration(Duration::from_millis(1));
    }
    false
}

fn wait_drq_set(ports: &Mutex<Ports>, timeout_ms: u64) -> bool {
    for _ in 0..timeout_ms {
        {
            let mut p = ports.lock();
            let s = unsafe { p.command.read() };
            if (s & ATA_SR_BSY) != 0 {
            } else if (s & ATA_SR_ERR) != 0 {
                return false;
            } else if (s & ATA_SR_DRQ) != 0 {
                return true;
            }
        }
        wait_duration(Duration::from_millis(1));
    }
    false
}

#[request_handler]
pub async fn ide_pdo_query_id(pdo: Arc<DeviceObject>, req: Arc<RwLock<Request>>) -> DriverStep {
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
    DriverStep::complete(DriverStatus::Success)
}

#[request_handler]
pub async fn ide_pdo_query_resources(
    pdo: Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
) -> DriverStep {
    let cdx = match pdo.try_devext::<ChildExt>() {
        Ok(x) => x,
        Err(_) => {
            return DriverStep::complete(DriverStatus::NoSuchDevice);
        }
    };

    let mut w = req.write();
    let Some(p) = w.pnp.as_mut() else {
        return DriverStep::complete(DriverStatus::InvalidParameter);
    };

    let Some(di) = cdx.disk_info.as_ref() else {
        return DriverStep::complete(DriverStatus::DeviceNotReady);
    };
    let di_ptr = di.as_ref() as *const DiskInfo as *const u8;
    let n = core::mem::size_of::<DiskInfo>();
    let bytes = unsafe { core::slice::from_raw_parts(di_ptr, n) };
    p.blob_out = bytes.to_vec();

    DriverStep::complete(DriverStatus::Success)
}

#[request_handler]
pub async fn ide_pdo_start(_pdo: Arc<DeviceObject>, _req: Arc<RwLock<Request>>) -> DriverStep {
    DriverStep::complete(DriverStatus::Success)
}
