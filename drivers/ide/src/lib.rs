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
use core::mem::forget;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use kernel_api::device::{DeviceInit, DeviceObject, DriverObject};
use kernel_api::irq::{IrqHandle, irq_register_isr, irq_wait_closed, irq_wait_null, irq_wait_ok};
use kernel_api::kernel_types::io::{DiskInfo, IoType, IoVtable, Synchronization};
use kernel_api::kernel_types::irq::{IrqHandlePtr, IrqMeta};
use kernel_api::kernel_types::pnp::DeviceIds;
use kernel_api::pnp::{
    DeviceRelationType, DriverStep, PnpMinorFunction, PnpRequest, PnpVtable, QueryIdType,
    ResourceKind, driver_set_evt_device_add, pnp_create_child_devnode_and_pdo_with_init,
    pnp_forward_request_to_next_lower,
};
use kernel_api::request::{Request, RequestType};
use kernel_api::runtime::block_on;
use kernel_api::status::DriverStatus;
use kernel_api::util::wait_ms;
use kernel_api::x86_64::instructions::port::Port;
use kernel_api::x86_64::structures::idt::InterruptStackFrame;
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
const IDE_PRIMARY_IRQ_VECTOR: u8 = 0x20 + 0x0E;

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
        Box::new([]),
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

        dx.cmd_base.store(cb, Ordering::Release);
        dx.ctrl_base.store(ctl, Ordering::Release);
        let vec = match cb {
            0x1F0 => 0x20 + 0x0E,
            0x170 => 0x20 + 0x0F,
            _ => 0x20 + 0x0E,
        };
        dx.irq_vector.store(vec, Ordering::Release);
        {
            let mut p = dx.ports.lock();
            *p = Ports::new(cb, alt);
            unsafe { p.control.write(0x00) };
        }

        register_ide_irq(&dx);

        dx.present.store(true, Ordering::Release);
        dx.enumerated.store(false, Ordering::Release);
    } else {
        let dx = dev.try_devext::<DevExt>().expect("ide: FDO DevExt missing");
        enable_ide_interrupts(&dx);
        register_ide_irq(&dx);
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

struct ControllerGuard<'a> {
    _guard: kernel_api::kernel_types::no_std_async::mutex::Guard<'a, ()>,
}

impl<'a> ControllerGuard<'a> {
    async fn new(dx: &'a DevExt) -> Self {
        let guard = dx.ctrl_lock.lock().await;
        Self { _guard: guard }
    }

    fn blocking(dx: &'a DevExt) -> Self {
        let guard = block_on(dx.ctrl_lock.lock());
        Self { _guard: guard }
    }
}

fn register_ide_irq(dx: &DevExt) {
    let mut slot = dx.irq_handle.lock();
    if slot.is_some() {
        return;
    }
    let vec = dx.irq_vector.load(Ordering::Acquire);
    if let Some(handle) = irq_register_isr(vec, ide_primary_irq, dx as *const _ as usize) {
        *slot = Some(handle);
    } else {
        println!("ide: failed to register irq handler");
    }
}

fn enable_ide_interrupts(dx: &DevExt) {
    let mut p = dx.ports.lock();
    unsafe { p.control.write(0x00) };
}

fn read_status(dx: &DevExt) -> u8 {
    let mut p = dx.ports.lock();
    unsafe { p.command.read() }
}

async fn wait_for_irq(dx: &DevExt) -> Result<IrqMeta, DriverStatus> {
    let handle = dx.irq_handle.lock().clone();
    let Some(handle) = handle else {
        return Err(DriverStatus::DeviceNotReady);
    };

    let res = handle.wait(IrqMeta::new()).await;
    if irq_wait_ok(res) {
        Ok(res.meta)
    } else if irq_wait_closed(res) || irq_wait_null(res) {
        Err(DriverStatus::NoSuchDevice)
    } else {
        Err(DriverStatus::Unsuccessful)
    }
}

fn status_from_meta_or_ports(dx: &DevExt, meta: IrqMeta) -> u8 {
    let status = (meta.tag & 0xFF) as u8;
    if status != 0 { status } else { read_status(dx) }
}

extern "win64" fn ide_primary_irq(
    _vector: u8,
    _cpu: u32,
    _frame: *mut InterruptStackFrame,
    handle: IrqHandlePtr,
    ctx: usize,
) -> bool {
    if ctx == 0 {
        return false;
    }

    let dx = unsafe { &*(ctx as *const DevExt) };

    let cmd_base = dx.cmd_base.load(Ordering::Acquire);
    let mut status_port: Port<u8> = unsafe { Port::new(cmd_base + 7) };
    let status = unsafe { status_port.read() };

    let hptr_usize = handle as usize;
    let tag = status as u64;

    kernel_api::runtime::spawn(async move {
        let hptr = hptr_usize as IrqHandlePtr;
        let meta = IrqMeta::with_tag(tag);

        unsafe {
            if let Some(h) = IrqHandle::from_raw(hptr) {
                h.signal_one(meta);
                core::mem::forget(h);
            }
        }
    });

    true
}
fn ide_enumerate_bus(parent: &Arc<DeviceObject>) {
    let dx = parent
        .try_devext::<DevExt>()
        .expect("ide: FDO DevExt missing");

    if dx.enumerated.load(Ordering::Acquire) || !dx.present.load(Ordering::Acquire) {
        return;
    }

    let _guard = ControllerGuard::blocking(&dx);

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
        if r.data.len() < len {
            return DriverStep::complete(DriverStatus::InsufficientResources);
        }
    }

    let dh = cdx.dh.load(Ordering::Acquire);
    let dx = match parent.try_devext::<DevExt>() {
        Ok(dx) => dx,
        Err(_) => return DriverStep::complete(DriverStatus::NoSuchDevice),
    };

    let _guard = ControllerGuard::new(&dx).await;

    enable_ide_interrupts(&dx);

    let status = {
        let mut w = req.write();
        let buf = &mut w.data[..len];
        ata_pio_read_async(&dx, dh, lba as u32, sectors, buf).await
    };

    DriverStep::complete(status)
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
        if r.data.len() < len {
            return DriverStep::complete(DriverStatus::InsufficientResources);
        }
    }

    let dh = cdx.dh.load(Ordering::Acquire);
    let dx = match parent.try_devext::<DevExt>() {
        Ok(dx) => dx,
        Err(_) => return DriverStep::complete(DriverStatus::NoSuchDevice),
    };

    let _guard = ControllerGuard::new(&dx).await;

    enable_ide_interrupts(&dx);

    let status = {
        let r = req.read();
        let buf = &r.data[..len];
        ata_pio_write_async(&dx, dh, lba as u32, sectors, buf).await
    };

    DriverStep::complete(status)
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
            let _guard = ControllerGuard::new(&dx).await;

            enable_ide_interrupts(&dx);

            {
                let mut p = dx.ports.lock();
                unsafe { p.command.write(ATA_CMD_FLUSH_CACHE) };
            }

            let status = match wait_for_irq(&dx).await {
                Ok(meta) => status_from_meta_or_ports(&dx, meta),
                Err(_) => {
                    if wait_not_busy(&dx.ports, TIMEOUT_MS) {
                        read_status(&dx)
                    } else {
                        return DriverStep::complete(DriverStatus::Unsuccessful);
                    }
                }
            };

            if (status & ATA_SR_ERR) == 0 {
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

async fn ata_pio_read_async(
    dx: &DevExt,
    dh: u8,
    lba: u32,
    sectors: u32,
    out: &mut [u8],
) -> DriverStatus {
    let mut off = 0usize;
    let mut cur_lba = lba;

    for _ in 0..sectors {
        if !wait_ready(&dx.ports, TIMEOUT_MS) {
            return DriverStatus::DeviceNotReady;
        }

        {
            let mut p = dx.ports.lock();
            let devsel = (dh & 0xF0) | ((cur_lba >> 24) as u8 & 0x0F);
            unsafe {
                p.drive_head.write(devsel);
                io_wait_400ns(&mut p.control);
                p.sector_count.write(1);
                p.lba_lo.write((cur_lba & 0xFF) as u8);
                p.lba_mid.write(((cur_lba >> 8) & 0xFF) as u8);
                p.lba_hi.write(((cur_lba >> 16) & 0xFF) as u8);
                p.command.write(ATA_CMD_READ_SECTORS);
            }
        }

        let _status = loop {
            let status = match wait_for_irq(dx).await {
                Ok(meta) => status_from_meta_or_ports(dx, meta),
                Err(_) => {
                    if wait_drq_set(&dx.ports, TIMEOUT_MS) {
                        read_status(dx)
                    } else {
                        return DriverStatus::Unsuccessful;
                    }
                }
            };

            if (status & ATA_SR_ERR) != 0 {
                return DriverStatus::Unsuccessful;
            }

            if (status & ATA_SR_DRQ) != 0 {
                break status;
            }
        };

        {
            let mut p = dx.ports.lock();
            if off + 512 > out.len() {
                return DriverStatus::InvalidParameter;
            }
            for _ in 0..256 {
                let w: u16 = unsafe { p.data.read() };
                out[off] = (w & 0xFF) as u8;
                out[off + 1] = (w >> 8) as u8;
                off += 2;
            }
        }

        cur_lba = cur_lba.wrapping_add(1);
    }

    DriverStatus::Success
}

async fn ata_pio_write_async(
    dx: &DevExt,
    dh: u8,
    lba: u32,
    sectors: u32,
    data: &[u8],
) -> DriverStatus {
    let mut off = 0usize;
    let mut cur_lba = lba;

    for _ in 0..sectors {
        if !wait_ready(&dx.ports, TIMEOUT_MS) {
            return DriverStatus::DeviceNotReady;
        }

        {
            let mut p = dx.ports.lock();
            let devsel = (dh & 0xF0) | ((cur_lba >> 24) as u8 & 0x0F);
            unsafe {
                p.drive_head.write(devsel);
                io_wait_400ns(&mut p.control);
                p.sector_count.write(1);
                p.lba_lo.write((cur_lba & 0xFF) as u8);
                p.lba_mid.write(((cur_lba >> 8) & 0xFF) as u8);
                p.lba_hi.write(((cur_lba >> 16) & 0xFF) as u8);
                p.command.write(ATA_CMD_WRITE_SECTORS);
            }
        }

        let _status = loop {
            let status = match wait_for_irq(dx).await {
                Ok(meta) => status_from_meta_or_ports(dx, meta),
                Err(_) => {
                    if wait_drq_set(&dx.ports, TIMEOUT_MS) {
                        read_status(dx)
                    } else {
                        return DriverStatus::Unsuccessful;
                    }
                }
            };
            if (status & ATA_SR_ERR) != 0 {
                return DriverStatus::Unsuccessful;
            }

            if (status & ATA_SR_DRQ) != 0 {
                break status;
            }
        };

        {
            let mut p = dx.ports.lock();
            if off + 512 > data.len() {
                return DriverStatus::InvalidParameter;
            }
            for _ in 0..256 {
                let lo = data[off] as u16;
                let hi = data[off + 1] as u16;
                unsafe { p.data.write(lo | (hi << 8)) };
                off += 2;
            }
        }

        cur_lba = cur_lba.wrapping_add(1);
    }

    {
        let mut p = dx.ports.lock();
        unsafe { p.command.write(ATA_CMD_FLUSH_CACHE) };
    }

    match wait_for_irq(dx).await {
        Ok(meta) => {
            let status = status_from_meta_or_ports(dx, meta);
            if (status & ATA_SR_ERR) != 0 {
                return DriverStatus::Unsuccessful;
            }
        }
        Err(_) => {
            if !wait_not_busy(&dx.ports, TIMEOUT_MS) {
                return DriverStatus::Unsuccessful;
            }
        }
    }

    DriverStatus::Success
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
        wait_ms(1);
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
        wait_ms(1);
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
        wait_ms(1);
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
