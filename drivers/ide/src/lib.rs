// TODO: legacy driver so not the biggest prio but there is a memory corruption race condition somewhere that needs to be fixed.
// the race can be triggered by sending a request then awaiting it and so on for a while. It will occur at some point shows as a GPF.
#![no_std]
#![no_main]
#![feature(const_option_ops)]
#![feature(const_trait_impl)]
extern crate alloc;

mod dev_ext;

use alloc::sync::Weak;
use alloc::vec;
use alloc::{
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use core::time::Duration;
use kernel_api::device::{DeviceInit, DeviceObject, DriverObject};
use kernel_api::irq::{IrqHandle, irq_register_isr, irq_register_isr_gsi, irq_wait_ok};
use kernel_api::kernel_types::io::{DiskInfo, IoType, IoVtable};
use kernel_api::kernel_types::irq::{IrqHandlePtr, IrqMeta};
use kernel_api::kernel_types::pnp::DeviceIds;
use kernel_api::kernel_types::request::RequestData;
use kernel_api::pnp::{
    DeviceRelationType, DriverStep, PnpMinorFunction, PnpRequest, PnpVtable, QueryIdType,
    ResourceKind, driver_set_evt_device_add, pnp_create_child_devnode_and_pdo_with_init,
    pnp_forward_request_to_next_lower,
};
use kernel_api::request::{RequestHandle, RequestType};
use kernel_api::request_handler;
use kernel_api::status::DriverStatus;
use kernel_api::util::wait_duration;
use kernel_api::x86_64::instructions::port::Port;

use dev_ext::{ControllerState, DevExt, Ports};

static MOD_NAME: &str = option_env!("CARGO_PKG_NAME").unwrap_or(module_path!());

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    use kernel_api::util::panic_common;
    panic_common(MOD_NAME, info)
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

fn complete_req(req: &mut RequestHandle, status: DriverStatus) -> DriverStep {
    {
        let mut w = req.write();
        w.status = status;
    }
    DriverStep::complete(status)
}

fn continue_req(req: &mut RequestHandle) -> DriverStep {
    {
        let mut w = req.write();
        w.status = DriverStatus::ContinueStep;
    }
    DriverStep::Continue
}

/// IDE interrupt service routine.
/// `ctx` = I/O base port address, used to read the status register and clear the IRQ.
extern "win64" fn ide_isr(
    _vector: u8,
    _cpu: u32,
    _frame: *mut kernel_api::x86_64::structures::idt::InterruptStackFrame,
    handle: IrqHandlePtr,
    ctx: usize,
) -> bool {
    // Read the status register to acknowledge/clear the IDE interrupt.
    let io_base = ctx as u16;
    let mut status_port: Port<u8> = Port::new(io_base + 7);
    let _status = unsafe { status_port.read() };

    if let Some(h) = unsafe { IrqHandle::from_raw(handle) } {
        h.signal_one(IrqMeta {
            tag: 0,
            data: [0; 3],
        });
        core::mem::forget(h);
    }
    true
}

#[repr(C)]
pub struct ChildExt {
    pub parent_device: Weak<DeviceObject>,
    pub dh: AtomicU8,
    pub present: AtomicBool,
    pub disk_info: Option<DiskInfo>,
}

#[unsafe(no_mangle)]
pub extern "win64" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    driver_set_evt_device_add(driver, ide_device_add);
    DriverStatus::Success
}

pub extern "win64" fn ide_device_add(
    _driver: &Arc<DriverObject>,
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
async fn ide_pnp_start<'a, 'b>(
    dev: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
) -> DriverStep {
    let mut child_handle = RequestHandle::new_pnp(
        PnpRequest {
            minor_function: PnpMinorFunction::QueryResources,
            relation: DeviceRelationType::TargetDeviceRelation,
            id_type: QueryIdType::CompatibleIds,
            ids_out: Vec::new(),
            data_out: RequestData::empty(),
        },
        RequestData::empty(),
    );
    let st = pnp_forward_request_to_next_lower(dev.clone(), &mut child_handle).await;
    if st != DriverStatus::NoSuchDevice {
        let qst = child_handle.read().status;
        if qst != DriverStatus::Success {
            return complete_req(req, qst);
        }
        let binding = child_handle.read();
        let bars = {
            let data = binding.pnp.as_ref().unwrap().data_out.as_slice();
            parse_ide_bars(data)
        };

        let dx = dev.try_devext::<DevExt>().expect("ide: FDO DevExt missing");

        let cb = bars.cmd;
        let ctl = bars.ctl;
        let alt = ctl.wrapping_add(2);

        {
            let mut ctrl = dx.controller.lock().await;
            ctrl.ports = Ports::new(cb, alt);
        }

        // Register IRQ handler
        let irq_handle = if let Some(gsi) = bars.gsi {
            if gsi < 64 {
                irq_register_isr_gsi(gsi as u8, ide_isr, cb as usize)
            } else {
                None
            }
        } else if let Some(line) = bars.irq_line {
            if line < 16 {
                let vector = 0x20 + line;
                irq_register_isr(vector, ide_isr, cb as usize)
            } else {
                None
            }
        } else {
            None
        };

        unsafe {
            *dx.irq_handle.get() = irq_handle;
        }

        // Enable interrupts: clear nIEN bit (write 0x00 instead of 0x02)
        {
            let mut ctrl = dx.controller.lock().await;
            unsafe { ctrl.ports.control.write(0x00) };
        }

        dx.present.store(true, Ordering::Release);
        dx.enumerated.store(false, Ordering::Release);
    } else {
        let dx = dev.try_devext::<DevExt>().expect("ide: FDO DevExt missing");
        dx.present.store(true, Ordering::Release);
        dx.enumerated.store(false, Ordering::Release);
    }

    continue_req(req)
}

#[request_handler]
async fn ide_pnp_query_devrels<'a, 'b>(
    dev: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
) -> DriverStep {
    let relation = { req.read().pnp.as_ref().unwrap().relation };
    if relation == DeviceRelationType::BusRelations {
        ide_enumerate_bus(&dev);
        return complete_req(req, DriverStatus::Success);
    }
    continue_req(req)
}

fn ide_enumerate_bus(parent: &Arc<DeviceObject>) {
    let dx = parent
        .try_devext::<DevExt>()
        .expect("ide: FDO DevExt missing");

    if dx.enumerated.load(Ordering::Acquire) || !dx.present.load(Ordering::Acquire) {
        return;
    }

    // Probe and identify drives while holding the controller lock.
    let mut ctrl = dx.controller.lock_blocking();
    let master_words = ata_identify_words_sync(&mut ctrl.ports, 0xE0);
    let slave_words = ata_identify_words_sync(&mut ctrl.ports, 0xF0);
    drop(ctrl);

    // Create PDOs outside the lock.
    if master_words.is_some() {
        create_child_pdo(parent, 0, 0, master_words);
    }
    if slave_words.is_some() {
        create_child_pdo(parent, 0, 1, slave_words);
    }

    dx.enumerated.store(true, Ordering::Release);
}

fn create_child_pdo(
    parent: &Arc<DeviceObject>,
    channel: u8,
    drive: u8,
    id_words_opt: Option<[u16; 256]>,
) {
    let dh = if drive == 0 { 0xE0 } else { 0xF0 };

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
    io_vtable.set(IoType::Read(ide_pdo_read), 0);
    io_vtable.set(IoType::Write(ide_pdo_write), 0);
    io_vtable.set(IoType::DeviceControl(ide_pdo_internal_ioctl), 0);

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
            Some(disk_info_from_identify(&words))
        } else {
            Some(DiskInfo {
                logical_block_size: 512,
                physical_block_size: 0,
                total_logical_blocks: 0,
                total_bytes_low: 0,
                total_bytes_high: 0,
            })
        },
    });

    let short_name = alloc::format!("IDE_Disk_{}_{}", channel, drive);
    let instance = alloc::format!("IDE\\DRV_{:02}", drive);

    let (_dn, _pdo) = pnp_create_child_devnode_and_pdo_with_init(
        &parent_dn, short_name, instance, ids, class, child_init,
    );
}

#[request_handler]
pub async fn ide_pdo_read<'a, 'b>(
    pdo: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
    _buf_len: usize,
) -> DriverStep {
    let cdx = match pdo.try_devext::<ChildExt>() {
        Ok(x) => x,
        Err(_) => return complete_req(req, DriverStatus::NoSuchDevice),
    };

    if !cdx.present.load(Ordering::Acquire) {
        return complete_req(req, DriverStatus::NoSuchDevice);
    }

    let parent = match cdx.parent_device.upgrade() {
        Some(p) => p,
        None => return complete_req(req, DriverStatus::NoSuchDevice),
    };

    let dx = match parent.try_devext::<DevExt>() {
        Ok(dx) => dx,
        Err(_) => return complete_req(req, DriverStatus::NoSuchDevice),
    };

    let kind = {
        let r = req.read();
        r.kind
    };
    let (offset, len) = match kind {
        RequestType::Read { offset, len } => (offset, len),
        _ => return complete_req(req, DriverStatus::InvalidParameter),
    };

    if len == 0 {
        return complete_req(req, DriverStatus::Success);
    }

    if (offset & 0x1FF) != 0 || (len & 0x1FF) != 0 {
        return complete_req(req, DriverStatus::InvalidParameter);
    }

    let lba = offset >> 9;
    let sectors = (len / 512) as u32;

    if sectors == 0 || (lba >> 28) != 0 {
        return complete_req(req, DriverStatus::InvalidParameter);
    }

    let has_buffer = {
        let r = req.read();
        r.data_len() >= len
    };
    if !has_buffer {
        return complete_req(req, DriverStatus::InsufficientResources);
    }

    let dh = cdx.dh.load(Ordering::Acquire);
    let irq = unsafe { dx.irq() };

    let mut ctrl = dx.controller.lock().await;
    let mut w = req.write();
    let buf = &mut w.data_slice_mut()[..len];

    let ok = ata_pio_read_async(&mut ctrl, irq, dh, lba as u32, sectors, buf).await;
    drop(ctrl);
    drop(w);

    complete_req(
        req,
        if ok {
            DriverStatus::Success
        } else {
            DriverStatus::Unsuccessful
        },
    )
}

#[request_handler]
pub async fn ide_pdo_write<'a, 'b>(
    pdo: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
    _buf_len: usize,
) -> DriverStep {
    let cdx = match pdo.try_devext::<ChildExt>() {
        Ok(x) => x,
        Err(_) => return complete_req(req, DriverStatus::NoSuchDevice),
    };

    if !cdx.present.load(Ordering::Acquire) {
        return complete_req(req, DriverStatus::NoSuchDevice);
    }

    let parent = match cdx.parent_device.upgrade() {
        Some(p) => p,
        None => return complete_req(req, DriverStatus::NoSuchDevice),
    };

    let dx = match parent.try_devext::<DevExt>() {
        Ok(dx) => dx,
        Err(_) => return complete_req(req, DriverStatus::NoSuchDevice),
    };

    let kind = {
        let r = req.read();
        r.kind
    };
    let (offset, len) = match kind {
        RequestType::Write { offset, len, .. } => (offset, len),
        _ => return complete_req(req, DriverStatus::InvalidParameter),
    };

    if len == 0 {
        return complete_req(req, DriverStatus::Success);
    }

    if (offset & 0x1FF) != 0 || (len & 0x1FF) != 0 {
        return complete_req(req, DriverStatus::InvalidParameter);
    }

    let lba = offset >> 9;
    let sectors = (len / 512) as u32;

    if sectors == 0 || (lba >> 28) != 0 {
        return complete_req(req, DriverStatus::InvalidParameter);
    }

    let has_buffer = {
        let r = req.read();
        r.data_len() >= len
    };
    if !has_buffer {
        return complete_req(req, DriverStatus::InsufficientResources);
    }

    let dh = cdx.dh.load(Ordering::Acquire);
    let irq = unsafe { dx.irq() };

    let mut ctrl = dx.controller.lock().await;
    let r = req.read();
    let buf = &r.data_slice()[..len];

    let ok = ata_pio_write_async(&mut ctrl, irq, dh, lba as u32, sectors, buf).await;
    drop(ctrl);
    drop(r);

    complete_req(
        req,
        if ok {
            DriverStatus::Success
        } else {
            DriverStatus::Unsuccessful
        },
    )
}

#[request_handler]
pub async fn ide_pdo_internal_ioctl<'a, 'b>(
    pdo: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
) -> DriverStep {
    let cdx = match pdo.try_devext::<ChildExt>() {
        Ok(x) => x,
        Err(_) => return complete_req(req, DriverStatus::NoSuchDevice),
    };

    if !cdx.present.load(Ordering::Acquire) {
        return complete_req(req, DriverStatus::NoSuchDevice);
    }

    let parent: Arc<DeviceObject> = match cdx.parent_device.upgrade() {
        Some(p) => p,
        None => return complete_req(req, DriverStatus::NoSuchDevice),
    };
    let dx = match parent.try_devext::<DevExt>() {
        Ok(dx) => dx,
        Err(_) => return complete_req(req, DriverStatus::NoSuchDevice),
    };

    let kind = {
        let r = req.read();
        r.kind
    };
    let code = match kind {
        RequestType::DeviceControl(c) => c,
        _ => return complete_req(req, DriverStatus::InvalidParameter),
    };

    match code {
        IOCTL_BLOCK_FLUSH => {
            let irq = unsafe { dx.irq() };
            let mut ctrl = dx.controller.lock().await;

            unsafe { ctrl.ports.command.write(ATA_CMD_FLUSH_CACHE) };

            let ok = wait_not_busy_async(&mut ctrl.ports, irq, TIMEOUT_MS).await;
            drop(ctrl);

            if ok {
                complete_req(req, DriverStatus::Success)
            } else {
                complete_req(req, DriverStatus::Unsuccessful)
            }
        }
        _ => complete_req(req, DriverStatus::NotImplemented),
    }
}

#[derive(Default, Clone, Copy)]
struct IdeBars {
    cmd: u16,
    ctl: u16,
    bm: u16,
    gsi: Option<u32>,
    irq_line: Option<u8>,
}

fn parse_ide_bars(blob: &[u8]) -> IdeBars {
    let mut bars = IdeBars::default();

    if blob.len() < 12 || &blob[0..4] != b"RSRC" {
        bars.cmd = 0x1F0;
        bars.ctl = 0x3F4;
        bars.irq_line = Some(14);
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

        if kind == ResourceKind::Gsi as u32 {
            bars.gsi = Some(start as u32);
            continue;
        }
        if kind == ResourceKind::Interrupt as u32 {
            bars.irq_line = Some(start as u8);
            continue;
        }

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
    if bars.gsi.is_none() && bars.irq_line.is_none() {
        bars.irq_line = Some(if bars.cmd == 0x170 { 15 } else { 14 });
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

fn ata_identify_words_sync(ports: &mut Ports, dh: u8) -> Option<[u16; 256]> {
    if !wait_not_busy_sync(ports, TIMEOUT_MS) {
        return None;
    }

    unsafe { ports.drive_head.write(dh) };
    io_wait_400ns(&mut ports.control);
    unsafe { ports.command.write(ATA_CMD_IDENTIFY) };

    if !wait_ready_sync(ports, TIMEOUT_MS) {
        return None;
    }

    let st = unsafe { ports.command.read() };
    if st == 0 || (st & ATA_SR_ERR) != 0 {
        return None;
    }

    if (st & ATA_SR_DRQ) == 0 {
        return None;
    }

    let mut words = [0u16; 256];
    for i in 0..256 {
        words[i] = unsafe { ports.data.read() };
    }
    Some(words)
}

fn ata_probe_drive_sync(ports: &mut Ports, dh: u8) -> bool {
    ata_identify_words_sync(ports, dh).is_some()
}

async fn ata_pio_read_async(
    ctrl: &mut ControllerState,
    irq: &Option<IrqHandle>,
    dh: u8,
    mut lba: u32,
    mut sectors: u32,
    out: &mut [u8],
) -> bool {
    let mut off = 0usize;
    let p = &mut ctrl.ports;

    while sectors > 0 {
        let chunk = core::cmp::min(sectors, 256);
        let sc = if chunk == 256 { 0u8 } else { chunk as u8 };

        if !wait_ready_async(p, irq, TIMEOUT_MS).await {
            return false;
        }

        let devsel = (dh & 0xF0) | ((lba >> 24) as u8 & 0x0F);
        unsafe { p.drive_head.write(devsel) };
        io_wait_400ns(&mut p.control);

        if !wait_ready_async(p, irq, TIMEOUT_MS).await {
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
            if !wait_drq_async(p, irq, TIMEOUT_MS).await {
                return false;
            }
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

        lba = lba.wrapping_add(chunk);
        sectors -= chunk;
    }

    true
}

async fn ata_pio_write_async(
    ctrl: &mut ControllerState,
    irq: &Option<IrqHandle>,
    dh: u8,
    mut lba: u32,
    mut sectors: u32,
    data: &[u8],
) -> bool {
    let mut off = 0usize;
    let p = &mut ctrl.ports;

    while sectors > 0 {
        let chunk = core::cmp::min(sectors, 256);
        let sc = if chunk == 256 { 0u8 } else { chunk as u8 };

        if !wait_ready_async(p, irq, TIMEOUT_MS).await {
            return false;
        }

        let devsel = (dh & 0xF0) | ((lba >> 24) as u8 & 0x0F);
        unsafe { p.drive_head.write(devsel) };
        io_wait_400ns(&mut p.control);

        if !wait_ready_async(p, irq, TIMEOUT_MS).await {
            return false;
        }

        unsafe {
            p.sector_count.write(sc);
            p.lba_lo.write((lba & 0xFF) as u8);
            p.lba_mid.write(((lba >> 8) & 0xFF) as u8);
            p.lba_hi.write(((lba >> 16) & 0xFF) as u8);
            p.command.write(ATA_CMD_WRITE_SECTORS);
        }

        for sec_idx in 0..chunk {
            if sec_idx == 0 {
                // First sector: DRQ is immediate after command, no IRQ fires.
                if !wait_drq_poll_brief(p) {
                    return false;
                }
            } else {
                // Subsequent sectors: wait for IRQ signaling device ready.
                if !wait_drq_async(p, irq, TIMEOUT_MS).await {
                    return false;
                }
            }

            if off + 512 > data.len() {
                return false;
            }
            for _ in 0..256 {
                let lo = data[off] as u16;
                let hi = data[off + 1] as u16;
                unsafe { p.data.write(lo | (hi << 8)) };
                off += 2;
            }
        }

        lba = lba.wrapping_add(chunk);
        sectors -= chunk;
    }

    // Wait for final write to complete
    if !wait_not_busy_async(p, irq, TIMEOUT_MS).await {
        return false;
    }

    // Flush cache
    unsafe { p.command.write(ATA_CMD_FLUSH_CACHE) };
    wait_not_busy_async(p, irq, TIMEOUT_MS).await
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

// ── Synchronous wait helpers (used during enumeration, before IRQ is available) ──

fn wait_not_busy_sync(ports: &mut Ports, timeout_ms: u64) -> bool {
    for _ in 0..timeout_ms {
        let s = unsafe { ports.command.read() };
        if (s & ATA_SR_BSY) == 0 {
            return true;
        }
        wait_duration(Duration::from_millis(1));
    }
    false
}

fn wait_ready_sync(ports: &mut Ports, timeout_ms: u64) -> bool {
    for _ in 0..timeout_ms {
        let s = unsafe { ports.command.read() };
        if (s & ATA_SR_BSY) == 0 && (s & ATA_SR_DRDY) != 0 {
            return true;
        }
        wait_duration(Duration::from_millis(1));
    }
    false
}

fn wait_drq_sync(ports: &mut Ports, timeout_ms: u64) -> bool {
    for _ in 0..timeout_ms {
        let s = unsafe { ports.command.read() };
        if (s & ATA_SR_BSY) != 0 {
        } else if (s & ATA_SR_ERR) != 0 {
            return false;
        } else if (s & ATA_SR_DRQ) != 0 {
            return true;
        }
        wait_duration(Duration::from_millis(1));
    }
    false
}

// ── Async interrupt-driven wait helpers ──

async fn wait_not_busy_async(ports: &mut Ports, irq: &Option<IrqHandle>, timeout_ms: u64) -> bool {
    let s = unsafe { ports.command.read() };
    if (s & ATA_SR_BSY) == 0 {
        return true;
    }

    if let Some(handle) = irq {
        let meta = IrqMeta {
            tag: 0,
            data: [0; 3],
        };
        for _ in 0..(timeout_ms / 10).max(1) {
            let result = handle.wait(meta).await;
            if !irq_wait_ok(result) {
                return false;
            }
            let s = unsafe { ports.command.read() };
            if (s & ATA_SR_BSY) == 0 {
                return true;
            }
        }
        false
    } else {
        wait_not_busy_sync(ports, timeout_ms)
    }
}

async fn wait_ready_async(ports: &mut Ports, irq: &Option<IrqHandle>, timeout_ms: u64) -> bool {
    let s = unsafe { ports.command.read() };
    if (s & ATA_SR_BSY) == 0 && (s & ATA_SR_DRDY) != 0 {
        return true;
    }

    if let Some(handle) = irq {
        let meta = IrqMeta {
            tag: 0,
            data: [0; 3],
        };
        for _ in 0..(timeout_ms / 10).max(1) {
            let result = handle.wait(meta).await;
            if !irq_wait_ok(result) {
                return false;
            }
            let s = unsafe { ports.command.read() };
            if (s & ATA_SR_BSY) == 0 && (s & ATA_SR_DRDY) != 0 {
                return true;
            }
        }
        false
    } else {
        wait_ready_sync(ports, timeout_ms)
    }
}

async fn wait_drq_async(ports: &mut Ports, irq: &Option<IrqHandle>, timeout_ms: u64) -> bool {
    let s = unsafe { ports.command.read() };
    if (s & ATA_SR_BSY) == 0 {
        if (s & ATA_SR_ERR) != 0 {
            return false;
        }
        if (s & ATA_SR_DRQ) != 0 {
            return true;
        }
    }

    if let Some(handle) = irq {
        let meta = IrqMeta {
            tag: 0,
            data: [0; 3],
        };
        for _ in 0..(timeout_ms / 10).max(1) {
            let result = handle.wait(meta).await;
            if !irq_wait_ok(result) {
                return false;
            }
            let s = unsafe { ports.command.read() };
            if (s & ATA_SR_BSY) != 0 {
                continue;
            }
            if (s & ATA_SR_ERR) != 0 {
                return false;
            }
            if (s & ATA_SR_DRQ) != 0 {
                return true;
            }
        }
        false
    } else {
        wait_drq_sync(ports, timeout_ms)
    }
}

/// Brief synchronous poll for DRQ — used for the first sector of a WRITE command
/// where the ATA spec says no IRQ fires.
fn wait_drq_poll_brief(ports: &mut Ports) -> bool {
    for _ in 0..1000u32 {
        let s = unsafe { ports.command.read() };
        if (s & ATA_SR_BSY) == 0 && (s & ATA_SR_DRQ) != 0 {
            return true;
        }
        if (s & ATA_SR_ERR) != 0 {
            return false;
        }
    }
    false
}

#[request_handler]
pub async fn ide_pdo_query_id<'a, 'b>(
    pdo: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
) -> DriverStep {
    use QueryIdType::*;
    let ty = { req.read().pnp.as_ref().unwrap().id_type };

    {
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
    }
    complete_req(req, DriverStatus::Success)
}

#[request_handler]
pub async fn ide_pdo_query_resources<'a, 'b>(
    pdo: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
) -> DriverStep {
    let cdx = match pdo.try_devext::<ChildExt>() {
        Ok(x) => x,
        Err(_) => {
            return complete_req(req, DriverStatus::NoSuchDevice);
        }
    };

    let status = {
        let mut w = req.write();
        match w.pnp.as_mut() {
            Some(p) => match cdx.disk_info.as_ref() {
                Some(di) => {
                    p.data_out = RequestData::from_t::<DiskInfo>(*di);
                    DriverStatus::Success
                }
                None => DriverStatus::DeviceNotReady,
            },
            None => DriverStatus::InvalidParameter,
        }
    };

    complete_req(req, status)
}

#[request_handler]
pub async fn ide_pdo_start<'a, 'b>(
    _pdo: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
) -> DriverStep {
    complete_req(req, DriverStatus::Success)
}
