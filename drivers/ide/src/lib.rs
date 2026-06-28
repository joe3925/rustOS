#![cfg(target_arch = "x86_64")]
#![no_std]
#![no_main]
#![feature(const_option_ops)]
#![feature(const_trait_impl)]

extern crate alloc;

mod dev_ext;



use kernel_api::kernel_types::pci::BarKind;
use kernel_api::kernel_types::protocol::pci::PciProtocol;
use kernel_api::pnp::InitComplete;
use kernel_api::pnp::QueryDeviceRelations;
use kernel_api::pnp::QueryId;
use kernel_api::pnp::QueryResources;
use kernel_api::pnp::StartDevice;
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
use kernel_api::device::{open_protocol_to_next_lower, ProtocolHandle, register_protocol, DeviceInit, DeviceObject, DriverObject, publish_stack_protocol};
use kernel_api::irq::IrqBorrowedHandleExt;
use kernel_api::irq::{
    IrqBorrowedHandle, IrqHandle, IrqHandleExt, irq_register_isr, irq_register_isr_gsi, irq_wait_ok,
};
use kernel_api::kernel_types::dma::{FromDevice, IoBuffer, IoBufferAccess, ToDevice};
use kernel_api::kernel_types::io::{
    DeviceControlHandler, DeviceControlOp, DeviceRead, DeviceReadOp, DeviceWrite, DeviceWriteOp,
    DiskInfo,
};
use kernel_api::kernel_types::protocol::disk::{DiskInfoProtocol, DiskInfoProtocolVTable};
use kernel_api::kernel_types::irq::{IrqFrame, IrqMeta};
use kernel_api::kernel_types::pnp::DeviceIds;
use kernel_api::kernel_types::port::Port;
use kernel_api::memory::{PhysAddr, VirtAddr, map_mmio_region, unmap_mmio_region};
use kernel_api::pnp::{
    DeviceRelationType, DriverStep, PnpOp, PnpOps, QueryIdType, ResourceKind,
    ResourceSet, driver_set_evt_device_add, pnp, pnp_create_child_devnode_and_pdo_with_init,
};
use kernel_api::request::{DeviceControl, Read, Write};
use kernel_api::request_handler;
use kernel_api::status::DriverStatus;
use kernel_api::util::wait_duration;

use dev_ext::{ControllerState, DevExt, Ports};

static MOD_NAME: &str = option_env!("CARGO_PKG_NAME").unwrap_or(module_path!());

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    use kernel_api::util::panic_common;
    panic_common(MOD_NAME, info)
}

const ATA_CMD_IDENTIFY: u8 = 0xEC;
const ATA_CMD_READ_SECTORS: u8 = 0x20;
const ATA_CMD_WRITE_SECTORS: u8 = 0x30;
const ATA_CMD_FLUSH_CACHE: u8 = 0xE7;
const IOCTL_BLOCK_FLUSH: u32 = 0xB000_0003;

const ATA_SR_BSY: u8 = 1 << 7;
const ATA_SR_DRDY: u8 = 1 << 6;
const ATA_SR_DRQ: u8 = 1 << 3;
const ATA_SR_ERR: u8 = 1 << 0;

const TIMEOUT_MS: u64 = 10000;

fn complete_req<K>(_req: &mut K, status: DriverStatus) -> DriverStep {
    DriverStep::complete(status)
}

fn continue_req<K>(_req: &mut K) -> DriverStep {
    DriverStep::Continue
}

#[derive(Clone, Copy)]
struct PhysRun {
    cpu_addr: usize,
    byte_len: usize,
}

struct PhysCursor {
    runs: Vec<PhysRun>,
    run_idx: usize,
    run_offset: usize,
    remaining: usize,
}

impl PhysCursor {
    fn from_buffer<'backing, 'data, Access>(
        buffer: &IoBuffer<'backing, 'data, Access>,
        len: usize,
    ) -> Option<Self>
    where
        Access: IoBufferAccess,
    {
        if buffer.len() < len {
            return None;
        }

        let mut runs = Vec::new();
        let mut remaining = len;

        for region in buffer.regions() {
            if remaining == 0 {
                break;
            }

            let mut region_remaining = core::cmp::min(region.len(), remaining);
            let mut frame_offset = region.frame_offset();

            for frame in region.page_frames() {
                if region_remaining == 0 {
                    break;
                }

                let frame_len = usize::try_from(frame.len()).ok()?;

                if frame_offset >= frame_len {
                    frame_offset -= frame_len;
                    continue;
                }

                let cpu_base = frame.cpu_address().as_u64() as usize;
                if cpu_base == 0 {
                    return None;
                }

                let take = core::cmp::min(region_remaining, frame_len - frame_offset);
                let cpu_addr = cpu_base.checked_add(frame_offset)?;

                runs.push(PhysRun {
                    cpu_addr,
                    byte_len: take,
                });

                region_remaining -= take;
                remaining -= take;
                frame_offset = 0;
            }

            if region_remaining != 0 {
                return None;
            }
        }

        if remaining != 0 {
            return None;
        }

        Some(Self {
            runs,
            run_idx: 0,
            run_offset: 0,
            remaining: len,
        })
    }

    fn byte_ptr(&self) -> Option<*mut u8> {
        let run = self.runs.get(self.run_idx)?;
        if self.run_offset >= run.byte_len {
            return None;
        }

        Some(run.cpu_addr.checked_add(self.run_offset)? as *mut u8)
    }

    fn advance(&mut self) -> bool {
        if self.remaining == 0 {
            return false;
        }

        let Some(run) = self.runs.get(self.run_idx) else {
            return false;
        };

        self.remaining -= 1;
        self.run_offset += 1;

        if self.run_offset >= run.byte_len {
            self.run_idx += 1;
            self.run_offset = 0;
        }

        true
    }

    fn read_u8(&mut self) -> Option<u8> {
        if self.remaining == 0 {
            return None;
        }

        let ptr = self.byte_ptr()? as *const u8;
        let value = unsafe { core::ptr::read(ptr) };

        self.advance().then_some(value)
    }

    fn write_u8(&mut self, value: u8) -> bool {
        if self.remaining == 0 {
            return false;
        }

        let Some(ptr) = self.byte_ptr() else {
            return false;
        };

        unsafe {
            core::ptr::write(ptr, value);
        }

        self.advance()
    }

    fn read_u16_le(&mut self) -> Option<u16> {
        let lo = self.read_u8()? as u16;
        let hi = self.read_u8()? as u16;
        Some(lo | (hi << 8))
    }

    fn write_u16_le(&mut self, value: u16) -> bool {
        self.write_u8((value & 0xFF) as u8) && self.write_u8((value >> 8) as u8)
    }
}

fn read_buffer_cursor<'backing, 'data>(
    buffer: &IoBuffer<'backing, 'data, FromDevice>,
    len: usize,
) -> Option<PhysCursor> {
    PhysCursor::from_buffer(buffer, len)
}

fn write_buffer_cursor<'backing, 'data>(
    buffer: &IoBuffer<'backing, 'data, ToDevice>,
    len: usize,
) -> Option<PhysCursor> {
    PhysCursor::from_buffer(buffer, len)
}

extern "C" fn ide_isr(
    _vector: u8,
    _cpu: u32,
    _frame: &mut IrqFrame,
    handle: IrqBorrowedHandle,
    ctx: usize,
) -> bool {
    let io_base = ctx as u16;
    let mut status_port: Port<u8> = Port::new(io_base + 7);
    let _status = unsafe { status_port.read() };

    handle.signal_one(IrqMeta {
        tag: 0,
        data: [0; 3],
    });

    true
}

#[repr(C)]
pub struct ChildExt {
    pub parent_device: Weak<DeviceObject>,
    pub dh: AtomicU8,
    pub present: AtomicBool,
    pub disk_info: Option<DiskInfo>,
}

struct IdePdoIo;

#[inline]
fn ide_lba_sectors(offset: u64, len: usize) -> Result<Option<(u32, u32)>, DriverStatus> {
    if len == 0 {
        return Ok(None);
    }

    if (offset & 0x1ff) != 0 || (len & 0x1ff) != 0 {
        return Err(DriverStatus::InvalidParameter);
    }

    let sector_count = len >> 9;
    if sector_count == 0 || sector_count > u32::MAX as usize {
        return Err(DriverStatus::InvalidParameter);
    }

    let lba = offset >> 9;
    let sectors = sector_count as u32;

    let Some(end_lba) = lba.checked_add(sectors as u64) else {
        return Err(DriverStatus::InvalidParameter);
    };

    if end_lba > (1u64 << 28) {
        return Err(DriverStatus::InvalidParameter);
    }

    Ok(Some((lba as u32, sectors)))
}

fn validate_ide_read_chain<'data>(first: &Read<'data>) -> Result<bool, DriverStatus> {
    let mut any = false;

    for read in first.iter() {
        let Some((_lba, _sectors)) = ide_lba_sectors(read.offset, read.len)? else {
            continue;
        };

        if read.no_buffer {
            return Err(DriverStatus::InvalidParameter);
        }

        let Some(buffer) = read.buffer.as_ref() else {
            return Err(DriverStatus::InvalidParameter);
        };

        if read_buffer_cursor(buffer, read.len).is_none() {
            return Err(DriverStatus::InsufficientResources);
        }

        any = true;
    }

    Ok(any)
}

fn validate_ide_write_chain<'data>(first: &Write<'data>) -> Result<bool, DriverStatus> {
    let mut any = false;

    for write in first.iter() {
        let Some((_lba, _sectors)) = ide_lba_sectors(write.offset, write.len)? else {
            continue;
        };

        if write.no_buffer {
            return Err(DriverStatus::InvalidParameter);
        }

        let Some(buffer) = write.buffer.as_ref() else {
            return Err(DriverStatus::InvalidParameter);
        };

        if write_buffer_cursor(buffer, write.len).is_none() {
            return Err(DriverStatus::InsufficientResources);
        }

        any = true;
    }

    Ok(any)
}

impl DeviceRead for IdePdoIo {
    #[request_handler]
    async fn handler<'req, 'data, 'b>(
        pdo: &Arc<DeviceObject>,
        req: &'b mut Read<'data>,
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

        let any = {
            let r = &*req;
            match validate_ide_read_chain(&r) {
                Ok(any) => any,
                Err(status) => return complete_req(req, status),
            }
        };

        if !any {
            return complete_req(req, DriverStatus::Success);
        }

        let dh = cdx.dh.load(Ordering::Acquire);
        let irq = unsafe { dx.irq() };

        let mut ctrl = dx.controller.lock().await;
        let mut chain_index = 0usize;
        let mut read_status = DriverStatus::Success;

        loop {
            let next = {
                let r = &*req;
                let mut out = Ok(None);

                for (idx, read) in r.iter().enumerate() {
                    if idx < chain_index {
                        continue;
                    }

                    chain_index = idx + 1;

                    let (lba, sectors) = match ide_lba_sectors(read.offset, read.len) {
                        Ok(Some(v)) => v,
                        Ok(None) => continue,
                        Err(status) => {
                            out = Err(status);
                            break;
                        }
                    };

                    let Some(buffer) = read.buffer.as_ref() else {
                        out = Err(DriverStatus::InvalidParameter);
                        break;
                    };

                    let Some(cursor) = read_buffer_cursor(buffer, read.len) else {
                        out = Err(DriverStatus::InsufficientResources);
                        break;
                    };

                    out = Ok(Some((lba, sectors, cursor)));
                    break;
                }

                out
            };

            let Some((lba, sectors, cursor)) = (match next {
                Ok(v) => v,
                Err(status) => {
                    read_status = status;
                    break;
                }
            }) else {
                break;
            };

            if !ata_pio_read_phys_async(&mut ctrl, irq, dh, lba, sectors, cursor).await {
                read_status = DriverStatus::Unsuccessful;
                break;
            }
        }

        drop(ctrl);

        complete_req(req, read_status)
    }
}

impl DeviceWrite for IdePdoIo {
    #[request_handler]
    async fn handler<'req, 'data, 'b>(
        pdo: &Arc<DeviceObject>,
        req: &'b mut Write<'data>,
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

        let any = {
            let r = &*req;
            match validate_ide_write_chain(&r) {
                Ok(any) => any,
                Err(status) => return complete_req(req, status),
            }
        };

        if !any {
            return complete_req(req, DriverStatus::Success);
        }

        let dh = cdx.dh.load(Ordering::Acquire);
        let irq = unsafe { dx.irq() };

        let mut ctrl = dx.controller.lock().await;
        let mut chain_index = 0usize;
        let mut write_status = DriverStatus::Success;

        loop {
            let next = {
                let r = &*req;
                let mut out = Ok(None);

                for (idx, write) in r.iter().enumerate() {
                    if idx < chain_index {
                        continue;
                    }

                    chain_index = idx + 1;

                    let (lba, sectors) = match ide_lba_sectors(write.offset, write.len) {
                        Ok(Some(v)) => v,
                        Ok(None) => continue,
                        Err(status) => {
                            out = Err(status);
                            break;
                        }
                    };

                    let Some(buffer) = write.buffer.as_ref() else {
                        out = Err(DriverStatus::InvalidParameter);
                        break;
                    };

                    let Some(cursor) = write_buffer_cursor(buffer, write.len) else {
                        out = Err(DriverStatus::InsufficientResources);
                        break;
                    };

                    out = Ok(Some((lba, sectors, cursor)));
                    break;
                }

                out
            };

            let Some((lba, sectors, cursor)) = (match next {
                Ok(v) => v,
                Err(status) => {
                    write_status = status;
                    break;
                }
            }) else {
                break;
            };

            if !ata_pio_write_phys_async(&mut ctrl, irq, dh, lba, sectors, cursor).await {
                write_status = DriverStatus::Unsuccessful;
                break;
            }
        }

        drop(ctrl);

        complete_req(req, write_status)
    }
}

impl DeviceControlHandler for IdePdoIo {
    #[request_handler]
    async fn handler<'req, 'data, 'b>(
        pdo: &Arc<DeviceObject>,
        req: &'b mut DeviceControl<'data>,
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

        let code = { req.code };

        match code {
            IOCTL_BLOCK_FLUSH => {
                let irq = unsafe { dx.irq() };
                let mut ctrl = dx.controller.lock().await;

                unsafe {
                    ctrl.ports.command.write(ATA_CMD_FLUSH_CACHE);
                }

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
}

#[unsafe(no_mangle)]
pub extern "C" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    driver_set_evt_device_add(driver, ide_device_add);
    DriverStatus::Success
}

pub extern "C" fn ide_device_add(
    _driver: &Arc<DriverObject>,
    dev_init: &mut DeviceInit,
) -> DriverStep {
    let mut vt = PnpOps::new();

    vt.init_complete.set(ide_init_complete);
    vt.query_device_relations.set(ide_pnp_query_devrels);

    let init = DeviceInit::with_pnp(Some(vt));
    *dev_init = init;

    dev_init.set_dev_ext_from(DevExt::new(0x1F0, 0x3F4));

    DriverStep::complete(DriverStatus::Success)
}

#[request_handler]
async fn ide_init_complete<'req, 'data, 'b>(
    dev: &Arc<DeviceObject>,
    _op: PnpOp,
    req: &'b mut InitComplete,
) -> DriverStep {
    let proto = open_protocol_to_next_lower::<PciProtocol>(dev).ok();

    if proto.is_some() || pnp::send_next_lower(dev.clone(), &mut QueryResources { resources: ResourceSet::default() }).await != DriverStatus::NoSuchDevice {
        let bars = parse_ide_bars(proto.as_ref());

        let dx = dev.try_devext::<DevExt>().expect("ide: FDO DevExt missing");

        let cb = bars.cmd;
        let ctl = bars.ctl;
        let alt = ctl.wrapping_add(2);

        {
            let mut ctrl = dx.controller.lock().await;
            ctrl.ports = Ports::new(cb, alt);
        }

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

        {
            let mut ctrl = dx.controller.lock().await;
            unsafe {
                ctrl.ports.control.write(0x00);
            }
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
async fn ide_pnp_query_devrels<'req, 'data, 'b>(
    dev: &Arc<DeviceObject>,
    _op: PnpOp,
    req: &'b mut QueryDeviceRelations,
) -> DriverStep {
    let relation = req.relation;

    if relation == DeviceRelationType::BusRelations {
        ide_enumerate_bus(dev);
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

    let mut ctrl = dx.controller.lock_blocking();
    let master_words = ata_identify_words_sync(&mut ctrl.ports, 0xE0);
    let slave_words = ata_identify_words_sync(&mut ctrl.ports, 0xF0);
    drop(ctrl);

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

    let mut pvt = PnpOps::new();
    pvt.query_id.set(ide_pdo_query_id);
    pvt.start_device.set(ide_pdo_start);

    let mut child_init = DeviceInit::with_pnp(Some(pvt));

    child_init.ops.register::<DeviceReadOp, IdePdoIo>();
    child_init.ops.register::<DeviceWriteOp, IdePdoIo>();
    child_init.ops.register::<DeviceControlOp, IdePdoIo>();

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

    let (_dn, pdo) = pnp_create_child_devnode_and_pdo_with_init(
        &parent_dn, short_name, instance, ids, class, child_init,
    );
}

const DISK_INFO_VTABLE: DiskInfoProtocolVTable = DiskInfoProtocolVTable {
    query: ide_disk_info,
};

extern "C" fn ide_disk_info(device: &Arc<DeviceObject>) -> Result<DiskInfo, DriverStatus> {
    let cdx = device.try_devext::<ChildExt>().map_err(|_| DriverStatus::NoSuchDevice)?;
    if let Some(di) = cdx.disk_info {
        Ok(di)
    } else {
        Err(DriverStatus::Unsuccessful)
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


fn parse_ide_bars(proto: Option<&ProtocolHandle<PciProtocol>>) -> IdeBars {
    let mut bars = IdeBars::default();

    if let Some(proto) = proto {
        for i in 0..6 {
            if let Some(b) = (proto.get_bar)(&proto.provider(), i) {
                if b.kind != BarKind::Io {
                    continue;
                }
                match i {
                    0 => bars.cmd = b.base as u16,
                    1 => bars.ctl = b.base as u16,
                    4 => bars.bm = b.base as u16,
                    _ => {
                        if bars.cmd == 0 && (b.size == 8 || b.size == 16) {
                            bars.cmd = b.base as u16;
                        } else if bars.ctl == 0 && (b.size == 4 || b.size == 2) {
                            bars.ctl = b.base as u16;
                        } else if bars.bm == 0 && (b.size == 0x10 || b.size == 0x08) {
                            bars.bm = b.base as u16;
                        }
                    }
                }
            }
        }
        bars.irq_line = (proto.get_interrupt_line)(&proto.provider());
        bars.gsi = (proto.get_gsi)(&proto.provider()).map(|x| x as u32);
    }

    if bars.cmd == 0 {
        bars.cmd = 0x1F0;
        bars.ctl = 0x3F4;
        bars.irq_line = Some(14);
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

    unsafe {
        ports.drive_head.write(dh);
    }

    io_wait_400ns(&mut ports.control);

    unsafe {
        ports.command.write(ATA_CMD_IDENTIFY);
    }

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

async fn ata_pio_read_phys_async(
    ctrl: &mut ControllerState,
    irq: &Option<IrqHandle>,
    dh: u8,
    mut lba: u32,
    mut sectors: u32,
    mut out: PhysCursor,
) -> bool {
    let p = &mut ctrl.ports;

    while sectors > 0 {
        let chunk = core::cmp::min(sectors, 256);
        let sc = if chunk == 256 { 0u8 } else { chunk as u8 };

        if !wait_ready_async(p, irq, TIMEOUT_MS).await {
            return false;
        }

        let devsel = (dh & 0xF0) | ((lba >> 24) as u8 & 0x0F);

        unsafe {
            p.drive_head.write(devsel);
        }

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

            for _ in 0..256 {
                let word: u16 = unsafe { p.data.read() };

                if !out.write_u16_le(word) {
                    return false;
                }
            }
        }

        lba = lba.wrapping_add(chunk);
        sectors -= chunk;
    }

    true
}

async fn ata_pio_write_phys_async(
    ctrl: &mut ControllerState,
    irq: &Option<IrqHandle>,
    dh: u8,
    mut lba: u32,
    mut sectors: u32,
    mut data: PhysCursor,
) -> bool {
    let p = &mut ctrl.ports;

    while sectors > 0 {
        let chunk = core::cmp::min(sectors, 256);
        let sc = if chunk == 256 { 0u8 } else { chunk as u8 };

        if !wait_ready_async(p, irq, TIMEOUT_MS).await {
            return false;
        }

        let devsel = (dh & 0xF0) | ((lba >> 24) as u8 & 0x0F);

        unsafe {
            p.drive_head.write(devsel);
        }

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
                if !wait_drq_poll_brief(p) {
                    return false;
                }
            } else if !wait_drq_async(p, irq, TIMEOUT_MS).await {
                return false;
            }

            for _ in 0..256 {
                let Some(word) = data.read_u16_le() else {
                    return false;
                };

                unsafe {
                    p.data.write(word);
                }
            }
        }

        lba = lba.wrapping_add(chunk);
        sectors -= chunk;
    }

    if !wait_not_busy_async(p, irq, TIMEOUT_MS).await {
        return false;
    }

    unsafe {
        p.command.write(ATA_CMD_FLUSH_CACHE);
    }

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
pub async fn ide_pdo_query_id<'req, 'data, 'b>(
    pdo: &Arc<DeviceObject>,
    _op: PnpOp,
    req: &'b mut QueryId,
) -> DriverStep {
    use QueryIdType::*;

    match req.id_type {
        HardwareIds => {
            req.ids.push("IDE\\Disk".into());
            req.ids.push("GenDisk".into());
        }
        CompatibleIds => {
            req.ids.push("IDE\\Disk".into());
            req.ids.push("GenDisk".into());
        }
        DeviceId => {
            req.ids.push("IDE\\Disk".into());
        }
        InstanceId => {
            req.ids.push(
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

    complete_req(req, DriverStatus::Success)
}

#[request_handler]
pub async fn ide_pdo_start<'req, 'data, 'b>(
    _pdo: &Arc<DeviceObject>,
    _op: PnpOp,
    req: &'b mut StartDevice,
) -> DriverStep {
    if let Some(dn) = _pdo.dev_node.get() {
        if let Some(dn) = dn.upgrade() {
            register_protocol::<DiskInfoProtocol>(_pdo, &DISK_INFO_VTABLE);
            publish_stack_protocol::<DiskInfoProtocol>(&dn);
        }
    }
    complete_req(req, DriverStatus::Success)
}
