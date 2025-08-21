#![no_std]
#![no_main]

extern crate alloc;

mod dev_ext;
mod msvc_shims;

use alloc::{boxed::Box, string::ToString, sync::Arc};
use core::{mem::size_of, panic::PanicInfo, ptr};
use dev_ext::DevExt;
use kernel_api::{
    DeviceObject, DeviceRelationType, DriverObject, DriverStatus, KernelAllocator, Request,
    RequestType, ResourceKind,
    alloc_api::{
        DeviceIds, DeviceInit,
        ffi::{
            InvalidateDeviceRelations, driver_set_evt_device_add, pnp_complete_request,
            pnp_create_child_devnode_and_pdo_with_init, pnp_forward_request_to_next_lower,
        },
    },
    x86_64::instructions::port::Port,
};

// =========================== Global ===========================

#[global_allocator]
static ALLOCATOR: KernelAllocator = KernelAllocator;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

// =========================== IOCTLs & wire formats ===========================

pub const IOCTL_IDE_IDENTIFY: u32 = 0x8000_0100;
pub const IOCTL_IDE_READ_LBA28: u32 = 0x8000_0101;

#[repr(C)]
pub struct IdeReadLba28 {
    pub lba: u32,     // 28-bit effective
    pub sectors: u16, // 1..=256 (256 => 0 on-wire)
}

// =========================== ATA constants ===========================

const ATA_CMD_IDENTIFY: u8 = 0xEC;
const ATA_CMD_READ_SECTORS: u8 = 0x20;

const ATA_SR_BSY: u8 = 1 << 7;
const ATA_SR_DRDY: u8 = 1 << 6;
const ATA_SR_DRQ: u8 = 1 << 3;
const ATA_SR_ERR: u8 = 1 << 0;

// =========================== Driver entry ===========================

#[unsafe(no_mangle)]
pub extern "win64" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    unsafe { driver_set_evt_device_add(driver, ide_device_add) };
    DriverStatus::Success
}

pub extern "win64" fn ide_device_add(
    _driver: &Arc<DriverObject>,
    dev_init_ptr: &mut DeviceInit,
) -> DriverStatus {
    dev_init_ptr.dev_ext_size = size_of::<DevExt>();
    dev_init_ptr.evt_pnp = Some(ide_pnp_dispatch);
    dev_init_ptr.io_device_control = Some(ioctl_handler);
    DriverStatus::Success
}

// =========================== PnP path (async Start → QueryResources) ===========================

#[repr(C)]
struct PrepareHardwareCtx {
    device: Arc<DeviceObject>,
    start_req: Box<Request>,
}

pub extern "win64" fn ide_pnp_dispatch(dev: &Arc<DeviceObject>, req: &mut Request) {
    use kernel_api::alloc_api::PnpRequest;
    use kernel_api::{DeviceRelationType, PnpMinorFunction};

    let Some(pnp) = req.pnp.as_mut() else {
        req.status = DriverStatus::InvalidParameter;
        unsafe { pnp_complete_request(req) };
        return;
    };

    match pnp.minor_function {
        PnpMinorFunction::StartDevice => {
            let ctx = Box::into_raw(Box::new(PrepareHardwareCtx {
                device: Arc::clone(dev),
                start_req: Box::new(unsafe { core::ptr::read(req) }),
            })) as usize;

            let mut q = Request {
                id: 0,
                kind: RequestType::Pnp,
                data: Box::new([]),
                ioctl_code: None,
                completed: false,
                status: DriverStatus::Pending,
                pnp: Some(PnpRequest {
                    minor_function: PnpMinorFunction::QueryResources,
                    relation: kernel_api::DeviceRelationType::TargetDeviceRelation,
                    id_type: kernel_api::QueryIdType::CompatibleIds,
                    ids_out: alloc::vec::Vec::new(),
                    blob_out: alloc::vec::Vec::new(),
                }),
                completion_routine: Some(ide_on_query_resources_complete),
                completion_context: ctx,
            };
            let _ = unsafe { pnp_forward_request_to_next_lower(dev, &mut q) };
        }

        PnpMinorFunction::QueryDeviceRelations => {
            if pnp.relation == DeviceRelationType::BusRelations {
                ide_enumerate_bus(dev);
                req.status = DriverStatus::Success;
                unsafe { pnp_complete_request(req) };
            } else {
                let _ = unsafe { pnp_forward_request_to_next_lower(dev, req) };
            }
        }

        _ => {
            let _ = unsafe { pnp_forward_request_to_next_lower(dev, req) };
        }
    }
}

extern "win64" fn ide_on_query_resources_complete(req: &mut Request, ctx: usize) {
    use kernel_api::alloc_api::ffi::{pnp_complete_request, pnp_forward_request_to_next_lower};

    let mut prep = unsafe { Box::from_raw(ctx as *mut PrepareHardwareCtx) };
    let device = prep.device;

    if req.status != DriverStatus::Success {
        prep.start_req.status = req.status;
        unsafe { pnp_complete_request(&mut prep.start_req) };
        return;
    }

    // Parse port BARs from parent blob and program DevExt
    let pnp_payload = req.pnp.as_ref().expect("missing PnP payload");
    let bars = parse_ide_bars(&pnp_payload.blob_out);

    let dx: &mut DevExt =
        unsafe { &mut *((&*device.dev_ext).as_ptr() as *const DevExt as *mut DevExt) };

    let cb = bars.cmd;
    let ctb = bars.ctl; // control-block base (e.g., 0x3F4); ALT-STATUS = base+2

    dx.data_port = Port::new(cb + 0);
    dx.error_port = Port::new(cb + 1);
    dx.sector_count_port = Port::new(cb + 2);
    dx.lba_lo_port = Port::new(cb + 3);
    dx.lba_mid_port = Port::new(cb + 4);
    dx.lba_hi_port = Port::new(cb + 5);
    dx.drive_head_port = Port::new(cb + 6);
    dx.command_port = Port::new(cb + 7);

    dx.alternative_command_port = Port::new(ctb + 2); // ALT-STATUS (read)
    dx.control_port = Port::new(ctb + 2); // DEVICE CONTROL (write)

    dx.present = true;
    dx.enumerated = false;

    // Forward original Start down. If lower stack returns NoSuchDevice, complete Success.
    let status = unsafe { pnp_forward_request_to_next_lower(&device, &mut prep.start_req) };
    if status == DriverStatus::NoSuchDevice {
        prep.start_req.status = DriverStatus::Success;
        unsafe { pnp_complete_request(&mut prep.start_req) };
    }

    unsafe { InvalidateDeviceRelations(&device, DeviceRelationType::BusRelations) };
}

// =========================== Parent resource parsing ===========================

#[derive(Default, Clone, Copy)]
struct IdeBars {
    // Primary channel only for minimal path
    cmd: u16, // BAR0 or legacy 0x1F0
    ctl: u16, // BAR1 control-block BASE (legacy 0x3F4); ALT-STATUS at base+2
    bm: u16,  // BMIDE BAR (BAR4), optional
}

fn parse_ide_bars(blob: &[u8]) -> IdeBars {
    // Parent blob format: "RSRC"<ver><count> repeating (kind,u32)(flags,u32)(start,u64)(len,u64)
    let mut bars = IdeBars::default();
    if blob.len() < 12 || &blob[0..4] != b"RSRC" {
        // Legacy fallback: cmd at 0x1F0, control-block base at 0x3F4
        bars.cmd = 0x1F0;
        bars.ctl = 0x3F4; // not 0x3F6; ALT-STATUS is ctl+2 == 0x3F6
        return bars;
    }

    let mut off = 12usize;
    while off + 24 <= blob.len() {
        let kind = u32::from_le_bytes([blob[off + 0], blob[off + 1], blob[off + 2], blob[off + 3]]);
        let _flg = u32::from_le_bytes([blob[off + 4], blob[off + 5], blob[off + 6], blob[off + 7]]);
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

        if kind == ResourceKind::Port as u32 {
            let base = start as u16;
            match len as u16 {
                8 | 16 => {
                    if bars.cmd == 0 {
                        bars.cmd = base;
                    }
                }
                4 | 2 => {
                    if bars.ctl == 0 {
                        bars.ctl = base; // expect 0x3F4; ALT-STATUS at base+2
                    }
                }
                0x10 | 0x08 if bars.bm == 0 => {
                    bars.bm = base;
                }
                _ => {}
            }
        }
    }

    if bars.cmd == 0 {
        bars.cmd = 0x1F0;
    }
    if bars.ctl == 0 {
        bars.ctl = 0x3F4; // ensure base+2 = 0x3F6
    }
    bars
}

// =========================== Bus enumeration ===========================

fn ide_enumerate_bus(parent: &Arc<DeviceObject>) {
    let dx: &mut DevExt =
        unsafe { &mut *((&*parent.dev_ext).as_ptr() as *const DevExt as *mut DevExt) };
    if dx.enumerated || !dx.present {
        return;
    }

    let mut found = false;

    // Probe primary master (DH 0xE0) and primary slave (DH 0xF0)
    if ata_probe_drive(dx, 0xE0) {
        create_child_pdo(parent, 0, 0);
        found = true;
    }
    if ata_probe_drive(dx, 0xF0) {
        create_child_pdo(parent, 0, 1);
        found = true;
    }

    dx.enumerated = true;

    if !found {
        // nothing found; do nothing else
    }
}

fn create_child_pdo(parent: &Arc<DeviceObject>, channel: u8, drive: u8) {
    let parent_dn = unsafe {
        (*(Arc::as_ptr(parent) as *const DeviceObject))
            .dev_node
            .upgrade()
            .expect("IDE FDO has no DevNode")
    };

    let ids = DeviceIds {
        hardware: alloc::vec![alloc::string::String::from("IDE\\DISK")],
        compatible: alloc::vec![alloc::string::String::from("IDE\\GenDisk")],
    };

    let child_init = DeviceInit {
        dev_ext_size: 0,
        io_read: None,
        io_write: None,
        io_device_control: None,
        evt_device_prepare_hardware: None,
        evt_bus_enumerate_devices: None,
        evt_pnp: None,
    };

    let short_name = alloc::format!("IDE_Disk_{}_{}", channel, drive);
    let instance = alloc::format!("IDE\\CH_{:02}&DRV_{:02}", channel, drive);

    let (pdo, _) = unsafe {
        pnp_create_child_devnode_and_pdo_with_init(
            &parent_dn,
            short_name,
            instance,
            ids,
            Some("disk".to_string()),
            child_init,
        )
    };
}

fn ata_probe_drive(dx: &mut DevExt, dh: u8) -> bool {
    unsafe {
        dx.drive_head_port.write(dh);
    }
    io_wait_400ns(&mut dx.alternative_command_port);

    unsafe { dx.command_port.write(ATA_CMD_IDENTIFY) };

    let st: u8 = unsafe { dx.command_port.read() };
    if st == 0 || (st & ATA_SR_ERR) != 0 {
        return false;
    }

    for _ in 0..256 {
        let _w: u16 = unsafe { dx.data_port.read() };
    }
    true
}

// =========================== IOCTL path ===========================

pub extern "win64" fn ioctl_handler(device: &Arc<DeviceObject>, request: &mut Request, code: u32) {
    let dx: &mut DevExt =
        unsafe { &mut *((&*device.dev_ext).as_ptr() as *const DevExt as *mut DevExt) };

    if !dx.present {
        request.status = DriverStatus::NoSuchDevice;
        unsafe { pnp_complete_request(request) };
        return;
    }

    match code {
        IOCTL_IDE_IDENTIFY => {
            let ok = ata_identify(dx, request);
            request.status = if ok {
                DriverStatus::Success
            } else {
                DriverStatus::IoError
            };
            unsafe { pnp_complete_request(request) };
        }
        IOCTL_IDE_READ_LBA28 => {
            let ok = ata_read_lba28(dx, request);
            request.status = if ok {
                DriverStatus::Success
            } else {
                DriverStatus::IoError
            };
            unsafe { pnp_complete_request(request) };
        }
        _ => {
            request.status = DriverStatus::InvalidParameter;
            unsafe { pnp_complete_request(request) };
        }
    }
}

// =========================== ATA helpers and ops ===========================

fn io_wait_400ns(alt: &mut Port<u8>) {
    unsafe {
        let _ = alt.read();
        let _ = alt.read();
        let _ = alt.read();
        let _ = alt.read();
    }
}

fn wait_not_busy(alt: &mut Port<u8>) -> bool {
    for _ in 0..100_000 {
        let s = unsafe { alt.read() };
        if (s & ATA_SR_BSY) == 0 {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

fn wait_drq_set(alt: &mut Port<u8>) -> bool {
    for _ in 0..100_000 {
        let s = unsafe { alt.read() };
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
}

fn ata_identify(dx: &mut DevExt, req: &mut Request) -> bool {
    if req.data.len() < 512 {
        return false;
    }

    unsafe {
        dx.drive_head_port.write(0xE0); // master by default
    }
    io_wait_400ns(&mut dx.alternative_command_port);

    unsafe {
        dx.sector_count_port.write(0u8);
        dx.lba_lo_port.write(0u8);
        dx.lba_mid_port.write(0u8);
        dx.lba_hi_port.write(0u8);
        dx.command_port.write(ATA_CMD_IDENTIFY);
    }

    if !wait_not_busy(&mut dx.alternative_command_port) {
        return false;
    }
    if !wait_drq_set(&mut dx.alternative_command_port) {
        return false;
    }

    let mut i = 0usize;
    while i < 512 {
        let w: u16 = unsafe { dx.data_port.read() };
        req.data[i] = (w & 0xFF) as u8;
        req.data[i + 1] = (w >> 8) as u8;
        i += 2;
    }
    true
}

fn ata_read_lba28(dx: &mut DevExt, req: &mut Request) -> bool {
    if req.data.len() < size_of::<IdeReadLba28>() {
        return false;
    }

    let params: IdeReadLba28 = unsafe { ptr::read(req.data.as_ptr() as *const IdeReadLba28) };
    let lba = params.lba & 0x0FFF_FFFF;
    let mut sectors = params.sectors;
    if sectors == 0 {
        return false;
    }

    let out_needed = (sectors as usize) * 512;
    if req.data.len() < size_of::<IdeReadLba28>() + out_needed {
        return false;
    }

    // Select master for now (extend later to route by PDO)
    unsafe {
        dx.drive_head_port.write(0xE0 | ((lba >> 24) as u8 & 0x0F));
    }
    io_wait_400ns(&mut dx.alternative_command_port);

    let sc = if sectors == 256 { 0u8 } else { sectors as u8 };

    unsafe {
        dx.sector_count_port.write(sc);
        dx.lba_lo_port.write((lba & 0xFF) as u8);
        dx.lba_mid_port.write(((lba >> 8) & 0xFF) as u8);
        dx.lba_hi_port.write(((lba >> 16) & 0xFF) as u8);
        dx.command_port.write(ATA_CMD_READ_SECTORS);
    }

    let out = &mut req.data[size_of::<IdeReadLba28>()..];
    let mut off = 0usize;

    while sectors > 0 {
        if !wait_drq_set(&mut dx.alternative_command_port) {
            return false;
        }
        for _ in 0..256 {
            let w: u16 = unsafe { dx.data_port.read() };
            out[off] = (w & 0xFF) as u8;
            out[off + 1] = (w >> 8) as u8;
            off += 2;
        }
        sectors -= 1;
    }
    true
}
