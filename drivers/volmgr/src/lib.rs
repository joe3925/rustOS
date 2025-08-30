#![no_std]
#![no_main]

extern crate alloc;

use crate::alloc::vec;
use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};
use core::{mem::size_of, panic::PanicInfo};
use kernel_api::{GptHeader, GptPartitionEntry};

use kernel_api::{
    DeviceObject, DriverObject, DriverStatus, KernelAllocator, Request, RequestType,
    alloc_api::{
        DeviceIds, DeviceInit, PnpRequest,
        ffi::{
            driver_set_evt_device_add, pnp_complete_request,
            pnp_create_child_devnode_and_pdo_with_init, pnp_forward_request_to_next_lower,
        },
    },
    println,
};

#[global_allocator]
static ALLOCATOR: KernelAllocator = KernelAllocator;
mod msvc_shims;

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("{}", info);
    loop {}
}

#[repr(C)]
struct VolExt {
    have_gpt: bool,
    have_entry: bool,
    hdr: GptHeader,
    entry: GptPartitionEntry,
    enumerated: AtomicBool,
}

#[inline]
fn ext_mut<T>(dev: &Arc<DeviceObject>) -> &mut T {
    unsafe { &mut *((&*dev.dev_ext).as_ptr() as *const T as *mut T) }
}

#[inline]
fn guid_to_string(g: &[u8; 16]) -> String {
    let d1 = u32::from_le_bytes([g[0], g[1], g[2], g[3]]);
    let d2 = u16::from_le_bytes([g[4], g[5]]);
    let d3 = u16::from_le_bytes([g[6], g[7]]);
    alloc::format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        d1,
        d2,
        d3,
        g[8],
        g[9],
        g[10],
        g[11],
        g[12],
        g[13],
        g[14],
        g[15]
    )
}

#[unsafe(no_mangle)]
pub extern "win64" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    unsafe { driver_set_evt_device_add(driver, vol_device_add) };
    DriverStatus::Success
}

pub extern "win64" fn vol_device_add(
    _driver: &Arc<DriverObject>,
    dev_init: &mut DeviceInit,
) -> DriverStatus {
    dev_init.dev_ext_size = size_of::<VolExt>();
    dev_init.evt_device_prepare_hardware = Some(vol_prepare_hardware);
    dev_init.evt_bus_enumerate_devices = Some(vol_enumerate_devices);
    dev_init.io_read = Some(vol_pdo_read);
    dev_init.io_write = Some(vol_pdo_write);
    DriverStatus::Success
}

extern "win64" fn vol_queryres_complete(child: &mut Request, ctx: usize) {
    let dev = unsafe { Arc::from_raw(ctx as *const DeviceObject) };

    if child.status == DriverStatus::Success {
        let dx = ext_mut::<VolExt>(&dev);
        let blob = &child.pnp.as_ref().unwrap().blob_out;

        dx.have_gpt = false;
        dx.have_entry = false;

        if blob.len() == 512 {
            let hdr: GptHeader = unsafe { core::ptr::read(blob.as_ptr() as *const _) };
            dx.hdr = hdr;
            dx.have_gpt = true;
        } else if blob.len() == 512 + 128 {
            let hdr: GptHeader = unsafe { core::ptr::read(blob.as_ptr() as *const _) };
            let ent_off = 512;
            let ent: GptPartitionEntry =
                unsafe { core::ptr::read(blob.as_ptr().add(ent_off) as *const _) };
            dx.hdr = hdr;
            dx.entry = ent;
            dx.have_gpt = true;
            dx.have_entry = true;
        }
    }
}

extern "win64" fn vol_prepare_hardware(dev: &Arc<DeviceObject>) -> DriverStatus {
    let mut req = Request::new(RequestType::Pnp, Box::new([]));
    req.pnp = Some(PnpRequest {
        minor_function: kernel_api::PnpMinorFunction::QueryResources,
        relation: kernel_api::DeviceRelationType::TargetDeviceRelation,
        id_type: kernel_api::QueryIdType::DeviceId,
        ids_out: Vec::new(),
        blob_out: Vec::new(),
    });

    let ctx = Arc::into_raw(dev.clone()) as usize;
    req.set_completion(vol_queryres_complete, ctx);

    let _ = unsafe { pnp_forward_request_to_next_lower(dev, &mut req) };
    DriverStatus::Success
}

pub extern "win64" fn vol_enumerate_devices(
    device: &Arc<DeviceObject>,
    request: &mut Request,
) -> DriverStatus {
    let dx = ext_mut::<VolExt>(device);

    if !dx.have_entry {
        request.status = DriverStatus::Success;
        return DriverStatus::Success;
    }
    if dx.enumerated.swap(true, Ordering::AcqRel) {
        request.status = DriverStatus::Success;
        return DriverStatus::Success;
    }

    let parent_dn = match device.dev_node.upgrade() {
        Some(dn) => dn,
        None => {
            request.status = DriverStatus::Unsuccessful;
            return DriverStatus::Unsuccessful;
        }
    };

    let zero = [0u8; 16];

    const EFI_SYSTEM: [u8; 16] = [
        0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9,
        0x3B,
    ];
    const BIOS_BOOT: [u8; 16] = [
        0x48, 0x61, 0x68, 0x21, 0x49, 0x64, 0x6F, 0x6E, 0x74, 0x4E, 0x65, 0x66, 0x64, 0x45, 0x46,
        0x49,
    ];

    let ptype = dx.entry.partition_type_guid;
    if ptype == zero || ptype == EFI_SYSTEM || ptype == BIOS_BOOT {
        request.status = DriverStatus::Success;
        return DriverStatus::Success;
    }

    let part_guid_s = guid_to_string(&dx.entry.unique_partition_guid);
    let name = alloc::format!("Volume{}", &part_guid_s[..8]);
    let inst = alloc::format!("STOR\\VOLUME\\{}\\0000", part_guid_s);

    let ids = DeviceIds {
        hardware: vec!["STOR\\Volume".into(), "STOR\\Volume\\GPT".into()],
        compatible: vec!["STOR\\Volume".into()],
    };

    let mut init = DeviceInit {
        dev_ext_size: 0,
        io_read: None,
        io_write: None,
        io_device_control: None,
        evt_device_prepare_hardware: None,
        evt_bus_enumerate_devices: None,
        evt_pnp: None,
    };

    let (_dn_child, _pdo) = unsafe {
        pnp_create_child_devnode_and_pdo_with_init(
            &parent_dn,
            name,
            inst,
            ids,
            Some("volume".into()),
            init,
        )
    };

    request.status = DriverStatus::Success;
    DriverStatus::Success
}

pub extern "win64" fn vol_pdo_read(dev: &Arc<DeviceObject>, parent: &mut Request, _buf_len: usize) {
    let _ = unsafe { pnp_forward_request_to_next_lower(dev, parent) };
}

pub extern "win64" fn vol_pdo_write(
    dev: &Arc<DeviceObject>,
    parent: &mut Request,
    _buf_len: usize,
) {
    let _ = unsafe { pnp_forward_request_to_next_lower(dev, parent) };
}
