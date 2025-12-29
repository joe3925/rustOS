#![no_std]
#![no_main]
#![feature(const_option_ops)]
#![feature(const_trait_impl)]
extern crate alloc;

use crate::alloc::vec;
use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};
use core::mem;
use core::mem::take;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering::Acquire;
use core::sync::atomic::Ordering::Relaxed;
use core::sync::atomic::Ordering::Release;
use core::sync::atomic::{AtomicBool, Ordering};
use core::{mem::size_of, panic::PanicInfo};
use kernel_api::RequestExt;
use kernel_api::acpi::handler;
use kernel_api::device::DevExtRef;
use kernel_api::device::DeviceInit;
use kernel_api::device::DeviceObject;
use kernel_api::device::DriverObject;
use kernel_api::kernel_types::io::IoTarget;
use kernel_api::kernel_types::io::IoType;
use kernel_api::kernel_types::io::IoVtable;
use kernel_api::kernel_types::io::PartitionInfo;
use kernel_api::kernel_types::io::Synchronization;
use kernel_api::kernel_types::pnp::DeviceIds;
use kernel_api::pnp::DeviceRelationType;
use kernel_api::pnp::DriverStep;
use kernel_api::pnp::PnpMinorFunction;
use kernel_api::pnp::PnpRequest;
use kernel_api::pnp::PnpVtable;
use kernel_api::pnp::QueryIdType;
use kernel_api::pnp::driver_set_evt_device_add;
use kernel_api::pnp::pnp_complete_request;
use kernel_api::pnp::pnp_create_child_devnode_and_pdo_with_init;
use kernel_api::pnp::pnp_forward_request_to_next_lower;
use kernel_api::pnp::pnp_get_device_target;
use kernel_api::pnp::pnp_send_request;
use kernel_api::println;
use kernel_api::request::Request;
use kernel_api::request::RequestType;
use kernel_api::request::TraversalPolicy;
use kernel_api::request_handler;
use kernel_api::status::DriverStatus;
use kernel_api::util::bytes_to_box;
use spin::Once;
use spin::RwLock;

mod msvc_shims;

static MOD_NAME: &str = option_env!("CARGO_PKG_NAME").unwrap_or(module_path!());

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    unsafe {
        use kernel_api::util::panic_common;
        panic_common(MOD_NAME, info)
    }
}
#[repr(C)]
#[derive(Default)]
struct VolExt {
    part: Once<PartitionInfo>,
    enumerated: AtomicBool,
}

#[inline]
pub fn ext<'a, T>(dev: &'a Arc<DeviceObject>) -> DevExtRef<'a, T> {
    dev.try_devext().expect("Failed to get partmgr dev ext")
}
#[repr(C)]
#[derive(Default)]
struct VolPdoExt {
    backing: Once<IoTarget>,
    part: Once<PartitionInfo>,
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
    driver_set_evt_device_add(driver, vol_device_add);
    DriverStatus::Success
}

pub extern "win64" fn vol_device_add(
    _driver: Arc<DriverObject>,
    dev_init: &mut DeviceInit,
) -> DriverStep {
    let mut pnp_vtable = PnpVtable::new();
    pnp_vtable.set(PnpMinorFunction::StartDevice, vol_prepare_hardware);
    pnp_vtable.set(
        PnpMinorFunction::QueryDeviceRelations,
        vol_enumerate_devices,
    );

    dev_init.set_dev_ext_default::<VolExt>();
    dev_init.pnp_vtable = Some(pnp_vtable);
    DriverStep::complete(DriverStatus::Success)
}

#[request_handler]
pub async fn vol_prepare_hardware(
    dev: Arc<DeviceObject>,
    _req: Arc<RwLock<Request>>,
) -> DriverStep {
    let mut req = Request::new_pnp(
        PnpRequest {
            minor_function: PnpMinorFunction::QueryResources,
            relation: DeviceRelationType::TargetDeviceRelation,
            id_type: QueryIdType::DeviceId,
            ids_out: Vec::new(),
            blob_out: Vec::new(),
        },
        Box::new([]),
    );

    let req_lock = Arc::new(RwLock::new(req));
    let st = pnp_forward_request_to_next_lower(dev.clone(), req_lock.clone()).await;
    if st == DriverStatus::NoSuchDevice {
        return DriverStep::complete(DriverStatus::Success);
    }

    let mut g = req_lock.write();
    let mut dx = ext::<VolExt>(&dev);

    if g.status != DriverStatus::Success {
        return DriverStep::complete(g.status);
    }

    let pi_opt: Option<PartitionInfo> = {
        let pnp = g.pnp.as_mut().unwrap();
        let buf = take(&mut pnp.blob_out);

        if buf.len() == core::mem::size_of::<PartitionInfo>() {
            let boxed_bytes: Box<[u8]> = buf.into_boxed_slice();
            let boxed_pi: Box<PartitionInfo> = unsafe { bytes_to_box(boxed_bytes) };
            Some(*boxed_pi)
        } else {
            None
        }
    };
    if let Some(pi) = pi_opt {
        dx.part.call_once(|| pi);
    }

    DriverStep::Continue
}
#[request_handler]
pub async fn vol_enumerate_devices(
    device: Arc<DeviceObject>,
    request: Arc<RwLock<Request>>,
) -> DriverStep {
    let dx = ext::<VolExt>(&device);

    let binding = dx.part.get();
    let pi = if let Some(ref pi) = binding {
        pi
    } else {
        return DriverStep::Continue;
    };

    let binding = (pi.gpt_header, pi.gpt_entry);
    let (_hdr, ent) = if let (Some(ref hdr), Some(ref ent)) = binding {
        (hdr, ent)
    } else {
        return DriverStep::Continue;
    };

    if dx
        .enumerated
        .swap(true, core::sync::atomic::Ordering::AcqRel)
    {
        return DriverStep::Continue;
    }

    let parent_dn = if let Some(dn) = device.dev_node.get().unwrap().upgrade() {
        dn
    } else {
        return DriverStep::complete(DriverStatus::Unsuccessful);
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

    let ptype = ent.partition_type_guid;
    if ptype == zero || ptype == EFI_SYSTEM || ptype == BIOS_BOOT {
        return DriverStep::Continue;
    }

    let part_guid_s = guid_to_string(&ent.unique_partition_guid);
    let name = alloc::format!("Volume{}", &part_guid_s[..8]);
    let inst = alloc::format!("STOR\\VOLUME\\{}\\0000", part_guid_s);

    let ids = DeviceIds {
        hardware: vec!["STOR\\Volume".into(), "STOR\\Volume\\GPT".into()],
        compatible: vec!["STOR\\Volume".into()],
    };

    let mut io_table = IoVtable::new();
    io_table.set(IoType::Read(vol_pdo_read), Synchronization::Sync, 0);
    io_table.set(IoType::Write(vol_pdo_write), Synchronization::Sync, 0);

    let mut pnp_vtable = PnpVtable::new();
    pnp_vtable.set(PnpMinorFunction::QueryResources, vol_pdo_query_resources);
    let mut init = DeviceInit::new(io_table, Some(pnp_vtable));
    init.set_dev_ext_default::<VolPdoExt>();
    let (_dn, pdo) = pnp_create_child_devnode_and_pdo_with_init(
        &parent_dn,
        name,
        inst,
        ids,
        Some("volume".into()),
        init,
    );

    if let Some(tgt) = pnp_get_device_target(&parent_dn.instance_path) {
        ext::<VolPdoExt>(&pdo).backing.call_once(|| tgt);
        ext::<VolPdoExt>(&pdo)
            .part
            .call_once(|| dx.part.get().unwrap().clone());
    }
    DriverStep::Continue
}
#[request_handler]
pub async fn vol_pdo_read(
    dev: Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
    _buf_len: usize,
) -> DriverStep {
    {
        let r = req.read();
        match r.kind {
            RequestType::Read { len, .. } if len == 0 => {
                return DriverStep::complete(DriverStatus::Success);
            }
            RequestType::Read { .. } => {}
            _ => return DriverStep::complete(DriverStatus::InvalidParameter),
        }
    }

    let binding = ext::<VolPdoExt>(&dev);
    let tgt = match binding.backing.get() {
        Some(t) => t.clone(),
        None => return DriverStep::complete(DriverStatus::NoSuchDevice),
    };

    let status = pnp_send_request(tgt, req).await;
    DriverStep::complete(status)
}

#[request_handler]
pub async fn vol_pdo_write(
    dev: Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
    _buf_len: usize,
) -> DriverStep {
    {
        let r = req.read();
        match r.kind {
            RequestType::Write { len, .. } if len == 0 => {
                return DriverStep::complete(DriverStatus::Success);
            }
            RequestType::Write { .. } => {}
            _ => return DriverStep::complete(DriverStatus::InvalidParameter),
        }
    }

    let binding = ext::<VolPdoExt>(&dev);
    let tgt = match binding.backing.get() {
        Some(t) => t.clone(),
        None => return DriverStep::complete(DriverStatus::NoSuchDevice),
    };

    let status = pnp_send_request(tgt, req).await;
    DriverStep::complete(status)
}
#[request_handler]
async fn vol_pdo_query_resources(pdo: Arc<DeviceObject>, req: Arc<RwLock<Request>>) -> DriverStep {
    let mut w = req.write();
    let pnp = match w.pnp.as_mut() {
        Some(p) => p,
        None => {
            w.status = DriverStatus::InvalidParameter;
            return DriverStep::complete(DriverStatus::InvalidParameter);
        }
    };

    if let Some(pi) = ext::<VolPdoExt>(&pdo).part.get() {
        let mut out = vec![0u8; core::mem::size_of::<PartitionInfo>()];
        unsafe {
            core::ptr::copy_nonoverlapping(
                (pi as *const PartitionInfo) as *const u8,
                out.as_mut_ptr(),
                out.len(),
            );
        }
        pnp.blob_out = out;
    } else {
        pnp.blob_out.clear();
    }

    DriverStep::complete(DriverStatus::Success)
}
