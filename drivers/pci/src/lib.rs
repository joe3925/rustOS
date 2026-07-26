#![no_std]
#![no_main]
#![feature(const_option_ops)]
#![feature(const_trait_impl)]
extern crate alloc;

mod dev_ext;
mod msix;

use kernel_api::device::{publish_stack_protocol, register_protocol};
use kernel_api::error::{error, DriverErrorKind, ErrorKind, KernelError, ResultErrorContext};
use kernel_api::pnp::QueryDeviceRelations;
use kernel_api::pnp::QueryId;
use kernel_api::pnp::StartDevice;
use alloc::{sync::Arc, vec::Vec};
#[cfg(not(test))]
use core::panic::PanicInfo;
use kernel_api::dma::dma::DMA_PCI_IDENTITY_FLAG_BUS_MASTER_CAPABLE;
use kernel_api::dma::dma::DMA_PCI_IDENTITY_FLAG_BUS_MASTER_ENABLED;
use kernel_api::dma::dma::DmaPciDeviceIdentity;

use dev_ext::{
    DevExt, McfgSegment, PciPdoExt, PrtEntry, ecam_bus_base_from_segment,
    hwids_for, instance_path_for, load_segments_from_parent, map_ecam_bus, map_ecam_segment_range,
    name_for, parse_ecam_segments_from_blob, parse_prt_from_blob, scan_ecam_bus_mapped,
};

use kernel_api::{
    IOCTL_PCI_SETUP_MSIX,
    device::{DevNode, DeviceInit, DeviceObject, DriverObject},
    dma::register_pci_pdo,
    kernel_types::{io::{DeviceControlHandler, DeviceControlOp}, pnp::DeviceIds},
    memory::{VirtAddr, unmap_mmio_region},
    pnp::{
        DeviceRelationType, DriverStep, PnpOp, PnpOps, QueryIdType, QueryResources, ResourceSet,
        driver_set_evt_device_add, pnp, pnp_create_child_devnode_and_pdo_with_init,
    },
    println,
    request::DeviceControl,
    request_handler,
    runtime::spawn_blocking,
};
use spin::Once;

static MOD_NAME: &str = option_env!("CARGO_PKG_NAME").unwrap_or(module_path!());

use kernel_api::kernel_types::pci::{Bar, MsixInfo};
use kernel_api::kernel_types::protocol::pci::{PciProtocol, PciProtocolVTable};

extern "C" fn pci_proto_get_bar(dev: &Arc<DeviceObject>, index: u8) -> Option<Bar> {
    let ext = dev.try_devext::<PciPdoExt>().ok()?;
    if index >= 6 { return None; }
    Some(ext.bars[index as usize])
}

extern "C" fn pci_proto_get_config_space_phys(dev: &Arc<DeviceObject>) -> Option<(u64, u64)> {
    let ext = dev.try_devext::<PciPdoExt>().ok()?;
    Some((ext.cfg_phys, 4096))
}

extern "C" fn pci_proto_get_gsi(dev: &Arc<DeviceObject>) -> Option<u16> {
    let ext = dev.try_devext::<PciPdoExt>().ok()?;
    ext.irq_gsi
}

extern "C" fn pci_proto_get_interrupt_line(dev: &Arc<DeviceObject>) -> Option<u8> {
    let ext = dev.try_devext::<PciPdoExt>().ok()?;
    if ext.irq_line == 0 || ext.irq_line == 0xFF {
        None
    } else {
        Some(ext.irq_line)
    }
}

extern "C" fn pci_proto_get_msix(dev: &Arc<DeviceObject>) -> Option<MsixInfo> {
    let ext = dev.try_devext::<PciPdoExt>().ok()?;
    ext.msix
}

static PCI_PROTO_VTABLE: PciProtocolVTable = PciProtocolVTable {
    get_bar: pci_proto_get_bar,
    get_config_space_phys: pci_proto_get_config_space_phys,
    get_gsi: pci_proto_get_gsi,
    get_interrupt_line: pci_proto_get_interrupt_line,
    get_msix: pci_proto_get_msix,
};

struct PciPdoIo;

impl DeviceControlHandler for PciPdoIo {
    #[request_handler]
    async fn handler<'req, 'data, 'b>(
        dev: &Arc<DeviceObject>,
        req: &'b mut DeviceControl<'data>,
    ) -> Result<DriverStep, kernel_api::error::KernelError> {
        let code = req.code;

        match code {
            IOCTL_PCI_SETUP_MSIX => msix::pci_setup_msix(dev.clone(), req).await,
            _ => Err(kernel_api::error::error(kernel_api::error::DriverErrorKind::NotImplemented)),
        }
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    use kernel_api::util::panic_common;
    panic_common(MOD_NAME, info)
}

#[unsafe(no_mangle)]
pub extern "C" fn DriverEntry(driver: &Arc<DriverObject>) -> Result<(), kernel_api::error::KernelError> {
    driver_set_evt_device_add(driver, bus_driver_device_add);
    Ok(())
}

pub extern "C" fn bus_driver_device_add(
    _driver: &Arc<DriverObject>,
    dev_init: &mut DeviceInit,
) -> Result<DriverStep, kernel_api::error::KernelError> {
    let mut vt = PnpOps::new();
    vt.start_device.set(pci_bus_pnp_start);
    vt.query_device_relations.set(pci_bus_pnp_query_devrels);
    dev_init.pnp_ops = Some(vt);

    dev_init.set_dev_ext_from(DevExt {
        segments: Once::new(),
        prt: Once::new(),
    });

    Ok(DriverStep::Complete)
}

#[request_handler]
pub async fn pci_bus_pnp_start<'req, 'data, 'b>(
    device: &Arc<DeviceObject>,
    _op: PnpOp,
    _req: &'b mut StartDevice,
) -> Result<DriverStep, kernel_api::error::KernelError> {
    let mut query_handle = QueryResources {
        resources: ResourceSet::default(),
    };

    match pnp::send_next_lower(device.clone(), &mut query_handle).await {
        Ok(_) => {
        let blob = match query_handle.resources {
            ResourceSet::Encoded(blob) => blob,
            _ => Vec::new(),
        };
        let segs = parse_ecam_segments_from_blob(&blob);

        if segs.is_empty() {
            println!("[PCI] no ECAM block found in parent resources");
            return Ok(DriverStep::Continue);
        }

        let prt_entries = parse_prt_from_blob(&blob);

        if let Ok(ext) = device.try_devext::<DevExt>() {
            ext.segments.call_once(|| segs);
            if !prt_entries.is_empty() {
                ext.prt.call_once(|| prt_entries);
            }
        } else {
            return Ok(DriverStep::Continue);
        }
        }
        Err(error) if error.kind() == ErrorKind::Driver(DriverErrorKind::NoSuchDevice) => {
        let segs = load_segments_from_parent(&device)
            .await
            .with_context(|| "loading PCI segments from the parent device")?;
        if let Ok(ext) = device.try_devext::<DevExt>() {
            if !segs.is_empty() {
                ext.segments.call_once(|| segs);
            }
        } else {
            return Ok(DriverStep::Continue);
        }
        }
        Err(error) => {
            return Err(error.with_context("querying parent resources for PCI ECAM data"));
        }
    }

    Ok(DriverStep::Continue)
}

#[request_handler]
pub async fn pci_bus_pnp_query_devrels<'req, 'data, 'b>(
    device: &Arc<DeviceObject>,
    _op: PnpOp,
    req: &'b mut QueryDeviceRelations,
) -> Result<DriverStep, kernel_api::error::KernelError> {
    let relation = req.relation;
    if relation == DeviceRelationType::BusRelations {
        enumerate_bus(&device)
            .await
            .with_context(|| "enumerating the PCI bus")?;
        return Ok(DriverStep::Continue);
    }

    Ok(DriverStep::Continue)
}

fn resolve_gsi(p: &mut PciPdoExt, prt: &[PrtEntry]) {
    if p.irq_pin == 0 {
        return;
    }
    let prt_pin = p.irq_pin - 1;
    if let Some(entry) = prt.iter().find(|e| e.device == p.dev && e.pin == prt_pin) {
        p.irq_gsi = Some(entry.gsi);
    }
}

#[derive(Clone, Copy)]
struct MapToUnmap {
    base: VirtAddr,
    size: u64,
}

#[derive(Clone, Copy)]
struct BusWork {
    seg: McfgSegment,
    bus: u8,
    bus_base: VirtAddr,
}

pub async fn enumerate_bus(device: &Arc<DeviceObject>) -> Result<(), KernelError> {
    let devnode = match device.dev_node.get().unwrap().upgrade() {
        Some(dn) => dn,
        None => {
            println!("[PCI] PDO missing DevNode");
            return Err(error(DriverErrorKind::NoSuchDevice));
        }
    };

    let (segments, prt_vec) = match device.try_devext::<DevExt>() {
        Ok(g) => (
            g.segments.get().cloned(),
            g.prt.get().cloned().unwrap_or_default(),
        ),
        Err(_) => {
            println!("[PCI] missing DevExt");
            return Err(error(DriverErrorKind::NoSuchDevice));
        }
    };

    let prt_arc: Arc<[PrtEntry]> = Arc::from(prt_vec.clone());

    if segments.is_none() {
        if !dev_ext::platform_config_access_available() {
            println!("[PCI] no ECAM segments and no platform PCI config access");
            return Err(error(DriverErrorKind::NotImplemented));
        }

        println!("[PCI] No ECAM segments; scanning through platform PCI config access.");
        for bus in 0u8..=255 {
            for dev in 0u8..32 {
                let ht = match dev_ext::header_type_config(bus, dev) {
                    Some(v) => v,
                    None => continue,
                };
                let multi = (ht & 0x80) != 0;
                let func_span = if multi { 0u8..8 } else { 0u8..1 };
                for func in func_span {
                    if let Some(mut p) = dev_ext::probe_function_config(bus, dev, func) {
                        resolve_gsi(&mut p, prt_vec.as_slice());
                        make_pdo_for_function(&devnode, &p);
                    }
                }
            }
        }
        return Ok(());
    }

    let mut unmaps: Vec<MapToUnmap> = Vec::new();
    let mut work: Vec<BusWork> = Vec::new();

    for seg in segments.unwrap() {
        match map_ecam_segment_range(&seg) {
            Ok(map) => {
                unmaps.push(MapToUnmap {
                    base: map.base,
                    size: map.size,
                });
                for bus in seg.start_bus..=seg.end_bus {
                    let bus_base = ecam_bus_base_from_segment(map, bus);
                    work.push(BusWork { seg, bus, bus_base });
                }
            }
            Err(e) => {
                println!(
                    "[PCI] segment {} bulk ECAM map failed ({:?}); falling back to per-bus maps",
                    seg.seg, e
                );
                for bus in seg.start_bus..=seg.end_bus {
                    match map_ecam_bus(&seg, bus) {
                        Ok((bus_base, sz)) => {
                            unmaps.push(MapToUnmap {
                                base: bus_base,
                                size: sz,
                            });
                            work.push(BusWork { seg, bus, bus_base });
                        }
                        Err(be) => {
                            println!(
                                "[PCI] failed to map segment {} bus {}: {:?}",
                                seg.seg, bus, be
                            );
                        }
                    }
                }
            }
        }
    }

    let mut joins = Vec::new();
    for w in work {
        let seg_copy = w.seg;
        let bus = w.bus;
        let bus_base = w.bus_base;
        let prt_copy = prt_arc.clone();

        joins.push(spawn_blocking(move || {
            let mut devices = unsafe { scan_ecam_bus_mapped(&seg_copy, bus, bus_base) };

            if !prt_copy.is_empty() {
                for p in devices.iter_mut() {
                    resolve_gsi(p, prt_copy.as_ref());
                }
            }

            devices
        }));
    }
    for join in joins {
        for p in join.await {
            make_pdo_for_function(&devnode, &p);
        }
    }

    for m in unmaps {
        let _ = unsafe { unmap_mmio_region(m.base, m.size) };
    }
    Ok(())
}

fn make_pdo_for_function(parent: &Arc<DevNode>, p: &PciPdoExt) {
    let (hardware, compatible, class_tag) = hwids_for(p);
    let ids = DeviceIds {
        hardware,
        compatible,
    };

    let mut vt = PnpOps::new();
    vt.query_id.set(pci_pdo_query_id);

    vt.start_device.set(pci_pdo_start);
    vt.query_device_relations.set(pci_pdo_query_devrels);

    let mut child_init = DeviceInit::with_pnp(Some(vt));
    child_init.ops.register::<DeviceControlOp, PciPdoIo>();
    child_init.set_dev_ext_from(*p);

    let name = name_for(p);
    let instance_path = instance_path_for(p);

    let (_child_dn, child_pdo) = pnp_create_child_devnode_and_pdo_with_init(
        parent,
        name,
        instance_path,
        ids,
        Some(class_tag),
        child_init,
    );

    let mut flags = DMA_PCI_IDENTITY_FLAG_BUS_MASTER_CAPABLE;
    if (p.command & (1 << 2)) != 0 {
        flags |= DMA_PCI_IDENTITY_FLAG_BUS_MASTER_ENABLED;
    }

    let result = register_pci_pdo(
        &child_pdo,
        DmaPciDeviceIdentity {
            segment: p.seg,
            bus: p.bus,
            device: p.dev,
            function: p.func,
            requester_id: ((p.bus as u16) << 8) | ((p.dev as u16) << 3) | p.func as u16,
            flags,
            command: p.command,
            reserved: 0,
            config_space_phys: p.cfg_phys,
        },
    );
    if let Err(error) = result {
        panic!(
            "[PCI] DMA manager registration failed for {}:{}:{}.{}: {:?}",
            p.seg, p.bus, p.dev, p.func, error
        );
    }
}

#[request_handler]
pub async fn pci_pdo_query_id<'req, 'data, 'b>(
    dev: &Arc<DeviceObject>,
    _op: PnpOp,
    req: &'b mut QueryId,
) -> Result<DriverStep, kernel_api::error::KernelError> {
    let ext = match dev.try_devext::<PciPdoExt>() {
        Ok(g) => g,
        Err(_) => return Err(kernel_api::error::error(kernel_api::error::DriverErrorKind::NoSuchDevice)),
    };

    match req.id_type {
        QueryIdType::HardwareIds => {
            let (hw, _cmp, _) = hwids_for(&ext);
            req.ids.extend(hw);
        }
        QueryIdType::CompatibleIds => {
            let (_hw, cmp, _) = hwids_for(&ext);
            req.ids.extend(cmp);
        }
        QueryIdType::DeviceId => {
            let (hw, _, _) = hwids_for(&ext);
            if let Some(primary) = hw.first() {
                req.ids.push(primary.clone());
            } else {
                return Err(kernel_api::error::error(kernel_api::error::DriverErrorKind::NoSuchDevice));
            }
        }
        QueryIdType::InstanceId => {
            req.ids.push(instance_path_for(&ext));
        }
    }
    Ok(DriverStep::Complete)
}

#[request_handler]
pub async fn pci_pdo_start<'req, 'data, 'b>(
    _dev: &Arc<DeviceObject>,
    _op: PnpOp,
    _req: &'b mut StartDevice,
) -> Result<DriverStep, kernel_api::error::KernelError> {
    let dn = _dev
        .dev_node
        .get()
        .and_then(|node| node.upgrade())
        .ok_or_else(|| error(DriverErrorKind::NoSuchDevice))?;
    register_protocol::<PciProtocol>(_dev, &PCI_PROTO_VTABLE)
        .map_err(error)
        .with_context(|| "registering the PCI protocol on the PDO")?;
    publish_stack_protocol::<PciProtocol>(&dn)
        .map_err(error)
        .with_context(|| "publishing the PCI protocol on the device stack")?;
    Ok(DriverStep::Complete)
}

#[request_handler]
pub async fn pci_pdo_query_devrels<'req, 'data, 'b>(
    _dev: &Arc<DeviceObject>,
    _op: PnpOp,
    _req: &'b mut QueryDeviceRelations,
) -> Result<DriverStep, kernel_api::error::KernelError> {
    Ok(DriverStep::Complete)
}
