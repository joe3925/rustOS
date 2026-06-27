#![no_std]
#![no_main]

extern crate alloc;

use alloc::{
    format,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
#[cfg(not(test))]
use core::panic::PanicInfo;
use core::{slice, str};
use device_tree::{DeviceTree, Node};
use kernel_api::{
    device::{DevNode, DeviceInit, DeviceObject, DriverObject},
    kernel_types::{fdt::FdtHeader, pnp::DeviceIds},
    pnp::{
        DeviceRelationType, DriverStep, PnpMinorFunction, PnpVtable, QueryIdType,
        ResourceDescriptor, driver_set_evt_device_add, encode_resource_descriptors,
        get_device_tree_blob, pnp_create_child_devnode_and_pdo_with_init,
    },
    request::{Pnp, RequestData, RequestHandle},
    request_handler,
    status::DriverStatus,
};
use spin::Once;

static MOD_NAME: &str = env!("CARGO_PKG_NAME");

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    kernel_api::util::panic_common(MOD_NAME, info)
}

#[repr(C)]
#[derive(Default)]
pub struct DevTreeExt {
    tree: Once<Arc<DeviceTree>>,
}

#[repr(C)]
pub struct DtPdoExt {
    tree: Arc<DeviceTree>,
    path: String,
    ids: DeviceIds,
    resources: Vec<u8>,
}

#[unsafe(no_mangle)]
pub extern "C" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    driver_set_evt_device_add(driver, devicetree_device_add);
    DriverStatus::Success
}

pub extern "C" fn devicetree_device_add(
    _driver: &Arc<DriverObject>,
    dev_init: &mut DeviceInit,
) -> DriverStep {
    let pnp = PnpVtable::new();
    pnp.set(PnpMinorFunction::StartDevice, devicetree_start);
    pnp.set(
        PnpMinorFunction::QueryDeviceRelations,
        devicetree_query_devrels,
    );
    dev_init.set_dev_ext_default::<DevTreeExt>();
    dev_init.pnp_vtable = Some(pnp);
    DriverStep::complete(DriverStatus::Success)
}

#[request_handler]
pub async fn devicetree_start<'req, 'data, 'b>(
    device: &Arc<DeviceObject>,
    _req: &'b mut RequestHandle<'req, Pnp<'data>>,
) -> DriverStep {
    if has_lower_dt_pdo(device) {
        return DriverStep::complete(DriverStatus::Success);
    }

    let Ok(ext) = device.try_devext::<DevTreeExt>() else {
        return DriverStep::complete(DriverStatus::NoSuchDevice);
    };

    if ext.tree.get().is_some() {
        return DriverStep::complete(DriverStatus::Success);
    }

    let Some(blob) = fdt_blob() else {
        return DriverStep::complete(DriverStatus::NoSuchDevice);
    };

    let tree = match DeviceTree::load(blob) {
        Ok(tree) => tree,
        Err(_) => return DriverStep::complete(DriverStatus::InvalidParameter),
    };

    ext.tree.call_once(|| Arc::new(tree));
    DriverStep::complete(DriverStatus::Success)
}

#[request_handler]
pub async fn devicetree_query_devrels<'req, 'data, 'b>(
    device: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'req, Pnp<'data>>,
) -> DriverStep {
    if req.get().body.request.relation != DeviceRelationType::BusRelations {
        return DriverStep::Continue;
    }

    let Some(parent_dn) = device.dev_node.get().and_then(|dn| dn.upgrade()) else {
        return DriverStep::complete(DriverStatus::NoSuchDevice);
    };

    let Some((tree, path)) = enumeration_context(device) else {
        return DriverStep::complete(DriverStatus::NoSuchDevice);
    };

    let Some(node) = tree.find(&path) else {
        return DriverStep::complete(DriverStatus::NoSuchDevice);
    };

    for child in node.children.iter() {
        create_dt_child(&parent_dn, &tree, &path, node, child);
    }

    DriverStep::complete(DriverStatus::Success)
}

fn has_lower_dt_pdo(device: &Arc<DeviceObject>) -> bool {
    device
        .lower_device
        .get()
        .and_then(|lower| lower.try_devext::<DtPdoExt>().ok())
        .is_some()
}

fn enumeration_context(device: &Arc<DeviceObject>) -> Option<(Arc<DeviceTree>, String)> {
    if let Ok(ext) = device.try_devext::<DevTreeExt>() {
        if let Some(tree) = ext.tree.get() {
            return Some((tree.clone(), "/".to_string()));
        }
    }

    let lower = device.lower_device.get()?;
    let pdo = lower.try_devext::<DtPdoExt>().ok()?;
    Some((pdo.tree.clone(), pdo.path.clone()))
}

fn fdt_blob() -> Option<&'static [u8]> {
    let ptr = get_device_tree_blob()?;
    if ptr.is_null() {
        return None;
    }

    let header = unsafe { &*ptr };
    if header.magic() != FdtHeader::MAGIC {
        return None;
    }

    let len = header.total_size() as usize;
    if len < core::mem::size_of::<FdtHeader>() {
        return None;
    }

    Some(unsafe { slice::from_raw_parts(ptr.cast::<u8>(), len) })
}

fn create_dt_child(
    parent_dn: &Arc<DevNode>,
    tree: &Arc<DeviceTree>,
    parent_path: &str,
    parent_node: &Node,
    node: &Node,
) {
    let path = join_path(parent_path, &node.name);
    let instance_path = instance_path_for(&path);
    if child_exists(parent_dn, &instance_path) {
        return;
    }

    let ids = ids_for_node(node);
    let resources = resources_for_node(parent_node, node);

    let pnp = PnpVtable::new();
    pnp.set(PnpMinorFunction::QueryId, dt_pdo_query_id);
    pnp.set(PnpMinorFunction::QueryResources, dt_pdo_query_resources);
    pnp.set(PnpMinorFunction::QueryDeviceRelations, dt_pdo_query_devrels);
    pnp.set(PnpMinorFunction::StartDevice, dt_pdo_start);

    let mut init = DeviceInit::with_pnp(Some(pnp));
    init.set_dev_ext_from(DtPdoExt {
        tree: tree.clone(),
        path,
        ids: ids.clone(),
        resources,
    });

    let _ = pnp_create_child_devnode_and_pdo_with_init(
        parent_dn,
        node.name.clone(),
        instance_path,
        ids,
        None,
        init,
    );
}

#[request_handler]
pub async fn dt_pdo_query_id<'req, 'data, 'b>(
    dev: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'req, Pnp<'data>>,
) -> DriverStep {
    let Ok(ext) = dev.try_devext::<DtPdoExt>() else {
        return DriverStep::complete(DriverStatus::NoSuchDevice);
    };
    let id_type = req.get().body.request.id_type;

    {
        let w = req.get_mut();
        let pnp = &mut w.body.request;
        match id_type {
            QueryIdType::DeviceId => {
                if let Some(id) = ext.ids.hardware.first() {
                    pnp.ids_out.push(id.clone());
                }
            }
            QueryIdType::HardwareIds => pnp.ids_out.extend(ext.ids.hardware.iter().cloned()),
            QueryIdType::CompatibleIds => pnp.ids_out.extend(ext.ids.compatible.iter().cloned()),
            QueryIdType::InstanceId => pnp.ids_out.push(ext.path.clone()),
        }
        w.status = DriverStatus::Success;
    }

    DriverStep::complete(DriverStatus::Success)
}

#[request_handler]
pub async fn dt_pdo_query_resources<'req, 'data, 'b>(
    dev: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'req, Pnp<'data>>,
) -> DriverStep {
    let Ok(ext) = dev.try_devext::<DtPdoExt>() else {
        return DriverStep::complete(DriverStatus::NoSuchDevice);
    };

    {
        let w = req.get_mut();
        w.body.request.data_out = RequestData::from_t::<Vec<u8>>(ext.resources.clone());
        w.status = DriverStatus::Success;
    }

    DriverStep::complete(DriverStatus::Success)
}

#[request_handler]
pub async fn dt_pdo_query_devrels<'req, 'data, 'b>(
    dev: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'req, Pnp<'data>>,
) -> DriverStep {
    if req.get().body.request.relation != DeviceRelationType::BusRelations {
        return DriverStep::Continue;
    }

    let Ok(ext) = dev.try_devext::<DtPdoExt>() else {
        return DriverStep::complete(DriverStatus::NoSuchDevice);
    };
    let Some(parent_dn) = dev.dev_node.get().and_then(|dn| dn.upgrade()) else {
        return DriverStep::complete(DriverStatus::NoSuchDevice);
    };
    let Some(node) = ext.tree.find(&ext.path) else {
        return DriverStep::complete(DriverStatus::NoSuchDevice);
    };

    for child in node.children.iter() {
        create_dt_child(&parent_dn, &ext.tree, &ext.path, node, child);
    }

    DriverStep::complete(DriverStatus::Success)
}

#[request_handler]
pub async fn dt_pdo_start<'req, 'data, 'b>(
    _dev: &Arc<DeviceObject>,
    _req: &'b mut RequestHandle<'req, Pnp<'data>>,
) -> DriverStep {
    DriverStep::complete(DriverStatus::Success)
}

fn child_exists(parent: &Arc<DevNode>, instance_path: &str) -> bool {
    parent
        .children
        .read()
        .iter()
        .any(|child| child.instance_path == instance_path)
}

fn ids_for_node(node: &Node) -> DeviceIds {
    let compatibles = compatible_strings(node);
    let mut hardware = Vec::new();
    let mut compatible = Vec::new();

    if let Some(first) = compatibles.first() {
        hardware.push(of_id(first));
        compatible.extend(compatibles.iter().skip(1).map(|s| of_id(s)));
    } else if !node.children.is_empty() {
        hardware.push("FDT\\BUS".to_string());
    } else {
        hardware.push(format!("FDT\\{}", sanitize_id(&node_base_name(&node.name))));
    }

    if !node.children.is_empty() && !compatible.iter().any(|id| id == "FDT\\BUS") {
        compatible.push("FDT\\BUS".to_string());
    }
    compatible.push("FDT\\NODE".to_string());

    DeviceIds {
        hardware,
        compatible,
    }
}

fn compatible_strings(node: &Node) -> Vec<String> {
    let Some(raw) = node.prop_raw("compatible") else {
        return Vec::new();
    };

    raw.split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .filter_map(|s| str::from_utf8(s).ok())
        .map(ToString::to_string)
        .collect()
}

fn of_id(compatible: &str) -> String {
    format!("OF\\{}", sanitize_id(compatible))
}

fn node_base_name(name: &str) -> String {
    name.split('@').next().unwrap_or(name).to_string()
}

fn sanitize_id(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' | '/' | ':' => out.push('_'),
            _ => out.push(ch),
        }
    }
    out
}

fn join_path(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}

fn instance_path_for(path: &str) -> String {
    if path == "/" {
        return "FDT\\ROOT\\0".to_string();
    }

    let mut out = String::from("FDT");
    for comp in path.trim_start_matches('/').split('/') {
        out.push('\\');
        out.push_str(&sanitize_instance_component(comp));
    }
    out
}

fn sanitize_instance_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' | '/' => out.push('_'),
            _ => out.push(ch),
        }
    }
    out
}

fn resources_for_node(parent: &Node, node: &Node) -> Vec<u8> {
    let mut entries = Vec::<ResourceDescriptor>::new();
    append_reg_entries(&mut entries, parent, node);
    append_interrupt_entries(&mut entries, node);
    encode_resource_descriptors(&entries)
}

fn append_reg_entries(entries: &mut Vec<ResourceDescriptor>, parent: &Node, node: &Node) {
    let Some(raw) = node.prop_raw("reg") else {
        return;
    };

    let address_cells = prop_u32(parent, "#address-cells").unwrap_or(2).min(2) as usize;
    let size_cells = prop_u32(parent, "#size-cells").unwrap_or(1).min(2) as usize;
    let entry_cells = address_cells + size_cells;
    if entry_cells == 0 {
        return;
    }

    let entry_bytes = entry_cells * 4;
    let mut offset = 0usize;
    let mut index = 0u32;
    while offset + entry_bytes <= raw.len() {
        let Some(start) = read_cells(raw, offset, address_cells) else {
            return;
        };
        let Some(length) = read_cells(raw, offset + address_cells * 4, size_cells) else {
            return;
        };
        entries.push(ResourceDescriptor::memory(index, start, length));
        offset += entry_bytes;
        index += 1;
    }
}

fn append_interrupt_entries(entries: &mut Vec<ResourceDescriptor>, node: &Node) {
    let Some(raw) = node.prop_raw("interrupts") else {
        return;
    };

    let mut offset = 0usize;
    let mut index = 0u32;
    while offset + 4 <= raw.len() {
        let irq = u32::from_be_bytes([
            raw[offset],
            raw[offset + 1],
            raw[offset + 2],
            raw[offset + 3],
        ]);
        entries.push(ResourceDescriptor::interrupt(index, irq as u64));
        offset += 4;
        index += 1;
    }
}

fn prop_u32(node: &Node, name: &str) -> Option<u32> {
    node.prop_u32(name).ok()
}

fn read_cells(raw: &[u8], offset: usize, cells: usize) -> Option<u64> {
    if cells == 0 {
        return Some(0);
    }
    if cells > 2 || offset + cells * 4 > raw.len() {
        return None;
    }

    let mut value = 0u64;
    for i in 0..cells {
        let pos = offset + i * 4;
        let part = u32::from_be_bytes([raw[pos], raw[pos + 1], raw[pos + 2], raw[pos + 3]]);
        value = (value << 32) | part as u64;
    }
    Some(value)
}
