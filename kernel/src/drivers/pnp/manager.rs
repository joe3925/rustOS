use super::driver_index::{
    self as idx, escape_key, DriverBinding, DriverPackage, DriverRuntime, DriverState, HwIndex,
    MatchClass,
};
use super::request::IoTarget;
use crate::drivers::driver_install::{BootType, DriverError};
use crate::drivers::pnp::device::{DevNode, DevNodeState, DeviceIds, DeviceStack, StackLayer};
use crate::drivers::pnp::driver_object::{
    ClassAddCallback, ClassListener, DeviceInit, DeviceObject, DeviceRelationType, DriverObject,
    DriverStatus, PnpMinorFunction, PnpRequest, QueryIdType, Request, RequestType, Synchronization,
};
use crate::executable::program::{ModuleHandle, PROGRAM_MANAGER};
use crate::object_manager::{ObjRef, Object, ObjectPayload, ObjectTag, OmError, OBJECT_MANAGER};
use crate::println;
use crate::registry::reg::{get_key, get_value, list_keys};
use crate::registry::{self as reg, Data, RegError};
use crate::util::{generate_guid, random_number};
use alloc::string::ToString;
use alloc::vec;
use alloc::{boxed::Box, collections::BTreeMap, string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};
use spin::{Mutex, RwLock};

pub struct PnpManager {
    hw: RwLock<Arc<HwIndex>>,
    drivers: RwLock<BTreeMap<String, Arc<DriverObject>>>,
    dev_root: Arc<DevNode>,
    class_listeners: Mutex<BTreeMap<u64, ClassListener>>,
    next_listener_id: AtomicU64,
}

impl PnpManager {
    pub fn new() -> Self {
        Self {
            hw: RwLock::new(Arc::new(HwIndex::new())),
            drivers: RwLock::new(BTreeMap::new()),
            dev_root: DevNode::new_root(),
            class_listeners: Mutex::new(BTreeMap::new()),
            next_listener_id: AtomicU64::new(0),
        }
    }

    pub fn root(&self) -> Arc<DevNode> {
        self.dev_root.clone()
    }

    pub fn init_from_registry(&self) -> Result<(), RegError> {
        self.rebuild_index()?;
        let root_node = self.root();
        let boot_packages: Vec<_> = {
            let hw = self.hw.read();
            hw.by_driver
                .values()
                .filter(|p| p.start == BootType::Boot)
                .cloned()
                .collect()
        };

        for pkg in boot_packages {
            if let Err(e) = self.ensure_loaded(&pkg) {
                println!("-> load boot-start {} failed: {:?}", pkg.name, e);
                continue;
            }
            let instance_path = alloc::format!("ROOT\\{}\\0000", pkg.name);
            let device_ids = DeviceIds {
                hardware: vec![alloc::format!("ROOT\\{}", pkg.name)],
                compatible: Vec::new(),
            };
            let mut pdo_init = DeviceInit::new();
            pdo_init.dev_ext_size = 0;

            let (devnode, _pdo) = self.create_child_devnode_and_pdo_with_init(
                &root_node,
                pkg.name.clone(),
                instance_path,
                device_ids,
                None,
                pdo_init,
            );
            if let Err(e) = self.bind_and_start(&devnode) {
                println!("-> bind/start '{}' failed: {:?}", devnode.name, e);
            }
        }

        self.init_io_dispatcher();
        Ok(())
    }

    pub fn rebuild_index(&self) -> Result<(), RegError> {
        *self.hw.write() = Arc::new(idx::build_hw_index()?);
        Ok(())
    }
    pub fn recheck_all_devices(&self) {
        self.rebuild_index();
        let root = self.root();
        self.rebind_tree(&root);
        self.rescan_buses_started(&root);
    }

    pub fn rebind_faulted_and_unbound(&self) {
        if self.hw.read().by_driver.is_empty() {
            let _ = self.rebuild_index();
        }
        let root = self.root();
        self.rebind_tree(&root);
    }

    fn rebind_tree(&self, dn: &Arc<DevNode>) {
        let state = dn.get_state();
        let needs_function = {
            let g = dn.stack.read();
            match g.as_ref() {
                None => true,
                Some(stk) => stk
                    .function
                    .as_ref()
                    .and_then(|l| l.devobj.as_ref())
                    .is_none(),
            }
        };
        if needs_function
            && matches!(
                state,
                DevNodeState::Initialized | DevNodeState::Faulted | DevNodeState::Stopped
            )
        {
            let _ = self.bind_and_start(dn);
        }
        let kids: Vec<Arc<DevNode>> = {
            let g = dn.children.read();
            g.iter().cloned().collect()
        };
        for ch in kids {
            self.rebind_tree(&ch);
        }
    }

    fn rescan_buses_started(&self, dn: &Arc<DevNode>) {
        if dn.get_state() == DevNodeState::Started {
            let _ = self.invalidate_device_relations_for_node(dn, DeviceRelationType::BusRelations);
        }
        let kids: Vec<Arc<DevNode>> = {
            let g = dn.children.read();
            g.iter().cloned().collect()
        };
        for ch in kids {
            self.rescan_buses_started(&ch);
        }
    }
    pub fn create_child_devnode_and_pdo(
        &self,
        parent: &Arc<DevNode>,
        name: String,
        instance_path: String,
        ids: DeviceIds,
        class: Option<String>,
    ) -> (Arc<DevNode>, Arc<DeviceObject>) {
        let dev_node = DevNode::new_child(name, instance_path, ids, class, parent);
        let pdo = DeviceObject::new(0);
        unsafe {
            let p = &mut *(Arc::as_ptr(&pdo) as *mut DeviceObject);
            p.dev_node = Arc::downgrade(&dev_node);
        }
        dev_node.set_pdo(pdo.clone());

        let base = alloc::format!("\\Device\\{}", dev_node.instance_path);
        let _ = OBJECT_MANAGER.mkdir_p("\\Device".to_string());
        let _ = OBJECT_MANAGER.mkdir_p(base.clone());
        let pdo_obj = Object::with_name(
            ObjectTag::Device,
            "PDO".into(),
            ObjectPayload::Device(pdo.clone()),
        );
        let _ = OBJECT_MANAGER.link(alloc::format!("{}\\PDO", base), &pdo_obj);
        self.notify_class_listeners(&dev_node);
        (dev_node, pdo)
    }

    pub fn create_child_devnode_and_pdo_with_init(
        &self,
        parent: &Arc<DevNode>,
        name: String,
        instance_path: String,
        ids: DeviceIds,
        class: Option<String>,
        mut init: DeviceInit,
    ) -> (Arc<DevNode>, Arc<DeviceObject>) {
        let dev_node = DevNode::new_child(name, instance_path, ids, class, parent);
        let pdo = DeviceObject::new(init.dev_ext_size);
        unsafe {
            let p = &mut *(Arc::as_ptr(&pdo) as *mut DeviceObject);
            p.dev_node = Arc::downgrade(&dev_node);
            p.dev_init = init;
        }
        dev_node.set_pdo(pdo.clone());

        let base = alloc::format!("\\Device\\{}", dev_node.instance_path);
        let _ = OBJECT_MANAGER.mkdir_p("\\Device".to_string());
        let _ = OBJECT_MANAGER.mkdir_p(base.clone());
        let pdo_obj = Object::with_name(
            ObjectTag::Device,
            "PDO".into(),
            ObjectPayload::Device(pdo.clone()),
        );
        let _ = OBJECT_MANAGER.link(alloc::format!("{}\\PDO", base), &pdo_obj);
        self.notify_class_listeners(&dev_node);
        (dev_node, pdo)
    }

    pub fn bind_and_start(&self, dn: &Arc<DevNode>) -> Result<(), DriverError> {
        self.bind_device(dn)?;
        self.start_stack(dn);
        Ok(())
    }

    fn bind_device(&self, dn: &Arc<DevNode>) -> Result<(), DriverError> {
        let mut func_pkg: Option<Arc<DriverPackage>> = None;

        if let Some(hwid) = dn.ids.hardware.get(0) {
            if hwid.starts_with("ROOT\\") {
                if let Some(driver_name) = hwid.split('\\').nth(1) {
                    if let Some(pkg) = self.hw.read().by_driver.get(driver_name) {
                        func_pkg = Some(pkg.clone());
                    }
                }
            }
        }
        if func_pkg.is_none() {
            let ids_slice: Vec<&str> = dn
                .ids
                .hardware
                .iter()
                .map(|s| s.as_str())
                .chain(dn.ids.compatible.iter().map(|s| s.as_str()))
                .collect();
            if let Some(best) = self.hw.read().match_best(&ids_slice) {
                func_pkg = Some(best.pkg.clone());
            }
        }
        if func_pkg.is_none() {
            if let Some(pkg) = self.resolve_class_driver(dn.class.as_deref())? {
                func_pkg = Some(pkg);
            }
        }
        let Some(resolved_func_pkg) = func_pkg else {
            dn.set_state(DevNodeState::Initialized);
            return Ok(());
        };
        let func_drv = self.ensure_loaded(&resolved_func_pkg)?;

        let class_name = dn.class.as_deref();
        let (lower_pkgs, upper_pkgs) = self.resolve_filters(
            &dn.ids
                .hardware
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>(),
            class_name,
            &resolved_func_pkg.name,
        )?;

        let lower_layers: Vec<_> = lower_pkgs
            .into_iter()
            .map(|pkg| {
                Ok(StackLayer {
                    driver: self.ensure_loaded(&pkg)?,
                    devobj: None,
                })
            })
            .collect::<Result<_, DriverError>>()?;
        let upper_layers: Vec<_> = upper_pkgs
            .into_iter()
            .map(|pkg| {
                Ok(StackLayer {
                    driver: self.ensure_loaded(&pkg)?,
                    devobj: None,
                })
            })
            .collect::<Result<_, DriverError>>()?;
        let function_layer = StackLayer {
            driver: func_drv,
            devobj: None,
        };

        {
            let mut g = dn.stack.write();
            let stk = g.as_mut().unwrap();
            stk.function = Some(function_layer);
            stk.lower = lower_layers;
            stk.upper = upper_layers;
        }
        dn.set_state(DevNodeState::DriversBound);
        Ok(())
    }

    fn resolve_class_driver(
        &self,
        class_opt: Option<&str>,
    ) -> Result<Option<Arc<DriverPackage>>, DriverError> {
        let Some(class) = class_opt else {
            return Ok(None);
        };
        let class_key = alloc::format!("SYSTEM/CurrentControlSet/Class/{}", class);
        let svc = match get_value(&class_key, "Class") {
            Some(Data::Str(s)) if !s.is_empty() => s,
            _ => return Ok(None),
        };
        if let Some(pkg) = self.hw.read().by_driver.get(&svc) {
            return Ok(Some(pkg.clone()));
        }

        let svc_key = alloc::format!("SYSTEM/CurrentControlSet/Services/{svc}");
        let image = match get_value(&svc_key, "ImagePath") {
            Some(Data::Str(s)) => s,
            _ => return Ok(None),
        };
        let toml_path = match get_value(&svc_key, "TomlPath") {
            Some(Data::Str(s)) => s,
            _ => return Ok(None),
        };
        let start = match get_value(&svc_key, "Start") {
            Some(Data::U32(v)) => match v {
                0 => BootType::Boot,
                1 => BootType::System,
                2 => BootType::Demand,
                3 => BootType::Disabled,
                _ => BootType::Demand,
            },
            _ => BootType::Demand,
        };
        Ok(Some(Arc::new(DriverPackage {
            name: svc.clone(),
            image_path: image,
            toml_path,
            start,
            hwids: Vec::new(),
        })))
    }

    fn resolve_filters(
        &self,
        ids: &[&str],
        class_opt: Option<&str>,
        function_service: &str,
    ) -> Result<(Vec<Arc<DriverPackage>>, Vec<Arc<DriverPackage>>), DriverError> {
        #[derive(Clone)]
        struct Item {
            order: u32,
            service: String,
        }
        let mut lowers: Vec<Item> = Vec::new();
        let mut uppers: Vec<Item> = Vec::new();

        for id in ids {
            let key = idx::escape_key(id);
            for pos in ["lower", "upper"] {
                let base = alloc::format!("SYSTEM/CurrentControlSet/Filters/hwid/{key}/{pos}");
                if let Some(children) = list_keys(&base).ok() {
                    for svc_path in children {
                        let order = match get_value(&svc_path, "Order") {
                            Some(Data::U32(v)) => v,
                            _ => 100,
                        };
                        let service = match get_value(&svc_path, "Service") {
                            Some(Data::Str(s)) => s,
                            _ => svc_path
                                .rsplit_once('/')
                                .map(|(_, s)| s.to_string())
                                .unwrap_or_else(|| svc_path.clone()),
                        };
                        if pos == "lower" {
                            lowers.push(Item { order, service });
                        } else {
                            uppers.push(Item { order, service });
                        }
                    }
                }
            }
        }

        if let Some(class) = class_opt {
            let key = idx::escape_key(class);
            for pos in ["lower", "upper"] {
                let base = alloc::format!("SYSTEM/CurrentControlSet/Filters/class/{key}/{pos}");
                if let Some(children) = list_keys(&base).ok() {
                    for svc_path in children {
                        let order = match get_value(&svc_path, "Order") {
                            Some(Data::U32(v)) => v,
                            _ => 100,
                        };
                        let service = match get_value(&svc_path, "Service") {
                            Some(Data::Str(s)) => s,
                            _ => svc_path
                                .rsplit_once('/')
                                .map(|(_, s)| s.to_string())
                                .unwrap_or_else(|| svc_path.clone()),
                        };
                        if pos == "lower" {
                            lowers.push(Item { order, service });
                        } else {
                            uppers.push(Item { order, service });
                        }
                    }
                }
            }
            let class_key = alloc::format!("SYSTEM/CurrentControlSet/Class/{class}");
            for (list_name, target_vec) in
                [("LowerFilters", &mut lowers), ("UpperFilters", &mut uppers)]
            {
                let list_key = alloc::format!("{class_key}/{list_name}");
                if let Some(k) = get_key(&list_key) {
                    let base_order = if list_name == "LowerFilters" {
                        10_000
                    } else {
                        20_000
                    };
                    for i in 0..k.values.len() {
                        let idxs = alloc::format!("{}", i);
                        if let Some(Data::Str(svc)) = get_value(&list_key, &idxs) {
                            target_vec.push(Item {
                                order: base_order + (i as u32),
                                service: svc,
                            });
                        }
                    }
                }
            }
        }

        for pos in ["lower", "upper"] {
            let base = alloc::format!(
                "SYSTEM/CurrentControlSet/Filters/driver/{}/{}",
                idx::escape_key(function_service),
                pos
            );
            if let Some(children) = list_keys(&base).ok() {
                for svc_path in children {
                    let order = match get_value(&svc_path, "Order") {
                        Some(Data::U32(v)) => v,
                        _ => 100,
                    };
                    let service = match get_value(&svc_path, "Service") {
                        Some(Data::Str(s)) => s,
                        _ => svc_path
                            .rsplit_once('/')
                            .map(|(_, s)| s.to_string())
                            .unwrap_or_else(|| svc_path.clone()),
                    };
                    if pos == "lower" {
                        lowers.push(Item { order, service });
                    } else {
                        uppers.push(Item { order, service });
                    }
                }
            }
        }

        lowers.sort_by(|a, b| {
            a.order
                .cmp(&b.order)
                .then_with(|| a.service.cmp(&b.service))
        });
        uppers.sort_by(|a, b| {
            a.order
                .cmp(&b.order)
                .then_with(|| a.service.cmp(&b.service))
        });

        let mut seen_l = BTreeMap::<String, u32>::new();
        let mut seen_u = BTreeMap::<String, u32>::new();
        let mut lower_svcs = Vec::new();
        let mut upper_svcs = Vec::new();
        for it in lowers {
            if !seen_l.contains_key(&it.service) {
                seen_l.insert(it.service.clone(), it.order);
                lower_svcs.push(it.service);
            }
        }
        for it in uppers {
            if !seen_u.contains_key(&it.service) {
                seen_u.insert(it.service.clone(), it.order);
                upper_svcs.push(it.service);
            }
        }

        let mut lower_rts = Vec::new();
        for svc in lower_svcs {
            if let Some(rt) = self.pkg_by_service(&svc) {
                lower_rts.push(rt);
            }
        }
        let mut upper_rts = Vec::new();
        for svc in upper_svcs {
            if let Some(rt) = self.pkg_by_service(&svc) {
                upper_rts.push(rt);
            }
        }
        Ok((lower_rts, upper_rts))
    }

    fn pkg_by_service(&self, svc: &str) -> Option<Arc<DriverPackage>> {
        if let Some(p) = self.hw.read().by_driver.get(svc) {
            return Some(p.clone());
        }
        let key = alloc::format!("SYSTEM/CurrentControlSet/Services/{svc}");
        let image = match get_value(&key, "ImagePath") {
            Some(Data::Str(s)) => s,
            _ => return None,
        };
        let toml = match get_value(&key, "TomlPath") {
            Some(Data::Str(s)) => s,
            _ => return None,
        };
        let start = match get_value(&key, "Start") {
            Some(Data::U32(v)) => match v {
                0 => BootType::Boot,
                1 => BootType::System,
                2 => BootType::Demand,
                3 => BootType::Disabled,
                _ => BootType::Demand,
            },
            _ => BootType::Demand,
        };
        Some(Arc::new(DriverPackage {
            name: svc.to_string(),
            image_path: image,
            toml_path: toml,
            start,
            hwids: Vec::new(),
        }))
    }

    #[inline]
    fn ensure_driver_entry(&self, drv: &Arc<DriverObject>) -> bool {
        let rt = &drv.runtime;
        match rt.get_state() {
            DriverState::Started | DriverState::Pending => return true,
            DriverState::Failed => return false,
            _ => {}
        }
        let m = rt.module.read();
        if let Some((_, rva)) = m.symbols.iter().find(|(s, _)| s == "DriverEntry") {
            let entry: unsafe extern "win64" fn(&Arc<DriverObject>) -> DriverStatus =
                unsafe { core::mem::transmute((m.image_base.as_u64() + *rva as u64) as *const ()) };
            let st = unsafe { entry(drv) };
            match st {
                DriverStatus::Success | DriverStatus::Pending => {
                    rt.set_state(DriverState::Started);
                    true
                }
                _ => {
                    rt.set_state(DriverState::Failed);
                    false
                }
            }
        } else {
            rt.set_state(DriverState::Failed);
            false
        }
    }

    #[inline]
    fn attach_one_above(
        &self,
        dn: &Arc<DevNode>,
        below: Option<Arc<DeviceObject>>,
        drv: &Arc<DriverObject>,
    ) -> Option<Arc<DeviceObject>> {
        if !self.ensure_driver_entry(drv) {
            return None;
        }
        if let Some(cb) = drv.evt_device_add {
            let mut dev_init = DeviceInit::new();
            let st = cb(drv, &mut dev_init);
            if st == DriverStatus::Success {
                let devobj = DeviceObject::new(dev_init.dev_ext_size);
                unsafe {
                    let me = &mut *(Arc::as_ptr(&devobj) as *mut DeviceObject);
                    me.dev_init = dev_init;
                    me.dev_node = Arc::downgrade(dn);
                }
                DeviceObject::set_lower_upper(&devobj, below);

                let stack_dir = alloc::format!("\\Device\\{}\\Stack", dn.instance_path);
                let _ = OBJECT_MANAGER.mkdir_p(stack_dir.clone());
                let uniq = (Arc::as_ptr(&devobj) as usize) as u64;
                let leaf = alloc::format!("{}-{:x}", drv.driver_name, uniq);
                let obj = Object::with_name(
                    ObjectTag::Device,
                    leaf.clone(),
                    ObjectPayload::Device(devobj.clone()),
                );
                let _ = OBJECT_MANAGER.link(alloc::format!("{}\\{}", stack_dir, leaf), &obj);
                return Some(devobj);
            }
        }
        None
    }

    fn ensure_function_attached(&self, dn: &Arc<DevNode>, stk: &mut DeviceStack) -> bool {
        if stk
            .function
            .as_ref()
            .and_then(|l| l.devobj.as_ref())
            .is_some()
        {
            return true;
        }
        let class = match dn.class.as_deref() {
            Some(c) => c,
            None => return false,
        };
        let pkg = match self.resolve_class_driver(Some(class)).ok().flatten() {
            Some(p) => p,
            None => return false,
        };
        let drv = match self.ensure_loaded(&pkg) {
            Ok(d) => d,
            Err(_) => return false,
        };
        let mut below = dn.get_pdo();
        for l in &stk.lower {
            if let Some(d) = &l.devobj {
                below = Some(d.clone());
            }
        }
        if let Some(devobj) = self.attach_one_above(dn, below, &drv) {
            stk.function = Some(StackLayer {
                driver: drv,
                devobj: Some(devobj),
            });
            true
        } else {
            false
        }
    }

    fn start_stack(&self, dn: &Arc<DevNode>) {
        let top_of_stack: Option<Arc<DeviceObject>> = {
            let mut guard = dn.stack.write();
            let stk = guard.as_mut().unwrap();

            {
                let mut layers: Vec<*mut StackLayer> = Vec::new();
                for l in stk.lower.iter_mut() {
                    layers.push(l as *mut _);
                }
                if let Some(f) = stk.function.as_mut() {
                    layers.push(f as *mut _);
                }
                for u in stk.upper.iter_mut() {
                    layers.push(u as *mut _);
                }

                let mut prev_do: Option<Arc<DeviceObject>> = dn.get_pdo();
                for layer_ptr in layers {
                    let layer = unsafe { &mut *layer_ptr };
                    let drv = &layer.driver;
                    if let Some(devobj) = self.attach_one_above(dn, prev_do.clone(), drv) {
                        layer.devobj = Some(devobj.clone());
                        prev_do = Some(devobj);
                    }
                }
            }

            let have_function = self.ensure_function_attached(dn, stk);
            if !have_function {
                stk.lower.clear();
                stk.upper.clear();
                stk.function = None;
                None
            } else {
                stk.lower.retain(|l| l.devobj.is_some());
                stk.upper.retain(|l| l.devobj.is_some());
                let mut current_bottom = dn.get_pdo();
                let all = stk
                    .lower
                    .iter()
                    .chain(stk.function.iter())
                    .chain(stk.upper.iter());
                for layer in all {
                    let current_do = layer.devobj.as_ref().unwrap();
                    DeviceObject::set_lower_upper(current_do, current_bottom.clone());
                    current_bottom = Some(current_do.clone());
                }
                current_bottom
            }
        };

        if let Some(top_device) = top_of_stack {
            let base = alloc::format!("\\Device\\{}", dn.instance_path);
            let _ = OBJECT_MANAGER.mkdir_p(base.clone());
            let _ = OBJECT_MANAGER.unlink(alloc::format!("{}\\Top", base));
            let top_obj = Object::with_name(
                ObjectTag::Device,
                "Top".into(),
                ObjectPayload::Device(top_device.clone()),
            );
            let _ = OBJECT_MANAGER.link(alloc::format!("{}\\Top", base), &top_obj);

            let pnp_payload = PnpRequest {
                minor_function: PnpMinorFunction::StartDevice,
                relation: DeviceRelationType::TargetDeviceRelation,
                id_type: QueryIdType::CompatibleIds,
                ids_out: Vec::new(),
                blob_out: Vec::new(),
            };
            let mut start_request = Request::new(RequestType::Pnp, Box::new([]));
            start_request.pnp = Some(pnp_payload);
            let ctx = Arc::into_raw(dn.clone()) as usize;
            start_request.set_completion(Self::start_io, ctx);

            let req_arc = Arc::new(RwLock::new(start_request));

            let target = IoTarget {
                target_device: top_device,
            };
            let st = self.send_request(&target, req_arc.clone());
        } else {
            dn.set_state(DevNodeState::Faulted);
        }
    }

    pub extern "win64" fn start_io(req: &mut Request, context: usize) {
        if context == 0 {
            return;
        }
        let dev_node = unsafe { Arc::from_raw(context as *const DevNode) };

        if req.status == DriverStatus::Success {
            dev_node.set_state(DevNodeState::Started);
            let pnp_manager = &*PNP_MANAGER;
            if let Some(top_device) = dev_node
                .stack
                .read()
                .as_ref()
                .and_then(|s| s.get_top_device_object())
            {
                let pnp_payload = PnpRequest {
                    minor_function: PnpMinorFunction::QueryDeviceRelations,
                    relation: DeviceRelationType::BusRelations,
                    id_type: QueryIdType::CompatibleIds,
                    ids_out: Vec::new(),
                    blob_out: Vec::new(),
                };
                let mut bus_enum_request = Request::new(RequestType::Pnp, Box::new([]));
                bus_enum_request.pnp = Some(pnp_payload);
                let ctx = Arc::into_raw(dev_node.clone()) as usize;
                bus_enum_request.set_completion(Self::process_enumerated_children, ctx);

                let req_arc = Arc::new(RwLock::new(bus_enum_request));

                let target = IoTarget {
                    target_device: top_device,
                };
                let st = pnp_manager.send_request(&target, req_arc.clone());
            }
        } else {
            dev_node.set_state(DevNodeState::Stopped);
        }
    }

    pub extern "win64" fn process_enumerated_children(req: &mut Request, context: usize) {
        if context == 0 {
            return;
        }
        let parent_dev_node = unsafe { Arc::from_raw(context as *const DevNode) };

        if req.status == DriverStatus::NotImplemented {
            return;
        }
        if req.status != DriverStatus::Success {
            return;
        }

        let pnp_manager = &*PNP_MANAGER;
        let children_to_start: Vec<Arc<DevNode>> = parent_dev_node
            .children
            .read()
            .iter()
            .filter(|c| c.get_state() == DevNodeState::Initialized)
            .cloned()
            .collect();
        for child_dn in children_to_start {
            let r = pnp_manager.bind_and_start(&child_dn);
            if let Err(e) = r {}
        }
    }

    fn ensure_loaded(&self, pkg: &Arc<DriverPackage>) -> Result<Arc<DriverObject>, DriverError> {
        let mut map = self.drivers.write();

        if let Some(d) = map.get(&pkg.name).cloned() {
            return Ok(d);
        }

        let module = {
            let pm = PROGRAM_MANAGER.get(0).expect("Kernel terminated").clone();
            let mut prog = pm.write();
            prog.load_module(pkg.image_path.clone())?
        };

        let _ = OBJECT_MANAGER.mkdir_p("\\Modules".to_string());
        let mod_obj = Object::with_name(
            ObjectTag::Module,
            pkg.name.clone(),
            ObjectPayload::Module(module.clone()),
        );
        let _ = OBJECT_MANAGER.link(alloc::format!("\\Modules\\{}", pkg.name), &mod_obj);

        let rt = Arc::new(DriverRuntime {
            pkg: pkg.clone(),
            module,
            state: AtomicU8::new(DriverState::Loaded as u8),
            refcnt: AtomicU32::new(0),
        });
        let drv_obj = DriverObject::allocate(rt, pkg.name.clone());

        let _ = OBJECT_MANAGER.mkdir_p("\\Drivers".to_string());
        let any: ObjRef = drv_obj.clone();
        let drv_om = Object::with_name(
            ObjectTag::Generic,
            pkg.name.clone(),
            ObjectPayload::Generic(any),
        );
        let _ = OBJECT_MANAGER.link(alloc::format!("\\Drivers\\{}", pkg.name), &drv_om);

        map.insert(pkg.name.clone(), drv_obj.clone());
        Ok(drv_obj)
    }

    pub fn invalidate_device_relations_for_node(
        &self,
        dev_node: &Arc<DevNode>,
        relation: DeviceRelationType,
    ) -> DriverStatus {
        let Some(top) = dev_node
            .stack
            .read()
            .as_ref()
            .and_then(|s| s.get_top_device_object())
            .or_else(|| dev_node.get_pdo())
        else {
            return DriverStatus::NoSuchDevice;
        };
        let pnp_payload = PnpRequest {
            minor_function: PnpMinorFunction::QueryDeviceRelations,
            relation,
            id_type: QueryIdType::CompatibleIds,
            ids_out: Vec::new(),
            blob_out: Vec::new(),
        };
        let mut req = Request::new(RequestType::Pnp, Box::new([]));
        req.pnp = Some(pnp_payload);
        let ctx = Arc::into_raw(dev_node.clone()) as usize;
        req.set_completion(Self::process_enumerated_children, ctx);
        let tgt = IoTarget { target_device: top };
        self.send_request(&tgt, Arc::new(RwLock::new(req)))
    }

    pub fn create_symlink(&self, link_path: String, target_path: String) -> Result<(), OmError> {
        OBJECT_MANAGER
            .symlink(link_path.to_string(), target_path.to_string(), true)
            .map(|_| ())
    }

    pub fn replace_symlink(&self, link_path: String, target_path: String) -> Result<(), OmError> {
        let _ = OBJECT_MANAGER.unlink(link_path.to_string());
        OBJECT_MANAGER
            .symlink(link_path.to_string(), target_path.to_string(), true)
            .map(|_| ())
    }

    pub fn create_device_symlink_top(
        &self,
        instance_path: String,
        link_path: String,
    ) -> Result<(), OmError> {
        let target = alloc::format!("\\Device\\{}\\Top", instance_path);
        OBJECT_MANAGER
            .symlink(link_path.to_string(), target, true)
            .map(|_| ())
    }

    pub fn remove_symlink(&self, link_path: String) -> Result<(), OmError> {
        OBJECT_MANAGER.unlink(link_path.to_string())
    }

    pub fn resolve_targetio_from_symlink(&self, mut p: String) -> Option<IoTarget> {
        for _ in 0..32 {
            let o = OBJECT_MANAGER.open(p.clone()).ok()?;
            match &o.payload {
                ObjectPayload::Device(d) => {
                    return Some(IoTarget {
                        target_device: d.clone(),
                    })
                }
                ObjectPayload::Directory(_) => {
                    p = alloc::format!("{}\\Top", p);
                }
                ObjectPayload::Symlink(target) => {
                    p = target.clone().target;
                }
                _ => return None,
            }
        }
        None
    }

    pub fn send_request_via_symlink(
        &self,
        link_path: String,
        req: Arc<RwLock<Request>>,
    ) -> DriverStatus {
        match self.resolve_targetio_from_symlink(link_path.clone()) {
            Some(tgt) => {
                let kind = { req.read().kind };
                let st = self.send_request(&tgt, req.clone());
                st
            }
            None => DriverStatus::NoSuchDevice,
        }
    }

    pub fn ioctl_via_symlink(
        &self,
        link_path: String,
        _control_code: u32,
        req: Arc<RwLock<Request>>,
    ) -> DriverStatus {
        self.send_request_via_symlink(link_path, req)
    }

    pub fn add_class_listener(
        &self,
        class: String,
        listener_dev: Arc<DeviceObject>,
        cb: ClassAddCallback,
    ) -> u64 {
        let id = self.next_listener_id.fetch_add(1, Ordering::AcqRel) + 1;
        self.class_listeners.lock().insert(
            id,
            ClassListener {
                class,
                dev: listener_dev,
                cb,
            },
        );
        id
    }

    pub fn remove_class_listener(&self, id: u64) -> bool {
        self.class_listeners.lock().remove(&id).is_some()
    }

    fn notify_class_listeners(&self, dn: &Arc<DevNode>) {
        let Some(cls) = dn.class.as_ref() else { return };
        let hits: Vec<(Arc<DeviceObject>, ClassAddCallback)> = {
            let map = self.class_listeners.lock();
            map.values()
                .filter(|l| l.class.eq_ignore_ascii_case(cls))
                .map(|l| (l.dev.clone(), l.cb))
                .collect()
        };
        for (dev, cb) in hits {
            cb(dn, &dev);
        }
    }

    pub fn print_device_tree(&self) {
        fn state_rank(s: DevNodeState) -> u8 {
            match s {
                DevNodeState::Started => 7,
                DevNodeState::DriversBound => 6,
                DevNodeState::Initialized => 5,
                DevNodeState::Stopped => 4,
                DevNodeState::Faulted => 3,
                DevNodeState::SurpriseRemoved => 2,
                DevNodeState::Deleted => 1,
                DevNodeState::Empty => 0,
            }
        }
        fn make_indent(depth: usize) -> alloc::string::String {
            let mut s = alloc::string::String::new();
            for _ in 0..depth {
                s.push_str("  ");
            }
            s
        }
        fn print_node_line(dn: &Arc<DevNode>, depth: usize) {
            let indent = make_indent(depth);
            let state = dn.get_state();
            let class = dn.class.as_deref().unwrap_or("-");
            let hwid = dn.ids.hardware.get(0).map(|s| s.as_str()).unwrap_or("-");
            crate::println!(
                "{}{}  [{}]  class={}  inst={}  hwid={}",
                indent,
                dn.name,
                match state {
                    DevNodeState::Empty => "Empty",
                    DevNodeState::Initialized => "Initialized",
                    DevNodeState::DriversBound => "DriversBound",
                    DevNodeState::Started => "Started",
                    DevNodeState::Stopped => "Stopped",
                    DevNodeState::SurpriseRemoved => "SurpriseRemoved",
                    DevNodeState::Deleted => "Deleted",
                    DevNodeState::Faulted => "Faulted",
                },
                class,
                dn.instance_path,
                hwid
            );
            if let Some(stk) = dn.stack.read().as_ref() {
                let mut parts: alloc::vec::Vec<&str> = alloc::vec::Vec::new();
                if !stk.lower.is_empty() {
                    parts.push("lower");
                }
                if stk.function.is_some() {
                    parts.push("func");
                }
                if !stk.upper.is_empty() {
                    parts.push("upper");
                }
                if !parts.is_empty() {
                    let sub = make_indent(depth + 1);
                    crate::println!("{}stack: {}", sub, parts.join("/"));
                }
            }
        }
        fn print_subtree(me: &PnpManager, dn: &Arc<DevNode>, depth: usize) {
            print_node_line(dn, depth);
            let mut kids = {
                let g = dn.children.read();
                g.iter().cloned().collect::<alloc::vec::Vec<_>>()
            };
            kids.sort_by(|a, b| {
                state_rank(a.get_state())
                    .cmp(&state_rank(b.get_state()))
                    .then_with(|| a.name.cmp(&b.name))
            });
            for ch in kids {
                print_subtree(me, &ch, depth + 1);
            }
        }
        let root = self.root();
        print_subtree(self, &root, 0);
    }

    pub fn get_device_target(&self, instance_path: &str) -> Option<IoTarget> {
        let om_path = alloc::format!("\\Device\\{}\\Top", instance_path);
        if let Ok(o) = OBJECT_MANAGER.open(om_path) {
            if let ObjectPayload::Device(d) = &o.payload {
                return Some(IoTarget {
                    target_device: d.clone(),
                });
            }
        }
        self.dev_root
            .find_child_by_path(instance_path)
            .and_then(|dn| {
                dn.stack
                    .read()
                    .as_ref()
                    .and_then(|s| s.get_top_device_object())
            })
            .map(|dev_obj| IoTarget {
                target_device: dev_obj,
            })
    }

    pub fn create_devnode_over_pdo_with_function(
        &self,
        parent_dn: Arc<DevNode>,
        instance_path: String,
        ids: DeviceIds,
        class: Option<String>,
        function_service: &str,
        function_fdo: Arc<DeviceObject>,
        init_pdo: DeviceInit,
    ) -> Result<(Arc<DevNode>, Arc<DeviceObject>), DriverError> {
        let name = instance_path
            .rsplit('\\')
            .next()
            .unwrap_or("NODE")
            .to_string();
        let dn = DevNode::new_child(
            name,
            instance_path.clone(),
            ids.clone(),
            class.clone(),
            &parent_dn,
        );
        *dn.stack.write() = Some(DeviceStack::new());

        let pdo = DeviceObject::new(init_pdo.dev_ext_size);
        unsafe {
            let p = &mut *(Arc::as_ptr(&pdo) as *mut DeviceObject);
            p.dev_node = Arc::downgrade(&dn);
            p.dev_init = init_pdo;
        }
        dn.set_pdo(pdo.clone());

        let base = alloc::format!("\\Device\\{}", dn.instance_path);
        let _ = OBJECT_MANAGER.mkdir_p("\\Device".to_string());
        let _ = OBJECT_MANAGER.mkdir_p(base.clone());
        let pdo_obj = Object::with_name(
            ObjectTag::Device,
            "PDO".to_string(),
            ObjectPayload::Device(pdo.clone()),
        );
        let _ = OBJECT_MANAGER.link(alloc::format!("{}\\PDO", base), &pdo_obj);

        let func_pkg = self
            .pkg_by_service(function_service)
            .ok_or(DriverError::NoParent)?;
        let func_drv = self.ensure_loaded(&func_pkg)?;

        let id_strs: Vec<&str> = ids
            .hardware
            .iter()
            .map(|s| s.as_str())
            .chain(ids.compatible.iter().map(|s| s.as_str()))
            .collect();
        let (lower_pkgs, upper_pkgs) =
            self.resolve_filters(&id_strs, class.as_deref(), function_service)?;

        let lower_layers: Vec<StackLayer> = lower_pkgs
            .into_iter()
            .map(|p| {
                Ok::<StackLayer, DriverError>(StackLayer {
                    driver: self.ensure_loaded(&p)?,
                    devobj: None,
                })
            })
            .collect::<Result<Vec<StackLayer>, DriverError>>()?;

        let upper_layers: Vec<StackLayer> = upper_pkgs
            .into_iter()
            .map(|p| {
                Ok::<StackLayer, DriverError>(StackLayer {
                    driver: self.ensure_loaded(&p)?,
                    devobj: None,
                })
            })
            .collect::<Result<Vec<StackLayer>, DriverError>>()?;

        {
            let mut g = dn.stack.write();
            let stk = g.as_mut().unwrap();
            stk.lower = lower_layers;
            stk.function = Some(StackLayer {
                driver: func_drv.clone(),
                devobj: None,
            });
            stk.upper = upper_layers;
        }

        let stack_dir = alloc::format!("\\Device\\{}\\Stack", dn.instance_path);
        let _ = OBJECT_MANAGER.mkdir_p(stack_dir.clone());

        let mut prev = pdo.clone();

        {
            let mut g = dn.stack.write();
            let stk = g.as_mut().unwrap();

            for layer in stk.lower.iter_mut() {
                if let Some(dobj) = self.attach_one_above(&dn, Some(prev.clone()), &layer.driver) {
                    layer.devobj = Some(dobj.clone());
                    prev = dobj;
                }
            }

            unsafe {
                let me = &mut *(Arc::as_ptr(&function_fdo) as *mut DeviceObject);
                me.dev_node = Arc::downgrade(&dn);
            }
            DeviceObject::set_lower_upper(&function_fdo, Some(prev.clone()));
            let uniq = (Arc::as_ptr(&function_fdo) as usize) as u64;
            let leaf = alloc::format!("{}-{:x}", func_drv.driver_name, uniq);
            let obj = Object::with_name(
                ObjectTag::Device,
                leaf.clone(),
                ObjectPayload::Device(function_fdo.clone()),
            );
            let _ = OBJECT_MANAGER.link(alloc::format!("{}\\{}", stack_dir, leaf), &obj);

            if let Some(f) = stk.function.as_mut() {
                f.devobj = Some(function_fdo.clone());
            }
            prev = function_fdo.clone();

            for layer in stk.upper.iter_mut() {
                if let Some(dobj) = self.attach_one_above(&dn, Some(prev.clone()), &layer.driver) {
                    layer.devobj = Some(dobj.clone());
                    prev = dobj;
                }
            }
        }

        let top = prev.clone();

        let _ = OBJECT_MANAGER.unlink(alloc::format!("{}\\Top", base));
        let top_obj = Object::with_name(
            ObjectTag::Device,
            "Top".to_string(),
            ObjectPayload::Device(top.clone()),
        );
        let _ = OBJECT_MANAGER.link(alloc::format!("{}\\Top", base), &top_obj);

        let pnp_payload = PnpRequest {
            minor_function: PnpMinorFunction::StartDevice,
            relation: DeviceRelationType::TargetDeviceRelation,
            id_type: QueryIdType::CompatibleIds,
            ids_out: Vec::new(),
            blob_out: Vec::new(),
        };
        let mut start_request = Request::new(RequestType::Pnp, Box::new([]));
        start_request.pnp = Some(pnp_payload);
        let ctx = Arc::into_raw(dn.clone()) as usize;
        start_request.set_completion(Self::start_io, ctx);

        let tgt = IoTarget {
            target_device: top.clone(),
        };
        let _ = self.send_request(&tgt, Arc::new(RwLock::new(start_request)));

        dn.set_state(DevNodeState::Started);
        Ok((dn, top))
    }

    pub fn create_control_device_with_init(
        &self,
        name: String,
        mut init: DeviceInit,
    ) -> (Arc<DeviceObject>, String) {
        init.pnp_vtable = None;

        let dev = DeviceObject::new(init.dev_ext_size);
        unsafe {
            let p = &mut *(Arc::as_ptr(&dev) as *mut DeviceObject);
            p.dev_init = init;
        }

        let base = alloc::format!("\\Device\\Control\\{}", name);
        let _ = OBJECT_MANAGER.mkdir_p("\\Device\\Control".to_string());
        let _ = OBJECT_MANAGER.mkdir_p(base.clone());

        let obj = Object::with_name(
            ObjectTag::Device,
            "Device".to_string(),
            ObjectPayload::Device(dev.clone()),
        );
        let dev_path = alloc::format!("{}\\Device", base);
        let _ = OBJECT_MANAGER.link(dev_path.clone(), &obj);

        (dev, dev_path)
    }

    pub fn create_control_device_and_link(
        &self,
        name: String,
        init: DeviceInit,
        link_path: String,
    ) -> Arc<DeviceObject> {
        let (dev, dev_path) = self.create_control_device_with_init(name, init);
        let _ = OBJECT_MANAGER.symlink(link_path, dev_path, true);
        dev
    }

    pub fn load_service(&self, svc: &str) -> Option<Arc<DriverObject>> {
        if let Some(drv) = self.drivers.read().get(svc).cloned() {
            let _ = self.ensure_driver_entry(&drv);
            return Some(drv);
        }

        let pkg = if let Some(p) = self.hw.read().by_driver.get(svc) {
            p.clone()
        } else {
            match self.pkg_by_service(svc) {
                Some(p) => p,
                None => return None,
            }
        };

        let drv = match self.ensure_loaded(&pkg) {
            Ok(d) => d,
            Err(_) => return None,
        };

        let _ = self.ensure_driver_entry(&drv);
        Some(drv)
    }
}

lazy_static::lazy_static! {
    pub static ref PNP_MANAGER: PnpManager = PnpManager::new();
}
