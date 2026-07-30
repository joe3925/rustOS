use super::driver_index::{self, HwIndex};
use crate::drivers::pnp::device::DevNodeExt;
use crate::error::error_with_message;
use crate::executable::program::PROGRAM_MANAGER;
use crate::object_manager::{OBJECT_MANAGER, ObjRef, Object, ObjectPayload};
use kernel_types::error::{DriverErrorKind, KernelError, ResultErrorContext};
use kernel_types::object_manager::ObjectTag;
use kernel_types::object_manager::OmError;

use crate::println;
use crate::registry::reg::{create_key, get_key, get_value, list_keys, set_value};
use alloc::string::ToString;
use alloc::vec;
use alloc::{collections::BTreeMap, format, string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};
use kernel_executor::runtime::runtime::spawn_detached;
use kernel_routing::pnp;
use kernel_types::ClassEventCallback;
use kernel_types::device::{
    DevNode, DevNodeState, DeviceInit, DeviceObject, DeviceStack, DriverObject, DriverPackage,
    DriverRuntime, DriverState, StackLayer,
};
use kernel_types::fs::Path;
use kernel_types::io::IoTarget;
use kernel_types::pnp::{
    BootType, DeviceEvent, DeviceIds, DeviceRelationType, DriverRole, DriverStep, InitComplete,
    ProbeContext, ProbeOutcome, QueryDeviceRelations, RemoveDevice, StartDevice,
};
use kernel_types::status::Data;
use spin::{Mutex, RwLock};

fn device_link_path(path: &str) -> String {
    let trimmed = path.trim_start_matches(['\\', '/']);
    let relative = trimmed
        .strip_prefix("GLOBAL\\")
        .or_else(|| trimmed.strip_prefix("global\\"))
        .or_else(|| {
            trimmed
                .get(..14)
                .filter(|prefix| prefix.eq_ignore_ascii_case("Links\\Devices\\"))
                .map(|_| &trimmed[14..])
        })
        .unwrap_or(trimmed);
    alloc::format!("\\Links\\Devices\\{}", relative)
}

fn device_link_path_if_public(path: &str) -> String {
    let trimmed = path.trim_start_matches(['\\', '/']);
    if trimmed
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("GLOBAL\\"))
        || trimmed
            .get(..14)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("Links\\Devices\\"))
    {
        device_link_path(path)
    } else {
        path.to_string()
    }
}

#[repr(C)]
pub struct ClassListener {
    pub class: String,
    pub dev: Arc<DeviceObject>,
    pub cb: ClassEventCallback,
}

pub struct PnpManager {
    hw: RwLock<Arc<HwIndex>>,
    drivers: RwLock<BTreeMap<String, Arc<DriverObject>>>,
    dev_root: Arc<DevNode>,
    class_listeners: Mutex<BTreeMap<u64, ClassListener>>,
    next_listener_id: AtomicU64,
}

impl PnpManager {
    const BINDINGS_KEY: &'static str = "SYSTEM/CurrentControlSet/Pnp/Bindings";
    const PREFERRED_FUNCTION_DRIVER: &'static str = "PreferredFunctionDriver";

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

    pub async fn init_from_registry(&self) -> Result<(), KernelError> {
        self.rebuild_index().await?;
        let boot_packages = self.collect_boot_packages();

        for pkg in boot_packages {
            match self.ensure_loaded(&pkg).await {
                Ok(driver) if self.ensure_driver_entry(&driver).is_ok() => {}
                Ok(_) => println!("-> initialize boot service {} failed", pkg.name),
                Err(error) => println!("-> load boot service {} failed: {:?}", pkg.name, error),
            }
        }

        let root = self.root();
        if root.get_pdo().is_none() {
            let pdo = DeviceObject::new(DeviceInit::new());
            pdo.attach_devnode(&root);
            root.set_pdo(pdo.clone());
            let base = alloc::format!("\\Device\\{}", root.instance_path);
            let _ = OBJECT_MANAGER.mkdir_p(base.clone());
            let object = Object::with_name(
                ObjectTag::Device,
                "PDO".to_string(),
                ObjectPayload::Device(pdo),
            );
            let _ = OBJECT_MANAGER.link(alloc::format!("{base}\\PDO"), &object);
        }
        if let Err(error) = self.bind_and_start(&root).await {
            println!("-> bind/start root failed: {:?}", error);
        }

        Ok(())
    }

    fn collect_boot_packages(&self) -> Vec<Arc<DriverPackage>> {
        let hw = self.hw.read();
        hw.by_driver
            .values()
            .filter(|p| p.start == BootType::Boot && p.role == DriverRole::Service)
            .cloned()
            .collect()
    }

    pub async fn rebuild_index(&self) -> Result<(), KernelError> {
        let hw = driver_index::build_hw_index().await?;
        *self.hw.write() = Arc::new(hw);
        Ok(())
    }

    pub async fn recheck_all_devices(&self) {
        if let Err(error) = self.rebuild_index().await {
            println!("[MANAGER] Failed to rebuild driver index: {error}");
            return;
        }
        let root = self.root();
        self.rebind_tree(&root).await;
        self.rescan_buses_started(&root);
    }

    pub async fn rebind_faulted_and_unbound(&self) {
        if self.hw.read().by_driver.is_empty() {
            if let Err(error) = self.rebuild_index().await {
                println!("[MANAGER] Failed to rebuild driver index: {error}");
                return;
            }
        }
        let root = self.root();
        self.rebind_tree(&root).await;
    }

    async fn rebind_tree(&self, dn: &Arc<DevNode>) {
        let mut stack: Vec<Arc<DevNode>> = Vec::new();
        stack.push(dn.clone());

        while let Some(node) = stack.pop() {
            let state = node.get_state();
            if Self::node_needs_function_driver(&node) && Self::can_rebind_state(state) {
                if let Err(error) = self.bind_and_start(&node).await {
                    println!(
                        "[MANAGER] Failed to bind/start `{}`: {}",
                        node.instance_path, error
                    );
                }
            }

            for ch in Self::collect_children(&node) {
                stack.push(ch);
            }
        }
    }

    fn rescan_buses_started(&self, dn: &Arc<DevNode>) {
        if dn.get_state() == DevNodeState::Started {
            let dn2 = dn.clone();
            spawn_detached(async move {
                let _ = PNP_MANAGER
                    .invalidate_device_relations_for_node(&dn2, DeviceRelationType::BusRelations)
                    .await;
            });
        }

        for ch in Self::collect_children(dn) {
            self.rescan_buses_started(&ch);
        }
    }

    fn node_needs_function_driver(node: &Arc<DevNode>) -> bool {
        let stack = node.stack.read();
        match stack.as_ref() {
            None => true,
            Some(stk) => stk
                .function
                .as_ref()
                .and_then(|layer| layer.devobj.as_ref())
                .is_none(),
        }
    }

    fn can_rebind_state(state: DevNodeState) -> bool {
        matches!(
            state,
            DevNodeState::Initialized | DevNodeState::Faulted | DevNodeState::Stopped
        )
    }

    fn collect_children(node: &Arc<DevNode>) -> Vec<Arc<DevNode>> {
        let children = node.children.read();
        children.iter().cloned().collect()
    }

    pub fn create_child_devnode_and_pdo(
        &self,
        parent: &Arc<DevNode>,
        name: String,
        instance_path: String,
        ids: DeviceIds,
        class: Option<String>,
    ) -> (Arc<DevNode>, Arc<DeviceObject>) {
        self.create_child_devnode_and_pdo_inner(
            parent,
            name,
            instance_path,
            ids,
            class,
            DeviceInit::new(),
        )
    }

    pub fn create_child_devnode_and_pdo_with_init(
        &self,
        parent: &Arc<DevNode>,
        name: String,
        instance_path: String,
        ids: DeviceIds,
        class: Option<String>,
        init: DeviceInit,
    ) -> (Arc<DevNode>, Arc<DeviceObject>) {
        self.create_child_devnode_and_pdo_inner(parent, name, instance_path, ids, class, init)
    }

    fn create_child_devnode_and_pdo_inner(
        &self,
        parent: &Arc<DevNode>,
        name: String,
        instance_path: String,
        ids: DeviceIds,
        class: Option<String>,
        init: DeviceInit,
    ) -> (Arc<DevNode>, Arc<DeviceObject>) {
        let dev_node = DevNode::new_child(name, instance_path, ids, class, parent);
        let pdo = DeviceObject::new(init);
        pdo.attach_devnode(&dev_node);

        dev_node.set_pdo(pdo.clone());

        let base = alloc::format!("\\Device\\{}", dev_node.instance_path);
        let _ = OBJECT_MANAGER.mkdir_p("\\Device");
        let _ = OBJECT_MANAGER.mkdir_p(base.clone());
        let pdo_obj = Object::with_name(
            ObjectTag::Device,
            "PDO".into(),
            ObjectPayload::Device(pdo.clone()),
        );
        let _ = OBJECT_MANAGER.link(alloc::format!("{}\\PDO", base), &pdo_obj);
        self.notify_class_listeners(&dev_node, DeviceEvent::Created);
        (dev_node, pdo)
    }

    pub async fn bind_and_start(&self, dn: &Arc<DevNode>) -> Result<(), KernelError> {
        let pdo = dn.get_pdo().ok_or_else(|| {
            error_with_message(
                DriverErrorKind::NoSuchDevice,
                format_args!("device node `{}` has no PDO", dn.instance_path),
            )
        })?;
        if let Err(error) = Self::start_device_object(&pdo).await {
            dn.set_state(DevNodeState::Faulted);
            return Err(error.with_context(format!("starting PDO for `{}`", dn.instance_path)));
        }
        self.bind_device(dn).await?;
        let has_function = dn
            .stack
            .read()
            .as_ref()
            .and_then(|stack| stack.function.as_ref())
            .is_some();
        if !has_function {
            return Ok(());
        }
        self.start_stack(dn).await;
        Ok(())
    }

    async fn start_device_object(device: &Arc<DeviceObject>) -> Result<(), KernelError> {
        if device.is_started() {
            return Ok(());
        }
        let mut start = StartDevice {
            resources: Vec::new(),
        };
        pnp::send_to_device(device.clone(), &mut start)
            .await
            .with_context(|| "sending StartDevice")?;
        let mut init = InitComplete;
        pnp::send_to_device(device.clone(), &mut init)
            .await
            .with_context(|| "sending InitComplete")?;
        device.set_started(true);
        Ok(())
    }

    async fn bind_device(&self, dn: &Arc<DevNode>) -> Result<(), KernelError> {
        let Some(function_pkg) = self.select_function_package(dn).await? else {
            dn.set_state(DevNodeState::Initialized);
            return Ok(());
        };

        let function_driver = self.ensure_loaded(&function_pkg).await?;
        let (lower_pkgs, upper_pkgs) = self
            .resolve_filters(
                &Self::hardware_ids(dn),
                dn.class.as_deref(),
                &function_pkg.name,
            )
            .await?;

        let function_layer = StackLayer {
            driver: function_driver,
            devobj: None,
        };
        let lower_layers = self.load_stack_layers(lower_pkgs).await?;
        let upper_layers = self.load_stack_layers(upper_pkgs).await?;

        Self::install_bound_stack(dn, function_layer, lower_layers, upper_layers);
        dn.set_state(DevNodeState::DriversBound);
        Ok(())
    }

    async fn select_function_package(
        &self,
        dn: &Arc<DevNode>,
    ) -> Result<Option<Arc<DriverPackage>>, KernelError> {
        let ids = Self::all_driver_ids(dn);
        let mut candidates = self.hw.read().matching(&ids, DriverRole::Function);
        let target = dn.get_pdo().ok_or_else(|| {
            error_with_message(
                DriverErrorKind::NoSuchDevice,
                format_args!("device node `{}` has no PDO", dn.instance_path),
            )
        })?;

        if let Some(hint) = Self::preferred_function_driver(dn).await {
            if let Some(index) = candidates
                .iter()
                .position(|candidate| candidate.pkg.name == hint)
            {
                candidates[..=index].rotate_right(1);
            }
        }

        for candidate in candidates {
            let driver = self.ensure_loaded(&candidate.pkg).await?;
            self.ensure_driver_entry(&driver)?;
            let callback = *driver.evt_probe_device.read();
            let outcome = match callback {
                Some(callback) => {
                    let context = ProbeContext {
                        devnode: dn.clone(),
                        lower_target: target.clone(),
                        generation: target.generation(),
                    };
                    callback(&driver, &context).await
                }
                None => ProbeOutcome::Match,
            };
            match outcome {
                ProbeOutcome::Match => return Ok(Some(candidate.pkg)),
                ProbeOutcome::NoMatch => continue,
                ProbeOutcome::Error(error) => return Err(error),
            }
        }

        let Some(package) = self.resolve_class_driver(dn.class.as_deref()).await? else {
            return Ok(None);
        };
        let driver = self.ensure_loaded(&package).await?;
        self.ensure_driver_entry(&driver)?;
        let context = ProbeContext {
            devnode: dn.clone(),
            lower_target: target,
            generation: dn.get_pdo().map_or(0, |pdo| pdo.generation()),
        };
        let callback = *driver.evt_probe_device.read();
        match callback {
            Some(callback) => match callback(&driver, &context).await {
                ProbeOutcome::Match => Ok(Some(package)),
                ProbeOutcome::NoMatch => Ok(None),
                ProbeOutcome::Error(error) => Err(error),
            },
            None => Ok(Some(package)),
        }
    }
    fn binding_key(instance_path: &str) -> String {
        alloc::format!(
            "{}/{}",
            Self::BINDINGS_KEY,
            driver_index::escape_key(instance_path)
        )
    }

    async fn preferred_function_driver(dn: &Arc<DevNode>) -> Option<String> {
        let key = Self::binding_key(&dn.instance_path);
        match get_value(&key, Self::PREFERRED_FUNCTION_DRIVER).await {
            Some(Data::Str(driver_name)) if !driver_name.is_empty() => Some(driver_name),
            _ => None,
        }
    }

    pub async fn set_preferred_function_driver(
        &self,
        instance_path: &str,
        driver_name: &str,
    ) -> Result<(), KernelError> {
        for key in [
            "SYSTEM/CurrentControlSet/Pnp",
            Self::BINDINGS_KEY,
            &Self::binding_key(instance_path),
        ] {
            if get_key(key).await.is_none() {
                create_key(key.to_string()).await?;
            }
        }
        set_value(
            &Self::binding_key(instance_path),
            Self::PREFERRED_FUNCTION_DRIVER,
            Data::Str(driver_name.to_string()),
        )
        .await
    }

    fn hardware_ids(dn: &Arc<DevNode>) -> Vec<&str> {
        dn.ids.hardware.iter().map(|s| s.as_str()).collect()
    }

    fn all_driver_ids(dn: &Arc<DevNode>) -> Vec<&str> {
        dn.ids
            .hardware
            .iter()
            .map(|s| s.as_str())
            .chain(dn.ids.compatible.iter().map(|s| s.as_str()))
            .collect()
    }

    async fn load_stack_layers(
        &self,
        packages: Vec<Arc<DriverPackage>>,
    ) -> Result<Vec<StackLayer>, KernelError> {
        let mut layers = Vec::with_capacity(packages.len());

        for pkg in packages {
            let driver = self.ensure_loaded(&pkg).await?;
            layers.push(StackLayer {
                driver,
                devobj: None,
            });
        }

        Ok(layers)
    }

    fn install_bound_stack(
        dn: &Arc<DevNode>,
        function_layer: StackLayer,
        lower_layers: Vec<StackLayer>,
        upper_layers: Vec<StackLayer>,
    ) {
        let mut stack = dn.stack.write();
        let stack = stack.as_mut().unwrap();
        stack.function = Some(function_layer);
        stack.lower = lower_layers;
        stack.upper = upper_layers;
    }

    async fn resolve_class_driver(
        &self,
        class_opt: Option<&str>,
    ) -> Result<Option<Arc<DriverPackage>>, KernelError> {
        let Some(class) = class_opt else {
            return Ok(None);
        };

        let class_key = alloc::format!("SYSTEM/CurrentControlSet/Class/{}", class);
        let svc = match get_value(&class_key, "Class").await {
            Some(Data::Str(s)) if !s.is_empty() => s,
            _ => return Ok(None),
        };

        if let Some(pkg) = self.hw.read().by_driver.get(&svc) {
            return Ok(Some(pkg.clone()));
        }

        let svc_key = alloc::format!("SYSTEM/CurrentControlSet/Services/{svc}");

        let image = match get_value(&svc_key, "ImagePath").await {
            Some(Data::Str(s)) => Path::from_string(&s),
            _ => return Ok(None),
        };

        let toml_path = match get_value(&svc_key, "TomlPath").await {
            Some(Data::Str(s)) => s,
            _ => return Ok(None),
        };

        let start = match get_value(&svc_key, "Start").await {
            Some(Data::U32(v)) => match v {
                0 => BootType::Boot,
                1 => BootType::Demand,
                2 => BootType::Disabled,
                _ => BootType::Demand,
            },
            _ => BootType::Demand,
        };
        let role = match get_value(&svc_key, "Role").await {
            Some(Data::U32(1)) => DriverRole::Function,
            _ => return Ok(None),
        };

        Ok(Some(Arc::new(DriverPackage {
            name: svc.clone(),
            image_path: image,
            toml_path,
            start,
            role,
            hwids: Vec::new(),
        })))
    }

    async fn resolve_filters(
        &self,
        ids: &[&str],
        class_opt: Option<&str>,
        function_service: &str,
    ) -> Result<(Vec<Arc<DriverPackage>>, Vec<Arc<DriverPackage>>), KernelError> {
        #[derive(Clone)]
        struct Item {
            order: u32,
            service: String,
        }

        let mut lowers: Vec<Item> = Vec::new();
        let mut uppers: Vec<Item> = Vec::new();

        for id in ids {
            let key = driver_index::escape_key(id);
            for pos in ["lower", "upper"] {
                let base = alloc::format!("SYSTEM/CurrentControlSet/Filters/hwid/{key}/{pos}");
                if let Ok(children) = list_keys(&base).await {
                    for svc_path in children {
                        let order = match get_value(&svc_path, "Order").await {
                            Some(Data::U32(v)) => v,
                            _ => 100,
                        };
                        let service = match get_value(&svc_path, "Service").await {
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
            let key = driver_index::escape_key(class);
            for pos in ["lower", "upper"] {
                let base = alloc::format!("SYSTEM/CurrentControlSet/Filters/class/{key}/{pos}");
                if let Ok(children) = list_keys(&base).await {
                    for svc_path in children {
                        let order = match get_value(&svc_path, "Order").await {
                            Some(Data::U32(v)) => v,
                            _ => 100,
                        };
                        let service = match get_value(&svc_path, "Service").await {
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
                if let Some(k) = get_key(&list_key).await {
                    let base_order = if list_name == "LowerFilters" {
                        10_000
                    } else {
                        20_000
                    };
                    for i in 0..k.values.len() {
                        let idxs = alloc::format!("{}", i);
                        if let Some(Data::Str(svc)) = get_value(&list_key, &idxs).await {
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
                driver_index::escape_key(function_service),
                pos
            );
            if let Ok(children) = list_keys(&base).await {
                for svc_path in children {
                    let order = match get_value(&svc_path, "Order").await {
                        Some(Data::U32(v)) => v,
                        _ => 100,
                    };
                    let service = match get_value(&svc_path, "Service").await {
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
            if let Some(rt) = self.pkg_by_service(&svc).await {
                lower_rts.push(rt);
            }
        }

        let mut upper_rts = Vec::new();
        for svc in upper_svcs {
            if let Some(rt) = self.pkg_by_service(&svc).await {
                upper_rts.push(rt);
            }
        }

        Ok((lower_rts, upper_rts))
    }

    async fn pkg_by_service(&self, svc: &str) -> Option<Arc<DriverPackage>> {
        if let Some(p) = self.hw.read().by_driver.get(svc) {
            return Some(p.clone());
        }

        let key = alloc::format!("SYSTEM/CurrentControlSet/Services/{svc}");

        let image = match get_value(&key, "ImagePath").await {
            Some(Data::Str(s)) => Path::from_string(&s),
            _ => return None,
        };

        let toml = match get_value(&key, "TomlPath").await {
            Some(Data::Str(s)) => s,
            _ => return None,
        };

        let start = match get_value(&key, "Start").await {
            Some(Data::U32(v)) => match v {
                0 => BootType::Boot,
                1 => BootType::Demand,
                2 => BootType::Disabled,
                _ => BootType::Demand,
            },
            _ => BootType::Demand,
        };
        let role = match get_value(&key, "Role").await {
            Some(Data::U32(0)) => DriverRole::Service,
            Some(Data::U32(1)) => DriverRole::Function,
            Some(Data::U32(2)) => DriverRole::Filter,
            _ => return None,
        };

        Some(Arc::new(DriverPackage {
            name: svc.to_string(),
            image_path: image,
            toml_path: toml,
            start,
            role,
            hwids: Vec::new(),
        }))
    }

    #[inline]
    fn ensure_driver_entry(&self, drv: &Arc<DriverObject>) -> Result<(), KernelError> {
        let rt = &drv.runtime;
        match rt.get_state() {
            DriverState::Started | DriverState::Continue => return Ok(()),
            DriverState::Failed => {
                return Err(error_with_message(
                    DriverErrorKind::DeviceError,
                    format_args!(
                        "driver `{}` previously failed initialization",
                        drv.driver_name
                    ),
                ));
            }
            _ => {}
        }
        let m = rt.module.read();
        if let Some((_, rva)) = m.exports.iter().find(|(s, _)| s == "DriverEntry") {
            let entry: unsafe extern "C" fn(&Arc<DriverObject>) -> Result<(), KernelError> =
                unsafe { core::mem::transmute((m.image_base.as_u64() + *rva as u64) as *const ()) };
            match unsafe { entry(drv) } {
                Ok(()) => {
                    rt.set_state(DriverState::Started);
                    Ok(())
                }
                Err(error) => {
                    rt.set_state(DriverState::Failed);
                    Err(error.with_context(format!("initializing driver `{}`", drv.driver_name)))
                }
            }
        } else {
            rt.set_state(DriverState::Failed);
            Err(error_with_message(
                DriverErrorKind::DeviceError,
                format_args!("driver `{}` does not export DriverEntry", drv.driver_name),
            ))
        }
    }

    #[inline]
    fn attach_one_above(
        &self,
        dn: &Arc<DevNode>,
        below: Option<Arc<DeviceObject>>,
        drv: &Arc<DriverObject>,
    ) -> Result<Option<Arc<DeviceObject>>, KernelError> {
        self.ensure_driver_entry(drv)?;

        let Some(cb) = *drv.evt_device_add.read() else {
            return Ok(None);
        };

        let mut dev_init = DeviceInit::new();
        let _step = cb(drv, &mut dev_init).map_err(|error| {
            error.with_context(format!("adding device for driver `{}`", drv.driver_name))
        })?;

        let devobj = DeviceObject::new(dev_init);
        devobj.attach_devnode(dn);

        if let Some(lower) = below {
            DeviceObject::set_lower_upper(&devobj, lower);
        }

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

        Ok(Some(devobj))
    }

    async fn probe_driver(
        &self,
        driver: &Arc<DriverObject>,
        dn: &Arc<DevNode>,
        lower_target: &Arc<DeviceObject>,
    ) -> ProbeOutcome {
        if let Err(error) = self.ensure_driver_entry(driver) {
            return ProbeOutcome::Error(error);
        }
        let callback = *driver.evt_probe_device.read();
        let Some(callback) = callback else {
            return ProbeOutcome::Match;
        };
        let context = ProbeContext {
            devnode: dn.clone(),
            lower_target: lower_target.clone(),
            generation: lower_target.generation(),
        };
        callback(driver, &context).await
    }

    async fn rollback_attached(
        dn: &Arc<DevNode>,
        attached: &[(Arc<DriverObject>, Arc<DeviceObject>)],
    ) {
        let stack_dir = alloc::format!("\\Device\\{}\\Stack", dn.instance_path);
        for (driver, device) in attached.iter().rev() {
            let mut remove = RemoveDevice;
            if let Err(error) = pnp::send_to_device(device.clone(), &mut remove).await {
                println!(
                    "[MANAGER] Rollback remove failed for driver `{}`: {}",
                    driver.driver_name, error
                );
            }
            device.set_started(false);
            DeviceObject::detach(device);
            let leaf = alloc::format!("{}-{:x}", driver.driver_name, Arc::as_ptr(device) as usize);
            let _ = OBJECT_MANAGER.unlink(alloc::format!("{stack_dir}\\{leaf}"));
        }
    }

    async fn start_stack(&self, dn: &Arc<DevNode>) {
        let pdo = match dn.get_pdo() {
            Some(p) => p,
            None => {
                dn.set_state(DevNodeState::Faulted);
                return;
            }
        };

        // Snapshot driver layers without holding the write lock during driver callbacks.
        let (lower_drivers, function_driver, upper_drivers) = {
            let guard = dn.stack.read();
            let stk = match guard.as_ref() {
                Some(s) => s,
                None => {
                    dn.set_state(DevNodeState::Faulted);
                    return;
                }
            };
            (
                stk.lower
                    .iter()
                    .map(|l| l.driver.clone())
                    .collect::<Vec<_>>(),
                stk.function.as_ref().map(|l| l.driver.clone()),
                stk.upper
                    .iter()
                    .map(|l| l.driver.clone())
                    .collect::<Vec<_>>(),
            )
        };

        // Stage attachments outside of the stack lock.
        let mut prev_do: Option<Arc<DeviceObject>> = Some(pdo.clone());
        let mut attached = Vec::<(Arc<DriverObject>, Arc<DeviceObject>)>::new();

        let mut lower_layers: Vec<StackLayer> = Vec::with_capacity(lower_drivers.len());
        for drv in lower_drivers {
            let target = prev_do.as_ref().unwrap();
            match self.probe_driver(&drv, dn, target).await {
                ProbeOutcome::NoMatch => continue,
                ProbeOutcome::Error(error) => {
                    Self::rollback_attached(dn, &attached).await;
                    Self::finish_start(dn.clone(), Err(error)).await;
                    return;
                }
                ProbeOutcome::Match => {}
            }
            match self.attach_one_above(dn, prev_do.clone(), &drv) {
                Ok(Some(devobj)) => {
                    attached.push((drv.clone(), devobj.clone()));
                    if let Err(error) = Self::start_device_object(&devobj).await {
                        Self::rollback_attached(dn, &attached).await;
                        Self::finish_start(dn.clone(), Err(error)).await;
                        return;
                    }
                    prev_do = Some(devobj.clone());
                    lower_layers.push(StackLayer {
                        driver: drv,
                        devobj: Some(devobj),
                    });
                }
                Ok(None) => {}
                Err(error) => {
                    Self::rollback_attached(dn, &attached).await;
                    Self::finish_start(dn.clone(), Err(error)).await;
                    return;
                }
            }
        }

        let mut function_layer: Option<StackLayer> = None;
        if let Some(drv) = function_driver {
            match self.attach_one_above(dn, prev_do.clone(), &drv) {
                Ok(Some(devobj)) => {
                    attached.push((drv.clone(), devobj.clone()));
                    if let Err(error) = Self::start_device_object(&devobj).await {
                        Self::rollback_attached(dn, &attached).await;
                        Self::finish_start(dn.clone(), Err(error)).await;
                        return;
                    }
                    prev_do = Some(devobj.clone());
                    function_layer = Some(StackLayer {
                        driver: drv,
                        devobj: Some(devobj),
                    });
                }
                Ok(None) => {}
                Err(error) => {
                    Self::rollback_attached(dn, &attached).await;
                    Self::finish_start(dn.clone(), Err(error)).await;
                    return;
                }
            }
        }

        let mut upper_layers: Vec<StackLayer> = Vec::with_capacity(upper_drivers.len());
        for drv in upper_drivers {
            let target = prev_do.as_ref().unwrap();
            match self.probe_driver(&drv, dn, target).await {
                ProbeOutcome::NoMatch => continue,
                ProbeOutcome::Error(error) => {
                    Self::rollback_attached(dn, &attached).await;
                    Self::finish_start(dn.clone(), Err(error)).await;
                    return;
                }
                ProbeOutcome::Match => {}
            }
            match self.attach_one_above(dn, prev_do.clone(), &drv) {
                Ok(Some(devobj)) => {
                    attached.push((drv.clone(), devobj.clone()));
                    if let Err(error) = Self::start_device_object(&devobj).await {
                        Self::rollback_attached(dn, &attached).await;
                        Self::finish_start(dn.clone(), Err(error)).await;
                        return;
                    }
                    prev_do = Some(devobj.clone());
                    upper_layers.push(StackLayer {
                        driver: drv,
                        devobj: Some(devobj),
                    });
                }
                Ok(None) => {}
                Err(error) => {
                    Self::rollback_attached(dn, &attached).await;
                    Self::finish_start(dn.clone(), Err(error)).await;
                    return;
                }
            }
        }

        let top_of_stack: Option<Arc<DeviceObject>> = if function_layer.is_none() {
            Self::rollback_attached(dn, &attached).await;
            let mut guard = dn.stack.write();
            if let Some(stk) = guard.as_mut() {
                stk.lower.clear();
                stk.upper.clear();
                stk.function = None;
            }
            None
        } else {
            let mut guard = dn.stack.write();
            let stk = guard.as_mut().unwrap();

            stk.lower = lower_layers;
            stk.function = function_layer;
            stk.upper = upper_layers;

            let mut current_bottom = Some(pdo.clone());
            for layer in stk
                .lower
                .iter()
                .chain(stk.function.iter())
                .chain(stk.upper.iter())
            {
                if let Some(current_do) = layer.devobj.as_ref() {
                    if let Some(bottom) = current_bottom {
                        DeviceObject::set_lower_upper(current_do, bottom.clone());
                    }
                    current_bottom = Some(current_do.clone());
                }
            }
            current_bottom
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

            let layers = {
                let stack = dn.stack.read();
                let stack = stack.as_ref().unwrap();
                stack
                    .lower
                    .iter()
                    .chain(stack.function.iter())
                    .chain(stack.upper.iter())
                    .filter_map(|layer| layer.devobj.clone())
                    .collect::<Vec<_>>()
            };
            let mut result = Ok(());
            for layer in layers {
                result = Self::start_device_object(&layer).await;
                if result.is_err() {
                    break;
                }
            }
            Self::finish_start(dn.clone(), result).await;
        } else {
            dn.set_state(DevNodeState::Faulted);
        }
    }

    async fn finish_start(dev_node: Arc<DevNode>, result: Result<(), KernelError>) {
        if result.is_ok() {
            dev_node.set_state(DevNodeState::Started);
            PNP_MANAGER.notify_class_listeners(&dev_node, DeviceEvent::Started);

            if let Some(top_device) = dev_node
                .stack
                .read()
                .as_ref()
                .and_then(|s| s.get_top_device_object())
            {
                let mut bus_enum_request = QueryDeviceRelations {
                    relation: DeviceRelationType::BusRelations,
                    devices: Vec::new(),
                };
                let result = pnp::send_down_stack(top_device, &mut bus_enum_request).await;
                Self::process_enumerated_children(&dev_node, result);
            }
        } else {
            if let Err(error) = result {
                println!(
                    "[MANAGER] Failed to start `{}`: {}",
                    dev_node.instance_path, error
                );
            }
            dev_node.set_state(DevNodeState::Stopped);
            PNP_MANAGER.notify_class_listeners(&dev_node, DeviceEvent::Failed);
        }
    }

    fn process_enumerated_children(
        parent_dev_node: &Arc<DevNode>,
        result: Result<DriverStep, KernelError>,
    ) {
        if let Err(error) = result {
            println!(
                "[MANAGER] Failed to enumerate children of `{}`: {}",
                parent_dev_node.instance_path, error
            );
            return;
        }

        let children_to_start: Vec<Arc<DevNode>> = parent_dev_node
            .children
            .read()
            .iter()
            .filter(|c| c.get_state() == DevNodeState::Initialized)
            .cloned()
            .collect();
        for child_dn in children_to_start {
            let dn = child_dn.clone();
            spawn_detached(async move {
                let status = PNP_MANAGER.bind_and_start(&dn).await;
                if let Some(err) = status.err() {
                    println!(
                        "[MANAGER] Failed to bind and start node: {:#?} with error: {:#?}",
                        dn.instance_path, err
                    );
                }
            });
        }
    }

    async fn ensure_loaded(
        &self,
        pkg: &Arc<DriverPackage>,
    ) -> Result<Arc<DriverObject>, KernelError> {
        let mut map = self.drivers.write();

        if let Some(d) = map.get(&pkg.name).cloned() {
            return Ok(d);
        }

        let module = {
            let pm = PROGRAM_MANAGER.get(0).expect("Kernel terminated").clone();
            let mut prog = pm.write();
            prog.load_module(pkg.image_path.clone())
                .await
                .map_err(|load_error| {
                    error_with_message(
                        DriverErrorKind::DeviceError,
                        format_args!(
                            "failed to load driver module `{}` from `{:?}`: {load_error:?}",
                            pkg.name, pkg.image_path
                        ),
                    )
                })?
        };

        let _ = OBJECT_MANAGER.mkdir_p("\\Modules");
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

        let _ = OBJECT_MANAGER.mkdir_p("\\Drivers");
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

    pub async fn invalidate_device_relations_for_node(
        &self,
        dev_node: &Arc<DevNode>,
        relation: DeviceRelationType,
    ) -> Result<(), KernelError> {
        let Some(top) = dev_node
            .stack
            .read()
            .as_ref()
            .and_then(|s| s.get_top_device_object())
            .or_else(|| dev_node.get_pdo())
        else {
            return Err(error_with_message(
                DriverErrorKind::NoSuchDevice,
                format_args!(
                    "device node `{}` has no routable device",
                    dev_node.instance_path
                ),
            ));
        };

        let mut req = QueryDeviceRelations {
            relation,
            devices: Vec::new(),
        };
        let result = pnp::send_down_stack(top, &mut req).await;
        match result {
            Ok(step) => {
                Self::process_enumerated_children(dev_node, Ok(step));
                Ok(())
            }
            Err(error) => {
                Self::process_enumerated_children(dev_node, Err(error.clone()));
                Err(error)
            }
        }
    }

    pub fn create_symlink(&self, link_path: String, target_path: String) -> Result<(), OmError> {
        let link_path = device_link_path(&link_path);
        let target_path = device_link_path_if_public(&target_path);
        OBJECT_MANAGER
            .symlink(&link_path, target_path.to_string(), true)
            .map(|_| ())
    }

    pub fn replace_symlink(&self, link_path: String, target_path: String) -> Result<(), OmError> {
        let link_path = device_link_path(&link_path);
        let target_path = device_link_path_if_public(&target_path);
        let _ = OBJECT_MANAGER.unlink(&link_path);
        OBJECT_MANAGER
            .symlink(&link_path, target_path.to_string(), true)
            .map(|_| ())
    }

    pub fn create_device_symlink_top(
        &self,
        instance_path: String,
        link_path: String,
    ) -> Result<(), OmError> {
        let target = alloc::format!("\\Device\\{}\\Top", instance_path);
        let link_path = device_link_path(&link_path);
        OBJECT_MANAGER.symlink(&link_path, target, true).map(|_| ())
    }

    pub fn remove_symlink(&self, link_path: String) -> Result<(), OmError> {
        OBJECT_MANAGER.unlink(device_link_path(&link_path))
    }

    pub fn resolve_targetio_from_symlink(&self, p: String) -> Option<IoTarget> {
        self.resolve_targetio_from_symlink_ref(&p)
    }

    pub fn resolve_targetio_from_symlink_ref(&self, p: &str) -> Option<IoTarget> {
        enum ResolvePath<'a> {
            Borrowed(&'a str),
            Owned(String),
        }

        impl ResolvePath<'_> {
            fn as_str(&self) -> &str {
                match self {
                    Self::Borrowed(p) => p,
                    Self::Owned(p) => p.as_str(),
                }
            }
        }

        let public_path = device_link_path_if_public(p);
        let mut p = if public_path == p {
            ResolvePath::Borrowed(p)
        } else {
            ResolvePath::Owned(public_path)
        };
        for _ in 0..32 {
            let o = OBJECT_MANAGER.open(p.as_str()).ok()?;
            match &o.payload {
                ObjectPayload::Device(d) => return Some(d.clone()),
                ObjectPayload::Directory(_) => {
                    p = ResolvePath::Owned(alloc::format!("{}\\Top", p.as_str()));
                }
                ObjectPayload::Symlink(_) => return None,
                _ => return None,
            }
        }
        None
    }

    pub fn add_class_listener(
        &self,
        class: String,
        listener_dev: Arc<DeviceObject>,
        cb: ClassEventCallback,
    ) -> u64 {
        let id = self.next_listener_id.fetch_add(1, Ordering::AcqRel) + 1;
        self.class_listeners.lock().insert(
            id,
            ClassListener {
                class: class.clone(),
                dev: listener_dev.clone(),
                cb,
            },
        );
        let mut pending = Vec::new();
        let mut nodes = vec![self.root()];
        while let Some(node) = nodes.pop() {
            nodes.extend(node.children.read().iter().cloned());
            if node
                .class
                .as_ref()
                .is_some_and(|candidate| candidate.eq_ignore_ascii_case(&class))
            {
                pending.push(node);
            }
        }
        for node in pending {
            let event = if node.state() == DevNodeState::Started {
                DeviceEvent::Started
            } else {
                DeviceEvent::Created
            };
            cb(node, event, &listener_dev);
        }
        id
    }

    pub fn remove_class_listener(&self, id: u64) -> bool {
        self.class_listeners.lock().remove(&id).is_some()
    }

    fn notify_class_listeners(&self, dn: &Arc<DevNode>, event: DeviceEvent) {
        let Some(cls) = dn.class.as_ref() else { return };
        let hits: Vec<(Arc<DeviceObject>, ClassEventCallback)> = {
            let map = self.class_listeners.lock();
            map.values()
                .filter(|l| l.class.eq_ignore_ascii_case(cls))
                .map(|l| (l.dev.clone(), l.cb))
                .collect()
        };
        for (dev, cb) in hits {
            cb(dn.clone(), event, &dev);
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
            let hwid = dn.ids.hardware.first().map(|s| s.as_str()).unwrap_or("-");
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
                return Some(d.clone());
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
    }

    pub fn create_control_device_with_init(
        &self,
        name: String,
        mut init: DeviceInit,
    ) -> (Arc<DeviceObject>, String) {
        init.pnp_ops = None;

        let dev = DeviceObject::new(init);

        let base = alloc::format!("\\Device\\Control\\{}", name);
        let _ = OBJECT_MANAGER.mkdir_p("\\Device\\Control");
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
}

lazy_static::lazy_static! {
    pub static ref PNP_MANAGER: PnpManager = PnpManager::new();
}
