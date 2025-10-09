use crate::alloc::vec;
use crate::drivers::pnp::driver_object::{
    ClassAddCallback, ClassListener, PnpRequest, QueryIdType, Synchronization,
};
use crate::util::{generate_guid, random_number};
use acpi::handler;
use alloc::boxed::Box;
use alloc::collections::vec_deque::VecDeque;
use alloc::format;
use alloc::{
    collections::btree_map::BTreeMap,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use bincode::de;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};
use spin::{Mutex, RwLock};

use crate::drivers::driver_install;
use crate::drivers::driver_install::{BootType, DriverError};
use crate::executable::program::{ModuleHandle, PROGRAM_MANAGER};
use crate::println;
use crate::registry::reg;
use crate::registry::{Data, RegError};
use crate::static_handlers::create_kernel_task;
use lazy_static::lazy_static;

use super::driver_object::{
    DeviceInit, DeviceObject, DeviceRelationType, DriverObject, DriverStatus, PnpMinorFunction,
    Request, RequestType,
};

pub type CompletionRoutine = extern "win64" fn(request: &mut Request, context: usize);
#[repr(C)]
#[derive(Clone)]
pub struct IoTarget {
    target_device: Arc<DeviceObject>,
}

pub type DpcFn = extern "win64" fn(usize);
#[derive(Clone, Copy)]
pub struct Dpc {
    pub func: DpcFn,
    pub arg: usize,
}

lazy_static! {
    static ref DISPATCH_DEVQ: spin::Mutex<VecDeque<Arc<DeviceObject>>> =
        spin::Mutex::new(VecDeque::new());
    static ref GLOBAL_DPCQ: spin::Mutex<VecDeque<Dpc>> = spin::Mutex::new(VecDeque::new());
}
pub const START_THREADS: usize = 1;
static DISPATCHER_STARTED: AtomicBool = AtomicBool::new(false);
pub type DriverEntryFn = unsafe extern "win64" fn(driver: &Arc<DriverObject>) -> DriverStatus;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DriverState {
    Loaded,
    Pending,
    Started,
    Stopped,
    Failed,
}
#[derive(Debug)]
pub struct DriverRuntime {
    pub pkg: Arc<DriverPackage>,
    pub module: ModuleHandle,
    pub state: AtomicU8,
    pub refcnt: AtomicU32,
}
impl DriverRuntime {
    fn set_state(&self, s: DriverState) {
        self.state.store(s as u8, Ordering::Release);
    }
    fn get_state(&self) -> DriverState {
        unsafe { core::mem::transmute(self.state.load(Ordering::Acquire)) }
    }
}

#[derive(Debug, Clone)]
pub struct DriverPackage {
    pub name: String,
    pub image_path: String,
    pub toml_path: String,
    pub start: BootType,
    pub hwids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchClass {
    Exact,
    Compatible,
    Class,
}

#[derive(Debug, Clone)]
pub struct DriverBinding {
    pub pkg: Arc<DriverPackage>,
    pub kind: MatchClass,
    pub score: u32,
}

fn rank(kind: MatchClass, start: BootType) -> u32 {
    let k = match kind {
        MatchClass::Exact => 3,
        MatchClass::Compatible => 2,
        MatchClass::Class => 1,
    };
    let s = match start {
        BootType::Boot => 4,
        BootType::System => 3,
        BootType::Demand => 2,
        BootType::Disabled => 0,
    };
    (k * 100) + s as u32
}
fn canonicalize_id(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        let c = ch.to_ascii_uppercase();
        match c {
            '\\' => out.push('\\'),
            '/' => out.push('\\'),
            _ => out.push(c),
        }
    }
    out
}

#[derive(Debug, Clone)]
pub struct HwIndex {
    pub by_id: BTreeMap<String, Vec<DriverBinding>>,
    pub by_driver: BTreeMap<String, Arc<DriverPackage>>,
}
impl HwIndex {
    pub fn new() -> Self {
        Self {
            by_id: BTreeMap::new(),
            by_driver: BTreeMap::new(),
        }
    }
    pub fn match_best<'a>(&'a self, ids: &[&str]) -> Option<&'a DriverBinding> {
        for id in ids {
            let key = canonicalize_id(id);
            if let Some(cands) = self.by_id.get(&key) {
                if let Some(best) = cands.first() {
                    return Some(best);
                }
            }
        }
        None
    }
}
#[repr(C)]
#[derive(Debug, Clone)]
pub struct DeviceIds {
    pub hardware: Vec<String>,   // e.g. ["PCI\VEN_8086&DEV_1234&SUBSYS_..."]
    pub compatible: Vec<String>, // broader/compatible ids
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevNodeState {
    Empty,
    Initialized,
    DriversBound,
    Started,
    Stopped,
    SurpriseRemoved,
    Deleted,
    Faulted,
}
#[derive(Debug, Clone)]
pub struct StackLayer {
    /// The loaded driver object for this layer (contains callbacks and per-driver config)
    pub driver: Arc<DriverObject>,

    /// The device object this driver created for this specific stack layer
    pub devobj: Option<Arc<DeviceObject>>,
}

#[derive(Debug)]
pub struct DeviceStack {
    pub pdo_bus_service: Option<String>,

    /// Lower filters (nearest to PDO first)
    pub lower: Vec<StackLayer>,

    /// Function driver for the PDO
    pub function: Option<StackLayer>,

    /// Upper filters (above the function driver)
    pub upper: Vec<StackLayer>,
}

impl DeviceStack {
    fn new() -> Self {
        Self {
            pdo_bus_service: None,
            lower: Vec::new(),
            function: None,
            upper: Vec::new(),
        }
    }

    pub fn get_top_device_object(&self) -> Option<Arc<DeviceObject>> {
        self.upper
            .last()
            .and_then(|l| l.devobj.clone())
            .or_else(|| self.function.as_ref().and_then(|l| l.devobj.clone()))
            .or_else(|| self.lower.last().and_then(|l| l.devobj.clone()))
    }
}
#[derive(Debug)]
#[repr(C)]
pub struct DevNode {
    pub name: String,
    pub parent: RwLock<Option<alloc::sync::Weak<DevNode>>>,
    pub children: RwLock<Vec<Arc<DevNode>>>,
    pub instance_path: String,
    pub ids: DeviceIds,
    pub class: Option<String>,
    pub state: AtomicU8,

    pub pdo: RwLock<Option<Arc<DeviceObject>>>,
    pub stack: RwLock<Option<DeviceStack>>,
}

impl DevNode {
    pub fn new_root() -> Arc<Self> {
        Arc::new(Self {
            name: "ROOT".to_string(),
            parent: RwLock::new(None),
            children: RwLock::new(Vec::new()),
            instance_path: "ROOT".to_string(),
            ids: DeviceIds {
                hardware: Vec::new(),
                compatible: Vec::new(),
            },
            class: None,
            state: AtomicU8::new(DevNodeState::Initialized as u8),
            pdo: RwLock::new(None),
            stack: RwLock::new(Some(DeviceStack::new())),
        })
    }

    pub fn new_child(
        name: String,
        instance_path: String,
        ids: DeviceIds,
        class: Option<String>,
        parent: &Arc<DevNode>,
    ) -> Arc<Self> {
        let dn = Arc::new(Self {
            name,
            parent: RwLock::new(Some(Arc::downgrade(parent))),
            children: RwLock::new(Vec::new()),
            instance_path,
            ids,
            class,
            state: AtomicU8::new(DevNodeState::Initialized as u8),
            pdo: RwLock::new(None),
            stack: RwLock::new(Some(DeviceStack::new())),
        });
        parent.children.write().push(dn.clone());
        dn
    }

    pub fn find_child_by_path(&self, path: &str) -> Option<Arc<DevNode>> {
        for child in self.children.read().iter() {
            if child.instance_path == path {
                return Some(child.clone());
            }
            if let Some(found) = child.find_child_by_path(path) {
                return Some(found);
            }
        }
        None
    }

    #[inline]
    pub fn set_pdo(&self, pdo: Arc<DeviceObject>) {
        *self.pdo.write() = Some(pdo);
    }

    #[inline]
    pub fn get_pdo(&self) -> Option<Arc<DeviceObject>> {
        self.pdo.read().clone()
    }

    fn set_state(&self, s: DevNodeState) {
        self.state.store(s as u8, Ordering::Release);
    }
    fn get_state(&self) -> DevNodeState {
        unsafe { core::mem::transmute(self.state.load(Ordering::Acquire)) }
    }
}

pub struct PnpManager {
    hw: RwLock<Arc<HwIndex>>,
    drivers: RwLock<BTreeMap<String, Arc<DriverObject>>>,
    dev_root: Arc<DevNode>,
    class_listeners: Mutex<BTreeMap<u64, ClassListener>>,
    next_listener_id: core::sync::atomic::AtomicU64,
}

impl PnpManager {
    pub fn new() -> Self {
        Self {
            hw: RwLock::new(Arc::new(HwIndex::new())),
            drivers: RwLock::new(BTreeMap::new()),
            dev_root: DevNode::new_root(),
            class_listeners: Mutex::new(BTreeMap::new()),
            next_listener_id: core::sync::atomic::AtomicU64::new(0),
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
                .filter(|pkg| pkg.start == BootType::Boot)
                .cloned()
                .collect()
        };

        for pkg in boot_packages {
            if let Err(e) = self.ensure_loaded(&pkg) {
                println!(
                    "  -> ERROR: Failed to load boot-start driver binary {}: {:?}",
                    pkg.name, e
                );
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
                println!(
                    "     -> ERROR: bind/start failed for '{}': {:?}",
                    devnode.name, e
                );
            }
        }

        self.init_io_dispatcher();
        Ok(())
    }

    pub fn rebuild_index(&self) -> Result<(), RegError> {
        let idx = Self::build_hw_index()?;
        *self.hw.write() = Arc::new(idx);
        Ok(())
    }
    /// These should only be called during the enumeration
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
        let _ = crate::object_manager::OBJECT_MANAGER.mkdir_p("\\Device".to_string());
        let _ = crate::object_manager::OBJECT_MANAGER.mkdir_p(base.clone());
        let pdo_obj = crate::object_manager::Object::with_name(
            crate::object_manager::ObjectTag::Device,
            "PDO".to_string(),
            crate::object_manager::ObjectPayload::Device(pdo.clone()),
        );
        let _ =
            crate::object_manager::OBJECT_MANAGER.link(alloc::format!("{}\\PDO", base), &pdo_obj);
        self.notify_class_listeners(&dev_node);
        (dev_node, pdo)
    }
    /// These should only be called during the enumeration
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
        let _ = crate::object_manager::OBJECT_MANAGER.mkdir_p("\\Device".to_string());
        let _ = crate::object_manager::OBJECT_MANAGER.mkdir_p(base.clone());
        let pdo_obj = crate::object_manager::Object::with_name(
            crate::object_manager::ObjectTag::Device,
            "PDO".to_string(),
            crate::object_manager::ObjectPayload::Device(pdo.clone()),
        );
        let _ =
            crate::object_manager::OBJECT_MANAGER.link(alloc::format!("{}\\PDO", base), &pdo_obj);
        self.notify_class_listeners(&dev_node);

        (dev_node, pdo)
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
        let _ = crate::object_manager::OBJECT_MANAGER.mkdir_p("\\Device".to_string());
        let _ = crate::object_manager::OBJECT_MANAGER.mkdir_p(base.clone());
        let pdo_obj = crate::object_manager::Object::with_name(
            crate::object_manager::ObjectTag::Device,
            "PDO".to_string(),
            crate::object_manager::ObjectPayload::Device(pdo.clone()),
        );
        let _ =
            crate::object_manager::OBJECT_MANAGER.link(alloc::format!("{}\\PDO", base), &pdo_obj);

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
                Ok(StackLayer {
                    driver: self.ensure_loaded(&p)?,
                    devobj: None,
                })
            })
            .collect::<Result<_, DriverError>>()?;
        let upper_layers: Vec<StackLayer> = upper_pkgs
            .into_iter()
            .map(|p| {
                Ok(StackLayer {
                    driver: self.ensure_loaded(&p)?,
                    devobj: None,
                })
            })
            .collect::<Result<_, DriverError>>()?;

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
        let _ = crate::object_manager::OBJECT_MANAGER.mkdir_p(stack_dir.clone());

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
            let obj = crate::object_manager::Object::with_name(
                crate::object_manager::ObjectTag::Device,
                leaf.clone(),
                crate::object_manager::ObjectPayload::Device(function_fdo.clone()),
            );
            let _ = crate::object_manager::OBJECT_MANAGER
                .link(alloc::format!("{}\\{}", stack_dir, leaf), &obj);

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

        let _ = crate::object_manager::OBJECT_MANAGER.unlink(alloc::format!("{}\\Top", base));
        let top_obj = crate::object_manager::Object::with_name(
            crate::object_manager::ObjectTag::Device,
            "Top".to_string(),
            crate::object_manager::ObjectPayload::Device(top.clone()),
        );
        let _ =
            crate::object_manager::OBJECT_MANAGER.link(alloc::format!("{}\\Top", base), &top_obj);

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

            let hw = self.hw.read();
            if let Some(best) = hw.match_best(&ids_slice) {
                func_pkg = Some(best.pkg.clone());
            }
        }

        // Fallback to class default service as the FUNCTION driver
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

        // Filters can still come from class + function service
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

        let lower_layers: Vec<StackLayer> = lower_pkgs
            .into_iter()
            .map(|pkg| {
                Ok(StackLayer {
                    driver: self.ensure_loaded(&pkg)?,
                    devobj: None,
                })
            })
            .collect::<Result<_, DriverError>>()?;

        let upper_layers: Vec<StackLayer> = upper_pkgs
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
            let mut guard = dn.stack.write();
            let stk = guard.as_mut().expect("Device stack must exist");
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

        // Class → service mapping: SYSTEM/CurrentControlSet/Class/<class>/Class = "<service>"
        let class_key = alloc::format!("SYSTEM/CurrentControlSet/Class/{}", class);
        let svc = match reg::get_value(&class_key, "Class") {
            Some(Data::Str(s)) if !s.is_empty() => s,
            _ => return Ok(None),
        };

        // Find package by driver/service name via index or Services node
        if let Some(pkg) = self.hw.read().by_driver.get(&svc) {
            return Ok(Some(pkg.clone()));
        }

        // Fallback: look under Services/<svc>
        let svc_key = alloc::format!("SYSTEM/CurrentControlSet/Services/{}", svc);
        let image = match reg::get_value(&svc_key, "ImagePath") {
            Some(Data::Str(s)) => s,
            _ => return Ok(None),
        };
        let toml_path = match reg::get_value(&svc_key, "TomlPath") {
            Some(Data::Str(s)) => s,
            _ => return Ok(None),
        };
        let start = match reg::get_value(&svc_key, "Start") {
            Some(Data::U32(v)) => match v {
                0 => BootType::Boot,
                1 => BootType::System,
                2 => BootType::Demand,
                3 => BootType::Disabled,
                _ => BootType::Demand,
            },
            _ => BootType::Demand,
        };

        let pkg = Arc::new(DriverPackage {
            name: svc.clone(),
            image_path: image,
            toml_path,
            start,
            hwids: Vec::new(),
        });

        return Ok(Some(pkg));
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
            let key = escape_key(id);
            for pos in ["lower", "upper"].iter() {
                let base = alloc::format!("SYSTEM/CurrentControlSet/Filters/hwid/{}/{}", key, pos);
                if let Some(children) = reg::list_keys(&base).ok() {
                    for svc_path in children {
                        let order = match reg::get_value(&svc_path, "Order") {
                            Some(Data::U32(v)) => v,
                            _ => 100,
                        };
                        let service = match reg::get_value(&svc_path, "Service") {
                            Some(Data::Str(s)) => s,
                            _ => svc_path
                                .rsplit_once('/')
                                .map(|(_, s)| s.to_string())
                                .unwrap_or_else(|| svc_path.clone()),
                        };
                        if *pos == "lower" {
                            lowers.push(Item { order, service });
                        } else {
                            uppers.push(Item { order, service });
                        }
                    }
                }
            }
        }

        if let Some(class) = class_opt {
            let key = escape_key(class);
            for pos in ["lower", "upper"].iter() {
                let base = alloc::format!("SYSTEM/CurrentControlSet/Filters/class/{}/{}", key, pos);
                if let Some(children) = reg::list_keys(&base).ok() {
                    for svc_path in children {
                        let order = match reg::get_value(&svc_path, "Order") {
                            Some(Data::U32(v)) => v,
                            _ => 100,
                        };
                        let service = match reg::get_value(&svc_path, "Service") {
                            Some(Data::Str(s)) => s,
                            _ => svc_path
                                .rsplit_once('/')
                                .map(|(_, s)| s.to_string())
                                .unwrap_or_else(|| svc_path.clone()),
                        };
                        if *pos == "lower" {
                            lowers.push(Item { order, service });
                        } else {
                            uppers.push(Item { order, service });
                        }
                    }
                }
            }

            let class_key = alloc::format!("SYSTEM/CurrentControlSet/Class/{}", class);
            for (list_name, target_vec) in
                [("LowerFilters", &mut lowers), ("UpperFilters", &mut uppers)]
            {
                let list_key = alloc::format!("{}/{}", class_key, list_name);
                if let Some(k) = reg::get_key(&list_key) {
                    let base_order = if list_name == "LowerFilters" {
                        10_000
                    } else {
                        20_000
                    };
                    for i in 0..k.values.len() {
                        let idx = alloc::format!("{}", i);
                        if let Some(Data::Str(svc)) = reg::get_value(&list_key, &idx) {
                            target_vec.push(Item {
                                order: base_order + (i as u32),
                                service: svc,
                            });
                        }
                    }
                }
            }
        }

        for pos in ["lower", "upper"].iter() {
            let base = alloc::format!(
                "SYSTEM/CurrentControlSet/Filters/driver/{}/{}",
                escape_key(function_service),
                pos
            );
            if let Some(children) = reg::list_keys(&base).ok() {
                for svc_path in children {
                    let order = match reg::get_value(&svc_path, "Order") {
                        Some(Data::U32(v)) => v,
                        _ => 100,
                    };
                    let service = match reg::get_value(&svc_path, "Service") {
                        Some(Data::Str(s)) => s,
                        _ => svc_path
                            .rsplit_once('/')
                            .map(|(_, s)| s.to_string())
                            .unwrap_or_else(|| svc_path.clone()),
                    };
                    if *pos == "lower" {
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
        let key = alloc::format!("SYSTEM/CurrentControlSet/Services/{}", svc);
        let image = match reg::get_value(&key, "ImagePath") {
            Some(Data::Str(s)) => s,
            _ => return None,
        };
        let toml = match reg::get_value(&key, "TomlPath") {
            Some(Data::Str(s)) => s,
            _ => return None,
        };
        let start = match reg::get_value(&key, "Start") {
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
            rt.set_state(DriverState::Pending);
            let entry: DriverEntryFn =
                unsafe { core::mem::transmute((m.image_base.as_u64() + *rva as u64) as *const ()) };
            let st = unsafe { entry(drv) };
            match st {
                DriverStatus::Success | DriverStatus::Pending => true,
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
                let _ = crate::object_manager::OBJECT_MANAGER.mkdir_p(stack_dir.clone());
                let uniq = (Arc::as_ptr(&devobj) as usize) as u64;
                let leaf = alloc::format!("{}-{:x}", drv.driver_name, uniq);
                let obj = crate::object_manager::Object::with_name(
                    crate::object_manager::ObjectTag::Device,
                    leaf.clone(),
                    crate::object_manager::ObjectPayload::Device(devobj.clone()),
                );
                let _ = crate::object_manager::OBJECT_MANAGER
                    .link(alloc::format!("{}\\{}", stack_dir, leaf), &obj);

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

    fn start_stack(&self, dn: &Arc<DevNode>) {
        println!(
            "   -> Building device stack for '{:#?}'",
            dn.ids.hardware.get(0)
        );

        let top_of_stack: Option<Arc<DeviceObject>> = {
            let mut guard = dn.stack.write();
            let stk = guard
                .as_mut()
                .expect("A device stack must exist to be started.");

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
                    } else {
                        println!("      -> NOTE: Driver {} did not attach.", drv.driver_name);
                    }
                }
            }

            let have_function = self.ensure_function_attached(dn, stk);

            if !have_function {
                println!("   -> CRITICAL: No usable function driver. Aborting start.");
                stk.lower.clear();
                stk.upper.clear();
                stk.function = None;
                None
            } else {
                stk.lower.retain(|l| l.devobj.is_some());
                stk.upper.retain(|l| l.devobj.is_some());

                let mut current_bottom = dn.get_pdo();
                let all_valid_layers = stk
                    .lower
                    .iter()
                    .chain(stk.function.iter())
                    .chain(stk.upper.iter());

                for layer in all_valid_layers {
                    let current_do = layer.devobj.as_ref().unwrap();
                    DeviceObject::set_lower_upper(current_do, current_bottom.clone());
                    current_bottom = Some(current_do.clone());
                }

                current_bottom
            }
        };

        if let Some(top_device) = top_of_stack {
            let base = alloc::format!("\\Device\\{}", dn.instance_path);
            let _ = crate::object_manager::OBJECT_MANAGER.mkdir_p(base.clone());
            let _ = crate::object_manager::OBJECT_MANAGER.unlink(alloc::format!("{}\\Top", base));
            let top_obj = crate::object_manager::Object::with_name(
                crate::object_manager::ObjectTag::Device,
                "Top".to_string(),
                crate::object_manager::ObjectPayload::Device(top_device.clone()),
            );
            let _ = crate::object_manager::OBJECT_MANAGER
                .link(alloc::format!("{}\\Top", base), &top_obj);

            let top_device_name = top_device.dev_node.upgrade().unwrap().name.clone();

            let pnp_payload = PnpRequest {
                minor_function: PnpMinorFunction::StartDevice,
                relation: DeviceRelationType::TargetDeviceRelation,
                id_type: QueryIdType::CompatibleIds,
                ids_out: Vec::new(),
                blob_out: Vec::new(),
            };
            let mut start_request = Request::new(RequestType::Pnp, Box::new([]));
            start_request.pnp = Some(pnp_payload);

            let devnode_ptr_as_context = Arc::into_raw(dn.clone()) as usize;
            start_request.set_completion(Self::start_io, devnode_ptr_as_context);

            let target = IoTarget {
                target_device: top_device,
            };
            self.send_request(&target, Arc::new(RwLock::new(start_request)));
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

                let devnode_ptr_as_context = Arc::into_raw(dev_node.clone()) as usize;
                bus_enum_request
                    .set_completion(Self::process_enumerated_children, devnode_ptr_as_context);

                let target = IoTarget {
                    target_device: top_device,
                };
                pnp_manager.send_request(&target, Arc::new(RwLock::new(bus_enum_request)));
            }
        } else {
            println!(
        "   -> FAILURE: PnP StartDevice failed for '{}' with status {:?}. Device is stopped.",
        dev_node.name, req.status
        );
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
            println!(
                "   -> FAILURE: Bus enumeration failed for '{}' with status {:?}.",
                parent_dev_node.name, req.status
            );
            return;
        }

        println!(
            "   -> COMPLETION: Bus enumeration complete for '{}'. Binding and starting children...",
            parent_dev_node.name
        );

        let pnp_manager = &*PNP_MANAGER;

        let children_to_start: Vec<Arc<DevNode>> = parent_dev_node
            .children
            .read()
            .iter()
            .filter(|child| child.get_state() == DevNodeState::Initialized)
            .cloned()
            .collect();
        for child_dn in children_to_start {
            pnp_manager.bind_and_start(&child_dn).expect("idk");
        }
    }
    fn ensure_loaded(&self, pkg: &Arc<DriverPackage>) -> Result<Arc<DriverObject>, DriverError> {
        if let Some(rt) = self.drivers.read().get(&pkg.name).cloned() {
            if matches!(
                rt.runtime.get_state(),
                DriverState::Started | DriverState::Loaded
            ) {
                return Ok(rt);
            }
        }

        let module = {
            let pm = PROGRAM_MANAGER
                .get(0)
                .expect("Kernel was terminated")
                .clone();
            let mut prog = pm.write();
            prog.load_module(pkg.image_path.clone())?
        };

        let _ = crate::object_manager::OBJECT_MANAGER.mkdir_p("\\Modules".to_string());
        let mod_obj = crate::object_manager::Object::with_name(
            crate::object_manager::ObjectTag::Module,
            pkg.name.clone(),
            crate::object_manager::ObjectPayload::Module(module.clone()),
        );
        let _ = crate::object_manager::OBJECT_MANAGER
            .link(alloc::format!("\\Modules\\{}", pkg.name), &mod_obj);

        let rt = Arc::new(DriverRuntime {
            pkg: pkg.clone(),
            module,
            state: AtomicU8::new(DriverState::Loaded as u8),
            refcnt: AtomicU32::new(0),
        });
        let drv_obj = DriverObject::allocate(rt, pkg.name.clone());

        let _ = crate::object_manager::OBJECT_MANAGER.mkdir_p("\\Drivers".to_string());
        let any: crate::object_manager::ObjRef = drv_obj.clone();
        let drv_om = crate::object_manager::Object::with_name(
            crate::object_manager::ObjectTag::Generic,
            pkg.name.clone(),
            crate::object_manager::ObjectPayload::Generic(any),
        );
        let _ = crate::object_manager::OBJECT_MANAGER
            .link(alloc::format!("\\Drivers\\{}", pkg.name), &drv_om);

        self.drivers
            .write()
            .insert(pkg.name.clone(), drv_obj.clone());
        Ok(drv_obj)
    }

    fn build_hw_index() -> Result<HwIndex, RegError> {
        let mut idx = HwIndex::new();

        let services_root = "SYSTEM/CurrentControlSet/Services";
        let service_keys = reg::list_keys(services_root)?;

        for kpath in service_keys {
            let rel = kpath
                .strip_prefix(&(services_root.to_string() + "/"))
                .unwrap_or("");
            if rel.contains('/') {
                continue;
            }

            let drv_name = rel.to_string();

            let image = match reg::get_value(&kpath, "ImagePath") {
                Some(Data::Str(s)) => s,
                _ => continue,
            };
            let toml_path = match reg::get_value(&kpath, "TomlPath") {
                Some(Data::Str(s)) => s,
                _ => continue,
            };
            let start = match reg::get_value(&kpath, "Start") {
                Some(Data::U32(v)) => match v {
                    0 => BootType::Boot,
                    1 => BootType::System,
                    2 => BootType::Demand,
                    3 => BootType::Disabled,
                    _ => BootType::Disabled,
                },
                _ => BootType::Demand,
            };

            let dt = match driver_install::parse_driver_toml(&toml_path) {
                Ok(d) => d,
                Err(_) => continue,
            };

            let pkg = Arc::new(DriverPackage {
                name: drv_name.clone(),
                image_path: image,
                toml_path,
                start,
                hwids: dt.hwids,
            });

            idx.by_driver.insert(drv_name, pkg.clone());

            for raw in &pkg.hwids {
                let id = canonicalize_id(raw);
                let kind = classify_id(&id);
                let sc = rank(kind, pkg.start);
                idx.by_id
                    .entry(id)
                    .or_insert_with(Vec::new)
                    .push(DriverBinding {
                        pkg: pkg.clone(),
                        kind,
                        score: sc,
                    });
            }
        }

        for (_id, vec) in idx.by_id.iter_mut() {
            vec.sort_by(|a, b| {
                b.score
                    .cmp(&a.score)
                    .then_with(|| a.pkg.name.cmp(&b.pkg.name))
            });
            vec.dedup_by(|a, b| a.pkg.name == b.pkg.name);
        }

        Ok(idx)
    }
    #[inline]
    pub fn run_once(&self) -> bool {
        let mut did = false;
        did |= self.run_one_dpc();
        did |= self.run_one_device_request();
        did
    }
    pub fn dispatch_forever(&self) -> ! {
        loop {
            let mut did_work = false;
            did_work |= self.run_one_dpc();
            did_work |= self.run_one_device_request();
            if !did_work {
                core::hint::spin_loop();
            }
        }
    }

    #[inline]
    fn run_one_dpc(&self) -> bool {
        let dpc_opt = GLOBAL_DPCQ.lock().pop_front();
        if let Some(dpc) = dpc_opt {
            (dpc.func)(dpc.arg);
            true
        } else {
            false
        }
    }

    #[inline]
    fn run_one_device_request(&self) -> bool {
        let dev = match { DISPATCH_DEVQ.lock().pop_front() } {
            Some(d) => d,
            None => return false,
        };

        let _ = dev
            .dispatch_tickets
            .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |cur| {
                Some(cur.saturating_sub(1))
            });

        loop {
            let req_opt = { dev.queue.lock().pop_front() };
            if let Some(req) = req_opt {
                self.call_device_handler(&dev, req);
                continue;
            }

            let more = dev.dispatch_tickets.load(Ordering::Acquire);
            let needs = more > 0 || { !dev.queue.lock().is_empty() };
            if needs {
                let mut dq = DISPATCH_DEVQ.lock();
                let already = dq.iter().any(|d| Arc::ptr_eq(d, &dev));
                if !already {
                    dq.push_back(dev.clone());
                }
            }
            return true;
        }
    }

    extern "win64" fn pnp_minor_dispatch(
        device: &Arc<DeviceObject>,
        request: Arc<RwLock<Request>>,
    ) {
        let pnp_manager = &*PNP_MANAGER;

        let minor_opt = { request.read().pnp.as_ref().map(|p| p.minor_function) };
        let Some(minor) = minor_opt else {
            let st = pnp_manager.send_request_to_next_lower(device, request.clone());
            if st == DriverStatus::NoSuchDevice {
                let mut r = take_req(&request);
                r.status = DriverStatus::NotImplemented;
                pnp_manager.complete_request(&mut r);
                put_req(&request, r);
            } else {
                request.write().status = DriverStatus::Pending;
            }
            return;
        };

        let cb_opt = device
            .dev_init
            .pnp_vtable
            .as_ref()
            .and_then(|vt| vt.get(minor));

        if let Some(cb) = cb_opt {
            match cb(device, request.clone()) {
                DriverStatus::Success => {
                    let mut r = take_req(&request);
                    r.status = DriverStatus::Success;
                    pnp_manager.complete_request(&mut r);
                    put_req(&request, r);
                }
                DriverStatus::Pending => {
                    request.write().status = DriverStatus::Pending;
                    let st = pnp_manager.send_request_to_next_lower(device, request.clone());
                    if st == DriverStatus::NoSuchDevice {
                        let mut r = take_req(&request);
                        r.status = match minor {
                            PnpMinorFunction::StartDevice
                            | PnpMinorFunction::QueryDeviceRelations => DriverStatus::Success,
                            _ => DriverStatus::NotImplemented,
                        };
                        pnp_manager.complete_request(&mut r);
                        put_req(&request, r);
                    }
                }
                other => {
                    let mut r = take_req(&request);
                    r.status = other;
                    pnp_manager.complete_request(&mut r);
                    put_req(&request, r);
                }
            }
            return;
        }

        match minor {
            PnpMinorFunction::StartDevice | PnpMinorFunction::QueryDeviceRelations => {
                let st = pnp_manager.send_request_to_next_lower(device, request.clone());
                if st == DriverStatus::NoSuchDevice {
                    let mut r = take_req(&request);
                    r.status = DriverStatus::Success;
                    pnp_manager.complete_request(&mut r);
                    put_req(&request, r);
                } else {
                    request.write().status = DriverStatus::Pending;
                }
            }
            _ => {
                let st = pnp_manager.send_request_to_next_lower(device, request.clone());
                if st == DriverStatus::NoSuchDevice {
                    let mut r = take_req(&request);
                    r.status = DriverStatus::NoSuchDevice;
                    pnp_manager.complete_request(&mut r);
                    put_req(&request, r);
                } else {
                    request.write().status = DriverStatus::Pending;
                }
            }
        }
    }

    #[inline]
    fn call_device_handler(&self, dev: &Arc<DeviceObject>, req_arc: Arc<RwLock<Request>>) {
        let kind = { req_arc.read().kind };
        if matches!(kind, RequestType::Dummy) {
            return;
        }
        if matches!(kind, RequestType::Pnp) {
            Self::pnp_minor_dispatch(dev, req_arc.clone());
            return;
        }
        if let Some(h) = dev.dev_init.io_vtable.get_for(&kind) {
            match h.synchronization {
                Synchronization::FireAndForget => {
                    h.handler.invoke(dev, req_arc.clone());
                }
                Synchronization::Sync | Synchronization::Async => {
                    let depth = if matches!(h.synchronization, Synchronization::Sync) {
                        1u64
                    } else {
                        h.depth as u64
                    };
                    let admit = h.running_request.fetch_update(
                        Ordering::AcqRel,
                        Ordering::Relaxed,
                        |cur| {
                            if depth == 0 || cur < depth {
                                Some(cur + 1)
                            } else {
                                None
                            }
                        },
                    );
                    // TODO: fix this
                    // if admit.is_err() {
                    //     dev.queue.lock().push_back(req_arc);
                    //     return;
                    // }
                    h.handler.invoke(dev, req_arc.clone());
                    h.running_request.fetch_sub(1, Ordering::Release);
                }
            }
        } else {
            req_arc.write().status = DriverStatus::Pending;
        }
        let st = { req_arc.read().status };
        if st == DriverStatus::Pending {
            let fwd = self.send_request_to_next_lower(dev, req_arc.clone());
            if fwd == DriverStatus::NoSuchDevice {
                let mut r = take_req(&req_arc);
                if let Some(pnp) = r.pnp.as_ref() {
                    r.status = match pnp.minor_function {
                        PnpMinorFunction::StartDevice | PnpMinorFunction::QueryDeviceRelations => {
                            DriverStatus::Success
                        }
                        _ => DriverStatus::NotImplemented,
                    };
                } else {
                    r.status = DriverStatus::NotImplemented;
                }
                if !r.completed {
                    self.complete_request(&mut r);
                }
                put_req(&req_arc, r);
            }
            return;
        }
        let mut r = take_req(&req_arc);
        if !r.completed {
            self.complete_request(&mut r);
        }
        put_req(&req_arc, r);
    }
    pub fn get_device_target(&self, instance_path: &str) -> Option<IoTarget> {
        let om_path = alloc::format!("\\Device\\{}\\Top", instance_path);
        if let Ok(o) = crate::object_manager::OBJECT_MANAGER.open(om_path) {
            if let crate::object_manager::ObjectPayload::Device(d) = &o.payload {
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

    pub fn send_request(&self, target: &IoTarget, req: Arc<RwLock<Request>>) -> DriverStatus {
        target.target_device.queue.lock().push_back(req);
        self.schedule_device_dispatch(&target.target_device);
        DriverStatus::Pending
    }

    pub fn send_request_to_next_lower(
        &self,
        from: &Arc<DeviceObject>,
        req: Arc<RwLock<Request>>,
    ) -> DriverStatus {
        if let Some(target_dev) = from.lower_device.clone() {
            let target = IoTarget {
                target_device: target_dev,
            };
            self.send_request(&target, req)
        } else {
            DriverStatus::NoSuchDevice
        }
    }

    pub fn complete_request(&self, req: &mut Request) {
        if let Some(completion) = req.completion_routine.take() {
            completion(req, req.completion_context);
        } else {
            //TODO: handle this correctly
            // Drop for now
        }
        req.completed = true;
    }

    #[inline]
    fn schedule_device_dispatch(&self, dev: &Arc<DeviceObject>) {
        let mut dq = DISPATCH_DEVQ.lock();
        // TODO: Tickets currently do not work correctly so this slow scan is used for now
        let mut prev = dev.dispatch_tickets.fetch_add(1, Ordering::AcqRel);
        prev = 0;
        let not_listed = !dq.iter().any(|d| Arc::ptr_eq(d, dev));
        if prev == 0 || not_listed {
            dq.push_back(dev.clone());
        }
    }

    pub fn queue_dpc(&self, func: DpcFn, arg: usize) {
        GLOBAL_DPCQ.lock().push_back(Dpc { func, arg });
    }
    pub fn init_io_dispatcher(&self) {
        if !DISPATCHER_STARTED.swap(true, Ordering::AcqRel) {
            for i in 0..START_THREADS {
                create_kernel_task(
                    io_dispatcher_trampoline as usize,
                    format!("io-dispatch{:#X}", random_number()),
                );
            }
        }
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
    pub fn create_symlink(
        &self,
        link_path: String,
        target_path: String,
    ) -> Result<(), crate::object_manager::OmError> {
        crate::object_manager::OBJECT_MANAGER
            .symlink(link_path.to_string(), target_path.to_string(), true)
            .map(|_| ())
    }

    pub fn replace_symlink(
        &self,
        link_path: String,
        target_path: String,
    ) -> Result<(), crate::object_manager::OmError> {
        let _ = crate::object_manager::OBJECT_MANAGER.unlink(link_path.to_string());
        crate::object_manager::OBJECT_MANAGER
            .symlink(link_path.to_string(), target_path.to_string(), true)
            .map(|_| ())
    }

    pub fn create_device_symlink_top(
        &self,
        instance_path: String,
        link_path: String,
    ) -> Result<(), crate::object_manager::OmError> {
        let target = alloc::format!("\\Device\\{}\\Top", instance_path);
        crate::object_manager::OBJECT_MANAGER
            .symlink(link_path.to_string(), target, true)
            .map(|_| ())
    }

    pub fn remove_symlink(&self, link_path: String) -> Result<(), crate::object_manager::OmError> {
        crate::object_manager::OBJECT_MANAGER.unlink(link_path.to_string())
    }
    pub fn resolve_targetio_from_symlink(&self, mut p: String) -> Option<IoTarget> {
        for _ in 0..32 {
            let o = crate::object_manager::OBJECT_MANAGER.open(p.clone()).ok()?;
            match &o.payload {
                crate::object_manager::ObjectPayload::Device(d) => {
                    return Some(IoTarget {
                        target_device: d.clone(),
                    })
                }
                crate::object_manager::ObjectPayload::Directory(_) => {
                    p = alloc::format!("{}\\Top", p);
                    continue;
                }
                crate::object_manager::ObjectPayload::Symlink(target) => {
                    p = target.clone().target;
                    continue;
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
        match self.resolve_targetio_from_symlink(link_path) {
            Some(tgt) => self.send_request(&tgt, req),
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
        let _ = crate::object_manager::OBJECT_MANAGER.mkdir_p("\\Device\\Control".to_string());
        let _ = crate::object_manager::OBJECT_MANAGER.mkdir_p(base.clone());

        let obj = crate::object_manager::Object::with_name(
            crate::object_manager::ObjectTag::Device,
            "Device".to_string(),
            crate::object_manager::ObjectPayload::Device(dev.clone()),
        );
        let dev_path = alloc::format!("{}\\Device", base);
        let _ = crate::object_manager::OBJECT_MANAGER.link(dev_path.clone(), &obj);

        (dev, dev_path)
    }

    pub fn create_control_device_and_link(
        &self,
        name: String,
        init: DeviceInit,
        link_path: String,
    ) -> Arc<DeviceObject> {
        let (dev, dev_path) = self.create_control_device_with_init(name, init);
        let _ = crate::object_manager::OBJECT_MANAGER.symlink(link_path, dev_path, true);
        dev
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
    #[inline]
    fn state_str(s: DevNodeState) -> &'static str {
        match s {
            DevNodeState::Empty => "Empty",
            DevNodeState::Initialized => "Initialized",
            DevNodeState::DriversBound => "DriversBound",
            DevNodeState::Started => "Started",
            DevNodeState::Stopped => "Stopped",
            DevNodeState::SurpriseRemoved => "SurpriseRemoved",
            DevNodeState::Deleted => "Deleted",
            DevNodeState::Faulted => "Faulted",
        }
    }

    #[inline]
    fn make_indent(depth: usize) -> alloc::string::String {
        let mut s = alloc::string::String::new();
        for _ in 0..depth {
            s.push_str("  ");
        }
        s
    }

    fn print_node_line(dn: &Arc<DevNode>, depth: usize) {
        let indent = Self::make_indent(depth);
        let state = dn.get_state();
        let class = dn.class.as_deref().unwrap_or("-");
        let hwid = dn.ids.hardware.get(0).map(|s| s.as_str()).unwrap_or("-");
        println!(
            "{}{}  [{}]  class={}  inst={}  hwid={}",
            indent,
            dn.name,
            Self::state_str(state),
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
                let sub = Self::make_indent(depth + 1);
                println!("{}stack: {}", sub, parts.join("/"));
            }
        }
    }

    #[inline]
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

    fn print_subtree(&self, dn: &Arc<DevNode>, depth: usize) {
        Self::print_node_line(dn, depth);

        let mut kids = {
            let g = dn.children.read();
            g.iter().cloned().collect::<alloc::vec::Vec<_>>()
        };
        kids.sort_by(|a, b| {
            let ra = Self::state_rank(a.get_state());
            let rb = Self::state_rank(b.get_state());
            ra.cmp(&rb).then_with(|| a.name.cmp(&b.name))
        });

        for ch in kids {
            self.print_subtree(&ch, depth + 1);
        }
    }

    pub fn print_device_tree(&self) {
        let root = self.root();
        self.print_subtree(&root, 0);
    }
}
#[inline]
fn take_req(r: &Arc<RwLock<Request>>) -> Request {
    let mut g = r.write();
    core::mem::replace(&mut *g, Request::empty())
}

#[inline]
fn put_req(r: &Arc<RwLock<Request>>, req: Request) {
    let mut g = r.write();
    *g = req;
}
fn classify_id(id: &str) -> MatchClass {
    if id.contains("\\CC_") || id.contains("\\CLASS_") {
        MatchClass::Class
    } else if id.contains("&") || id.matches('\\').count() >= 1 {
        MatchClass::Exact
    } else {
        MatchClass::Compatible
    }
}

fn escape_key(s: &str) -> alloc::string::String {
    let mut out = alloc::string::String::with_capacity(s.len());
    for b in s.bytes() {
        out.push(match b {
            b'\\' | b'/' => '#',
            b':' => '_',
            _ => b as char,
        });
    }
    out
}

extern "C" fn io_dispatcher_trampoline() {
    PNP_MANAGER.dispatch_forever();
}

lazy_static! {
    pub static ref PNP_MANAGER: PnpManager = PnpManager::new();
}
