use alloc::collections::vec_deque::VecDeque;
use alloc::rc::Weak;
use alloc::{
    collections::btree_map::BTreeMap,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};
use spin::{Mutex, RwLock};

use crate::drivers::driver_install;
use crate::drivers::driver_install::{BootType, DriverError};
use crate::executable::program::{ModuleHandle, PROGRAM_MANAGER};
use crate::file_system::file::{File, FileStatus, OpenFlags};
use crate::println;
use crate::registry::reg;
use crate::registry::{self as regmod, Data, RegError};
use crate::static_handlers::create_kernel_task;
use lazy_static::lazy_static;

use super::driver_object::{
    DeviceInit, DeviceObject, DriverObject, DriverStatus, Request, RequestType,
};
pub type DpcFn = fn(usize);
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

static DISPATCHER_STARTED: AtomicBool = AtomicBool::new(false);

pub type DriverEntryFn = unsafe extern "C" fn(driver: *const DriverObject) -> DriverStatus;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DriverState {
    Loaded,
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
    pub fn candidates<'a>(&'a self, ids: &[&str]) -> impl Iterator<Item = &'a DriverBinding> + 'a {
        let keys: Vec<String> = ids.iter().map(|s| canonicalize_id(s)).collect();
        keys.into_iter()
            .filter_map(move |k| self.by_id.get(&k))
            .flat_map(|v| v.iter())
    }
}

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

    /// Optional class driver (treated like an upper filter)
    pub class: Option<StackLayer>,
}

impl DeviceStack {
    fn new() -> Self {
        Self {
            pdo_bus_service: None,
            lower: Vec::new(),
            function: None,
            upper: Vec::new(),
            class: None,
        }
    }

    pub fn all_layers_bottom_to_top(&self) -> Vec<Arc<DriverObject>> {
        let mut out = Vec::new();
        out.extend(self.lower.iter().map(|l| l.driver.clone()));
        if let Some(f) = &self.function {
            out.push(f.driver.clone());
        }
        out.extend(self.upper.iter().map(|l| l.driver.clone()));
        if let Some(c) = &self.class {
            out.push(c.driver.clone());
        }
        out
    }
}
#[derive(Debug)]
pub struct DevNode {
    pub name: String,
    pub parent: RwLock<Option<alloc::sync::Weak<DevNode>>>,
    pub children: RwLock<Vec<Arc<DevNode>>>,
    pub instance_path: String,
    pub ids: DeviceIds,
    pub class: Option<String>,
    pub state: AtomicU8, // DevNodeState as u8

    /// PDO device object for this devnode (owned by the enumerating bus).
    pub pdo: RwLock<Option<Arc<DeviceObject>>>,

    /// Bound driver stack (PDO/filters/function/class). None until bound.
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
            pdo: RwLock::new(None), // <-- add
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
            pdo: RwLock::new(None), // <-- add
            stack: RwLock::new(Some(DeviceStack::new())),
        });
        parent.children.write().push(dn.clone());
        dn
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
}

impl PnpManager {
    pub fn new() -> Self {
        Self {
            hw: RwLock::new(Arc::new(HwIndex::new())),
            drivers: RwLock::new(BTreeMap::new()),
            dev_root: DevNode::new_root(),
        }
    }

    pub fn root(&self) -> Arc<DevNode> {
        self.dev_root.clone()
    }

    pub fn init_from_registry(&self) -> Result<(), RegError> {
        self.rebuild_index()?;

        // Start BOOT drivers (not device-bound; e.g., storage bus).
        {
            let hw = self.hw.read();
            for pkg in hw.by_driver.values() {
                if pkg.start == BootType::Boot {
                    let _ = self.ensure_started(pkg);
                }
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

    pub fn add_child_pdo(
        &self,
        parent: &Arc<DevNode>,
        name: &str,
        instance_path: &str,
        ids: DeviceIds,
        class: Option<String>,
        pdo_bus_service: Option<&str>,
    ) -> Arc<DevNode> {
        let dn = DevNode::new_child(
            name.to_string(),
            instance_path.to_string(),
            ids,
            class,
            parent,
        );
        if let Some(svc) = pdo_bus_service {
            if let Some(stk) = dn.stack.write().as_mut() {
                stk.pdo_bus_service = Some(svc.to_string());
            }
        }
        dn
    }

    pub fn bind_and_start(&self, dn: &Arc<DevNode>) -> Result<(), DriverError> {
        self.bind_device(dn)?;
        self.start_stack(dn)?;
        Ok(())
    }

    fn bind_device(&self, dn: &Arc<DevNode>) -> Result<(), DriverError> {
        let ids_slice: Vec<&str> = dn
            .ids
            .hardware
            .iter()
            .map(|s| s.as_str())
            .chain(dn.ids.compatible.iter().map(|s| s.as_str()))
            .collect();

        // 1. Match and load function driver
        let func_pkg = {
            let hw = self.hw.read();
            if let Some(best) = hw.match_best(&ids_slice) {
                best.pkg.clone()
            } else {
                dn.set_state(DevNodeState::Initialized);
                return Ok(());
            }
        };

        let func_drv = self.ensure_started(&func_pkg)?;

        let class_name = dn.class.as_deref();
        let (lower_pkgs, upper_pkgs) =
            self.resolve_filters(&ids_slice, class_name, &func_pkg.name)?;
        let class_drv = match self.resolve_class_driver(class_name)? {
            Some(pkg) => Some(self.ensure_started(&pkg)?),
            None => None,
        };

        let lower_layers: Vec<StackLayer> = lower_pkgs
            .into_iter()
            .map(|pkg| {
                Ok(StackLayer {
                    driver: self.ensure_started(&pkg)?,
                    devobj: None,
                })
            })
            .collect::<Result<_, DriverError>>()?;

        let upper_layers: Vec<StackLayer> = upper_pkgs
            .into_iter()
            .map(|pkg| {
                Ok(StackLayer {
                    driver: self.ensure_started(&pkg)?,
                    devobj: None,
                })
            })
            .collect::<Result<_, DriverError>>()?;

        let function_layer = StackLayer {
            driver: func_drv,
            devobj: None,
        };

        let class_layer = class_drv.map(|drv| StackLayer {
            driver: drv,
            devobj: None,
        });

        // 4. Commit to device stack
        {
            let mut guard = dn.stack.write();
            let stk = guard.as_mut().expect("Device stack must exist");
            stk.function = Some(function_layer);
            stk.lower = lower_layers;
            stk.upper = upper_layers;
            stk.class = class_layer;
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

    /// Gather lower/upper filter services from registry indices:
    ///   SYSTEM/CurrentControlSet/Filters/{hwid|class|driver}/<key>/{upper|lower}/<service> with "Order"=u32
    /// And class filters:
    ///   SYSTEM/CurrentControlSet/Class/<class>/{UpperFilters|LowerFilters}/(0..n) = "<service>"
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
                        let service = svc_path
                            .rsplit_once('/')
                            .map(|(_, s)| s.to_string())
                            .unwrap_or_default();
                        let order = match reg::get_value(&svc_path, "Order") {
                            Some(Data::U32(v)) => v,
                            _ => 100,
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

        // Add from Filters/class/*
        if let Some(class) = class_opt {
            let key = escape_key(class);
            for pos in ["lower", "upper"].iter() {
                let base = alloc::format!("SYSTEM/CurrentControlSet/Filters/class/{}/{}", key, pos);
                if let Some(children) = reg::list_keys(&base).ok() {
                    for svc_path in children {
                        let service = svc_path
                            .rsplit_once('/')
                            .map(|(_, s)| s.to_string())
                            .unwrap_or_default();
                        let order = match reg::get_value(&svc_path, "Order") {
                            Some(Data::U32(v)) => v,
                            _ => 100,
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
                    let service = svc_path
                        .rsplit_once('/')
                        .map(|(_, s)| s.to_string())
                        .unwrap_or_default();
                    let order = match reg::get_value(&svc_path, "Order") {
                        Some(Data::U32(v)) => v,
                        _ => 100,
                    };
                    if *pos == "lower" {
                        lowers.push(Item { order, service });
                    } else {
                        uppers.push(Item { order, service });
                    }
                }
            }
        }

        fn to_unique_sorted(mut v: Vec<Item>) -> Vec<String> {
            v.sort_by(|a, b| {
                a.order
                    .cmp(&b.order)
                    .then_with(|| a.service.cmp(&b.service))
            });
            let mut seen = BTreeMap::<String, u32>::new();
            let mut out = Vec::new();
            for it in v.into_iter() {
                if !seen.contains_key(&it.service) {
                    seen.insert(it.service.clone(), it.order);
                    out.push(it.service);
                }
            }
            out
        }

        let lower_svcs = to_unique_sorted(lowers);
        let upper_svcs = to_unique_sorted(uppers);

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

    fn start_stack(&self, dn: &Arc<DevNode>) -> Result<(), DriverError> {
        let mut guard = dn.stack.write();
        let stk = guard.as_mut().expect("stack");

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
        if let Some(c) = stk.class.as_mut() {
            layers.push(c as *mut _);
        }

        let mut prev_do: Option<Arc<DeviceObject>> = dn.get_pdo();

        for layer_ptr in layers {
            let layer = unsafe { &mut *layer_ptr };
            let drv = &layer.driver;
            let runtime = &drv.runtime;
            match runtime.get_state() {
                DriverState::Started | DriverState::Loaded => {}
                _ => {
                    let module = runtime.module.clone();
                    let m = module.read();

                    if let Some((_, rva)) = m.symbols.iter().find(|(s, _)| s == "driver_entry") {
                        let entry_addr = (m.image_base.as_u64() + *rva as u64) as *const ();
                        let entry: DriverEntryFn = unsafe { core::mem::transmute(entry_addr) };

                        let status = unsafe { entry(Arc::as_ptr(drv)) };
                        println!("Driver {} DriverEntry -> {:?}", m.title, status);

                        match status {
                            DriverStatus::Success | DriverStatus::Pending => {
                                runtime.set_state(DriverState::Started);
                            }
                            _ => {
                                runtime.set_state(DriverState::Failed);
                            }
                        }
                    } else {
                        println!("Driver {} missing symbol: driver_entry", m.title);
                        runtime.set_state(DriverState::Failed);
                    }
                }
            }

            if let Some(cb) = drv.evt_device_add {
                let mut dev_init = DeviceInit::new();
                let status = cb(drv, &mut dev_init);
                if status == DriverStatus::Success {
                    let devobj = DeviceObject::new(dev_init.dev_ext_size);
                    unsafe {
                        let me = &mut *(Arc::as_ptr(&devobj) as *mut DeviceObject);
                        me.dev_init = dev_init;
                    }
                    DeviceObject::set_lower_upper(&devobj, prev_do.clone());
                    layer.devobj = Some(devobj.clone());
                    prev_do = Some(devobj);
                } else {
                    println!("Driver {} rejected device: {:?}", drv.driver_name, status);
                }
            } else {
            }
        }

        dn.set_state(DevNodeState::Started);
        Ok(())
    }

    fn ensure_started(&self, pkg: &Arc<DriverPackage>) -> Result<Arc<DriverObject>, DriverError> {
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

        let rt = Arc::new(DriverRuntime {
            pkg: pkg.clone(),
            module,
            state: AtomicU8::new(DriverState::Loaded as u8),
            refcnt: AtomicU32::new(0),
        });
        let drv_obj = DriverObject::allocate(rt, pkg.name.clone());
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
    pub fn dispatch_forever(&self) -> ! {
        loop {
            let mut did_work = false;

            // 1) Run one global DPC if any
            did_work |= self.run_one_dpc();

            // 2) Run one request from one device (round-robin)
            did_work |= self.run_one_device_request();

            if !did_work {
                // Idle hint — replace with arch-specific pause/yield if available.
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
        let dev_opt = DISPATCH_DEVQ.lock().pop_front();
        let Some(dev) = dev_opt else {
            return false;
        };

        let req_arc_opt = { dev.queue.lock().pop_front() };
        if let Some(req_arc) = req_arc_opt {
            {
                let mut req = req_arc.lock();
                self.call_device_handler(&dev, &mut *req);
            }

            let has_more = { !dev.queue.lock().is_empty() };
            if has_more {
                DISPATCH_DEVQ.lock().push_back(dev.clone());
            } else {
                dev.dispatch_scheduled.store(false, Ordering::Release);
            }

            true
        } else {
            dev.dispatch_scheduled.store(false, Ordering::Release);
            false
        }
    }

    fn call_device_handler(&self, dev: &Arc<DeviceObject>, req: &mut Request) {
        match req.kind {
            RequestType::Read(h_req) => {
                if let Some(h) = dev.dev_init.io_read {
                    h(dev, req, req.data.len());
                } else {
                    h_req(dev, req);
                }
            }
            RequestType::Write(h_req) => {
                if let Some(h) = dev.dev_init.io_write {
                    h(dev, req, req.data.len());
                } else {
                    h_req(dev, req);
                }
            }
            RequestType::DeviceControl(h_req) => {
                if let Some(h) = dev.dev_init.io_device_control {
                    h(dev, req, req.ioctl_code.unwrap_or(0));
                } else {
                    h_req(dev, req);
                }
            }
        }
    }
    pub fn send_lower(&self, from: &Arc<DeviceObject>, req: Request) -> DriverStatus {
        let Some(target) = from.lower_device.clone() else {
            return DriverStatus::NoSuchDevice;
        };
        let req_arc = Arc::new(spin::Mutex::new(req));
        target.queue.lock().push_back(req_arc);
        self.schedule_device_dispatch(&target);
        DriverStatus::Pending
    }

    pub fn send_upper(&self, from: &Arc<DeviceObject>, req: Request) -> DriverStatus {
        let Some(target) = from.upper_device.read().as_ref().and_then(|w| w.upgrade()) else {
            return DriverStatus::NoSuchDevice;
        };
        let req_arc = Arc::new(spin::Mutex::new(req));
        target.queue.lock().push_back(req_arc);
        self.schedule_device_dispatch(&target);
        DriverStatus::Pending
    }
    #[inline]
    fn schedule_device_dispatch(&self, dev: &Arc<DeviceObject>) {
        if !dev.dispatch_scheduled.swap(true, Ordering::AcqRel) {
            DISPATCH_DEVQ.lock().push_back(dev.clone());
        }
    }

    pub fn queue_dpc(&self, func: DpcFn, arg: usize) {
        GLOBAL_DPCQ.lock().push_back(Dpc { func, arg });
    }
    pub fn init_io_dispatcher(&self) {
        if !DISPATCHER_STARTED.swap(true, Ordering::AcqRel) {
            create_kernel_task(io_dispatcher_trampoline as usize, "io-dispatch".to_string());
        }
    }
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
