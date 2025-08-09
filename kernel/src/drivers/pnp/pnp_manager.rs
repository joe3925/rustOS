use alloc::rc::Weak;
use alloc::{
    collections::btree_map::BTreeMap,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use spin::{Mutex, RwLock};

use crate::drivers::driver_install;
use crate::drivers::driver_install::{BootType, DriverError};
use crate::executable::program::{ModuleHandle, PROGRAM_MANAGER};
use crate::file_system::file::{File, FileStatus, OpenFlags};
use crate::println;
use crate::registry::reg;
use crate::registry::{self as regmod, Data, RegError};
use lazy_static::lazy_static;

type DriverEntryFn = unsafe extern "C" fn() -> u64;

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

#[derive(Debug)]
pub struct DeviceStack {
    /// Service name (driver name) of the bus that created the PDO (optional, for diagnostics).
    pub pdo_bus_service: Option<String>,

    /// Lower filters (nearest to PDO first, topologically they sit below the function driver).
    pub lower: Vec<Arc<DriverRuntime>>,

    /// Function driver bound to this device (FDO owner).
    pub function: Option<Arc<DriverRuntime>>,

    /// Upper filters (above the function driver; order is bottom-to-top).
    pub upper: Vec<Arc<DriverRuntime>>,

    /// Optional class driver (logically an upper filter specialized for the device class).
    pub class: Option<Arc<DriverRuntime>>,
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
    pub fn all_layers_bottom_to_top(&self) -> Vec<Arc<DriverRuntime>> {
        let mut out = Vec::new();
        out.extend(self.lower.iter().cloned());
        if let Some(f) = &self.function {
            out.push(f.clone());
        }
        out.extend(self.upper.iter().cloned());
        if let Some(c) = &self.class {
            out.push(c.clone());
        }
        out
    }
}

#[derive(Debug)]
pub struct DevNode {
    /// Human readable name or address under its parent (e.g., "PCI0", "0000:00:1F.2", "HID\VID_...").
    pub name: String,

    pub parent: RwLock<Option<alloc::sync::Weak<DevNode>>>,
    pub children: RwLock<Vec<Arc<DevNode>>>,

    /// PnP instance path like `ROOT\XYZ\0001` (unique per device).
    pub instance_path: String,

    /// IDs used for binding.
    pub ids: DeviceIds,

    /// Optional device class (e.g., "Mouse", "Keyboard", "Disk", custom).
    pub class: Option<String>,

    /// Current state.
    pub state: AtomicU8, // DevNodeState as u8

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
            stack: RwLock::new(Some(DeviceStack::new())),
        });
        parent.children.write().push(dn.clone());
        dn
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
    drivers: RwLock<BTreeMap<String, Arc<DriverRuntime>>>,
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

        let func_pkg = {
            let hw = self.hw.read();
            if let Some(best) = hw.match_best(&ids_slice) {
                best.pkg.clone()
            } else {
                dn.set_state(DevNodeState::Initialized);
                return Ok(());
            }
        };

        let func_rt = self.ensure_started(&func_pkg)?;

        let class_name = dn.class.as_deref();
        let (lower_list, upper_list) =
            self.resolve_filters(&ids_slice, class_name, &func_pkg.name)?;
        let class_rt = self.resolve_class_driver(class_name)?;

        {
            let mut guard = dn.stack.write();
            let stk = guard.as_mut().expect("Device stack must exist");
            stk.function = Some(func_rt);
            stk.lower = lower_list;
            stk.upper = upper_list;
            stk.class = class_rt;
        }

        dn.set_state(DevNodeState::DriversBound);
        Ok(())
    }

    fn resolve_class_driver(
        &self,
        class_opt: Option<&str>,
    ) -> Result<Option<Arc<DriverRuntime>>, DriverError> {
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
            return self.ensure_started(pkg).map(Some);
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

        self.ensure_started(&pkg).map(Some)
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
    ) -> Result<(Vec<Arc<DriverRuntime>>, Vec<Arc<DriverRuntime>>), DriverError> {
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
            if let Some(rt) = self
                .pkg_by_service(&svc)
                .and_then(|p| self.ensure_started(&p).ok())
            {
                lower_rts.push(rt);
            }
        }
        let mut upper_rts = Vec::new();
        for svc in upper_svcs {
            if let Some(rt) = self
                .pkg_by_service(&svc)
                .and_then(|p| self.ensure_started(&p).ok())
            {
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
        let layers = {
            let guard = dn.stack.read();
            let stk = guard.as_ref().expect("stack");
            stk.all_layers_bottom_to_top()
        };

        for rt in layers {
            match rt.get_state() {
                DriverState::Started | DriverState::Loaded => {}
                _ => {
                    let module = rt.module.clone();
                    if let Some((_, rva)) = module
                        .read()
                        .symbols
                        .iter()
                        .find(|(s, _)| s == "driver_entry")
                    {
                        let entry_addr =
                            (module.read().image_base.as_u64() + *rva as u64) as *const ();
                        let entry: DriverEntryFn = unsafe { core::mem::transmute(entry_addr) };
                        let status = unsafe { entry() };
                        println!(
                            "Driver {} exited with status {}",
                            module.read().title,
                            status
                        );
                    }
                    rt.set_state(DriverState::Started);
                }
            }
        }

        dn.set_state(DevNodeState::Started);
        Ok(())
    }

    fn ensure_started(&self, pkg: &Arc<DriverPackage>) -> Result<Arc<DriverRuntime>, DriverError> {
        if let Some(rt) = self.drivers.read().get(&pkg.name).cloned() {
            if matches!(rt.get_state(), DriverState::Started | DriverState::Loaded) {
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
        self.drivers.write().insert(pkg.name.clone(), rt.clone());
        Ok(rt)
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

lazy_static! {
    pub static ref PNP_MANAGER: PnpManager = PnpManager::new();
}
