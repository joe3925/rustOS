use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};

use alloc::{
    collections::btree_map::BTreeMap,
    rc::Weak,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use spin::{Mutex, RwLock};

use super::driver_install::DriverError;
use crate::{
    drivers::driver_install::{parse_driver_toml, BootType},
    executable::program::{Module, ModuleHandle, PROGRAM_MANAGER},
    file_system::file::{File, OpenFlags},
    println,
    registry::{Data, RegError},
};
use lazy_static::lazy_static;

type DriverEntryFn = unsafe extern "C" fn() -> u64;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DriverState {
    Loaded,
    Started,
    Stopped,
    Failed,
}

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
pub struct PnpManager {
    hw: RwLock<Arc<HwIndex>>,
    drivers: RwLock<BTreeMap<String, Arc<DriverRuntime>>>,
}
impl PnpManager {
    pub fn new() -> Self {
        Self {
            hw: RwLock::new(Arc::new(HwIndex::new())),
            drivers: RwLock::new(BTreeMap::new()),
        }
    }
    pub fn init_from_registry(&self) -> Result<(), RegError> {
        self.rebuild_index()?;

        // Start BOOT drivers
        {
            let hw = self.hw.read();
            for pkg in hw.by_driver.values() {
                if pkg.start == BootType::Boot {
                    if let Err(e) = self.start_driver(pkg) {
                        println!("Failed to start boot driver {}: {:?}", pkg.name, e);
                    }
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

    pub fn bind_pdo(&self, ids_descending_specificity: &[&str]) -> Option<Arc<DriverPackage>> {
        let hw = self.hw.read();
        hw.match_best(ids_descending_specificity)
            .map(|d| d.pkg.clone())
    }

    fn start_driver(&self, pkg: &Arc<DriverPackage>) -> Result<(), DriverError> {
        if let Some(rt) = self.drivers.read().get(&pkg.name).cloned() {
            match rt.get_state() {
                DriverState::Started | DriverState::Loaded => return Ok(()),
                _ => {}
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

        if let Some((_, rva)) = module
            .read()
            .symbols
            .iter()
            .find(|(s, _)| s == "driver_entry")
        {
            let entry_addr = (module.read().image_base.as_u64() + *rva as u64) as *const ();
            let entry: DriverEntryFn = unsafe { core::mem::transmute(entry_addr) };
            let status = unsafe { entry() };
            println!(
                "Driver {} exited with status {}",
                module.read().title,
                status
            );
        }

        let rt = Arc::new(DriverRuntime {
            pkg: pkg.clone(),
            module: module,
            state: AtomicU8::new(DriverState::Started as u8),
            refcnt: AtomicU32::new(0),
        });

        self.drivers.write().insert(rt.pkg.name.clone(), rt);
        Ok(())
    }

    fn build_hw_index() -> Result<HwIndex, RegError> {
        use crate::registry::reg;
        let mut idx = HwIndex::new();

        let services_root = "SYSTEM/CurrentControlSet/Services";
        let service_keys = reg::list_keys(services_root)?; // absolute paths

        for kpath in service_keys {
            // only immediate children of Services
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

            let dt = match parse_driver_toml(&toml_path) {
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
lazy_static! {
    pub static ref PNP_MANAGER: PnpManager = PnpManager::new();
}
