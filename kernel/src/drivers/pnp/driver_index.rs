use crate::drivers::driver_install::{self, DriverError};
use crate::registry::reg::{get_value, list_keys};
use crate::registry::{self as reg};
use alloc::string::ToString;
use alloc::{collections::BTreeMap, string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use kernel_types::device::DriverPackage;
use kernel_types::pnp::BootType;
use kernel_types::status::{Data, RegError};
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
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

pub fn rank(kind: MatchClass, start: BootType) -> u32 {
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
pub fn canonicalize_id(s: &str) -> String {
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
pub fn classify_id(id: &str) -> MatchClass {
    if id.contains("\\CC_") || id.contains("\\CLASS_") {
        MatchClass::Class
    } else if id.contains('&') || id.matches('\\').count() >= 1 {
        MatchClass::Exact
    } else {
        MatchClass::Compatible
    }
}
pub fn escape_key(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        out.push(match b {
            b'\\' | b'/' => '#',
            b':' => '_',
            _ => b as char,
        });
    }
    out
}

pub fn build_hw_index() -> Result<HwIndex, RegError> {
    let mut idx = HwIndex::new();
    let services_root = "SYSTEM/CurrentControlSet/Services";
    let service_keys = list_keys(services_root)?;
    for kpath in service_keys {
        let rel = kpath
            .strip_prefix(&(services_root.to_string() + "/"))
            .unwrap_or("");
        if rel.contains('/') {
            continue;
        }
        let drv_name = rel.to_string();

        let image = match get_value(&kpath, "ImagePath") {
            Some(Data::Str(s)) => s,
            _ => continue,
        };
        let toml_path = match get_value(&kpath, "TomlPath") {
            Some(Data::Str(s)) => s,
            _ => continue,
        };
        let start = match get_value(&kpath, "Start") {
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
