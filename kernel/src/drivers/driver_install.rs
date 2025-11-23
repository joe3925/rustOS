use crate::drivers::pnp::manager::PNP_MANAGER;
use crate::executable::pe_loadable::LoadError;
use crate::{format, println};
use alloc::{string::String, vec::Vec};
use kernel_types::fs::OpenFlags;
use kernel_types::pnp::BootType;
use kernel_types::status::{Data, FileStatus, RegError};
use toml::de::{DeInteger, DeTable};
use toml::Spanned;

use crate::alloc::string::ToString;
use crate::{file_system::file::File, registry::reg};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverRole {
    Function,
    Filter,
    Base,
}

impl DriverRole {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "function" | "" => Some(Self::Function),
            "filter" => Some(Self::Filter),
            "base" => Some(Self::Base),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterPosition {
    Upper,
    Lower,
}
impl FilterPosition {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "upper" => Some(Self::Upper),
            "lower" => Some(Self::Lower),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterTarget {
    Hwid(String),
    Class(String),
    Driver(String),
}
#[derive(Debug, Clone)]
pub struct RegWrite {
    pub path: String,
    pub values: Vec<(String, Data)>,
}

#[derive(Debug)]
pub struct FilterSpec {
    pub position: FilterPosition,
    pub order: u32,
    pub target: FilterTarget,
}

#[derive(Debug)]
pub struct DriverToml {
    pub image: String,
    pub start: BootType,
    pub hwids: Vec<String>,         // function-only; ignored when role==Filter
    pub role: DriverRole,           // default Function
    pub class: Option<String>,      // optional for function drivers
    pub filter: Option<FilterSpec>, // present when role==Filter
    pub reg_writes: Vec<RegWrite>,
}

#[derive(Debug)]
pub enum DriverError {
    File(FileStatus),
    InvalidUtf8,
    TomlParse,
    DriverAlreadyInstalled,
    NoParent,
    Registry(RegError),
    LoadErr(LoadError),
}
impl From<FileStatus> for DriverError {
    fn from(e: FileStatus) -> Self {
        if e == FileStatus::FileAlreadyExist {
            return DriverError::DriverAlreadyInstalled;
        }
        DriverError::File(e)
    }
}

impl From<RegError> for DriverError {
    fn from(e: RegError) -> Self {
        DriverError::Registry(e)
    }
}
impl From<LoadError> for DriverError {
    fn from(e: LoadError) -> Self {
        DriverError::LoadErr(e)
    }
}
#[inline(always)]
fn inner<'a, T>(s: &'a Spanned<T>) -> &'a T {
    s.get_ref()
}

pub fn parse_driver_toml(path: &str) -> Result<DriverToml, FileStatus> {
    let mut f = File::open(path, &[OpenFlags::ReadOnly, OpenFlags::Open])?;
    let bytes = f.read()?;
    let src = core::str::from_utf8(&bytes).map_err(|_| FileStatus::InternalError)?;

    let (tbl_span, _errs) = DeTable::parse_recoverable(src);
    let tbl: &DeTable = inner(&tbl_span);

    let image = tbl
        .get("image")
        .and_then(|v| inner(v).as_str())
        .map(|s| s.to_string())
        .ok_or(FileStatus::BadPath)?;

    let start = tbl
        .get("start")
        .and_then(|v| inner(v).as_str())
        .and_then(BootType::from_str)
        .ok_or(FileStatus::BadPath)?;

    let has_filter_tbl = tbl
        .get("filter")
        .and_then(|v| inner(v).as_table())
        .is_some();

    let explicit_role = tbl.get("role").and_then(|v| inner(v).as_str());
    let role = if has_filter_tbl {
        DriverRole::Filter
    } else {
        match explicit_role {
            Some("base") => DriverRole::Base,
            _ => DriverRole::Function,
        }
    };

    let hwids = tbl
        .get("hwids")
        .and_then(|v| inner(v).as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|val| inner(val).as_str().map(ToString::to_string))
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(Vec::new);

    let class = tbl
        .get("class")
        .and_then(|v| inner(v).as_str())
        .map(ToString::to_string);

    let filter = tbl
        .get("filter")
        .and_then(|v| inner(v).as_table())
        .map(|ftbl| {
            let position = ftbl
                .get("position")
                .and_then(|v| inner(v).as_str())
                .and_then(FilterPosition::from_str)
                .ok_or(FileStatus::BadPath)?;

            let order = ftbl
                .get("order")
                .and_then(|v| inner(v).as_integer())
                .and_then(deint_to_u32)
                .unwrap_or(100);

            let tgt = if let Some(s) = ftbl.get("hwid").and_then(|v| inner(v).as_str()) {
                FilterTarget::Hwid(s.to_string())
            } else if let Some(s) = ftbl.get("class").and_then(|v| inner(v).as_str()) {
                FilterTarget::Class(s.to_string())
            } else if let Some(s) = ftbl.get("driver").and_then(|v| inner(v).as_str()) {
                FilterTarget::Driver(s.to_string())
            } else {
                return Err(FileStatus::BadPath);
            };

            Ok::<FilterSpec, FileStatus>(FilterSpec {
                position,
                order,
                target: tgt,
            })
        })
        .transpose()?;

    if role == DriverRole::Filter && filter.is_none() {
        return Err(FileStatus::BadPath);
    }

    let reg_writes: Vec<RegWrite> = tbl
        .get("registry")
        .and_then(|v| inner(v).as_array())
        .map(|arr| {
            let mut out = Vec::new();
            for item in arr.iter() {
                let it = match inner(item).as_table() {
                    Some(t) => t,
                    None => continue,
                };

                let path = match it.get("path").and_then(|v| inner(v).as_str()) {
                    Some(p) if !p.is_empty() => p.to_string(),
                    _ => continue,
                };

                let mut values: Vec<(String, Data)> = Vec::new();
                if let Some(vtbl) = it.get("values").and_then(|v| inner(v).as_table()) {
                    for (k, vv) in vtbl.iter() {
                        if let Some(s) = inner(vv).as_str() {
                            values.push((k.to_string(), Data::Str(s.to_string())));
                        } else if let Some(di) = inner(vv).as_integer() {
                            if let Some(u) = deint_to_u32(di) {
                                values.push((k.to_string(), Data::U32(u)));
                            } else {
                            }
                        }
                    }
                }

                if !values.is_empty() {
                    out.push(RegWrite { path, values });
                }
            }
            out
        })
        .unwrap_or_default();

    Ok(DriverToml {
        image,
        start,
        hwids,
        role,
        class,
        filter,
        reg_writes,
    })
}

fn deint_to_u32(di: &DeInteger) -> Option<u32> {
    let s = di.as_str();
    let n = i128::from_str_radix(s, di.radix()).ok()?;
    u32::try_from(n).ok()
}

fn escape_key(s: &str) -> alloc::string::String {
    let mut out = alloc::string::String::with_capacity(s.len());
    for b in s.bytes() {
        out.push(match b {
            b'\\' => '#',
            b'/' => '#',
            b':' => '_',
            _ => b as char,
        });
    }
    out
}
fn ensure_class_key(cls: &str) -> Result<(), RegError> {
    let class_key = alloc::format!("SYSTEM/CurrentControlSet/Class/{}", cls);
    if reg::get_key(&class_key).is_none() {
        let _ = reg::create_key(&class_key);
    }
    let _ = reg::create_key(&alloc::format!("{}/UpperFilters", class_key));
    let _ = reg::create_key(&alloc::format!("{}/LowerFilters", class_key));
    Ok(())
}

fn reg_add_filter_index(
    tgt: &FilterTarget,
    pos: FilterPosition,
    order: u32,
    service: &str,
) -> Result<(), RegError> {
    let (kind, id) = match tgt {
        FilterTarget::Hwid(s) => ("hwid", s.as_str()),
        FilterTarget::Class(s) => ("class", s.as_str()),
        FilterTarget::Driver(s) => ("driver", s.as_str()),
    };
    let id_key = escape_key(id);
    let pos_s = match pos {
        FilterPosition::Upper => "upper",
        FilterPosition::Lower => "lower",
    };

    let base = alloc::format!("SYSTEM/CurrentControlSet/Filters/{}/{}", kind, id_key);
    reg::create_key(&base)?;
    let pos_path = alloc::format!("{}/{}", base, pos_s);
    reg::create_key(&pos_path)?;
    let svc_path = alloc::format!("{}/{}", pos_path, service);
    reg::create_key(&svc_path)?;
    reg::set_value(&svc_path, "Order", Data::U32(order))?;
    reg::set_value(&svc_path, "Service", Data::Str(service.to_string()))?;
    Ok(())
}
fn reg_append_class_filter(
    class: &str,
    pos: FilterPosition,
    service: &str,
) -> Result<(), RegError> {
    let class_key = alloc::format!("SYSTEM/CurrentControlSet/Class/{}", class);
    if reg::get_key(&class_key).is_none() {
        let _ = reg::create_key(&class_key);
    }
    let list_key = match pos {
        FilterPosition::Upper => alloc::format!("{}/UpperFilters", class_key),
        FilterPosition::Lower => alloc::format!("{}/LowerFilters", class_key),
    };
    if reg::get_key(&list_key).is_none() {
        let _ = reg::create_key(&list_key);
    }
    let idx = reg::get_key(&list_key).map(|k| k.values.len()).unwrap_or(0);
    reg::set_value(
        &list_key,
        &alloc::format!("{}", idx),
        Data::Str(service.to_string()),
    )
}
fn reg_append_class_member(class: &str, service: &str) -> Result<(), RegError> {
    let class_key = alloc::format!("SYSTEM/CurrentControlSet/Class/{}", class);
    if reg::get_key(&class_key).is_none() {
        let _ = reg::create_key(&class_key);
    }
    let members_key = alloc::format!("{}/Members", class_key);
    if reg::get_key(&members_key).is_none() {
        let _ = reg::create_key(&members_key);
    }
    if let Some(k) = reg::get_key(&members_key) {
        for (_k, v) in k.values {
            if let Data::Str(s) = v {
                if s == service {
                    return Ok(());
                }
            }
        }
    }
    let idx = reg::get_key(&members_key)
        .map(|k| k.values.len())
        .unwrap_or(0);
    reg::set_value(
        &members_key,
        &alloc::format!("{}", idx),
        Data::Str(service.to_string()),
    )
}
fn service_name_from_image(image: &str) -> &str {
    image.rsplit_once('.').map(|(n, _)| n).unwrap_or(image)
}
pub fn install_driver_toml(toml_path: &str) -> Result<(), DriverError> {
    let driver = parse_driver_toml(toml_path).map_err(|_| DriverError::TomlParse)?;
    let driver_name = service_name_from_image(&driver.image);

    let key_path = alloc::format!("SYSTEM/CurrentControlSet/Services/{}/", driver_name);

    let toml_target_path = alloc::format!("C:\\SYSTEM\\TOML\\{}.toml", driver_name);
    let img_target_path = alloc::format!("C:\\SYSTEM\\MOD\\{}", driver.image);

    let img_src_dir = toml_path.rsplit_once('\\').map(|(p, _)| p).unwrap_or("");
    let img_src_full = alloc::format!("{}\\{}", img_src_dir, driver.image);

    let _ = File::make_dir("C:\\SYSTEM".to_string());
    let _ = File::make_dir("C:\\SYSTEM\\TOML".to_string());
    let _ = File::make_dir("C:\\SYSTEM\\MOD".to_string());

    let img_src = File::open(&img_src_full, &[OpenFlags::ReadOnly, OpenFlags::Open])?;
    img_src.move_no_copy(&img_target_path)?;

    let toml_src = File::open(toml_path, &[OpenFlags::ReadOnly, OpenFlags::Open])?;
    toml_src.move_no_copy(&toml_target_path)?;

    reg::create_key(&key_path)?;
    reg::set_value(
        &key_path,
        "ImagePath",
        Data::Str(img_target_path.to_string()),
    )?;
    reg::set_value(
        &key_path,
        "TomlPath",
        Data::Str(toml_target_path.to_string()),
    )?;
    reg::set_value(&key_path, "Start", Data::U32(driver.start.as_u32()))?;

    let role_u32 = match driver.role {
        DriverRole::Function => 0,
        DriverRole::Filter => 1,
        DriverRole::Base => 2,
    };
    reg::set_value(&key_path, "Role", Data::U32(role_u32))?;

    match driver.role {
        DriverRole::Function => {
            if let Some(cls) = &driver.class {
                reg::set_value(&key_path, "Class", Data::Str(cls.clone()))?;
                ensure_class_key(cls)?;
                reg_append_class_member(cls, driver_name)?;

                if driver.hwids.is_empty() {
                    let class_key = alloc::format!("SYSTEM/CurrentControlSet/Class/{}", cls);
                    reg::set_value(&class_key, "Class", Data::Str(driver_name.to_string()))?;
                    if reg::get_value(&class_key, "Version").is_none() {
                        let _ = reg::set_value(&class_key, "Version", Data::U32(1));
                    }
                    if reg::get_value(&class_key, "Description").is_none() {
                        let _ = reg::set_value(&class_key, "Description", Data::Str(cls.clone()));
                    }
                }
            }

            if !driver.hwids.is_empty() {
                let hwk = alloc::format!("{}/Hwids", key_path.trim_end_matches('/'));
                reg::create_key(&hwk)?;
                for (i, h) in driver.hwids.iter().enumerate() {
                    reg::set_value(&hwk, &alloc::format!("{}", i), Data::Str(h.clone()))?;
                }
            }
        }

        DriverRole::Filter => {
            let f = driver.filter.as_ref().ok_or(DriverError::TomlParse)?;
            let flt_key = alloc::format!("{}/Filter", key_path.trim_end_matches('/'));
            reg::create_key(&flt_key)?;
            let pos_s = match f.position {
                FilterPosition::Upper => "upper",
                FilterPosition::Lower => "lower",
            };
            reg::set_value(&flt_key, "Position", Data::Str(pos_s.to_string()))?;
            reg::set_value(&flt_key, "Order", Data::U32(f.order))?;
            match &f.target {
                FilterTarget::Hwid(s) => {
                    reg::set_value(&flt_key, "TargetKind", Data::Str("hwid".into()))?;
                    reg::set_value(&flt_key, "Target", Data::Str(s.clone()))?;
                }
                FilterTarget::Class(s) => {
                    reg::set_value(&flt_key, "TargetKind", Data::Str("class".into()))?;
                    reg::set_value(&flt_key, "Target", Data::Str(s.clone()))?;
                    reg_append_class_filter(s, f.position, driver_name)?;
                    if driver.start != BootType::Demand {
                        reg::set_value(&key_path, "Start", Data::U32(BootType::Demand.as_u32()))?;
                    }
                }
                FilterTarget::Driver(s) => {
                    reg::set_value(&flt_key, "TargetKind", Data::Str("driver".into()))?;
                    reg::set_value(&flt_key, "Target", Data::Str(s.clone()))?;
                }
            }
            reg_add_filter_index(&f.target, f.position, f.order, driver_name)?;
        }

        DriverRole::Base => {}
    }

    for rw in driver.reg_writes.iter() {
        reg::create_key(&rw.path)?;
        for (name, val) in rw.values.iter() {
            reg::set_value(&rw.path, name, val.clone())?;
        }
    }

    PNP_MANAGER.recheck_all_devices();
    Ok(())
}

pub fn install_prepacked_drivers() -> Result<(), DriverError> {
    const DRIVER_ROOT: &str = "C:\\INSTALL\\DRIVERS";

    let packages = File::list_dir(DRIVER_ROOT).map_err(DriverError::File)?;

    for pkg in packages {
        let pkg_path = alloc::format!("{}\\{}", DRIVER_ROOT, pkg);

        let entries = match File::list_dir(&pkg_path) {
            Ok(e) => e,
            Err(_) => continue,
        };

        if let Some(toml_name) = entries
            .iter()
            .find(|n| n.to_ascii_lowercase().ends_with(".toml"))
        {
            let toml_path = alloc::format!("{}\\{}", pkg_path, toml_name);
            //TODO: log every non fatal error
            match install_driver_toml(&toml_path) {
                Ok(_) => {
                    println!("Installed {}", toml_path);
                }
                Err(DriverError::Registry(RegError::KeyAlreadyExists)) => {
                    println!(
                        "Couldn't install driver {} failed with error: {:#?}",
                        toml_path,
                        DriverError::Registry(RegError::KeyAlreadyExists)
                    );
                }
                Err(DriverError::Registry(e)) => {
                    return Err(DriverError::Registry(e));
                }
                Err(e) => {
                    println!(
                        "Couldn't install driver {} failed with error: {:#?}",
                        toml_path, e
                    );
                }
            }
        }
    }

    Ok(())
}
