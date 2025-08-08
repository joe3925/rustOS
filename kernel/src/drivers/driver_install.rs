use crate::registry::RegError;
use crate::{format, println};
use alloc::{string::String, vec::Vec};
use toml::de::DeTable;
use toml::Spanned;

use crate::alloc::string::ToString;
use crate::{
    file_system::file::{File, FileStatus, OpenFlags},
    registry::{reg, Data},
};

#[derive(Debug)]
pub struct DriverToml {
    pub image: String,
    pub start: BootType,
    pub hwids: Vec<String>,
}
#[derive(Debug)]
pub enum DriverError {
    File(crate::file_system::file::FileStatus),
    InvalidUtf8,
    TomlParse,
    DriverAlreadyInstalled,
    Registry(crate::registry::RegError),
}
impl From<crate::file_system::file::FileStatus> for DriverError {
    fn from(e: crate::file_system::file::FileStatus) -> Self {
        if e == FileStatus::FileAlreadyExist {
            return DriverError::DriverAlreadyInstalled;
        }
        DriverError::File(e)
    }
}

impl From<crate::registry::RegError> for DriverError {
    fn from(e: crate::registry::RegError) -> Self {
        DriverError::Registry(e)
    }
}
#[derive(Debug, Clone, Copy)]
pub enum BootType {
    Boot = 0,
    System = 1,
    Demand = 2,
    Disabled = 3,
}

impl BootType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "boot" => Some(BootType::Boot),
            "system" => Some(BootType::System),
            "demand" => Some(BootType::Demand),
            "disabled" => Some(BootType::Disabled),
            _ => None,
        }
    }

    pub fn as_u32(self) -> u32 {
        self as u32
    }
}

#[inline(always)]
fn inner<'a, T>(s: &'a Spanned<T>) -> &'a T {
    s.get_ref()
}

pub fn parse_driver_toml(path: &str) -> Result<DriverToml, FileStatus> {
    /* 1. Load the file ------------------------------------------------ */
    let mut f = File::open(path, &[OpenFlags::ReadOnly, OpenFlags::Open])?;
    let bytes = f.read()?;
    let src = core::str::from_utf8(&bytes).map_err(|_| FileStatus::InternalError)?;

    let (tbl_span, errs) = DeTable::parse_recoverable(src);
    if !errs.is_empty() {}
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

    let hwids = tbl
        .get("hwids")
        .and_then(|v| inner(v).as_array())
        .ok_or(FileStatus::BadPath)?
        .iter()
        .filter_map(|val| inner(val).as_str().map(ToString::to_string))
        .collect::<Vec<_>>();

    Ok(DriverToml {
        image,
        start,
        hwids,
    })
}
pub fn install_driver_toml(toml_path: &str) -> Result<(), DriverError> {
    let driver = parse_driver_toml(toml_path).map_err(|_| DriverError::TomlParse)?;

    let driver_name = driver
        .image
        .rsplit_once('.')
        .map(|(name, _)| name)
        .unwrap_or(driver.image.as_str());

    let key_path = format!("SYSTEM/CurrentControlSet/Services/{}", driver_name);

    let toml_target_path = format!("C:\\SYSTEM\\TOML\\{}.toml", driver_name);
    let img_target_path = format!("C:\\SYSTEM\\MOD\\{}", driver.image);

    let img_src_path = toml_path.rsplit_once('\\').map(|(p, _)| p).unwrap_or("");
    let img_src_full = format!("{}\\{}", img_src_path, driver.image);
    let img_file = File::open(&img_src_full, &[OpenFlags::ReadOnly, OpenFlags::Open])?;
    let img_data = img_file.read()?;
    let mut img_dest = File::open(&img_target_path, &[OpenFlags::CreateNew])?;
    img_dest.write(&img_data)?;

    let file = File::open(toml_path, &[OpenFlags::ReadOnly, OpenFlags::Open])?;
    let toml_bytes = file.read()?;
    let mut toml_dest = File::open(&toml_target_path, &[OpenFlags::CreateNew])?;
    toml_dest.write(&toml_bytes)?;

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
