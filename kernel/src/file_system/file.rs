#![no_std]

extern crate alloc;

use alloc::{
    boxed::Box,
    string::{String, ToString},
    vec::Vec,
};
use core::cmp::PartialEq;

use crate::file_system::{
    file_provider::provider,
    file_structs::{FileError, FsSeekWhence},
};
use crate::{
    drivers::drive::vfs::Vfs,
    file_system::file_provider::{self, install_file_provider, FileProvider},
    registry::{reg::rebind_and_persist_after_provider_switch, RegError},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FileAttribute {
    ReadOnly = 0x01,
    Hidden = 0x02,
    System = 0x04,
    VolumeLabel = 0x08,
    LFN = 0x0F,
    Directory = 0x10,
    Archive = 0x20,
    Unknown = 0xFF,
}
impl From<FileAttribute> for u8 {
    fn from(attribute: FileAttribute) -> Self {
        attribute as u8
    }
}
impl TryFrom<u8> for FileAttribute {
    type Error = ();
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0x01 => FileAttribute::ReadOnly,
            0x02 => FileAttribute::Hidden,
            0x04 => FileAttribute::System,
            0x08 => FileAttribute::VolumeLabel,
            0x0F => FileAttribute::LFN,
            0x10 => FileAttribute::Directory,
            0x20 => FileAttribute::Archive,
            _ => FileAttribute::Unknown,
        })
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenFlags {
    ReadOnly,
    WriteOnly,
    ReadWrite,
    Create,    // create if missing, otherwise open
    CreateNew, // create only if missing, error if exists
    Open,      // open only if exists
}

#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum FileStatus {
    Success = 0x00,
    FileAlreadyExist = 0x01,
    PathNotFound = 0x02,
    UnknownFail = 0x03,
    NotFat = 0x04,
    DriveNotFound,
    IncompatibleFlags,
    CorruptFat,
    InternalError,
    BadPath,
}
impl FileStatus {
    pub fn to_str(&self) -> &'static str {
        match self {
            FileStatus::Success => "Success",
            FileStatus::FileAlreadyExist => "File already exists",
            FileStatus::PathNotFound => "Path not found",
            FileStatus::UnknownFail => "The operation failed for an unknown reason",
            FileStatus::NotFat => "The partition is unformatted or not supported",
            FileStatus::DriveNotFound => "The drive specified doesn't exist",
            FileStatus::IncompatibleFlags => "The flags can contain CreateNew and Create",
            FileStatus::CorruptFat => "The File Allocation Table is corrupt",
            FileStatus::InternalError => "Internal error",
            FileStatus::BadPath => "Invalid path",
        }
    }
}
impl PartialEq for FileStatus {
    fn eq(&self, other: &FileStatus) -> bool {
        self.to_str() == other.to_str()
    }
}

#[derive(Debug)]
pub struct File {
    fs_file_id: u64,
    path: String,
    pub(crate) size: u64,
    is_dir: bool,
}

impl File {
    pub extern "win64" fn remove_drive_from_path(path: &str) -> &str {
        let b = path.as_bytes();
        if b.len() >= 2 && b[1] == b':' {
            &path[2..]
        } else {
            path
        }
    }
    pub extern "win64" fn remove_file_from_path(path: &str) -> &str {
        let parent = path.rsplit_once('\\').map_or("", |(parent, _)| parent);
        if parent.is_empty() || parent == "\\\\" {
            "\\"
        } else {
            parent
        }
    }
    pub extern "win64" fn get_drive_letter(path: &[u8]) -> Option<String> {
        if path.len() >= 3
            && (path[0] as char).is_ascii_alphabetic()
            && path[1] == b':'
            && path[2] == b'\\'
        {
            Some(String::from_utf8_lossy(&path[0..2]).to_string())
        } else {
            None
        }
    }

    pub extern "win64" fn check_path(path: &str) -> Result<(), FileStatus> {
        // Basic validation kept for callers that relied on it
        let sanitized = Self::remove_drive_from_path(path);
        let parts = sanitized.trim_matches('\\').split('\\');
        for comp in parts {
            if comp.is_empty() || comp == "." || comp == ".." {
                return Err(FileStatus::BadPath);
            }
            if comp.chars().count() > 255 {
                return Err(FileStatus::BadPath);
            }
            if comp.ends_with(' ') || comp.ends_with('.') {
                return Err(FileStatus::BadPath);
            }
            let invalid = ['\\', '/', ':', '*', '?', '"', '<', '>', '|'];
            for ch in comp.chars() {
                if ch < '\u{20}' || invalid.contains(&ch) {
                    return Err(FileStatus::BadPath);
                }
            }
        }
        Ok(())
    }

    pub extern "win64" fn open(path: &str, flags: &[OpenFlags]) -> Result<Self, FileStatus> {
        let (res, st) = file_provider::provider().open_path(path, flags);
        if st != crate::drivers::pnp::driver_object::DriverStatus::Success {
            return Err(FileStatus::UnknownFail);
        }
        if let Some(e) = res.error {
            return Err(file_provider::map_file_error(e));
        }
        Ok(Self {
            fs_file_id: res.fs_file_id,
            path: path.to_string(),
            size: res.size,
            is_dir: res.is_dir,
        })
    }

    pub extern "win64" fn delete(&mut self) -> Result<(), FileStatus> {
        let (r, st) = file_provider::provider().delete_path(&self.path);
        if st != crate::drivers::pnp::driver_object::DriverStatus::Success {
            return Err(FileStatus::UnknownFail);
        }
        match r.error {
            None => Ok(()),
            Some(e) => Err(file_provider::map_file_error(e)),
        }
    }

    pub extern "win64" fn list_dir(path: &str) -> Result<Vec<String>, FileStatus> {
        let (r, st) = file_provider::provider().list_dir_path(path);
        if st != crate::drivers::pnp::driver_object::DriverStatus::Success {
            return Err(FileStatus::UnknownFail);
        }
        match r.error {
            None => Ok(r.names),
            Some(e) => Err(file_provider::map_file_error(e)),
        }
    }

    pub extern "win64" fn remove_dir(path: String) -> Result<(), FileStatus> {
        let (r, st) = file_provider::provider().remove_dir_path(&path);
        if st != crate::drivers::pnp::driver_object::DriverStatus::Success {
            return Err(FileStatus::UnknownFail);
        }
        match r.error {
            None => Ok(()),
            Some(e) => Err(file_provider::map_file_error(e)),
        }
    }

    pub extern "win64" fn make_dir(path: String) -> Result<(), FileStatus> {
        let (r, st) = file_provider::provider().make_dir_path(&path);
        if st != crate::drivers::pnp::driver_object::DriverStatus::Success {
            return Err(FileStatus::UnknownFail);
        }
        match r.error {
            None => Ok(()),
            Some(e) => Err(file_provider::map_file_error(e)),
        }
    }

    pub extern "win64" fn read(&self) -> Result<Vec<u8>, FileStatus> {
        let (gi, st1) = file_provider::provider().get_info(self.fs_file_id);
        if st1 != crate::drivers::pnp::driver_object::DriverStatus::Success {
            return Err(FileStatus::UnknownFail);
        }
        if let Some(e) = gi.error {
            return Err(file_provider::map_file_error(e));
        }
        let size = gi.size as usize;
        let (rr, st2) = file_provider::provider().read_at(self.fs_file_id, 0, size as u32);
        if st2 != crate::drivers::pnp::driver_object::DriverStatus::Success {
            return Err(FileStatus::UnknownFail);
        }
        match rr.error {
            None => Ok(rr.data),
            Some(e) => Err(file_provider::map_file_error(e)),
        }
    }

    pub extern "win64" fn write(&mut self, data: &[u8]) -> Result<(), FileStatus> {
        let (wr, st) = file_provider::provider().write_at(self.fs_file_id, 0, data);
        if st != crate::drivers::pnp::driver_object::DriverStatus::Success {
            return Err(FileStatus::UnknownFail);
        }
        match wr.error {
            None => Ok(()),
            Some(e) => Err(file_provider::map_file_error(e)),
        }
    }

    pub extern "win64" fn move_no_copy(&self, dst: &str) -> Result<(), FileStatus> {
        let (r, st) = file_provider::provider().rename_path(&self.path, dst);
        if st != crate::drivers::pnp::driver_object::DriverStatus::Success {
            return Err(FileStatus::UnknownFail);
        }
        match r.error {
            None => Ok(()),
            Some(e) => Err(file_provider::map_file_error(e)),
        }
    }
}
fn list(dir: &str) -> alloc::vec::Vec<alloc::string::String> {
    let (res, _) = provider().list_dir_path(dir);
    if res.error.is_none() {
        res.names
    } else {
        alloc::vec::Vec::new()
    }
}

fn read_all(path: &str) -> Option<alloc::vec::Vec<u8>> {
    match File::open(path, &[OpenFlags::Open, OpenFlags::ReadOnly]) {
        Ok(mut f) => f.read().ok(),
        Err(_) => None,
    }
}

fn ensure_dir(path: &str) {
    let _ = provider().make_dir_path(path);
}

fn file_exists(path: &str) -> bool {
    match File::open(path, &[OpenFlags::Open, OpenFlags::ReadOnly]) {
        Ok(_) => true,
        Err(_) => false,
    }
}

pub fn switch_to_vfs() -> Result<(), RegError> {
    // TODO: At some point I need to figure out what to do with the boot strap drivers, DriverObject images not resolving.
    // Options:
    // 1. OM resolution, add memory backed files resolved from the OM

    // 2. create a ramfs driver that registers with the vfs, get rid of the file provider stuff

    // 3. add memory backed files that file system drivers must support.

    install_file_provider(Box::new(Vfs::new()));

    rebind_and_persist_after_provider_switch()?;

    let vfs_mod = "C:\\SYSTEM\\MOD";
    let vfs_toml = "C:\\SYSTEM\\TOML";
    ensure_dir(vfs_mod);
    ensure_dir(vfs_toml);

    Ok(())
}
pub(crate) fn file_parser(path: &str) -> Vec<&str> {
    path.trim_start_matches('\\').split('\\').collect()
}
