#![no_std]

extern crate alloc;

use alloc::{
    borrow::Cow,
    boxed::Box,
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::cmp::PartialEq;
use kernel_types::{
    fs::OpenFlags,
    status::{DriverStatus, FileStatus, RegError},
};

use crate::{
    drivers::drive::vfs::Vfs,
    file_system::file_provider::{self, install_file_provider, FileProvider},
    registry::reg::rebind_and_persist_after_provider_switch,
};
use crate::{
    drivers::{driver_install::install_prepacked_drivers, pnp::manager::PNP_MANAGER},
    file_system::file_provider::provider,
    registry::is_first_boot,
};
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
        if st != DriverStatus::Success {
            return Err(FileStatus::UnknownFail);
        }
        if let Some(e) = res.error {
            return Err(e);
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
        if st != DriverStatus::Success {
            return Err(FileStatus::UnknownFail);
        }
        match r.error {
            None => Ok(()),
            Some(e) => Err(e),
        }
    }

    pub extern "win64" fn list_dir(path: &str) -> Result<Vec<String>, FileStatus> {
        let (r, st) = file_provider::provider().list_dir_path(path);
        if st != DriverStatus::Success {
            return Err(FileStatus::UnknownFail);
        }
        match r.error {
            None => Ok(r.names),
            Some(e) => Err(e),
        }
    }

    pub extern "win64" fn remove_dir(path: String) -> Result<(), FileStatus> {
        let (r, st) = file_provider::provider().remove_dir_path(&path);
        if st != DriverStatus::Success {
            return Err(FileStatus::UnknownFail);
        }
        match r.error {
            None => Ok(()),
            Some(e) => Err(e),
        }
    }

    pub extern "win64" fn make_dir(path: String) -> Result<(), FileStatus> {
        let (r, st) = file_provider::provider().make_dir_path(&path);
        if st != DriverStatus::Success {
            return Err(FileStatus::UnknownFail);
        }
        match r.error {
            None => Ok(()),
            Some(e) => Err(e),
        }
    }

    pub extern "win64" fn read(&self) -> Result<Vec<u8>, FileStatus> {
        let (gi, st1) = file_provider::provider().get_info(self.fs_file_id);
        if st1 != DriverStatus::Success {
            return Err(FileStatus::UnknownFail);
        }
        if let Some(e) = gi.error {
            return Err(e);
        }
        let size = gi.size as usize;
        let (rr, st2) = file_provider::provider().read_at(self.fs_file_id, 0, size as u32);
        if st2 != DriverStatus::Success {
            return Err(FileStatus::UnknownFail);
        }
        match rr.error {
            None => Ok(rr.data),
            Some(e) => Err(e),
        }
    }

    pub extern "win64" fn write(&mut self, data: &[u8]) -> Result<(), FileStatus> {
        let (wr, st) = file_provider::provider().write_at(self.fs_file_id, 0, data);
        if st != DriverStatus::Success {
            return Err(FileStatus::UnknownFail);
        }
        match wr.error {
            None => Ok(()),
            Some(e) => Err(e),
        }
    }

    pub extern "win64" fn move_no_copy(&self, dst: &str) -> Result<(), FileStatus> {
        let (r, st) = file_provider::provider().rename_path(&self.path, dst);
        if st != DriverStatus::Success {
            return Err(FileStatus::UnknownFail);
        }
        match r.error {
            None => Ok(()),
            Some(e) => Err(e),
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
    if (is_first_boot()) {
        //install_prepacked_drivers();
    }
    Ok(())
}
pub(crate) fn file_parser(path: &str) -> Vec<&str> {
    path.trim_start_matches('\\').split('\\').collect()
}
