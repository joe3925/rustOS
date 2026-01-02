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
    memory::paging::frame_alloc::USED_MEMORY,
    println,
    registry::reg::rebind_and_persist_after_provider_switch,
    scheduling::runtime::runtime::spawn_detached,
    util::TOTAL_TIME,
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

    pub async fn open(path: &str, flags: &[OpenFlags]) -> Result<Self, FileStatus> {
        let (res, st) = file_provider::provider().open_path(path, flags).await;
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

    pub async fn delete(&mut self) -> Result<(), FileStatus> {
        let (r, st) = file_provider::provider().delete_path(&self.path).await;
        if st != DriverStatus::Success {
            return Err(FileStatus::UnknownFail);
        }
        match r.error {
            None => Ok(()),
            Some(e) => Err(e),
        }
    }

    pub async fn list_dir(path: &str) -> Result<Vec<String>, FileStatus> {
        let (r, st) = file_provider::provider().list_dir_path(path).await;
        if st != DriverStatus::Success {
            return Err(FileStatus::UnknownFail);
        }
        match r.error {
            None => Ok(r.names),
            Some(e) => Err(e),
        }
    }

    pub async fn remove_dir(path: String) -> Result<(), FileStatus> {
        let (r, st) = file_provider::provider().remove_dir_path(&path).await;
        if st != DriverStatus::Success {
            return Err(FileStatus::UnknownFail);
        }
        match r.error {
            None => Ok(()),
            Some(e) => Err(e),
        }
    }

    pub async fn make_dir(path: String) -> Result<(), FileStatus> {
        if path.is_empty() {
            return Err(FileStatus::BadPath);
        }

        let bytes = path.as_bytes();
        let drive = Self::get_drive_letter(bytes);

        let (base, rest) = if let Some(d) = drive {
            if bytes.len() < 3 || bytes[2] != b'\\' {
                return Err(FileStatus::BadPath);
            }
            (format!("{d}\\"), &path[2..])
        } else if path.starts_with('\\') {
            ("\\".to_string(), path.as_str())
        } else {
            ("".to_string(), path.as_str())
        };

        let trimmed = rest.trim_matches('\\');
        if trimmed.is_empty() {
            return Ok(());
        }

        let mut cur = base;

        for comp in trimmed.split('\\') {
            if comp.is_empty() {
                continue;
            }

            if !cur.is_empty() && !cur.ends_with('\\') {
                cur.push('\\');
            }
            cur.push_str(comp);

            let (r, st) = file_provider::provider().make_dir_path(&cur).await;
            if st != DriverStatus::Success {
                return Err(FileStatus::UnknownFail);
            }

            if let Some(e) = r.error {
                if e != FileStatus::FileAlreadyExist {
                    return Err(e);
                }
            }
        }

        Ok(())
    }
    pub async fn read(&self) -> Result<Vec<u8>, FileStatus> {
        let (gi, st1) = file_provider::provider().get_info(self.fs_file_id).await;
        if st1 != DriverStatus::Success {
            return Err(FileStatus::UnknownFail);
        }
        if let Some(e) = gi.error {
            return Err(e);
        }
        let size = gi.size as usize;
        let (rr, st2) = file_provider::provider()
            .read_at(self.fs_file_id, 0, size as u32)
            .await;
        if st2 != DriverStatus::Success {
            return Err(FileStatus::UnknownFail);
        }
        match rr.error {
            None => Ok(rr.data),
            Some(e) => Err(e),
        }
    }

    pub async fn write(&mut self, data: &[u8]) -> Result<(), FileStatus> {
        let (wr, st) = file_provider::provider()
            .write_at(self.fs_file_id, 0, data)
            .await;
        if st != DriverStatus::Success {
            return Err(FileStatus::UnknownFail);
        }
        match wr.error {
            None => Ok(()),
            Some(e) => Err(e),
        }
    }

    pub async fn move_no_copy(&self, dst: &str) -> Result<(), FileStatus> {
        let (r, st) = file_provider::provider().rename_path(&self.path, dst).await;
        if st != DriverStatus::Success {
            return Err(FileStatus::UnknownFail);
        }
        match r.error {
            None => Ok(()),
            Some(e) => Err(e),
        }
    }
    pub async fn seek(
        &self,
        offset: i64,
        origin: kernel_types::fs::FsSeekWhence,
    ) -> Result<u64, FileStatus> {
        let (res, st) = file_provider::provider()
            .seek_handle(self.fs_file_id, offset, origin)
            .await;

        if st != DriverStatus::Success {
            return Err(FileStatus::UnknownFail);
        }
        if let Some(e) = res.error {
            return Err(e);
        }
        Ok(res.pos)
    }

    pub async fn close(self) -> Result<(), FileStatus> {
        let (res, st) = file_provider::provider()
            .close_handle(self.fs_file_id)
            .await;

        if st != DriverStatus::Success {
            return Err(FileStatus::UnknownFail);
        }
        match res.error {
            None => Ok(()),
            Some(e) => Err(e),
        }
    }
}
impl Drop for File {
    fn drop(&mut self) {
        let id = core::mem::take(&mut self.fs_file_id);
        if id == 0 {
            return;
        }

        spawn_detached(async move {
            let _ = file_provider::provider().close_handle(id).await;
        });
    }
}

async fn list(dir: &str) -> alloc::vec::Vec<alloc::string::String> {
    let (res, _) = provider().list_dir_path(dir).await;
    if res.error.is_none() {
        res.names
    } else {
        alloc::vec::Vec::new()
    }
}

async fn read_all(path: &str) -> Option<alloc::vec::Vec<u8>> {
    match File::open(path, &[OpenFlags::Open, OpenFlags::ReadOnly]).await {
        Ok(f) => f.read().await.ok(),
        Err(_) => None,
    }
}

async fn ensure_dir(path: &str) {
    let _ = provider().make_dir_path(path);
}

async fn file_exists(path: &str) -> bool {
    match File::open(path, &[OpenFlags::Open, OpenFlags::ReadOnly]).await {
        Ok(_) => true,
        Err(_) => false,
    }
}

pub async fn switch_to_vfs() -> Result<(), RegError> {
    install_file_provider(Box::new(Vfs::new()));

    rebind_and_persist_after_provider_switch().await?;

    let vfs_mod = "C:\\system\\mod";
    let vfs_toml = "C:\\system\\toml";
    ensure_dir(vfs_mod).await;
    ensure_dir(vfs_toml).await;

    let boot_ms = TOTAL_TIME.get().unwrap().elapsed_millis();
    let secs = boot_ms / 1000;
    let frac = boot_ms % 1000;

    let used_bytes = USED_MEMORY.load(core::sync::atomic::Ordering::Acquire);
    let used_mib = used_bytes / (1024 * 1024);
    let used_mib_frac = (used_bytes % (1024 * 1024)) * 1000 / (1024 * 1024);

    println!(
        "boot time: {}.{:03}s, Used memory: {}.{:03} MiB",
        secs, frac, used_mib, used_mib_frac
    );

    Ok(())
}
pub(crate) fn file_parser(path: &str) -> Vec<&str> {
    path.trim_start_matches('\\').split('\\').collect()
}
