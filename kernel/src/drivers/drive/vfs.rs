// vfs.rs
#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::{collections::BTreeMap, string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::{Lazy, RwLock};

use crate::drivers::pnp::driver_object::{DriverStatus, FsOp, Request, RequestType};
use crate::file_system::file::OpenFlags;
use crate::file_system::file_provider::FileProvider;
use crate::file_system::file_structs::FsReadParams;
use crate::file_system::file_structs::{
    FileError, FsCloseParams, FsCloseResult, FsCreateParams, FsCreateResult, FsFlushParams,
    FsFlushResult, FsGetInfoParams, FsGetInfoResult, FsListDirParams, FsListDirResult,
    FsOpenParams, FsOpenResult, FsReadResult, FsRenameParams, FsRenameResult, FsSeekParams,
    FsSeekResult, FsWriteParams, FsWriteResult,
};
use crate::static_handlers::{pnp_send_request_via_symlink, pnp_wait_for_request};
use lazy_static::lazy_static;

#[derive(Clone, Debug)]
pub struct MountedVolume {
    pub label: String,
    pub mount_symlink: String,
    pub object_name: String,
}

/// Internal handle tracked by VFS (maps VFS handle -> underlying FS handle + symlink)
#[derive(Clone)]
struct VfsHandle {
    pub volume_symlink: String,
    pub inner_id: u64, // FS-specific handle id returned by the filesystem driver
    pub is_dir: bool,
}

/// The Virtual File System front-end.
/// - Resolves labels to mount symlinks
/// - Forwards FsOps to the appropriate filesystem driver device via its symlink
/// - Maintains per-process (or system-wide) handle table mapping VFS handles to FS handles
pub struct Vfs {
    label_map: RwLock<BTreeMap<String, String>>,
    next_vh: AtomicU64,
    handles: RwLock<BTreeMap<u64, VfsHandle>>,
}

impl Vfs {
    pub fn new() -> Self {
        Self {
            label_map: RwLock::new(BTreeMap::new()),
            next_vh: AtomicU64::new(1),
            handles: RwLock::new(BTreeMap::new()),
        }
    }

    pub fn set_label(&self, label: String, mount_symlink: String) {
        self.label_map.write().insert(label, mount_symlink);
    }

    pub fn remove_label(&self, label: &str) {
        self.label_map.write().remove(label);
    }

    /// Enumerate mounted volumes, refresh the internal label map, and return UI-friendly info.
    ///
    /// Enumerate mount objects (TODO: real MountMgr enumerate).
    ///
    /// Query each for status (`IOCTL_MOUNTMGR_QUERY`) -> parse "public=...;label=...".
    ///
    /// If no persistent label (TODO), assign a free label (C:..Z:) and (TODO) SetLabel.
    pub fn list_mounted_volumes(&self) -> (Vec<MountedVolume>, DriverStatus) {
        let mounts = self.enumerate_mount_symlinks(); // TODO: replace with real enumerate

        let mut out: Vec<MountedVolume> = Vec::new();
        let mut labels = self.label_map.write();

        for m in mounts {
            let (public, label_link, object_name) = match self.query_volume_status(&m) {
                Ok(t) => t,
                Err(_) => continue, // skip volumes we can’t talk to
            };

            let mut label = self.try_label_from_link(&label_link);

            // TODO: ask for a persistent friendly label provided by the volume/FS
            if label.is_none() {
                if let Some(persist) = self.query_persistent_label(&m) {
                    label = Some(persist);
                }
            }

            let label = match label {
                Some(l) => l,
                None => {
                    let assigned = self.assign_free_drive_label(&labels);
                    // TODO: push assigned label to the volume/MountMgr so it persists
                    let _ = self.send_set_label_ioctl(&m, &assigned);
                    assigned
                }
            };

            labels.insert(label.clone(), m.clone());

            let obj = if !public.is_empty() {
                public.clone()
            } else {
                m.clone()
            };
            out.push(MountedVolume {
                label,
                mount_symlink: m,
                object_name: obj,
            });
        }

        (out, DriverStatus::Success)
    }

    // TODO: Enumerate mount object symlinks from MountMgr.
    fn enumerate_mount_symlinks(&self) -> Vec<String> {
        Vec::new()
    }

    fn query_volume_status(
        &self,
        mount_symlink: &str,
    ) -> Result<(String, String, String), DriverStatus> {
        const IOCTL_MOUNTMGR_QUERY: u32 = 0x4D4D_0003;

        let req = Arc::new(RwLock::new(Request::new(
            RequestType::DeviceControl(IOCTL_MOUNTMGR_QUERY),
            Box::new([]),
        )));
        unsafe { pnp_send_request_via_symlink(mount_symlink.to_string(), req.clone()) };
        unsafe { pnp_wait_for_request(&req) };

        let r = req.read();
        if r.status != DriverStatus::Success {
            return Err(r.status);
        }

        let s = core::str::from_utf8(&r.data).unwrap_or_default();
        let mut public = String::new();
        let mut label = String::new();
        let mut object_name = String::new();

        for part in s.split(';') {
            if let Some((k, v)) = part.split_once('=') {
                match k.trim() {
                    "public" => public = v.trim().to_string(),
                    "label" => label = v.trim().to_string(),
                    "claimed" => {}
                    _ => {}
                }
            }
        }

        if object_name.is_empty() {
            object_name = if !public.is_empty() {
                public.clone()
            } else {
                mount_symlink.to_string()
            };
        }

        Ok((public, label, object_name))
    }

    /// Generate a default user-visible label from a label link like "\\GLOBAL\\Mounts\\VOL0001".
    fn try_label_from_link(&self, label_link: &str) -> Option<String> {
        if label_link.is_empty() {
            return None;
        }
        if let Some((_, leaf)) = label_link.rsplit_once('\\') {
            if !leaf.is_empty() {
                return Some(alloc::format!("{}:", leaf));
            }
        }
        None
    }

    /// Assign a free drive letter "C:".. "Z:"; fall back to "VOLn:".
    fn assign_free_drive_label(&self, map: &BTreeMap<String, String>) -> String {
        for ch in b'C'..=b'Z' {
            let cand = alloc::format!("{}:", ch as char);
            if !map.contains_key(&cand) {
                return cand;
            }
        }
        alloc::format!("VOL{}:", map.len() + 1)
    }

    // TODO: Ask the volume for a persistent friendly label (e.g., FAT volume label).
    fn query_persistent_label(&self, _mount_symlink: &str) -> Option<String> {
        None
    }

    // TODO: Push an assigned label back to the volume or MountMgr to persist it.
    fn send_set_label_ioctl(&self, _mount_symlink: &str, _label: &str) -> Result<(), DriverStatus> {
        Ok(())
    }

    #[inline]
    fn alloc_vh(&self) -> u64 {
        let v = self.next_vh.fetch_add(1, Ordering::AcqRel);
        if v == 0 {
            1
        } else {
            v
        }
    }
    fn resolve_path(&self, user_path: &str) -> Result<(String, String), FileError> {
        if user_path.is_empty() {
            return Err(FileError::BadPath);
        }

        // Case 1: raw symlink path prefix
        const GLOBAL_PREFIX: &str = "\\GLOBAL\\Mounts\\";
        if user_path.starts_with(GLOBAL_PREFIX) {
            // Split first component as the symlink path base
            // e.g. "\GLOBAL\Mounts\VOL0001\foo\bar"
            let mut parts = user_path.splitn(4, '\\'); // ["", "GLOBAL", "Mounts", "VOL0001\foo\bar"]
            let _ = parts.next(); // ""
            let g = parts.next().unwrap_or("");
            let m = parts.next().unwrap_or("");
            let rest = parts.next().unwrap_or(""); // "VOL0001\foo\bar" (or "")

            if g != "GLOBAL" || m != "Mounts" {
                return Err(FileError::BadPath);
            }
            let (mount, tail) = match rest.split_once('\\') {
                Some((a, b)) => (a, b),
                None => (rest, ""), // root of the mount
            };
            if mount.is_empty() {
                return Err(FileError::BadPath);
            }
            let symlink = alloc::format!("{}{}", GLOBAL_PREFIX, mount);
            let fs_path = if tail.is_empty() {
                "\\".to_string()
            } else {
                alloc::format!("\\{}", tail)
            };
            return Ok((symlink, fs_path));
        }

        if let Some(colon_pos) = user_path.find(':') {
            let (label, tail0) = user_path.split_at(colon_pos + 1); // includes ':'
                                                                    // Normalize fs path: must start with '\'
            let mut fs_path = if tail0.len() > 1 {
                // tail0 starts with ":\something" because split_at included ':'
                let after_colon = &tail0[1..];
                if after_colon.starts_with('\\') {
                    after_colon.to_string()
                } else {
                    alloc::format!("\\{}", after_colon)
                }
            } else {
                "\\".to_string()
            };

            // Resolve label -> symlink
            let symlink = match self.label_map.read().get(label) {
                Some(s) => s.clone(),
                None => {
                    let base = label.trim_end_matches(':');
                    alloc::format!("\\GLOBAL\\Mounts\\{}", base)
                }
            };

            if fs_path.is_empty() {
                fs_path = "\\".to_string();
            }
            return Ok((symlink, fs_path));
        }

        Err(FileError::BadPath)
    }

    // ---- Transport helpers (Box<T> <-> Box<[u8]>) ----
    fn box_to_bytes<T>(b: Box<T>) -> Box<[u8]> {
        let len = size_of::<T>();
        let ptr = Box::into_raw(b) as *mut u8;
        unsafe { Box::from_raw(core::slice::from_raw_parts_mut(ptr, len)) }
    }
    unsafe fn bytes_to_box<T>(b: Box<[u8]>) -> Box<T> {
        debug_assert_eq!(b.len(), size_of::<T>());
        let ptr = Box::into_raw(b) as *mut u8 as *mut T;
        Box::from_raw(ptr)
    }

    // ---- Core forwarding primitive ----
    fn call_fs<TParam, TResult>(
        &self,
        volume_symlink: &str,
        op: FsOp,
        param: TParam,
    ) -> Result<TResult, DriverStatus>
    where
        TParam: 'static,
        TResult: 'static,
    {
        let req = Arc::new(RwLock::new(Request::new(
            RequestType::Fs(op),
            Vfs::box_to_bytes(Box::new(param)),
        )));
        unsafe { pnp_send_request_via_symlink(volume_symlink.to_string(), req.clone()) };
        unsafe { pnp_wait_for_request(&req) };

        let mut w = req.write();
        if w.status != DriverStatus::Success {
            return Err(w.status);
        }
        // take out the result
        let raw = core::mem::replace(&mut w.data, Box::new([]));
        let out: Box<TResult> = unsafe { Self::bytes_to_box(raw) };
        Ok(*out)
    }

    // ========================= VFS API =========================

    pub fn open(&self, p: FsOpenParams) -> (FsOpenResult, DriverStatus) {
        let (symlink, fs_path) = match self.resolve_path(&p.path) {
            Ok(v) => v,
            Err(e) => {
                return (
                    FsOpenResult {
                        fs_file_id: 0,
                        is_dir: false,
                        size: 0,
                        error: Some(e),
                    },
                    DriverStatus::Success,
                )
            }
        };

        let inner = FsOpenParams {
            flags: p.flags,
            path: fs_path,
        };
        let inner_res: FsOpenResult = match self.call_fs(&symlink, FsOp::Open, inner) {
            Ok(r) => r,
            Err(st) => {
                return (
                    FsOpenResult {
                        fs_file_id: 0,
                        is_dir: false,
                        size: 0,
                        error: Some(FileError::Unknown),
                    },
                    st,
                )
            }
        };

        if let Some(err) = inner_res.error {
            return (inner_res, DriverStatus::Success);
        }

        let vhid = self.next_vh.fetch_add(1, Ordering::AcqRel).max(1);
        self.handles.write().insert(
            vhid,
            VfsHandle {
                volume_symlink: symlink,
                inner_id: inner_res.fs_file_id,
                is_dir: inner_res.is_dir,
            },
        );

        (
            FsOpenResult {
                fs_file_id: vhid,
                is_dir: inner_res.is_dir,
                size: inner_res.size,
                error: None,
            },
            DriverStatus::Success,
        )
    }

    pub fn close(&self, p: FsCloseParams) -> (FsCloseResult, DriverStatus) {
        let Some(h) = self.handles.write().remove(&p.fs_file_id) else {
            return (
                FsCloseResult {
                    error: Some(FileError::NotFound),
                },
                DriverStatus::Success,
            );
        };

        let inner = FsCloseParams {
            fs_file_id: h.inner_id,
        };
        let res: Result<FsCloseResult, DriverStatus> =
            self.call_fs(&h.volume_symlink, FsOp::Close, inner);
        match res {
            Ok(mut r) => {
                // even if FS returns error, the VFS mapping is gone
                if r.error.is_none() {
                    r.error = None;
                }
                (r, DriverStatus::Success)
            }
            Err(st) => (
                FsCloseResult {
                    error: Some(FileError::Unknown),
                },
                st,
            ),
        }
    }

    pub fn read(&self, p: FsReadParams) -> (FsReadResult, DriverStatus) {
        let Some(h) = self.handles.read().get(&p.fs_file_id).cloned() else {
            return (
                FsReadResult {
                    data: Vec::new(),
                    error: Some(FileError::NotFound),
                },
                DriverStatus::Success,
            );
        };
        let inner = FsReadParams {
            fs_file_id: h.inner_id,
            offset: p.offset,
            len: p.len,
        };
        match self.call_fs::<FsReadParams, FsReadResult>(&h.volume_symlink, FsOp::Read, inner) {
            Ok(r) => (r, DriverStatus::Success),
            Err(st) => (
                FsReadResult {
                    data: Vec::new(),
                    error: Some(FileError::Unknown),
                },
                st,
            ),
        }
    }

    pub fn write(&self, mut p: FsWriteParams) -> (FsWriteResult, DriverStatus) {
        let Some(h) = self.handles.read().get(&p.fs_file_id).cloned() else {
            return (
                FsWriteResult {
                    written: 0,
                    error: Some(FileError::NotFound),
                },
                DriverStatus::Success,
            );
        };
        // replace handle id with inner id; reuse caller buffers
        p.fs_file_id = h.inner_id;
        match self.call_fs::<FsWriteParams, FsWriteResult>(&h.volume_symlink, FsOp::Write, p) {
            Ok(r) => (r, DriverStatus::Success),
            Err(st) => (
                FsWriteResult {
                    written: 0,
                    error: Some(FileError::Unknown),
                },
                st,
            ),
        }
    }

    pub fn seek(&self, mut p: FsSeekParams) -> (FsSeekResult, DriverStatus) {
        let Some(h) = self.handles.read().get(&p.fs_file_id).cloned() else {
            return (
                FsSeekResult {
                    pos: 0,
                    error: Some(FileError::NotFound),
                },
                DriverStatus::Success,
            );
        };
        p.fs_file_id = h.inner_id;
        match self.call_fs::<FsSeekParams, FsSeekResult>(&h.volume_symlink, FsOp::Seek, p) {
            Ok(r) => (r, DriverStatus::Success),
            Err(st) => (
                FsSeekResult {
                    pos: 0,
                    error: Some(FileError::Unknown),
                },
                st,
            ),
        }
    }

    pub fn flush(&self, mut p: FsFlushParams) -> (FsFlushResult, DriverStatus) {
        let Some(h) = self.handles.read().get(&p.fs_file_id).cloned() else {
            return (
                FsFlushResult {
                    error: Some(FileError::NotFound),
                },
                DriverStatus::Success,
            );
        };
        p.fs_file_id = h.inner_id;
        match self.call_fs::<FsFlushParams, FsFlushResult>(&h.volume_symlink, FsOp::Flush, p) {
            Ok(r) => (r, DriverStatus::Success),
            Err(st) => (
                FsFlushResult {
                    error: Some(FileError::Unknown),
                },
                st,
            ),
        }
    }

    pub fn get_info(&self, mut p: FsGetInfoParams) -> (FsGetInfoResult, DriverStatus) {
        let Some(h) = self.handles.read().get(&p.fs_file_id).cloned() else {
            return (
                FsGetInfoResult {
                    size: 0,
                    is_dir: false,
                    attrs: 0,
                    error: Some(FileError::NotFound),
                },
                DriverStatus::Success,
            );
        };
        p.fs_file_id = h.inner_id;
        match self.call_fs::<FsGetInfoParams, FsGetInfoResult>(&h.volume_symlink, FsOp::GetInfo, p)
        {
            Ok(r) => (r, DriverStatus::Success),
            Err(st) => (
                FsGetInfoResult {
                    size: 0,
                    is_dir: false,
                    attrs: 0,
                    error: Some(FileError::Unknown),
                },
                st,
            ),
        }
    }

    pub fn create(&self, mut p: FsCreateParams) -> (FsCreateResult, DriverStatus) {
        let (symlink, fs_path) = match self.resolve_path(&p.path) {
            Ok(v) => v,
            Err(e) => return (FsCreateResult { error: Some(e) }, DriverStatus::Success),
        };
        p.path = fs_path;
        match self.call_fs::<FsCreateParams, FsCreateResult>(&symlink, FsOp::Create, p) {
            Ok(r) => (r, DriverStatus::Success),
            Err(st) => (
                FsCreateResult {
                    error: Some(FileError::Unknown),
                },
                st,
            ),
        }
    }

    pub fn rename(&self, mut p: FsRenameParams) -> (FsRenameResult, DriverStatus) {
        let (src_symlink, src_rel) = match self.resolve_path(&p.src) {
            Ok(v) => v,
            Err(e) => return (FsRenameResult { error: Some(e) }, DriverStatus::Success),
        };
        let (dst_symlink, dst_rel) = match self.resolve_path(&p.dst) {
            Ok(v) => v,
            Err(e) => return (FsRenameResult { error: Some(e) }, DriverStatus::Success),
        };
        if src_symlink != dst_symlink {
            return (
                FsRenameResult {
                    error: Some(FileError::Unsupported),
                },
                DriverStatus::Success,
            );
        }
        p.src = src_rel;
        p.dst = dst_rel;
        match self.call_fs::<FsRenameParams, FsRenameResult>(&src_symlink, FsOp::Rename, p) {
            Ok(r) => (r, DriverStatus::Success),
            Err(st) => (
                FsRenameResult {
                    error: Some(FileError::Unknown),
                },
                st,
            ),
        }
    }

    pub fn list_dir(&self, mut p: FsListDirParams) -> (FsListDirResult, DriverStatus) {
        let (symlink, fs_path) = match self.resolve_path(&p.path) {
            Ok(v) => v,
            Err(e) => {
                return (
                    FsListDirResult {
                        names: Vec::new(),
                        error: Some(e),
                    },
                    DriverStatus::Success,
                )
            }
        };
        p.path = fs_path;
        match self.call_fs::<FsListDirParams, FsListDirResult>(&symlink, FsOp::ReadDir, p) {
            Ok(r) => (r, DriverStatus::Success),
            Err(st) => (
                FsListDirResult {
                    names: Vec::new(),
                    error: Some(FileError::Unknown),
                },
                st,
            ),
        }
    }
}
impl FileProvider for Vfs {
    fn open_path(&self, path: &str, flags: &[OpenFlags]) -> (FsOpenResult, DriverStatus) {
        let f = *flags.get(0).unwrap_or(&OpenFlags::Open);
        self.open(FsOpenParams {
            flags: f,
            path: path.to_string(),
        })
    }

    fn close_handle(&self, file_id: u64) -> (FsCloseResult, DriverStatus) {
        self.close(FsCloseParams {
            fs_file_id: file_id,
        })
    }

    fn read_at(&self, file_id: u64, offset: u64, len: u32) -> (FsReadResult, DriverStatus) {
        self.read(FsReadParams {
            fs_file_id: file_id,
            offset,
            len: len as usize,
        })
    }

    fn write_at(&self, file_id: u64, offset: u64, data: &[u8]) -> (FsWriteResult, DriverStatus) {
        self.write(FsWriteParams {
            fs_file_id: file_id,
            offset,
            data: data.to_vec(),
        })
    }

    fn flush_handle(&self, file_id: u64) -> (FsFlushResult, DriverStatus) {
        self.flush(FsFlushParams {
            fs_file_id: file_id,
        })
    }

    fn get_info(&self, file_id: u64) -> (FsGetInfoResult, DriverStatus) {
        self.get_info(FsGetInfoParams {
            fs_file_id: file_id,
        })
    }

    fn list_dir_path(&self, path: &str) -> (FsListDirResult, DriverStatus) {
        self.list_dir(FsListDirParams {
            path: path.to_string(),
        })
    }

    fn make_dir_path(&self, path: &str) -> (FsCreateResult, DriverStatus) {
        self.create(FsCreateParams {
            path: path.to_string(),
            dir: true,
            flags: OpenFlags::Create,
        })
    }

    fn remove_dir_path(&self, _path: &str) -> (FsCreateResult, DriverStatus) {
        (
            FsCreateResult {
                error: Some(FileError::Unsupported),
            },
            DriverStatus::Success,
        )
    }

    fn rename_path(&self, src: &str, dst: &str) -> (FsRenameResult, DriverStatus) {
        self.rename(FsRenameParams {
            src: src.to_string(),
            dst: dst.to_string(),
        })
    }

    fn delete_path(&self, _path: &str) -> (FsCreateResult, DriverStatus) {
        (
            FsCreateResult {
                error: Some(FileError::Unsupported),
            },
            DriverStatus::Success,
        )
    }
}
