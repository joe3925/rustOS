#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::{collections::BTreeMap, string::String, sync::Arc, vec::Vec};
use core::mem::size_of;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::RwLock;

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
use crate::println;
use crate::static_handlers::{pnp_send_request_via_symlink, pnp_wait_for_request};

#[derive(Clone, Debug)]
pub struct MountedVolume {
    pub label: String,
    pub mount_symlink: String,
    pub object_name: String,
}

#[derive(Clone)]
struct VfsHandle {
    pub volume_symlink: String,
    pub inner_id: u64,
    pub is_dir: bool,
}

/// Resolves labels to mount symlinks and forwards FsOps to FS drivers.
/// Keeps a VFS-handle -> FS-handle table.
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

    pub fn list_mounted_volumes(&self) -> (Vec<MountedVolume>, DriverStatus) {
        let mounts = self.enumerate_mount_symlinks();

        let mut out: Vec<MountedVolume> = Vec::new();
        let mut labels = self.label_map.write();

        for m in mounts {
            let (public, label_link, object_name) = match self.query_volume_status(&m) {
                Ok(t) => t,
                Err(_) => continue,
            };

            let mut label = self.try_label_from_link(&label_link);
            if label.is_none() {
                if let Some(persist) = self.query_persistent_label(&m) {
                    label = Some(persist);
                }
            }

            let label = match label {
                Some(l) => l,
                None => {
                    let assigned = self.assign_free_drive_label(&labels);
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

    fn try_label_from_link(&self, label_link: &str) -> Option<String> {
        if label_link.is_empty() {
            return None;
        }
        if let Some((_, leaf)) = label_link.rsplit_once('\\') {
            if leaf.is_empty() {
                return None;
            }
            if leaf.chars().all(|c| c.is_ascii_digit()) {
                return Some(alloc::format!("VOL{:0>4}:", leaf));
            }
            return Some(alloc::format!("{}:", leaf));
        }
        None
    }

    fn assign_free_drive_label(&self, map: &BTreeMap<String, String>) -> String {
        for ch in b'C'..=b'Z' {
            let cand = alloc::format!("{}:", ch as char);
            if !map.contains_key(&cand) {
                return cand;
            }
        }
        alloc::format!("VOL{}:", map.len() + 1)
    }

    fn query_persistent_label(&self, _mount_symlink: &str) -> Option<String> {
        None
    }

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

        const VOL_PREFIX: &str = "\\GLOBAL\\Volumes\\";
        if user_path.starts_with(VOL_PREFIX) {
            let mut parts = user_path.splitn(4, '\\');
            let _ = parts.next();
            let g = parts.next().unwrap_or("");
            let v = parts.next().unwrap_or("");
            let rest = parts.next().unwrap_or("");
            if g != "GLOBAL" || v != "Volumes" {
                return Err(FileError::BadPath);
            }
            let (mount, tail) = match rest.split_once('\\') {
                Some((a, b)) => (a, b),
                None => (rest, ""),
            };
            if mount.is_empty() {
                return Err(FileError::BadPath);
            }
            let symlink = alloc::format!("{}{}", VOL_PREFIX, mount);
            let fs_path = if tail.is_empty() {
                "\\".to_string()
            } else {
                alloc::format!("\\{}", tail)
            };
            return Ok((symlink, fs_path));
        }

        if let Some(colon_pos) = user_path.find(':') {
            let (label, tail0) = user_path.split_at(colon_pos + 1);
            let mut fs_path = if tail0.len() > 1 {
                let after_colon = &tail0[1..];
                if after_colon.starts_with('\\') {
                    after_colon.to_string()
                } else {
                    alloc::format!("\\{}", after_colon)
                }
            } else {
                "\\".to_string()
            };

            let symlink = match self.label_map.read().get(label) {
                Some(s) => s.clone(),
                None => {
                    let base = label.trim_end_matches(':');
                    alloc::format!("\\GLOBAL\\StorageDevices\\{}", base)
                }
            };

            if fs_path.is_empty() {
                fs_path = "\\".to_string();
            }
            return Ok((symlink, fs_path));
        }

        Err(FileError::BadPath)
    }

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
        let raw = core::mem::replace(&mut w.data, Box::new([]));
        let out: Box<TResult> = unsafe { Self::bytes_to_box(raw) };
        Ok(*out)
    }

    #[inline]
    fn call_fs_async<TParam>(
        &self,
        volume_symlink: &str,
        op: FsOp,
        param: TParam,
    ) -> Arc<RwLock<Request>>
    where
        TParam: 'static,
    {
        let req = Arc::new(RwLock::new(Request::new(
            RequestType::Fs(op),
            Vfs::box_to_bytes(Box::new(param)),
        )));
        unsafe { pnp_send_request_via_symlink(volume_symlink.to_string(), req.clone()) };
        req
    }

    // ---------- ASYNC API: returns the sent Request; no waits ----------

    pub fn open_async(&self, p: FsOpenParams) -> Result<Arc<RwLock<Request>>, FileError> {
        let (symlink, fs_path) = self.resolve_path(&p.path)?;
        let param = FsOpenParams {
            flags: p.flags,
            path: fs_path,
        };
        Ok(self.call_fs_async(&symlink, FsOp::Open, param))
    }

    pub fn read_async(&self, p: FsReadParams) -> Result<Arc<RwLock<Request>>, FileError> {
        let h = self
            .handles
            .read()
            .get(&p.fs_file_id)
            .cloned()
            .ok_or(FileError::NotFound)?;
        let param = FsReadParams {
            fs_file_id: h.inner_id,
            offset: p.offset,
            len: p.len,
        };
        Ok(self.call_fs_async(&h.volume_symlink, FsOp::Read, param))
    }

    pub fn write_async(&self, p: FsWriteParams) -> Result<Arc<RwLock<Request>>, FileError> {
        let h = self
            .handles
            .read()
            .get(&p.fs_file_id)
            .cloned()
            .ok_or(FileError::NotFound)?;
        let param = FsWriteParams {
            fs_file_id: h.inner_id,
            offset: p.offset,
            data: p.data,
        };
        Ok(self.call_fs_async(&h.volume_symlink, FsOp::Write, param))
    }

    // ---------- SYNC API (unchanged behavior) ----------

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

        let call_open = |this: &Self, link: &String, path: String, flags: OpenFlags| {
            let inner = FsOpenParams { flags, path };
            match this.call_fs(link, FsOp::Open, inner) {
                Ok(r) => (r, DriverStatus::Success),
                Err(st) => (
                    FsOpenResult {
                        fs_file_id: 0,
                        is_dir: false,
                        size: 0,
                        error: Some(FileError::Unknown),
                    },
                    st,
                ),
            }
        };

        match p.flags {
            OpenFlags::CreateNew => {
                let creq = FsCreateParams {
                    path: fs_path.clone(),
                    dir: false,
                    flags: OpenFlags::CreateNew,
                };
                let cres: FsCreateResult = match self.call_fs(&symlink, FsOp::Create, creq) {
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
                if let Some(e) = cres.error {
                    return (
                        FsOpenResult {
                            fs_file_id: 0,
                            is_dir: false,
                            size: 0,
                            error: Some(e),
                        },
                        DriverStatus::Success,
                    );
                }
                let (inner_res, st) = call_open(self, &symlink, fs_path, OpenFlags::Open);
                if inner_res.error.is_some() {
                    return (inner_res, st);
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
                return (
                    FsOpenResult {
                        fs_file_id: vhid,
                        is_dir: inner_res.is_dir,
                        size: inner_res.size,
                        error: None,
                    },
                    DriverStatus::Success,
                );
            }

            OpenFlags::Create => {
                let (try_open, st) = call_open(self, &symlink, fs_path.clone(), OpenFlags::Open);
                if st != DriverStatus::Success {
                    return (try_open, st);
                }
                if try_open.error.is_none() {
                    let vhid = self.next_vh.fetch_add(1, Ordering::AcqRel).max(1);
                    self.handles.write().insert(
                        vhid,
                        VfsHandle {
                            volume_symlink: symlink,
                            inner_id: try_open.fs_file_id,
                            is_dir: try_open.is_dir,
                        },
                    );
                    return (
                        FsOpenResult {
                            fs_file_id: vhid,
                            is_dir: try_open.is_dir,
                            size: try_open.size,
                            error: None,
                        },
                        DriverStatus::Success,
                    );
                }
                if try_open.error == Some(FileError::NotFound) {
                    let creq = FsCreateParams {
                        path: fs_path.clone(),
                        dir: false,
                        flags: OpenFlags::Create,
                    };
                    let cres: FsCreateResult = match self.call_fs(&symlink, FsOp::Create, creq) {
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
                    if let Some(e) = cres.error {
                        return (
                            FsOpenResult {
                                fs_file_id: 0,
                                is_dir: false,
                                size: 0,
                                error: Some(e),
                            },
                            DriverStatus::Success,
                        );
                    }
                    let (inner_res, st2) = call_open(self, &symlink, fs_path, OpenFlags::Open);
                    if inner_res.error.is_some() {
                        return (inner_res, st2);
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
                    return (
                        FsOpenResult {
                            fs_file_id: vhid,
                            is_dir: inner_res.is_dir,
                            size: inner_res.size,
                            error: None,
                        },
                        DriverStatus::Success,
                    );
                }
                return (try_open, DriverStatus::Success);
            }

            OpenFlags::Open | OpenFlags::ReadOnly | OpenFlags::WriteOnly | OpenFlags::ReadWrite => {
                let (inner_res, st) = call_open(self, &symlink, fs_path, OpenFlags::Open);
                if inner_res.error.is_some() {
                    return (inner_res, st);
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
        }
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

    fn open_path_async(
        &self,
        path: &str,
        flags: &[OpenFlags],
    ) -> Result<Arc<RwLock<Request>>, FileError> {
        let f = *flags.get(0).unwrap_or(&OpenFlags::Open);
        self.open_async(FsOpenParams {
            flags: f,
            path: path.to_string(),
        })
    }

    fn read_at_async(
        &self,
        file_id: u64,
        offset: u64,
        len: u32,
    ) -> Result<Arc<RwLock<Request>>, FileError> {
        self.read_async(FsReadParams {
            fs_file_id: file_id,
            offset,
            len: len as usize,
        })
    }

    fn write_at_async(
        &self,
        file_id: u64,
        offset: u64,
        data: &[u8],
    ) -> Result<Arc<RwLock<Request>>, FileError> {
        self.write_async(FsWriteParams {
            fs_file_id: file_id,
            offset,
            data: data.to_vec(),
        })
    }
}
