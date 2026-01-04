#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::{collections::BTreeMap, string::String, sync::Arc, vec::Vec};
use core::mem::size_of;
use core::sync::atomic::{AtomicU64, Ordering};
use kernel_types::async_ffi::{FfiFuture, FutureExt};
use kernel_types::request::{Request, RequestType, TraversalPolicy};
use kernel_types::status::{DriverStatus, FileStatus};
use spin::RwLock;

use crate::drivers::pnp::request::RequestExt;
use crate::file_system::file_provider::FileProvider;
use crate::println;
use crate::static_handlers::pnp_send_request_via_symlink;
use kernel_types::fs::{Path, *};

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

    pub async fn list_mounted_volumes(&self) -> (Vec<MountedVolume>, DriverStatus) {
        let mounts = self.enumerate_mount_symlinks();

        let mut out: Vec<MountedVolume> = Vec::new();
        let mut labels = self.label_map.write();

        for m in mounts {
            let (public, label_link, object_name) = match self.query_volume_status(&m).await {
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

    async fn query_volume_status(
        &self,
        mount_symlink: &str,
    ) -> Result<(String, String, String), DriverStatus> {
        const IOCTL_MOUNTMGR_QUERY: u32 = 0x4D4D_0003;

        let req = Arc::new(RwLock::new(
            Request::new(
                RequestType::DeviceControl(IOCTL_MOUNTMGR_QUERY),
                Box::new([]),
            )
            .set_traversal_policy(TraversalPolicy::ForwardLower),
        ));
        pnp_send_request_via_symlink(mount_symlink.to_string(), req.clone()).await?;

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

    fn resolve_path(&self, user_path: &Path) -> Result<(String, Path), FileStatus> {
        if user_path.symlink.is_none() && user_path.components.is_empty() {
            return Err(FileStatus::BadPath);
        }

        // Build the fs_path from components (without drive)
        let fs_path = Path {
            symlink: None,
            components: user_path.components.clone(),
        };

        // Resolve drive letter to symlink
        if let Some(d) = user_path.symlink {
            let label = alloc::format!("{}:", d);
            let symlink = match self.label_map.read().get(&label) {
                Some(s) => s.clone(),
                None => {
                    alloc::format!("\\GLOBAL\\StorageDevices\\{}", d)
                }
            };
            return Ok((symlink, fs_path));
        }

        Err(FileStatus::BadPath)
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

    async fn call_fs<TParam, TResult>(
        &self,
        volume_symlink: &str,
        op: FsOp,
        param: TParam,
    ) -> Result<TResult, DriverStatus>
    where
        TParam: 'static,
        TResult: 'static,
    {
        let req = Arc::new(RwLock::new(
            Request::new(RequestType::Fs(op), Vfs::box_to_bytes(Box::new(param)))
                .set_traversal_policy(TraversalPolicy::ForwardLower),
        ));
        let status = pnp_send_request_via_symlink(volume_symlink.to_string(), req.clone()).await;
        if status != DriverStatus::Success {
            println!("Send request fail with status: {}", status);
            return Err(status);
        }

        let raw = core::mem::replace(&mut req.write().data, Box::new([]));
        let out: Box<TResult> = unsafe { Self::bytes_to_box(raw) };
        Ok(*out)
    }

    pub async fn open(&self, p: FsOpenParams) -> (FsOpenResult, DriverStatus) {
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

        let call_open = async |this: &Self, link: &String, path: Path, flags: OpenFlagsMask| {
            let inner = FsOpenParams { flags, path };
            match this
                .call_fs::<FsOpenParams, FsOpenResult>(link, FsOp::Open, inner)
                .await
            {
                Ok(mut r) => {
                    if matches!(r.error, Some(FileStatus::Success)) {
                        r.error = None;
                    }
                    (r, DriverStatus::Success)
                }
                Err(st) => (
                    FsOpenResult {
                        fs_file_id: 0,
                        is_dir: false,
                        size: 0,
                        error: Some(FileStatus::UnknownFail),
                    },
                    st,
                ),
            }
        };

        let has_create_new = p.flags.contains(OpenFlags::CreateNew);
        let has_create = p.flags.contains(OpenFlags::Create);

        if has_create_new {
            let creq = FsCreateParams {
                path: fs_path.clone(),
                dir: false,
                flags: OpenFlags::CreateNew,
            };
            let cres: FsCreateResult = match self.call_fs(&symlink, FsOp::Create, creq).await {
                Ok(r) => r,
                Err(st) => {
                    return (
                        FsOpenResult {
                            fs_file_id: 0,
                            is_dir: false,
                            size: 0,
                            error: Some(FileStatus::UnknownFail),
                        },
                        st,
                    )
                }
            };
            if let Some(e) = cres.error {
                if e != FileStatus::Success {
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
            }

            let (inner_res, st) = call_open(self, &symlink, fs_path, p.flags.clone()).await;
            if matches!(inner_res.error, Some(e) if e != FileStatus::Success) {
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
        } else if has_create {
            let (try_open, st) = call_open(self, &symlink, fs_path.clone(), p.flags.clone()).await;
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
            if try_open.error == Some(FileStatus::PathNotFound) {
                let creq = FsCreateParams {
                    path: fs_path.clone(),
                    dir: false,
                    flags: OpenFlags::Create,
                };
                let cres: FsCreateResult = match self.call_fs(&symlink, FsOp::Create, creq).await {
                    Ok(r) => r,
                    Err(st) => {
                        return (
                            FsOpenResult {
                                fs_file_id: 0,
                                is_dir: false,
                                size: 0,
                                error: Some(FileStatus::UnknownFail),
                            },
                            st,
                        )
                    }
                };
                if let Some(e) = cres.error {
                    if e != FileStatus::Success {
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
                }

                let (inner_res, st2) = call_open(self, &symlink, fs_path, p.flags.clone()).await;
                if matches!(inner_res.error, Some(e) if e != FileStatus::Success) {
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
            (try_open, DriverStatus::Success)
        } else {
            // Open, ReadOnly, WriteOnly, ReadWrite - just open
            let (inner_res, st) = call_open(self, &symlink, fs_path, p.flags.clone()).await;
            if matches!(inner_res.error, Some(e) if e != FileStatus::Success) {
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

    pub async fn close(&self, p: FsCloseParams) -> (FsCloseResult, DriverStatus) {
        let Some(h) = self.handles.write().remove(&p.fs_file_id) else {
            return (
                FsCloseResult {
                    error: Some(FileStatus::PathNotFound),
                },
                DriverStatus::Success,
            );
        };

        let inner = FsCloseParams {
            fs_file_id: h.inner_id,
        };
        let res: Result<FsCloseResult, DriverStatus> =
            self.call_fs(&h.volume_symlink, FsOp::Close, inner).await;
        match res {
            Ok(mut r) => {
                if r.error.is_none() {
                    r.error = None;
                }
                (r, DriverStatus::Success)
            }
            Err(st) => (
                FsCloseResult {
                    error: Some(FileStatus::UnknownFail),
                },
                st,
            ),
        }
    }

    pub async fn read(&self, p: FsReadParams) -> (FsReadResult, DriverStatus) {
        let Some(h) = self.handles.read().get(&p.fs_file_id).cloned() else {
            return (
                FsReadResult {
                    data: Vec::new(),
                    error: Some(FileStatus::PathNotFound),
                },
                DriverStatus::Success,
            );
        };
        let inner = FsReadParams {
            fs_file_id: h.inner_id,
            offset: p.offset,
            len: p.len,
        };
        match self
            .call_fs::<FsReadParams, FsReadResult>(&h.volume_symlink, FsOp::Read, inner)
            .await
        {
            Ok(r) => (r, DriverStatus::Success),
            Err(st) => (
                FsReadResult {
                    data: Vec::new(),
                    error: Some(FileStatus::UnknownFail),
                },
                st,
            ),
        }
    }

    pub async fn write(&self, mut p: FsWriteParams) -> (FsWriteResult, DriverStatus) {
        let Some(h) = self.handles.read().get(&p.fs_file_id).cloned() else {
            return (
                FsWriteResult {
                    written: 0,
                    error: Some(FileStatus::PathNotFound),
                },
                DriverStatus::Success,
            );
        };
        p.fs_file_id = h.inner_id;
        match self
            .call_fs::<FsWriteParams, FsWriteResult>(&h.volume_symlink, FsOp::Write, p)
            .await
        {
            Ok(r) => (r, DriverStatus::Success),
            Err(st) => (
                FsWriteResult {
                    written: 0,
                    error: Some(FileStatus::UnknownFail),
                },
                st,
            ),
        }
    }

    pub async fn seek(&self, mut p: FsSeekParams) -> (FsSeekResult, DriverStatus) {
        let Some(h) = self.handles.read().get(&p.fs_file_id).cloned() else {
            return (
                FsSeekResult {
                    pos: 0,
                    error: Some(FileStatus::PathNotFound),
                },
                DriverStatus::Success,
            );
        };
        p.fs_file_id = h.inner_id;
        match self
            .call_fs::<FsSeekParams, FsSeekResult>(&h.volume_symlink, FsOp::Seek, p)
            .await
        {
            Ok(r) => (r, DriverStatus::Success),
            Err(st) => (
                FsSeekResult {
                    pos: 0,
                    error: Some(FileStatus::UnknownFail),
                },
                st,
            ),
        }
    }

    pub async fn flush(&self, mut p: FsFlushParams) -> (FsFlushResult, DriverStatus) {
        let Some(h) = self.handles.read().get(&p.fs_file_id).cloned() else {
            return (
                FsFlushResult {
                    error: Some(FileStatus::PathNotFound),
                },
                DriverStatus::Success,
            );
        };
        p.fs_file_id = h.inner_id;
        match self
            .call_fs::<FsFlushParams, FsFlushResult>(&h.volume_symlink, FsOp::Flush, p)
            .await
        {
            Ok(r) => (r, DriverStatus::Success),
            Err(st) => (
                FsFlushResult {
                    error: Some(FileStatus::UnknownFail),
                },
                st,
            ),
        }
    }

    pub async fn get_info(&self, mut p: FsGetInfoParams) -> (FsGetInfoResult, DriverStatus) {
        let Some(h) = self.handles.read().get(&p.fs_file_id).cloned() else {
            return (
                FsGetInfoResult {
                    size: 0,
                    is_dir: false,
                    attrs: 0,
                    error: Some(FileStatus::PathNotFound),
                },
                DriverStatus::Success,
            );
        };
        p.fs_file_id = h.inner_id;
        match self
            .call_fs::<FsGetInfoParams, FsGetInfoResult>(&h.volume_symlink, FsOp::GetInfo, p)
            .await
        {
            Ok(r) => (r, DriverStatus::Success),
            Err(st) => (
                FsGetInfoResult {
                    size: 0,
                    is_dir: false,
                    attrs: 0,
                    error: Some(FileStatus::UnknownFail),
                },
                st,
            ),
        }
    }

    pub async fn create(&self, mut p: FsCreateParams) -> (FsCreateResult, DriverStatus) {
        let (symlink, fs_path) = match self.resolve_path(&p.path) {
            Ok(v) => v,
            Err(e) => return (FsCreateResult { error: Some(e) }, DriverStatus::Success),
        };
        p.path = fs_path;
        match self
            .call_fs::<FsCreateParams, FsCreateResult>(&symlink, FsOp::Create, p)
            .await
        {
            Ok(r) => (r, DriverStatus::Success),
            Err(st) => (
                FsCreateResult {
                    error: Some(FileStatus::UnknownFail),
                },
                st,
            ),
        }
    }

    pub async fn rename(&self, mut p: FsRenameParams) -> (FsRenameResult, DriverStatus) {
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
                    error: Some(FileStatus::UnknownFail),
                },
                DriverStatus::Success,
            );
        }
        p.src = src_rel;
        p.dst = dst_rel;
        match self
            .call_fs::<FsRenameParams, FsRenameResult>(&src_symlink, FsOp::Rename, p)
            .await
        {
            Ok(r) => (r, DriverStatus::Success),
            Err(st) => (
                FsRenameResult {
                    error: Some(FileStatus::UnknownFail),
                },
                st,
            ),
        }
    }

    pub async fn list_dir(&self, mut p: FsListDirParams) -> (FsListDirResult, DriverStatus) {
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
        match self
            .call_fs::<FsListDirParams, FsListDirResult>(&symlink, FsOp::ReadDir, p)
            .await
        {
            Ok(r) => (r, DriverStatus::Success),
            Err(st) => (
                FsListDirResult {
                    names: Vec::new(),
                    error: Some(FileStatus::UnknownFail),
                },
                st,
            ),
        }
    }
}

impl FileProvider for Vfs {
    fn open_path(
        &self,
        path: &Path,
        flags: &[OpenFlags],
    ) -> FfiFuture<(FsOpenResult, DriverStatus)> {
        let this: &'static Vfs = unsafe { &*(self as *const Vfs) };

        this.open(FsOpenParams {
            flags: OpenFlagsMask::from(flags),
            path: path.clone(),
        })
        .into_ffi()
    }

    fn close_handle(&self, file_id: u64) -> FfiFuture<(FsCloseResult, DriverStatus)> {
        let this: &'static Vfs = unsafe { &*(self as *const Vfs) };

        this.close(FsCloseParams {
            fs_file_id: file_id,
        })
        .into_ffi()
    }

    fn read_at(
        &self,
        file_id: u64,
        offset: u64,
        len: u32,
    ) -> FfiFuture<(FsReadResult, DriverStatus)> {
        let this: &'static Vfs = unsafe { &*(self as *const Vfs) };

        this.read(FsReadParams {
            fs_file_id: file_id,
            offset,
            len: len as usize,
        })
        .into_ffi()
    }
    fn seek_handle(
        &self,
        file_id: u64,
        offset: i64,
        origin: FsSeekWhence,
    ) -> FfiFuture<(FsSeekResult, DriverStatus)> {
        let this: &'static Vfs = unsafe { &*(self as *const Vfs) };

        this.seek(FsSeekParams {
            fs_file_id: file_id,
            offset,
            origin,
        })
        .into_ffi()
    }
    fn write_at(
        &self,
        file_id: u64,
        offset: u64,
        data: &[u8],
    ) -> FfiFuture<(FsWriteResult, DriverStatus)> {
        let this: &'static Vfs = unsafe { &*(self as *const Vfs) };
        let data = data.to_vec();

        this.write(FsWriteParams {
            fs_file_id: file_id,
            offset,
            data,
        })
        .into_ffi()
    }

    fn flush_handle(&self, file_id: u64) -> FfiFuture<(FsFlushResult, DriverStatus)> {
        let this: &'static Vfs = unsafe { &*(self as *const Vfs) };

        this.flush(FsFlushParams {
            fs_file_id: file_id,
        })
        .into_ffi()
    }

    fn get_info(&self, file_id: u64) -> FfiFuture<(FsGetInfoResult, DriverStatus)> {
        let this: &'static Vfs = unsafe { &*(self as *const Vfs) };

        this.get_info(FsGetInfoParams {
            fs_file_id: file_id,
        })
        .into_ffi()
    }

    fn list_dir_path(&self, path: &Path) -> FfiFuture<(FsListDirResult, DriverStatus)> {
        let this: &'static Vfs = unsafe { &*(self as *const Vfs) };

        this.list_dir(FsListDirParams { path: path.clone() })
            .into_ffi()
    }

    fn make_dir_path(&self, path: &Path) -> FfiFuture<(FsCreateResult, DriverStatus)> {
        let this: &'static Vfs = unsafe { &*(self as *const Vfs) };

        this.create(FsCreateParams {
            path: path.clone(),
            dir: true,
            flags: OpenFlags::Create,
        })
        .into_ffi()
    }

    fn remove_dir_path(&self, _path: &Path) -> FfiFuture<(FsCreateResult, DriverStatus)> {
        async {
            (
                FsCreateResult {
                    error: Some(FileStatus::UnknownFail),
                },
                DriverStatus::Success,
            )
        }
        .into_ffi()
    }

    fn rename_path(&self, src: &Path, dst: &Path) -> FfiFuture<(FsRenameResult, DriverStatus)> {
        let this: &'static Vfs = unsafe { &*(self as *const Vfs) };

        this.rename(FsRenameParams {
            src: src.clone(),
            dst: dst.clone(),
        })
        .into_ffi()
    }

    fn delete_path(&self, _path: &Path) -> FfiFuture<(FsCreateResult, DriverStatus)> {
        async {
            (
                FsCreateResult {
                    error: Some(FileStatus::UnknownFail),
                },
                DriverStatus::Success,
            )
        }
        .into_ffi()
    }
}
