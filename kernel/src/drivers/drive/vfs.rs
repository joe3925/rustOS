use crate::drivers::pnp::manager::PNP_MANAGER;
use crate::println;
use alloc::string::ToString;
use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::hint::spin_loop;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicU64, Ordering};
use kernel_types::async_types::{AsyncRwLock, AsyncRwLockReadGuard, AsyncRwLockWriteGuard};
use kernel_types::fs::{Path, *};
use kernel_types::io::IoTarget;
use kernel_types::request::{
    Fs, FsAppend, FsClose, FsCreate, FsFlush, FsGetInfo, FsOpen, FsOperation, FsPayload, FsRead,
    FsReadDir, FsRename, FsSeek, FsSetLen, FsWrite, FsZeroRange, RequestHandle, TraversalPolicy,
};
use kernel_types::status::{DriverStatus, FileStatus};

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
    pub target: Option<IoTarget>,
}

/// Resolves labels to mount symlinks and forwards FsOps to FS drivers.
/// Keeps a VFS-handle -> FS-handle table.
pub struct Vfs {
    label_map: AsyncRwLock<BTreeMap<String, String>>,
    target_cache: AsyncRwLock<BTreeMap<String, IoTarget>>,
    next_vh: AtomicU64,
    handles: AsyncRwLock<BTreeMap<u64, VfsHandle>>,
}

impl Vfs {
    #[inline]
    fn blocking_read<'a, T>(&self, lock: &'a AsyncRwLock<T>) -> AsyncRwLockReadGuard<'a, T> {
        loop {
            if let Some(g) = lock.try_read() {
                return g;
            }
            spin_loop();
        }
    }

    #[inline]
    fn blocking_write<'a, T>(&self, lock: &'a AsyncRwLock<T>) -> AsyncRwLockWriteGuard<'a, T> {
        loop {
            if let Some(g) = lock.try_write() {
                return g;
            }
            spin_loop();
        }
    }

    pub fn new() -> Self {
        Self {
            label_map: AsyncRwLock::new(BTreeMap::new()),
            target_cache: AsyncRwLock::new(BTreeMap::new()),
            next_vh: AtomicU64::new(1),
            handles: AsyncRwLock::new(BTreeMap::new()),
        }
    }

    pub fn set_label(&self, label: String, mount_symlink: String) {
        let tgt = PNP_MANAGER.resolve_targetio_from_symlink(mount_symlink.clone());
        let mut map = self.blocking_write(&self.label_map);
        if let Some(old) = map.insert(label, mount_symlink.clone()) {
            // drop old map entry from target cache
            self.blocking_write(&self.target_cache).remove(&old);
        }
        drop(map);
        if let Some(tgt) = tgt {
            // mount_symlink is consumed here — no further clone needed
            self.blocking_write(&self.target_cache)
                .insert(mount_symlink, tgt);
        }
    }

    pub fn remove_label(&self, label: &str) {
        if let Some(old) = self.blocking_write(&self.label_map).remove(label) {
            self.blocking_write(&self.target_cache).remove(&old);
        }
    }

    pub async fn list_mounted_volumes(&self) -> (Vec<MountedVolume>, DriverStatus) {
        let labels = self.label_map.read().await;
        let mut out: Vec<MountedVolume> = Vec::with_capacity(labels.len());

        for (label, mount_symlink) in labels.iter() {
            let symlink = mount_symlink.clone();
            out.push(MountedVolume {
                label: label.clone(),
                object_name: symlink.clone(),
                mount_symlink: symlink,
            });
        }

        (out, DriverStatus::Success)
    }

    #[inline]
    fn alloc_vh(&self) -> u64 {
        let v = self.next_vh.fetch_add(1, Ordering::AcqRel);
        if v == 0 { 1 } else { v }
    }

    fn resolve_path(&self, user_path: Path) -> Result<(String, Path), FileStatus> {
        if user_path.symlink.is_none() && user_path.components.is_empty() {
            return Err(FileStatus::BadPath);
        }

        // Resolve drive letter to symlink
        if let Some(d) = user_path.symlink {
            let label_buf: [u8; 2] = [d as u8, b':'];
            // SAFETY: d is a validated ASCII drive letter, so [d, ':'] is valid UTF-8
            let label_str = unsafe { core::str::from_utf8_unchecked(&label_buf) };
            let symlink = match self.blocking_read(&self.label_map).get(label_str) {
                Some(s) => s.clone(),
                None => {
                    alloc::format!("\\GLOBAL\\StorageDevices\\{}", d)
                }
            };
            // Build the fs_path from components (without drive)
            let fs_path = user_path.with_symlink(None);
            return Ok((symlink, fs_path));
        }

        Err(FileStatus::BadPath)
    }

    fn resolve_target(&self, symlink: &str) -> Option<IoTarget> {
        if let Some(t) = self.blocking_read(&self.target_cache).get(symlink).cloned() {
            return Some(t);
        }
        let tgt = PNP_MANAGER.resolve_targetio_from_symlink_ref(symlink)?;
        self.blocking_write(&self.target_cache)
            .insert(symlink.to_string(), tgt.clone());
        Some(tgt)
    }

    async fn call_fs<'data, O>(
        &self,
        volume_symlink: &str,
        target: Option<IoTarget>,
        params: O::Params<'data>,
    ) -> Result<O::Result, DriverStatus>
    where
        O: FsOperation + 'data,
        Fs<'data, O>: kernel_routing::RoutedRequest,
    {
        let mut request_handle = RequestHandle::new(Fs::<O> {
            payload: FsPayload {
                params,
                result: None,
                _marker: PhantomData,
            },
        });
        request_handle.set_traversal_policy(TraversalPolicy::ForwardLower);

        let status = {
            if let Some(tgt) = target {
                PNP_MANAGER.send_request(tgt, &mut request_handle).await
            } else {
                PNP_MANAGER
                    .send_request_via_symlink(volume_symlink.to_string(), &mut request_handle)
                    .await
            }
        };
        if status != DriverStatus::Success {
            println!("Send request failed with status: {}", status);
            return Err(status);
        }

        request_handle
            .write()
            .body
            .payload
            .result
            .take()
            .ok_or(DriverStatus::InvalidParameter)
    }
    pub async fn open(&self, p: FsOpenParams) -> (FsOpenResult, DriverStatus) {
        let (symlink, fs_path) = match self.resolve_path(p.path) {
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
                );
            }
        };

        let call_open = async |this: &Self,
                               link: &String,
                               path: Path,
                               flags: OpenFlagsMask,
                               write_through: bool| {
            let tgt = this.resolve_target(link);
            let inner = FsOpenParams {
                flags,
                write_through,
                path,
            };
            match this.call_fs::<FsOpen>(link, tgt, inner).await {
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
            let tgt = self.resolve_target(&symlink);
            let cres: FsCreateResult =
                match self.call_fs::<FsCreate>(&symlink, tgt.clone(), creq).await {
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
                        );
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

            let (inner_res, st) =
                call_open(self, &symlink, fs_path, p.flags, p.write_through).await;
            if matches!(inner_res.error, Some(e) if e != FileStatus::Success) {
                return (inner_res, st);
            }
            let tgt = self.resolve_target(&symlink);
            let vhid = self.next_vh.fetch_add(1, Ordering::AcqRel).max(1);
            self.handles.write().await.insert(
                vhid,
                VfsHandle {
                    volume_symlink: symlink,
                    inner_id: inner_res.fs_file_id,
                    is_dir: inner_res.is_dir,
                    target: tgt,
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
            let (try_open, st) =
                call_open(self, &symlink, fs_path.clone(), p.flags, p.write_through).await;
            if st != DriverStatus::Success {
                return (try_open, st);
            }
            if try_open.error.is_none() {
                let tgt = self.resolve_target(&symlink);
                let vhid = self.next_vh.fetch_add(1, Ordering::AcqRel).max(1);
                self.handles.write().await.insert(
                    vhid,
                    VfsHandle {
                        volume_symlink: symlink,
                        inner_id: try_open.fs_file_id,
                        is_dir: try_open.is_dir,
                        target: tgt,
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
                let tgt = self.resolve_target(&symlink);
                let cres: FsCreateResult =
                    match self.call_fs::<FsCreate>(&symlink, tgt.clone(), creq).await {
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
                            );
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

                let (inner_res, st2) =
                    call_open(self, &symlink, fs_path, p.flags, p.write_through).await;
                if matches!(inner_res.error, Some(e) if e != FileStatus::Success) {
                    return (inner_res, st2);
                }
                let tgt = self.resolve_target(&symlink);
                let vhid = self.next_vh.fetch_add(1, Ordering::AcqRel).max(1);
                self.handles.write().await.insert(
                    vhid,
                    VfsHandle {
                        volume_symlink: symlink,
                        inner_id: inner_res.fs_file_id,
                        is_dir: inner_res.is_dir,
                        target: tgt,
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
            let (inner_res, st) =
                call_open(self, &symlink, fs_path, p.flags, p.write_through).await;
            if matches!(inner_res.error, Some(e) if e != FileStatus::Success) {
                return (inner_res, st);
            }
            let tgt = self.resolve_target(&symlink);
            let vhid = self.next_vh.fetch_add(1, Ordering::AcqRel).max(1);
            self.handles.write().await.insert(
                vhid,
                VfsHandle {
                    volume_symlink: symlink,
                    inner_id: inner_res.fs_file_id,
                    is_dir: inner_res.is_dir,
                    target: tgt,
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
        let Some(h) = self.handles.write().await.remove(&p.fs_file_id) else {
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
        let res: Result<FsCloseResult, DriverStatus> = self
            .call_fs::<FsClose>(&h.volume_symlink, h.target.clone(), inner)
            .await;
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

    pub async fn read<'a>(&self, mut p: FsReadParams<'a>) -> (FsReadResult, DriverStatus) {
        let (target, inner_id, symlink_ptr) = {
            let binding = self.handles.read().await;
            if let Some(h) = binding.get(&p.fs_file_id) {
                (
                    h.target.clone(),
                    h.inner_id,
                    h.volume_symlink.as_str() as *const str,
                )
            } else {
                return (
                    FsReadResult {
                        bytes_read: 0,
                        error: Some(FileStatus::PathNotFound),
                    },
                    DriverStatus::Success,
                );
            }
        };

        p.fs_file_id = inner_id;

        let symlink: &str = if target.is_some() {
            ""
        } else {
            unsafe { &*symlink_ptr }
        };

        match self.call_fs::<FsRead>(symlink, target, p).await {
            Ok(r) => (r, DriverStatus::Success),
            Err(st) => (
                FsReadResult {
                    bytes_read: 0,
                    error: Some(FileStatus::UnknownFail),
                },
                st,
            ),
        }
    }

    pub async fn write<'a>(&self, mut p: FsWriteParams<'a>) -> (FsWriteResult, DriverStatus) {
        let (target, inner_id, symlink_ptr) = {
            let binding = self.handles.read().await;
            if let Some(h) = binding.get(&p.fs_file_id) {
                (
                    h.target.clone(),
                    h.inner_id,
                    h.volume_symlink.as_str() as *const str,
                )
            } else {
                return (
                    FsWriteResult {
                        written: 0,
                        error: Some(FileStatus::PathNotFound),
                    },
                    DriverStatus::Success,
                );
            }
        };

        p.fs_file_id = inner_id;

        let symlink: &str = if target.is_some() {
            ""
        } else {
            unsafe { &*symlink_ptr }
        };

        match self.call_fs::<FsWrite>(symlink, target, p).await {
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
        let (target, inner_id, symlink_ptr) = {
            let binding = self.handles.read().await;
            if let Some(h) = binding.get(&p.fs_file_id) {
                (
                    h.target.clone(),
                    h.inner_id,
                    h.volume_symlink.as_str() as *const str,
                )
            } else {
                return (
                    FsSeekResult {
                        pos: 0,
                        error: Some(FileStatus::PathNotFound),
                    },
                    DriverStatus::Success,
                );
            }
        };

        p.fs_file_id = inner_id;

        let symlink: &str = if target.is_some() {
            ""
        } else {
            unsafe { &*symlink_ptr }
        };

        match self.call_fs::<FsSeek>(symlink, target, p).await {
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
        let h = {
            let binding = self.handles.read().await;
            binding.get(&p.fs_file_id).cloned()
        };
        let Some(h) = h else {
            return (
                FsFlushResult {
                    error: Some(FileStatus::PathNotFound),
                },
                DriverStatus::Success,
            );
        };
        p.fs_file_id = h.inner_id;
        match self
            .call_fs::<FsFlush>(&h.volume_symlink, h.target.clone(), p)
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
        let h = {
            let binding = self.handles.read().await;
            binding.get(&p.fs_file_id).cloned()
        };
        let Some(h) = h else {
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
            .call_fs::<FsGetInfo>(&h.volume_symlink, h.target.clone(), p)
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
        let (symlink, fs_path) = match self.resolve_path(p.path) {
            Ok(v) => v,
            Err(e) => return (FsCreateResult { error: Some(e) }, DriverStatus::Success),
        };
        p.path = fs_path;
        match self
            .call_fs::<FsCreate>(&symlink, self.resolve_target(&symlink), p)
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
        let (src_symlink, src_rel) = match self.resolve_path(p.src) {
            Ok(v) => v,
            Err(e) => return (FsRenameResult { error: Some(e) }, DriverStatus::Success),
        };
        let (dst_symlink, dst_rel) = match self.resolve_path(p.dst) {
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
            .call_fs::<FsRename>(&src_symlink, self.resolve_target(&src_symlink), p)
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
        let (symlink, fs_path) = match self.resolve_path(p.path) {
            Ok(v) => v,
            Err(e) => {
                return (
                    FsListDirResult {
                        names: None,
                        error: Some(e),
                    },
                    DriverStatus::Success,
                );
            }
        };
        p.path = fs_path;
        match self
            .call_fs::<FsReadDir>(&symlink, self.resolve_target(&symlink), p)
            .await
        {
            Ok(r) => (r, DriverStatus::Success),
            Err(st) => (
                FsListDirResult {
                    names: None,
                    error: Some(FileStatus::UnknownFail),
                },
                st,
            ),
        }
    }

    pub async fn set_len(&self, mut p: FsSetLenParams) -> (FsSetLenResult, DriverStatus) {
        let h = {
            let binding = self.handles.read().await;
            binding.get(&p.fs_file_id).cloned()
        };
        let Some(h) = h else {
            return (
                FsSetLenResult {
                    error: Some(FileStatus::PathNotFound),
                },
                DriverStatus::Success,
            );
        };
        p.fs_file_id = h.inner_id;
        match self
            .call_fs::<FsSetLen>(&h.volume_symlink, h.target.clone(), p)
            .await
        {
            Ok(r) => (r, DriverStatus::Success),
            Err(st) => (
                FsSetLenResult {
                    error: Some(FileStatus::UnknownFail),
                },
                st,
            ),
        }
    }
    pub async fn append<'a>(&self, mut p: FsAppendParams<'a>) -> (FsAppendResult, DriverStatus) {
        let (target, inner_id, symlink) = {
            let binding = self.handles.read().await;
            if let Some(h) = binding.get(&p.fs_file_id) {
                (h.target.clone(), h.inner_id, h.volume_symlink.clone())
            } else {
                return (
                    FsAppendResult {
                        written: 0,
                        new_size: 0,
                        error: Some(FileStatus::PathNotFound),
                    },
                    DriverStatus::Success,
                );
            }
        };

        p.fs_file_id = inner_id;

        let symlink_ref: &str = if target.is_some() { "" } else { &symlink };

        match self.call_fs::<FsAppend>(symlink_ref, target, p).await {
            Ok(r) => (r, DriverStatus::Success),
            Err(st) => (
                FsAppendResult {
                    written: 0,
                    new_size: 0,
                    error: Some(FileStatus::UnknownFail),
                },
                st,
            ),
        }
    }

    pub async fn zero_range(&self, mut p: FsZeroRangeParams) -> (FsZeroRangeResult, DriverStatus) {
        let h = {
            let binding = self.handles.read().await;
            binding.get(&p.fs_file_id).cloned()
        };
        let Some(h) = h else {
            return (
                FsZeroRangeResult {
                    error: Some(FileStatus::PathNotFound),
                },
                DriverStatus::Success,
            );
        };
        p.fs_file_id = h.inner_id;
        match self
            .call_fs::<FsZeroRange>(&h.volume_symlink, h.target.clone(), p)
            .await
        {
            Ok(r) => (r, DriverStatus::Success),
            Err(st) => (
                FsZeroRangeResult {
                    error: Some(FileStatus::UnknownFail),
                },
                st,
            ),
        }
    }
}
