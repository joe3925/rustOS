use crate::drivers::pnp::manager::PNP_MANAGER;
use crate::println;
use alloc::string::ToString;
use alloc::{collections::BTreeMap, format, string::String, vec::Vec};
use core::hint::spin_loop;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicU64, Ordering};
use kernel_types::async_types::{AsyncRwLock, AsyncRwLockReadGuard, AsyncRwLockWriteGuard};
use kernel_types::error::{
    DriverErrorKind, ErrorKind, FileErrorKind, KernelError, ResultErrorContext,
};
use kernel_types::fs::{Path, *};
use kernel_types::io::IoTarget;
use kernel_types::request::{
    Fs, FsAppend, FsClose, FsCreate, FsFlush, FsGetInfo, FsOpen, FsOperation, FsPayload, FsRead,
    FsReadDir, FsRename, FsSeek, FsSetLen, FsWrite, FsZeroRange,
};

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
            // mount_symlink is consumed here â€” no further clone needed
            self.blocking_write(&self.target_cache)
                .insert(mount_symlink, tgt);
        }
    }

    pub fn remove_label(&self, label: &str) {
        if let Some(old) = self.blocking_write(&self.label_map).remove(label) {
            self.blocking_write(&self.target_cache).remove(&old);
        }
    }

    pub async fn list_mounted_volumes(&self) -> Vec<MountedVolume> {
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

        out
    }

    #[inline]
    fn alloc_vh(&self) -> u64 {
        let v = self.next_vh.fetch_add(1, Ordering::AcqRel);
        if v == 0 { 1 } else { v }
    }

    fn resolve_path(&self, user_path: Path) -> Result<(String, Path), FileErrorKind> {
        if user_path.symlink.is_none() && user_path.components.is_empty() {
            return Err(FileErrorKind::BadPath);
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

        Err(FileErrorKind::BadPath)
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
    ) -> Result<O::Result, KernelError>
    where
        O: FsOperation + 'data,
        Fs<'data, O>: kernel_routing::IoRequest,
    {
        let mut request_handle = Fs::<O> {
            payload: FsPayload {
                params,
                result: None,
                _marker: PhantomData,
            },
        };
        let target = match target {
            Some(target) => target,
            None => PNP_MANAGER
                .resolve_targetio_from_symlink_ref(volume_symlink)
                .ok_or_else(|| {
                    crate::error::error_with_message(
                        DriverErrorKind::NoSuchDevice,
                        format_args!("filesystem target `{volume_symlink}` was not found"),
                    )
                })?,
        };
        kernel_routing::io::send_down_stack(target, &mut request_handle)
            .await
            .with_context(|| format!("forwarding filesystem request to `{volume_symlink}`"))?;

        request_handle.payload.result.take().ok_or_else(|| {
            crate::error::error_with_message(
                DriverErrorKind::InvalidParameter,
                format_args!("filesystem driver for `{volume_symlink}` completed without a result"),
            )
        })
    }
    fn file_error(kind: FileErrorKind) -> KernelError {
        crate::error::error(kind)
    }

    async fn handle(&self, file_id: u64) -> Result<VfsHandle, KernelError> {
        self.handles
            .read()
            .await
            .get(&file_id)
            .cloned()
            .ok_or_else(|| Self::file_error(FileErrorKind::PathNotFound))
    }

    pub async fn open(&self, p: FsOpenParams) -> Result<FsOpenResult, KernelError> {
        let (symlink, fs_path) = self.resolve_path(p.path).map_err(Self::file_error)?;
        let target = self.resolve_target(&symlink);

        if p.flags.contains(OpenFlags::CreateNew) {
            let created = self
                .call_fs::<FsCreate>(
                    &symlink,
                    target.clone(),
                    FsCreateParams {
                        path: fs_path.clone(),
                        dir: false,
                        flags: OpenFlags::CreateNew,
                    },
                )
                .await
                .with_context(|| format!("creating `{fs_path:?}` with create-new semantics"))?;
            if let Some(error) = created.error {
                return Ok(FsOpenResult {
                    fs_file_id: 0,
                    is_dir: false,
                    size: 0,
                    error: Some(error),
                });
            }
        }

        let mut opened = self
            .call_fs::<FsOpen>(
                &symlink,
                target.clone(),
                FsOpenParams {
                    path: fs_path.clone(),
                    flags: p.flags,
                    write_through: p.write_through,
                },
            )
            .await
            .with_context(|| format!("opening `{fs_path:?}`"))?;

        if p.flags.contains(OpenFlags::Create)
            && matches!(
                opened.error.as_ref().map(KernelError::kind),
                Some(ErrorKind::File(FileErrorKind::PathNotFound))
            )
        {
            let created = self
                .call_fs::<FsCreate>(
                    &symlink,
                    target.clone(),
                    FsCreateParams {
                        path: fs_path.clone(),
                        dir: false,
                        flags: OpenFlags::Create,
                    },
                )
                .await
                .with_context(|| format!("creating missing file `{fs_path:?}`"))?;
            if let Some(error) = created.error {
                opened.error = Some(error);
                return Ok(opened);
            }
            opened = self
                .call_fs::<FsOpen>(
                    &symlink,
                    target.clone(),
                    FsOpenParams {
                        path: fs_path.clone(),
                        flags: p.flags,
                        write_through: p.write_through,
                    },
                )
                .await
                .with_context(|| format!("opening newly created file `{fs_path:?}`"))?;
        }

        if opened.error.is_some() {
            return Ok(opened);
        }

        let vfs_id = self.alloc_vh();
        self.handles.write().await.insert(
            vfs_id,
            VfsHandle {
                volume_symlink: symlink,
                inner_id: opened.fs_file_id,
                is_dir: opened.is_dir,
                target,
            },
        );
        opened.fs_file_id = vfs_id;
        Ok(opened)
    }

    pub async fn close(&self, p: FsCloseParams) -> Result<FsCloseResult, KernelError> {
        let handle = self
            .handles
            .write()
            .await
            .remove(&p.fs_file_id)
            .ok_or_else(|| Self::file_error(FileErrorKind::PathNotFound))?;
        self.call_fs::<FsClose>(
            &handle.volume_symlink,
            handle.target,
            FsCloseParams {
                fs_file_id: handle.inner_id,
            },
        )
        .await
        .with_context(|| format!("closing VFS handle {}", p.fs_file_id))
    }

    pub async fn read<'a>(&self, mut p: FsReadParams<'a>) -> Result<FsReadResult, KernelError> {
        if !p
            .buffer
            .as_ref()
            .is_some_and(|buffer| buffer.is_cpu_accessible())
        {
            return Ok(FsReadResult {
                bytes_read: 0,
                error: Some(Self::file_error(FileErrorKind::NoBuffer)),
            });
        }
        let handle = self.handle(p.fs_file_id).await?;
        p.fs_file_id = handle.inner_id;
        self.call_fs::<FsRead>(&handle.volume_symlink, handle.target, p)
            .await
            .with_context(|| format!("reading VFS handle {}", handle.inner_id))
    }

    pub async fn write<'a>(&self, mut p: FsWriteParams<'a>) -> Result<FsWriteResult, KernelError> {
        if !p
            .buffer
            .as_ref()
            .is_some_and(|buffer| buffer.is_cpu_accessible())
        {
            return Ok(FsWriteResult {
                written: 0,
                error: Some(Self::file_error(FileErrorKind::NoBuffer)),
            });
        }
        let handle = self.handle(p.fs_file_id).await?;
        p.fs_file_id = handle.inner_id;
        self.call_fs::<FsWrite>(&handle.volume_symlink, handle.target, p)
            .await
            .with_context(|| format!("writing VFS handle {}", handle.inner_id))
    }

    pub async fn seek(&self, mut p: FsSeekParams) -> Result<FsSeekResult, KernelError> {
        let handle = self.handle(p.fs_file_id).await?;
        p.fs_file_id = handle.inner_id;
        self.call_fs::<FsSeek>(&handle.volume_symlink, handle.target, p)
            .await
            .with_context(|| format!("seeking VFS handle {}", handle.inner_id))
    }

    pub async fn flush(&self, mut p: FsFlushParams) -> Result<FsFlushResult, KernelError> {
        let handle = self.handle(p.fs_file_id).await?;
        p.fs_file_id = handle.inner_id;
        self.call_fs::<FsFlush>(&handle.volume_symlink, handle.target, p)
            .await
            .with_context(|| format!("flushing VFS handle {}", handle.inner_id))
    }

    pub async fn get_info(&self, mut p: FsGetInfoParams) -> Result<FsGetInfoResult, KernelError> {
        let handle = self.handle(p.fs_file_id).await?;
        p.fs_file_id = handle.inner_id;
        self.call_fs::<FsGetInfo>(&handle.volume_symlink, handle.target, p)
            .await
            .with_context(|| format!("querying VFS handle {}", handle.inner_id))
    }

    pub async fn create(&self, mut p: FsCreateParams) -> Result<FsCreateResult, KernelError> {
        let (symlink, path) = self.resolve_path(p.path).map_err(Self::file_error)?;
        p.path = path.clone();
        self.call_fs::<FsCreate>(&symlink, self.resolve_target(&symlink), p)
            .await
            .with_context(|| format!("creating `{path:?}`"))
    }

    pub async fn rename(&self, mut p: FsRenameParams) -> Result<FsRenameResult, KernelError> {
        let (source_symlink, source) = self.resolve_path(p.src).map_err(Self::file_error)?;
        let (destination_symlink, destination) =
            self.resolve_path(p.dst).map_err(Self::file_error)?;
        if source_symlink != destination_symlink {
            return Ok(FsRenameResult {
                error: Some(crate::error::error_with_message(
                    FileErrorKind::BadPath,
                    format_args!("cross-volume rename is not supported"),
                )),
            });
        }
        p.src = source.clone();
        p.dst = destination.clone();
        self.call_fs::<FsRename>(&source_symlink, self.resolve_target(&source_symlink), p)
            .await
            .with_context(|| format!("renaming `{source:?}` to `{destination:?}`"))
    }

    pub async fn list_dir(&self, mut p: FsListDirParams) -> Result<FsListDirResult, KernelError> {
        let (symlink, path) = self.resolve_path(p.path).map_err(Self::file_error)?;
        p.path = path.clone();
        self.call_fs::<FsReadDir>(&symlink, self.resolve_target(&symlink), p)
            .await
            .with_context(|| format!("listing directory `{path:?}`"))
    }

    pub async fn set_len(&self, mut p: FsSetLenParams) -> Result<FsSetLenResult, KernelError> {
        let handle = self.handle(p.fs_file_id).await?;
        p.fs_file_id = handle.inner_id;
        self.call_fs::<FsSetLen>(&handle.volume_symlink, handle.target, p)
            .await
            .with_context(|| format!("resizing VFS handle {}", handle.inner_id))
    }

    pub async fn append<'a>(
        &self,
        mut p: FsAppendParams<'a>,
    ) -> Result<FsAppendResult, KernelError> {
        if !p
            .buffer
            .as_ref()
            .is_some_and(|buffer| buffer.is_cpu_accessible())
        {
            return Ok(FsAppendResult {
                written: 0,
                new_size: 0,
                error: Some(Self::file_error(FileErrorKind::NoBuffer)),
            });
        }
        let handle = self.handle(p.fs_file_id).await?;
        p.fs_file_id = handle.inner_id;
        self.call_fs::<FsAppend>(&handle.volume_symlink, handle.target, p)
            .await
            .with_context(|| format!("appending to VFS handle {}", handle.inner_id))
    }

    pub async fn zero_range(
        &self,
        mut p: FsZeroRangeParams,
    ) -> Result<FsZeroRangeResult, KernelError> {
        let handle = self.handle(p.fs_file_id).await?;
        p.fs_file_id = handle.inner_id;
        self.call_fs::<FsZeroRange>(&handle.volume_symlink, handle.target, p)
            .await
            .with_context(|| format!("zeroing range in VFS handle {}", handle.inner_id))
    }
}
