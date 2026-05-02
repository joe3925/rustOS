use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use fatfs::{
    CachedFileState, Dir as FatDirT, Error as FatError, FileSystem as FatFsT, IoBase,
    LossyOemCpConverter, NullTimeProvider, Read, SeekFrom, Write,
};
use kernel_api::kernel_types::fs::Path;
use kernel_api::println;
use spin::RwLock;

use kernel_api::device::DeviceObject;
use kernel_api::kernel_types::async_types::AsyncMutex;
use kernel_api::kernel_types::io::IoTarget;
use kernel_api::kernel_types::request::RequestData;
use kernel_api::pnp::{DriverStep, pnp_send_request};
use kernel_api::request::{RequestHandle, RequestType, TraversalPolicy};
use kernel_api::status::{DriverStatus, FileStatus};
use kernel_api::{
    fs::{
        FileAttribute, FsAppendParams, FsAppendResult, FsCloseParams, FsCloseResult,
        FsCreateParams, FsCreateResult, FsFlushParams, FsFlushResult, FsGetInfoParams,
        FsGetInfoResult, FsListDirParams, FsListDirResult, FsOp, FsOpenParams, FsOpenResult,
        FsReadParams, FsReadResult, FsRenameParams, FsRenameResult, FsSeekParams, FsSeekResult,
        FsSeekWhence, FsSetLenParams, FsSetLenResult, FsWriteParams, FsWriteResult,
        FsZeroRangeParams, FsZeroRangeResult,
    },
    request_handler,
};

use crate::block_dev::{BlockDev, flush_owner, flush_owner_blocking};
use crate::control::ext_mut;

type FatDev = BlockDev;
type TP = NullTimeProvider;
type OCC = LossyOemCpConverter;

type Fs = FatFsT<FatDev, TP, OCC>;
type FatFile<'a> = fatfs::File<'a, FatDev, TP, OCC>;
type FatDir<'a> = FatDirT<'a, FatDev, TP, OCC>;
type FsError = FatError<<FatDev as IoBase>::Error>;

pub(crate) const METADATA_OWNER_ID: u64 = 1;
pub(crate) const FIRST_FILE_OWNER_ID: u64 = METADATA_OWNER_ID + 1;
const SET_LEN_ZERO_CHUNK: usize = 64 * 1024;

#[repr(C)]
pub struct VolCtrlDevExt {
    pub fs: Arc<AsyncMutex<Fs>>,
    pub(crate) next_id: AtomicU64,
    pub(crate) table: RwLock<BTreeMap<u64, FileCtx>>,
    pub(crate) volume_target: IoTarget,
    pub should_flush: Arc<AtomicBool>,
    /// Owner tag of the requested pending flush (0 = no targeted owner pending).
    pub pending_flush_owner: Arc<AtomicU64>,
    /// Whether the pending flush must block until the cache confirms writeback.
    pub pending_flush_block: Arc<AtomicBool>,
    /// Current owner tag — shared with BlockDev, set once before each FS op.
    pub current_owner: Arc<AtomicU64>,
}

pub struct FileCtx {
    path: Arc<Path>,
    is_dir: bool,
    pos: u64,
    size: u64,
    cached: Option<CachedFileState>,
}

fn map_fatfs_err(e: &FsError) -> FileStatus {
    match e {
        fatfs::Error::NotFound => FileStatus::PathNotFound,
        fatfs::Error::AlreadyExists => FileStatus::FileAlreadyExist,
        fatfs::Error::InvalidInput => FileStatus::BadPath,
        fatfs::Error::NotEnoughSpace => FileStatus::NoSpace,
        fatfs::Error::CorruptedFileSystem => FileStatus::CorruptFilesystem,
        fatfs::Error::FileTooLarge => FileStatus::FileTooLarge,
        e => {
            println!("Mapping {:#?} to UnknownFail", e);
            FileStatus::UnknownFail
        }
    }
}

async fn create_entry(fs: &mut Fs, path: &Path, dir: bool) -> Result<(), FsError> {
    let path_str = path.as_str();
    if dir {
        let _ = fs.root_dir().create_dir(path_str).await?;
    } else {
        let mut file = fs.root_dir().create_file(path_str).await?;
        file.flush().await?;
    }
    Ok(())
}

async fn rename_entry(fs: &mut Fs, src: &Path, dst: &Path) -> Result<(), FsError> {
    let dst_dir = fs.root_dir();
    fs.root_dir()
        .rename(src.as_str(), &dst_dir, dst.as_str())
        .await
}

async fn list_names(fs: &mut Fs, path: &Path) -> Result<Vec<String>, FsError> {
    let dir: FatDir = fs.root_dir().open_dir(path.as_str()).await?;
    let mut out = Vec::new();
    let mut iter = dir.iter();
    while let Some(r) = iter.next().await {
        let e = r?;
        let name = e.file_name();
        out.push(name);
    }
    Ok(out)
}

async fn resize_file(file: &mut FatFile<'_>, new_size: u64) -> Result<(), FsError> {
    let old_size = file.seek(SeekFrom::End(0)).await?;
    // The resize will fail
    if new_size as u32 > u32::MAX {
        return Err(FsError::FileTooLarge);
    }
    if new_size <= old_size {
        file.seek(SeekFrom::Start(new_size)).await?;
        file.truncate().await?;
    } else {
        let zeros = vec![0u8; SET_LEN_ZERO_CHUNK];
        let mut remaining = new_size - old_size;
        while remaining != 0 {
            let take = remaining.min(zeros.len() as u64) as usize;
            file.write_all(&zeros[..take], fatfs::IoKind::Data).await?;
            remaining -= take as u64;
        }
    }
    file.flush().await?;
    Ok(())
}

fn next_file_id(vdx: &VolCtrlDevExt) -> u64 {
    loop {
        let id = vdx.next_id.fetch_add(1, Ordering::AcqRel);
        if id >= FIRST_FILE_OWNER_ID {
            return id;
        }
    }
}

fn take_file_ctx(vdx: &VolCtrlDevExt, fs_file_id: u64) -> Result<FileCtx, FileStatus> {
    vdx.table
        .write()
        .remove(&fs_file_id)
        .ok_or(FileStatus::PathNotFound)
}

fn restore_file_ctx(vdx: &VolCtrlDevExt, fs_file_id: u64, ctx: FileCtx) {
    vdx.table.write().insert(fs_file_id, ctx);
}

fn missing_cached_file_state(fs_file_id: u64) -> FileStatus {
    println!("Missing cached file state for fs_file_id {}", fs_file_id);
    FileStatus::UnknownFail
}

fn current_owner_for_op(op: FsOp, req: &mut RequestHandle<'_, '_>) -> Result<u64, DriverStatus> {
    match op {
        FsOp::Open | FsOp::Create | FsOp::ReadDir | FsOp::SetInfo | FsOp::Delete | FsOp::Rename => {
            Ok(METADATA_OWNER_ID)
        }
        FsOp::Close => req
            .data()
            .read_only()
            .view::<FsCloseParams>()
            .map(|p| p.fs_file_id)
            .ok_or(DriverStatus::InvalidParameter),
        FsOp::Read => req
            .data()
            .read_only()
            .view::<FsReadParams<'_>>()
            .map(|p| p.fs_file_id)
            .ok_or(DriverStatus::InvalidParameter),
        FsOp::Write => req
            .data()
            .read_only()
            .view::<FsWriteParams<'_>>()
            .map(|p| p.fs_file_id)
            .ok_or(DriverStatus::InvalidParameter),
        FsOp::Flush => req
            .data()
            .read_only()
            .view::<FsFlushParams>()
            .map(|p| p.fs_file_id)
            .ok_or(DriverStatus::InvalidParameter),
        FsOp::Seek => req
            .data()
            .read_only()
            .view::<FsSeekParams>()
            .map(|p| p.fs_file_id)
            .ok_or(DriverStatus::InvalidParameter),
        FsOp::GetInfo => req
            .data()
            .read_only()
            .view::<FsGetInfoParams>()
            .map(|p| p.fs_file_id)
            .ok_or(DriverStatus::InvalidParameter),
        FsOp::SetLen => req
            .data()
            .read_only()
            .view::<FsSetLenParams>()
            .map(|p| p.fs_file_id)
            .ok_or(DriverStatus::InvalidParameter),
        FsOp::Append => req
            .data()
            .read_only()
            .view::<FsAppendParams<'_>>()
            .map(|p| p.fs_file_id)
            .ok_or(DriverStatus::InvalidParameter),
        FsOp::ZeroRange => req
            .data()
            .read_only()
            .view::<FsZeroRangeParams>()
            .map(|p| p.fs_file_id)
            .ok_or(DriverStatus::InvalidParameter),
    }
}

async fn execute_fs_work(
    dev: &Arc<DeviceObject>,
    fs_arc: &Arc<AsyncMutex<Fs>>,
    req: &mut RequestHandle<'_, '_>,
) -> DriverStatus {
    let vdx = ext_mut::<VolCtrlDevExt>(dev);
    let mut fs = fs_arc.lock().await;

    let op = match req.read().kind {
        RequestType::Fs(op) => op,
        RequestType::DeviceControl(_) => return DriverStatus::NotImplemented,
        _ => return DriverStatus::InvalidParameter,
    };

    let owner = match current_owner_for_op(op, req) {
        Ok(owner) => owner,
        Err(status) => return status,
    };
    vdx.current_owner.store(owner, Ordering::Release);

    match op {
        FsOp::Open => {
            let result = {
                let data = req.data().read_only();

                let Some(p) = data.view::<FsOpenParams>() else {
                    return DriverStatus::InvalidParameter;
                };
                let _ = (p.flags, p.write_through); // driver uses path only; flags handled by VFS
                let path = &p.path;
                let path_str = path.as_str();
                let root = fs.root_dir();
                let open_res = match root.open_file(path_str).await {
                    Ok(mut f) => {
                        async {
                            let end = f.seek(SeekFrom::End(0)).await?;
                            f.seek(SeekFrom::Start(0)).await?;
                            f.flush().await?;
                            Ok((false, end, Some(f.into_cached_state())))
                        }
                        .await
                    }
                    Err(FatError::NotFound) | Err(FatError::InvalidInput) => {
                        match root.open_dir(path_str).await {
                            Ok(_d) => Ok((true, 0, None)),
                            Err(e) => Err(e),
                        }
                    }
                    Err(e) => Err(e),
                };
                match open_res {
                    Ok((is_dir, size, cached)) => {
                        let id = next_file_id(&vdx);
                        {
                            let mut tbl = vdx.table.write();
                            tbl.insert(
                                id,
                                FileCtx {
                                    path: Arc::new(path.clone()),
                                    is_dir,
                                    pos: 0,
                                    size,
                                    cached,
                                },
                            );
                        }
                        FsOpenResult {
                            fs_file_id: id,
                            is_dir,
                            size,
                            error: None,
                        }
                    }
                    Err(e) => FsOpenResult {
                        fs_file_id: 0,
                        is_dir: false,
                        size: 0,
                        error: Some(map_fatfs_err(&e)),
                    },
                }
            };

            req.write().set_data_t(result);
            DriverStatus::Success
        }

        FsOp::Close => {
            let fs_file_id = {
                let data = req.data().read_only();

                let Some(p) = data.view::<FsCloseParams>() else {
                    return DriverStatus::InvalidParameter;
                };
                p.fs_file_id
            };
            let removed_ctx = { vdx.table.write().remove(&fs_file_id) };
            let err = match removed_ctx {
                None => Some(FileStatus::PathNotFound),
                Some(ctx) if ctx.is_dir => None,
                Some(mut ctx) => match ctx.cached.take() {
                    Some(state) => {
                        let mut file = state.into_file(&*fs);
                        file.flush().await.err().map(|e| map_fatfs_err(&e))
                    }
                    None => Some(missing_cached_file_state(fs_file_id)),
                },
            };
            req.write().set_data_t(FsCloseResult { error: err });
            DriverStatus::Success
        }

        FsOp::Read => {
            // Extract the buffer pointer from the borrowed params without moving them.
            let (fs_file_id, offset, buf_ptr, buf_len) = {
                let data = req.data().read_only();

                let Some(p) = data.view::<FsReadParams<'_>>() else {
                    return DriverStatus::InvalidParameter;
                };
                (
                    p.fs_file_id,
                    p.offset,
                    p.buf.as_ptr() as *mut u8,
                    p.buf.len(),
                )
            };
            // SAFETY: ptr came from an &'caller mut [u8] that remains valid until the
            // BorrowedHandle drops after spawn_blocking returns.
            let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr, buf_len) };

            let result: Result<usize, FileStatus> = {
                match take_file_ctx(&vdx, fs_file_id) {
                    Err(e) => Err(e),
                    Ok(ctx) if ctx.is_dir => {
                        restore_file_ctx(&vdx, fs_file_id, ctx);
                        Err(FileStatus::AccessDenied)
                    }
                    Ok(mut ctx) => match ctx.cached.take() {
                        None => {
                            let err = missing_cached_file_state(fs_file_id);
                            restore_file_ctx(&vdx, fs_file_id, ctx);
                            Err(err)
                        }
                        Some(state) => {
                            let mut file = state.into_file(&*fs);
                            let res = if let Err(e) = file.seek(SeekFrom::Start(offset)).await {
                                Err(map_fatfs_err(&e))
                            } else {
                                match file.read(buf, fatfs::IoKind::Data).await {
                                    Ok(n) => Ok(n),
                                    Err(e) => Err(map_fatfs_err(&e)),
                                }
                            };
                            let res = match file.flush().await {
                                Ok(_) => res,
                                Err(e) => Err(map_fatfs_err(&e)),
                            };
                            ctx.cached = Some(file.into_cached_state());
                            restore_file_ctx(&vdx, fs_file_id, ctx);
                            res
                        }
                    },
                }
            };

            let res = match result {
                Ok(n) => {
                    let new_pos = offset.saturating_add(n as u64);
                    if let Some(ctx) = vdx.table.write().get_mut(&fs_file_id) {
                        ctx.pos = new_pos;
                    }
                    FsReadResult {
                        bytes_read: n,
                        error: None,
                    }
                }
                Err(e) => FsReadResult {
                    bytes_read: 0,
                    error: Some(e),
                },
            };
            req.write().set_data_t(res);
            DriverStatus::Success
        }

        FsOp::Write => {
            let (fs_file_id, offset, write_through, data_ptr, data_len) = {
                let data = req.data().read_only();

                let Some(p) = data.view::<FsWriteParams<'_>>() else {
                    return DriverStatus::InvalidParameter;
                };
                (
                    p.fs_file_id,
                    p.offset,
                    p.write_through,
                    p.data.as_ptr(),
                    p.data.len(),
                )
            };
            // SAFETY: ptr came from an &'caller [u8] that remains valid until the
            // BorrowedHandle drops after spawn_blocking returns.
            let data = unsafe { core::slice::from_raw_parts(data_ptr, data_len) };

            let write_res: Result<usize, FileStatus> = {
                match take_file_ctx(&vdx, fs_file_id) {
                    Err(e) => Err(e),
                    Ok(ctx) if ctx.is_dir => {
                        restore_file_ctx(&vdx, fs_file_id, ctx);
                        Err(FileStatus::AccessDenied)
                    }
                    Ok(mut ctx) => match ctx.cached.take() {
                        None => {
                            let err = missing_cached_file_state(fs_file_id);
                            restore_file_ctx(&vdx, fs_file_id, ctx);
                            Err(err)
                        }
                        Some(state) => {
                            let mut file = state.into_file(&*fs);
                            let n = data.len();
                            let res = if let Err(e) = file.seek(SeekFrom::Start(offset)).await {
                                Err(map_fatfs_err(&e))
                            } else {
                                match file.write_all(data, fatfs::IoKind::Data).await {
                                    Ok(()) => {
                                        if write_through {
                                            flush_owner_blocking(&vdx, fs_file_id);
                                        }
                                        Ok(n)
                                    }
                                    Err(e) => Err(map_fatfs_err(&e)),
                                }
                            };
                            let res = match file.flush().await {
                                Ok(_) => res,
                                Err(e) => Err(map_fatfs_err(&e)),
                            };
                            ctx.cached = Some(file.into_cached_state());
                            restore_file_ctx(&vdx, fs_file_id, ctx);
                            res
                        }
                    },
                }
            };

            if let Ok(written) = write_res {
                let mut tbl = vdx.table.write();
                if let Some(ctx) = tbl.get_mut(&fs_file_id) {
                    let end = offset.saturating_add(written as u64);
                    ctx.pos = end;
                    if end > ctx.size {
                        ctx.size = end;
                    }
                }
            }

            let res = match write_res {
                Ok(written) => FsWriteResult {
                    written,
                    error: None,
                },
                Err(e) => FsWriteResult {
                    written: 0,
                    error: Some(e),
                },
            };
            req.write().set_data_t(res);
            DriverStatus::Success
        }

        FsOp::Flush => {
            let fs_file_id = {
                let data = req.data().read_only();

                let Some(p) = data.view::<FsFlushParams>() else {
                    return DriverStatus::InvalidParameter;
                };
                p.fs_file_id
            };
            let err = {
                match take_file_ctx(&vdx, fs_file_id) {
                    Err(e) => Some(e),
                    Ok(ctx) if ctx.is_dir => {
                        restore_file_ctx(&vdx, fs_file_id, ctx);
                        None
                    }
                    Ok(mut ctx) => match ctx.cached.take() {
                        None => {
                            let err = missing_cached_file_state(fs_file_id);
                            restore_file_ctx(&vdx, fs_file_id, ctx);
                            Some(err)
                        }
                        Some(state) => {
                            let mut file = state.into_file(&*fs);
                            let err = file.flush().await.err().map(|e| map_fatfs_err(&e));
                            ctx.cached = Some(file.into_cached_state());
                            restore_file_ctx(&vdx, fs_file_id, ctx);
                            err
                        }
                    },
                }
            };
            flush_owner_blocking(&vdx, fs_file_id);
            req.write().set_data_t(FsFlushResult { error: err });
            DriverStatus::Success
        }

        FsOp::Create => {
            let err = {
                let data = req.data().read_only();

                let Some(p) = data.view::<FsCreateParams>() else {
                    return DriverStatus::InvalidParameter;
                };
                let dir = p.dir;
                match create_entry(&mut *fs, &p.path, dir).await {
                    Ok(()) => None,
                    Err(e) => Some(map_fatfs_err(&e)),
                }
            };
            req.write().set_data_t(FsCreateResult { error: err });
            DriverStatus::Success
        }

        FsOp::Rename => {
            let err = {
                let data = req.data().read_only();

                let Some(p) = data.view::<FsRenameParams>() else {
                    return DriverStatus::InvalidParameter;
                };
                match rename_entry(&mut *fs, &p.src, &p.dst).await {
                    Ok(()) => {
                        let mut tbl = vdx.table.write();
                        if let Some(ctx) = tbl.values_mut().find(|ctx| ctx.path.as_ref() == &p.src)
                        {
                            ctx.path = Arc::new(p.dst.clone());
                        }
                        None
                    }
                    Err(e) => Some(map_fatfs_err(&e)),
                }
            };
            req.write().set_data_t(FsRenameResult { error: err });
            DriverStatus::Success
        }

        FsOp::ReadDir => {
            let res = {
                let data = req.data().read_only();

                let Some(p) = data.view::<FsListDirParams>() else {
                    return DriverStatus::InvalidParameter;
                };
                match list_names(&mut *fs, &p.path).await {
                    Ok(names) => FsListDirResult {
                        names: Some(names),
                        error: None,
                    },
                    Err(e) => FsListDirResult {
                        names: None,
                        error: Some(map_fatfs_err(&e)),
                    },
                }
            };
            req.write().set_data_t(res);
            DriverStatus::Success
        }

        FsOp::GetInfo => {
            let fs_file_id = {
                let data = req.data().read_only();

                let Some(p) = data.view::<FsGetInfoParams>() else {
                    return DriverStatus::InvalidParameter;
                };
                p.fs_file_id
            };
            let result = {
                let tbl = vdx.table.read();
                match tbl.get(&fs_file_id) {
                    None => Err(FileStatus::PathNotFound),
                    Some(ctx) if ctx.is_dir => Ok((true, 0u64, u8::from(FileAttribute::Directory))),
                    Some(ctx) => Ok((false, ctx.size, u8::from(FileAttribute::Archive))),
                }
            };
            let res = match result {
                Ok((is_dir, size, attrs)) => FsGetInfoResult {
                    size,
                    is_dir,
                    attrs: attrs as u32,
                    error: None,
                },
                Err(e) => FsGetInfoResult {
                    size: 0,
                    is_dir: false,
                    attrs: 0,
                    error: Some(e),
                },
            };
            req.write().set_data_t(res);
            DriverStatus::Success
        }

        FsOp::SetLen => {
            let (fs_file_id, new_size) = {
                let data = req.data().read_only();

                let Some(p) = data.view::<FsSetLenParams>() else {
                    return DriverStatus::InvalidParameter;
                };
                (p.fs_file_id, p.new_size)
            };
            let err = {
                match take_file_ctx(&vdx, fs_file_id) {
                    Err(e) => Some(e),
                    Ok(ctx) if ctx.is_dir => {
                        restore_file_ctx(&vdx, fs_file_id, ctx);
                        Some(FileStatus::AccessDenied)
                    }
                    Ok(mut ctx) => match ctx.cached.take() {
                        None => {
                            let err = missing_cached_file_state(fs_file_id);
                            restore_file_ctx(&vdx, fs_file_id, ctx);
                            Some(err)
                        }
                        Some(state) => {
                            let mut file = state.into_file(&*fs);
                            let err = resize_file(&mut file, new_size)
                                .await
                                .err()
                                .map(|e| map_fatfs_err(&e));
                            ctx.cached = Some(file.into_cached_state());
                            restore_file_ctx(&vdx, fs_file_id, ctx);
                            err
                        }
                    },
                }
            };
            if err.is_none() {
                flush_owner_blocking(&vdx, fs_file_id);
            }
            if err.is_none() {
                let mut tbl = vdx.table.write();
                if let Some(ctx) = tbl.get_mut(&fs_file_id) {
                    ctx.size = new_size;
                    if ctx.pos > ctx.size {
                        ctx.pos = ctx.size;
                    }
                }
            }
            req.write().set_data_t(FsSetLenResult { error: err });
            DriverStatus::Success
        }

        FsOp::Append => {
            let (fs_file_id, write_through, data_ptr, data_len) = {
                let data = req.data().read_only();

                let Some(p) = data.view::<FsAppendParams<'_>>() else {
                    return DriverStatus::InvalidParameter;
                };
                (p.fs_file_id, p.write_through, p.data.as_ptr(), p.data.len())
            };
            // SAFETY: ptr came from an &'caller [u8] that remains valid until the
            // BorrowedHandle drops after spawn_blocking returns.
            let data = unsafe { core::slice::from_raw_parts(data_ptr, data_len) };

            let result: Result<(usize, u64), FileStatus> = {
                match take_file_ctx(&vdx, fs_file_id) {
                    Err(e) => Err(e),
                    Ok(ctx) if ctx.is_dir => {
                        restore_file_ctx(&vdx, fs_file_id, ctx);
                        Err(FileStatus::AccessDenied)
                    }
                    Ok(mut ctx) => match ctx.cached.take() {
                        None => {
                            let err = missing_cached_file_state(fs_file_id);
                            restore_file_ctx(&vdx, fs_file_id, ctx);
                            Err(err)
                        }
                        Some(state) => {
                            let start_off = ctx.size;
                            let mut file = state.into_file(&*fs);
                            let res = match file.seek(SeekFrom::Start(start_off)).await {
                                Ok(_) => {
                                    let n = data.len();
                                    match file.write_all(data, fatfs::IoKind::Data).await {
                                        Ok(()) => {
                                            if write_through {
                                                flush_owner_blocking(&vdx, fs_file_id);
                                            }
                                            Ok((n, start_off + n as u64))
                                        }
                                        Err(e) => Err(map_fatfs_err(&e)),
                                    }
                                }
                                Err(e) => Err(map_fatfs_err(&e)),
                            };
                            let res = match file.flush().await {
                                Ok(_) => res,
                                Err(e) => Err(map_fatfs_err(&e)),
                            };
                            ctx.cached = Some(file.into_cached_state());
                            restore_file_ctx(&vdx, fs_file_id, ctx);
                            res
                        }
                    },
                }
            };

            if let Ok((_, new_size)) = result {
                let mut tbl = vdx.table.write();
                if let Some(ctx) = tbl.get_mut(&fs_file_id) {
                    ctx.pos = new_size;
                    ctx.size = new_size;
                }
            }

            let res = match result {
                Ok((written, new_size)) => FsAppendResult {
                    written,
                    new_size,
                    error: None,
                },
                Err(e) => FsAppendResult {
                    written: 0,
                    new_size: 0,
                    error: Some(e),
                },
            };
            req.write().set_data_t(res);
            DriverStatus::Success
        }

        FsOp::ZeroRange => {
            let (fs_file_id, offset, len) = {
                let data = req.data().read_only();

                let Some(p) = data.view::<FsZeroRangeParams>() else {
                    return DriverStatus::InvalidParameter;
                };
                (p.fs_file_id, p.offset, p.len)
            };
            let err = {
                match take_file_ctx(&vdx, fs_file_id) {
                    Err(e) => Some(e),
                    Ok(ctx) if ctx.is_dir => {
                        restore_file_ctx(&vdx, fs_file_id, ctx);
                        Some(FileStatus::AccessDenied)
                    }
                    Ok(mut ctx) => match ctx.cached.take() {
                        None => {
                            let err = missing_cached_file_state(fs_file_id);
                            restore_file_ctx(&vdx, fs_file_id, ctx);
                            Some(err)
                        }
                        Some(state) => {
                            let mut file = state.into_file(&*fs);
                            let file_len = file.seek(SeekFrom::End(0)).await.unwrap_or(0);
                            let end = offset.saturating_add(len);
                            let res = if offset > file_len {
                                Some(FileStatus::BadPath)
                            } else {
                                let actual_end = end.min(file_len);
                                let zero_len = actual_end.saturating_sub(offset);
                                if zero_len == 0 {
                                    None
                                } else {
                                    match file.seek(SeekFrom::Start(offset)).await {
                                        Ok(_) => {
                                            let zeros = vec![0u8; zero_len as usize];
                                            match file.write_all(&zeros, fatfs::IoKind::Data).await
                                            {
                                                Ok(()) => {
                                                    flush_owner(&vdx, fs_file_id);
                                                    None
                                                }
                                                Err(e) => Some(map_fatfs_err(&e)),
                                            }
                                        }
                                        Err(e) => Some(map_fatfs_err(&e)),
                                    }
                                }
                            };
                            let res = match file.flush().await {
                                Ok(_) => res,
                                Err(e) => Some(map_fatfs_err(&e)),
                            };
                            ctx.cached = Some(file.into_cached_state());
                            restore_file_ctx(&vdx, fs_file_id, ctx);
                            res
                        }
                    },
                }
            };
            req.write().set_data_t(FsZeroRangeResult { error: err });
            DriverStatus::Success
        }

        FsOp::Seek => handle_seek_fast(dev, req),

        FsOp::SetInfo | FsOp::Delete => DriverStatus::NotImplemented,
    }
}

fn handle_seek_fast(dev: &Arc<DeviceObject>, req: &mut RequestHandle<'_, '_>) -> DriverStatus {
    let (fs_file_id, origin, offset) = {
        let data = req.data().read_only();

        let Some(p) = data.view::<FsSeekParams>() else {
            return DriverStatus::InvalidParameter;
        };
        (p.fs_file_id, p.origin, p.offset)
    };
    let vdx = ext_mut::<VolCtrlDevExt>(dev);
    let result = {
        let mut tbl = vdx.table.write();
        match tbl.get_mut(&fs_file_id) {
            Some(ctx) => {
                let size = if ctx.is_dir { 0 } else { ctx.size };
                let base: i128 = match origin {
                    FsSeekWhence::Set => 0,
                    FsSeekWhence::Cur => ctx.pos as i128,
                    FsSeekWhence::End => size as i128,
                };
                let pos_i = base + offset as i128;
                let clamped = if pos_i < 0 { 0 } else { pos_i as u64 };
                ctx.pos = clamped;
                Ok(clamped)
            }
            None => Err(FileStatus::PathNotFound),
        }
    };
    let res = match result {
        Ok(pos) => FsSeekResult { pos, error: None },
        Err(e) => FsSeekResult {
            pos: 0,
            error: Some(e),
        },
    };
    req.write().set_data_t(res);
    DriverStatus::Success
}

async fn send_flush_owner(volume_target: IoTarget, owner: u64, should_block: bool) -> DriverStatus {
    let mut flush_req = RequestHandle::new(
        RequestType::FlushOwner {
            owner,
            should_block,
        },
        RequestData::empty(),
    );
    flush_req.set_traversal_policy(TraversalPolicy::ForwardLower);
    pnp_send_request(volume_target, &mut flush_req).await
}

#[request_handler]
pub async fn fs_op_dispatch(
    dev: &Arc<DeviceObject>,
    req: &mut RequestHandle<'_, '_>,
) -> DriverStep {
    // Seek is fast-path: no FS lock, no owner tagging, no metadata flush.
    if matches!(req.read().kind, RequestType::Fs(FsOp::Seek)) {
        let status = handle_seek_fast(dev, req);
        req.write().status = status.clone();
        return DriverStep::complete(status);
    }
    let flush_metadata_after_op =
        matches!(req.read().kind, RequestType::Fs(FsOp::Close | FsOp::Flush));

    let (fs_arc, volume_target, flush_flag, pending_flush_owner, pending_flush_block) = {
        let vdx = ext_mut::<VolCtrlDevExt>(&dev);
        (
            vdx.fs.clone(),
            vdx.volume_target.clone(),
            vdx.should_flush.clone(),
            vdx.pending_flush_owner.clone(),
            vdx.pending_flush_block.clone(),
        )
    };

    let status = execute_fs_work(dev, &fs_arc, req).await;

    if flush_flag.swap(false, Ordering::AcqRel) {
        let owner = pending_flush_owner.swap(0, Ordering::AcqRel);
        let should_block = pending_flush_block.swap(false, Ordering::AcqRel);
        if owner != 0 {
            let _ = send_flush_owner(volume_target.clone(), owner, should_block).await;
        }
    }

    if flush_metadata_after_op {
        let _ = send_flush_owner(volume_target, METADATA_OWNER_ID, true).await;
    }

    req.write().status = status.clone();
    DriverStep::complete(status)
}
