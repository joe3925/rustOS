use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use fatfs::{
    Dir as FatDirT, Error as FatError, FileSystem as FatFsT, IoBase, LossyOemCpConverter,
    NullTimeProvider, Read, Seek, SeekFrom, Write,
};
use kernel_api::kernel_types::fs::Path;
use kernel_api::println;
use kernel_api::request::type_name_stripped;
use kernel_api::runtime::spawn_blocking;
use spin::{Mutex, RwLock};

use kernel_api::device::DeviceObject;
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
type FatDir<'a> = FatDirT<'a, FatDev, TP, OCC>;
type FsError = FatError<<FatDev as IoBase>::Error>;

#[repr(C)]
pub struct VolCtrlDevExt {
    pub fs: Arc<Mutex<Fs>>,
    pub(crate) next_id: AtomicU64,
    pub(crate) table: RwLock<BTreeMap<u64, FileCtx>>,
    pub(crate) volume_target: IoTarget,
    pub should_flush: Arc<AtomicBool>,
    /// Owner tag of the file that requested the pending flush (0 = flush all dirty).
    pub pending_flush_owner: Arc<AtomicU64>,
    /// Whether the pending flush must block until the cache confirms writeback.
    pub pending_flush_block: Arc<AtomicBool>,
    /// Current file owner tag — shared with BlockDev, set before FS writes.
    pub current_owner: Arc<AtomicU64>,
}

pub struct FileCtx {
    path: Path,
    is_dir: bool,
    pos: u64,
    size: u64,
}

fn map_fatfs_err(e: &FsError) -> FileStatus {
    match e {
        fatfs::Error::NotFound => FileStatus::PathNotFound,
        fatfs::Error::AlreadyExists => FileStatus::FileAlreadyExist,
        fatfs::Error::InvalidInput => FileStatus::BadPath,
        fatfs::Error::NotEnoughSpace => FileStatus::NoSpace,
        fatfs::Error::CorruptedFileSystem => FileStatus::CorruptFilesystem,
        _ => FileStatus::UnknownFail,
    }
}

fn create_entry(fs: &mut Fs, path: &Path, dir: bool) -> Result<(), FsError> {
    let path_str = path.as_str();
    if dir {
        let _ = fs.root_dir().create_dir(path_str)?;
    } else {
        let _ = fs.root_dir().create_file(path_str)?;
    }
    Ok(())
}

fn rename_entry(fs: &mut Fs, src: &Path, dst: &Path) -> Result<(), FsError> {
    let dst_dir = fs.root_dir();
    fs.root_dir().rename(src.as_str(), &dst_dir, dst.as_str())
}

fn list_names(fs: &mut Fs, path: &Path) -> Result<Vec<String>, FsError> {
    let dir: FatDir = fs.root_dir().open_dir(path.as_str())?;
    let mut out = Vec::new();
    for r in dir.iter() {
        let e = r?;
        let name = e.file_name();
        out.push(name);
    }
    Ok(out)
}

fn get_file_len(fs: &mut Fs, path: &Path) -> Result<u64, FsError> {
    let mut file = fs.root_dir().open_file(path.as_str())?;
    file.seek(SeekFrom::End(0))
}

fn execute_fs_work(
    dev: &Arc<DeviceObject>,
    fs_arc: &Arc<Mutex<Fs>>,
    req: &mut RequestHandle<'_>,
) -> DriverStatus {
    let vdx = ext_mut::<VolCtrlDevExt>(dev);
    let mut fs = fs_arc.lock();

    let op = match req.read().kind {
        RequestType::Fs(op) => op,
        RequestType::DeviceControl(_) => return DriverStatus::NotImplemented,
        _ => return DriverStatus::InvalidParameter,
    };

    match op {
        FsOp::Seek => return DriverStatus::InvalidParameter, // handled in dispatcher

        FsOp::Open => {
            let (path, flags, write_through) = {
                let guard = req.read();
                let Some(p) = guard.view_data::<FsOpenParams>() else {
                    return DriverStatus::InvalidParameter;
                };
                (p.path.clone(), p.flags, p.write_through)
            };
            let _ = (flags, write_through); // driver uses path only; flags handled by VFS
            let path_str = path.as_str();
            let open_res = {
                let root = fs.root_dir();
                match root.open_file(path_str) {
                    Ok(mut f) => match f.seek(SeekFrom::End(0)) {
                        Ok(end) => Ok((false, end)),
                        Err(e) => Err(e),
                    },
                    Err(FatError::NotFound) | Err(FatError::InvalidInput) => {
                        match root.open_dir(path_str) {
                            Ok(_d) => Ok((true, 0)),
                            Err(e) => Err(e),
                        }
                    }
                    Err(e) => Err(e),
                }
            };
            let result = match open_res {
                Ok((is_dir, size)) => {
                    let id = vdx.next_id.fetch_add(1, Ordering::AcqRel).max(1);
                    {
                        let mut tbl = vdx.table.write();
                        tbl.insert(
                            id,
                            FileCtx {
                                path,
                                is_dir,
                                pos: 0,
                                size,
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
            };

            req.write().set_data_t(result);
            DriverStatus::Success
        }

        FsOp::Close => {
            let fs_file_id = {
                let guard = req.read();
                let Some(p) = guard.view_data::<FsCloseParams>() else {
                    return DriverStatus::InvalidParameter;
                };
                p.fs_file_id
            };
            let err = if vdx.table.write().remove(&fs_file_id).is_some() {
                None
            } else {
                Some(FileStatus::PathNotFound)
            };
            req.write().set_data_t(FsCloseResult { error: err });
            DriverStatus::Success
        }

        FsOp::Read => {
            // Extract the buffer pointer from the borrowed params without moving them.
            let (fs_file_id, offset, buf_ptr, buf_len) = {
                let guard = req.read();
                let Some(p) = guard.view_data::<FsReadParams<'_>>() else {
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
                let tbl = vdx.table.read();
                match tbl.get(&fs_file_id) {
                    None => Err(FileStatus::PathNotFound),
                    Some(ctx) if ctx.is_dir => Err(FileStatus::AccessDenied),
                    Some(ctx) => match fs.root_dir().open_file(ctx.path.as_str()) {
                        Ok(mut file) => {
                            if let Err(e) = file.seek(SeekFrom::Start(offset)) {
                                Err(map_fatfs_err(&e))
                            } else {
                                match file.read(buf) {
                                    Ok(n) => Ok(n),
                                    Err(e) => Err(map_fatfs_err(&e)),
                                }
                            }
                        }
                        Err(e) => Err(map_fatfs_err(&e)),
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
                let guard = req.read();
                let Some(p) = guard.view_data::<FsWriteParams<'_>>() else {
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

            vdx.current_owner.store(fs_file_id, Ordering::Release);
            let write_res: Result<usize, FileStatus> = {
                let tbl = vdx.table.read();
                match tbl.get(&fs_file_id) {
                    None => Err(FileStatus::PathNotFound),
                    Some(ctx) if ctx.is_dir => Err(FileStatus::AccessDenied),
                    Some(ctx) => match fs.root_dir().open_file(ctx.path.as_str()) {
                        Ok(mut file) => {
                            let n = data.len();
                            if let Err(e) = file.seek(SeekFrom::Start(offset)) {
                                Err(map_fatfs_err(&e))
                            } else {
                                match file.write_all(data) {
                                    Ok(()) => {
                                        if write_through {
                                            flush_owner_blocking(&vdx, fs_file_id);
                                        }
                                        Ok(n)
                                    }
                                    Err(e) => Err(map_fatfs_err(&e)),
                                }
                            }
                        }
                        Err(e) => Err(map_fatfs_err(&e)),
                    },
                }
            };
            vdx.current_owner.store(0, Ordering::Release);

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
                let guard = req.read();
                let Some(p) = guard.view_data::<FsFlushParams>() else {
                    return DriverStatus::InvalidParameter;
                };
                p.fs_file_id
            };
            vdx.current_owner.store(fs_file_id, Ordering::Release);
            let err = {
                let tbl = vdx.table.read();
                match tbl.get(&fs_file_id) {
                    None => Some(FileStatus::PathNotFound),
                    Some(ctx) if ctx.is_dir => None,
                    Some(ctx) => match fs.root_dir().open_file(ctx.path.as_str()) {
                        Ok(mut f) => f.flush().err().map(|e| map_fatfs_err(&e)),
                        Err(e) => Some(map_fatfs_err(&e)),
                    },
                }
            };
            vdx.current_owner.store(0, Ordering::Release);
            flush_owner_blocking(&vdx, fs_file_id);
            req.write().set_data_t(FsFlushResult { error: err });
            DriverStatus::Success
        }

        FsOp::Create => {
            let err = {
                let guard = req.read();
                let Some(p) = guard.view_data::<FsCreateParams>() else {
                    return DriverStatus::InvalidParameter;
                };
                let dir = p.dir;
                match create_entry(&mut *fs, &p.path, dir) {
                    Ok(()) => None,
                    Err(e) => Some(map_fatfs_err(&e)),
                }
            };
            req.write().set_data_t(FsCreateResult { error: err });
            DriverStatus::Success
        }

        FsOp::Rename => {
            let (src, dst) = {
                let guard = req.read();
                let Some(p) = guard.view_data::<FsRenameParams>() else {
                    return DriverStatus::InvalidParameter;
                };
                (p.src.clone(), p.dst.clone())
            };
            let err = match rename_entry(&mut *fs, &src, &dst) {
                Ok(()) => {
                    let mut tbl = vdx.table.write();
                    if let Some(ctx) = tbl.values_mut().find(|ctx| ctx.path == src) {
                        ctx.path = dst;
                    }
                    None
                }
                Err(e) => Some(map_fatfs_err(&e)),
            };
            req.write().set_data_t(FsRenameResult { error: err });
            DriverStatus::Success
        }

        FsOp::ReadDir => {
            let res = {
                let guard = req.read();
                let Some(p) = guard.view_data::<FsListDirParams>() else {
                    return DriverStatus::InvalidParameter;
                };
                match list_names(&mut *fs, &p.path) {
                    Ok(names) => FsListDirResult { names, error: None },
                    Err(e) => FsListDirResult {
                        names: Vec::new(),
                        error: Some(map_fatfs_err(&e)),
                    },
                }
            };
            req.write().set_data_t(res);
            DriverStatus::Success
        }

        FsOp::GetInfo => {
            let fs_file_id = {
                let guard = req.read();
                let Some(p) = guard.view_data::<FsGetInfoParams>() else {
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
                let guard = req.read();
                let Some(p) = guard.view_data::<FsSetLenParams>() else {
                    return DriverStatus::InvalidParameter;
                };
                (p.fs_file_id, p.new_size)
            };
            let err = {
                let tbl = vdx.table.read();
                match tbl.get(&fs_file_id) {
                    None => Some(FileStatus::PathNotFound),
                    Some(ctx) if ctx.is_dir => Some(FileStatus::AccessDenied),
                    Some(ctx) => match fs.root_dir().open_file(ctx.path.as_str()) {
                        Ok(mut file) => match file.seek(SeekFrom::Start(new_size)) {
                            Ok(_) => match file.truncate() {
                                Ok(()) => None,
                                Err(e) => Some(map_fatfs_err(&e)),
                            },
                            Err(e) => Some(map_fatfs_err(&e)),
                        },
                        Err(e) => Some(map_fatfs_err(&e)),
                    },
                }
            };
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
                let guard = req.read();
                let Some(p) = guard.view_data::<FsAppendParams<'_>>() else {
                    return DriverStatus::InvalidParameter;
                };
                (p.fs_file_id, p.write_through, p.data.as_ptr(), p.data.len())
            };
            // SAFETY: ptr came from an &'caller [u8] that remains valid until the
            // BorrowedHandle drops after spawn_blocking returns.
            let data = unsafe { core::slice::from_raw_parts(data_ptr, data_len) };

            vdx.current_owner.store(fs_file_id, Ordering::Release);
            let result: Result<(usize, u64), FileStatus> = {
                let tbl = vdx.table.read();
                match tbl.get(&fs_file_id) {
                    None => Err(FileStatus::PathNotFound),
                    Some(ctx) if ctx.is_dir => Err(FileStatus::AccessDenied),
                    Some(ctx) => match fs.root_dir().open_file(ctx.path.as_str()) {
                        Ok(mut file) => {
                            let start_off = ctx.size;
                            match file.seek(SeekFrom::Start(start_off)) {
                                Ok(_) => {
                                    let n = data.len();
                                    match file.write_all(data) {
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
                            }
                        }
                        Err(e) => Err(map_fatfs_err(&e)),
                    },
                }
            };
            vdx.current_owner.store(0, Ordering::Release);

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
                let guard = req.read();
                let Some(p) = guard.view_data::<FsZeroRangeParams>() else {
                    return DriverStatus::InvalidParameter;
                };
                (p.fs_file_id, p.offset, p.len)
            };
            vdx.current_owner.store(fs_file_id, Ordering::Release);
            let err = {
                let tbl = vdx.table.read();
                match tbl.get(&fs_file_id) {
                    None => Some(FileStatus::PathNotFound),
                    Some(ctx) if ctx.is_dir => Some(FileStatus::AccessDenied),
                    Some(ctx) => match fs.root_dir().open_file(ctx.path.as_str()) {
                        Ok(mut file) => {
                            let file_len = file.seek(SeekFrom::End(0)).unwrap_or(0);
                            let end = offset.saturating_add(len);
                            if offset > file_len {
                                Some(FileStatus::BadPath)
                            } else {
                                let actual_end = end.min(file_len);
                                let zero_len = actual_end.saturating_sub(offset);
                                if zero_len == 0 {
                                    None
                                } else {
                                    match file.seek(SeekFrom::Start(offset)) {
                                        Ok(_) => {
                                            let zeros = vec![0u8; zero_len as usize];
                                            match file.write_all(&zeros) {
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
                            }
                        }
                        Err(e) => Some(map_fatfs_err(&e)),
                    },
                }
            };
            vdx.current_owner.store(0, Ordering::Release);
            req.write().set_data_t(FsZeroRangeResult { error: err });
            DriverStatus::Success
        }

        FsOp::SetInfo | FsOp::Delete => DriverStatus::NotImplemented,
    }
}

fn handle_seek_fast(dev: &Arc<DeviceObject>, req: &mut RequestHandle<'_>) -> DriverStatus {
    let (fs_file_id, origin, offset) = {
        let guard = req.read();
        let Some(p) = guard.view_data::<FsSeekParams>() else {
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

async fn send_flush_dirty(volume_target: IoTarget) -> DriverStatus {
    let mut flush_req = RequestHandle::new(
        RequestType::FlushDirty {
            should_block: false,
        },
        RequestData::empty(),
    );
    flush_req.set_traversal_policy(TraversalPolicy::ForwardLower);
    pnp_send_request(volume_target, &mut flush_req).await
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
pub async fn fs_op_dispatch(dev: &Arc<DeviceObject>, req: &mut RequestHandle<'_>) -> DriverStep {
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

    // Seek is fast-path: no FS lock needed, no thread spawn.
    if matches!(req.read().kind, RequestType::Fs(FsOp::Seek)) {
        let status = handle_seek_fast(dev, req);
        req.write().status = status;
        return DriverStep::complete(status);
    }

    let dev_cloned = dev.clone();
    // SAFETY: req is valid for the entire duration of this async fn. spawn_blocking is
    // .awaited to completion before req could be dropped, so the pointer is valid throughout.
    let req_ptr = req as *mut RequestHandle<'_> as usize;
    let join = spawn_blocking(move || {
        let req = unsafe { &mut *(req_ptr as *mut RequestHandle<'_>) };
        execute_fs_work(&dev_cloned, &fs_arc, req)
    });
    let status = join.await;

    if flush_flag.swap(false, Ordering::AcqRel) {
        let owner = pending_flush_owner.swap(0, Ordering::AcqRel);
        let should_block = pending_flush_block.swap(false, Ordering::AcqRel);
        if owner != 0 {
            let _ = send_flush_owner(volume_target, owner, should_block).await;
        } else {
            let _ = send_flush_dirty(volume_target).await;
        }
    }

    req.write().status = status;
    DriverStep::complete(status)
}
