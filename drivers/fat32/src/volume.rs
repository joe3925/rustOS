use crate::block_dev::flush_owner;
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

use crate::block_dev::BlockDev;
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
    /// Current file owner tag — shared with BlockDev, set before FS writes.
    pub current_owner: Arc<AtomicU64>,
}

pub struct FileCtx {
    path: Path,
    is_dir: bool,
    pos: u64,
    size: u64,
}

enum FsWork {
    Open(FsOpenParams),
    Close(FsCloseParams),
    Read(FsReadParams),
    Write(FsWriteParams),
    Seek(FsSeekParams),
    Flush(FsFlushParams),
    Create(FsCreateParams),
    Rename(FsRenameParams),
    ReadDir(FsListDirParams),
    GetInfo(FsGetInfoParams),
    SetLen(FsSetLenParams),
    Append(FsAppendParams),
    ZeroRange(FsZeroRangeParams),
    SetInfo,
    Delete,
}

enum FsReply {
    Open(FsOpenResult),
    Close(FsCloseResult),
    Read(FsReadResult),
    Write(FsWriteResult),
    Seek(FsSeekResult),
    Flush(FsFlushResult),
    Create(FsCreateResult),
    Rename(FsRenameResult),
    ReadDir(FsListDirResult),
    GetInfo(FsGetInfoResult),
    SetLen(FsSetLenResult),
    Append(FsAppendResult),
    ZeroRange(FsZeroRangeResult),
}

fn take_typed_params<T>(req: &mut RequestHandle<'_>) -> Result<T, DriverStatus> {
    let mut r = req.write();
    r.take_data::<T>().ok_or(DriverStatus::InvalidParameter)
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

fn parse_fs_work(req: &mut RequestHandle<'_>) -> Result<FsWork, DriverStatus> {
    let kind = { req.read().kind };
    match kind {
        RequestType::Fs(op) => match op {
            FsOp::Open => Ok(FsWork::Open(take_typed_params::<FsOpenParams>(req)?)),
            FsOp::Close => Ok(FsWork::Close(take_typed_params::<FsCloseParams>(req)?)),
            FsOp::Read => Ok(FsWork::Read(take_typed_params::<FsReadParams>(req)?)),
            FsOp::Write => Ok(FsWork::Write(take_typed_params::<FsWriteParams>(req)?)),
            FsOp::Seek => Ok(FsWork::Seek(take_typed_params::<FsSeekParams>(req)?)),
            FsOp::Flush => Ok(FsWork::Flush(take_typed_params::<FsFlushParams>(req)?)),
            FsOp::Create => Ok(FsWork::Create(take_typed_params::<FsCreateParams>(req)?)),
            FsOp::Rename => Ok(FsWork::Rename(take_typed_params::<FsRenameParams>(req)?)),
            FsOp::ReadDir => Ok(FsWork::ReadDir(take_typed_params::<FsListDirParams>(req)?)),
            FsOp::GetInfo => Ok(FsWork::GetInfo(take_typed_params::<FsGetInfoParams>(req)?)),
            FsOp::SetLen => Ok(FsWork::SetLen(take_typed_params::<FsSetLenParams>(req)?)),
            FsOp::Append => Ok(FsWork::Append(take_typed_params::<FsAppendParams>(req)?)),
            FsOp::ZeroRange => Ok(FsWork::ZeroRange(take_typed_params::<FsZeroRangeParams>(
                req,
            )?)),
            FsOp::SetInfo => Err(DriverStatus::NotImplemented),
            FsOp::Delete => Err(DriverStatus::NotImplemented),
        },
        RequestType::DeviceControl(_) => Err(DriverStatus::NotImplemented),
        _ => Err(DriverStatus::InvalidParameter),
    }
}

fn execute_fs_work(
    dev: &Arc<DeviceObject>,
    fs_arc: &Arc<Mutex<Fs>>,
    work: FsWork,
) -> (DriverStatus, Option<FsReply>) {
    let vdx = ext_mut::<VolCtrlDevExt>(dev);
    let mut fs = fs_arc.lock();

    match work {
        FsWork::Open(params) => {
            let path_str = params.path.as_str();
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
                                path: params.path,
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

            (DriverStatus::Success, Some(FsReply::Open(result)))
        }

        FsWork::Close(params) => {
            let err = {
                let mut tbl = vdx.table.write();
                if tbl.remove(&params.fs_file_id).is_some() {
                    None
                } else {
                    Some(FileStatus::PathNotFound)
                }
            };

            let res = FsCloseResult { error: err };
            (DriverStatus::Success, Some(FsReply::Close(res)))
        }

        FsWork::Read(params) => {
            let data_or_err = {
                let tbl = vdx.table.read();
                match tbl.get(&params.fs_file_id) {
                    None => Err(FileStatus::PathNotFound),
                    Some(ctx) if ctx.is_dir => Err(FileStatus::AccessDenied),
                    Some(ctx) => match fs.root_dir().open_file(ctx.path.as_str()) {
                        Ok(mut file) => {
                            if let Err(e) = file.seek(SeekFrom::Start(params.offset)) {
                                Err(map_fatfs_err(&e))
                            } else {
                                let mut buf = vec![0u8; params.len];
                                match file.read(&mut buf) {
                                    Ok(n) => {
                                        buf.truncate(n);
                                        Ok(buf)
                                    }
                                    Err(e) => Err(map_fatfs_err(&e)),
                                }
                            }
                        }
                        Err(e) => Err(map_fatfs_err(&e)),
                    },
                }
            };

            let res = match data_or_err {
                Ok(v) => {
                    let new_pos = params.offset.saturating_add(v.len() as u64);
                    let mut tbl = vdx.table.write();
                    if let Some(ctx) = tbl.get_mut(&params.fs_file_id) {
                        ctx.pos = new_pos;
                    }
                    FsReadResult {
                        data: v,
                        error: None,
                    }
                }
                Err(status) => FsReadResult {
                    data: Vec::new(),
                    error: Some(status),
                },
            };

            (DriverStatus::Success, Some(FsReply::Read(res)))
        }

        FsWork::Write(params) => {
            vdx.current_owner.store(params.fs_file_id, Ordering::Release);
            let write_res: Result<usize, FileStatus> = {
                let tbl = vdx.table.read();
                match tbl.get(&params.fs_file_id) {
                    None => Err(FileStatus::PathNotFound),
                    Some(ctx) if ctx.is_dir => Err(FileStatus::AccessDenied),
                    Some(ctx) => match fs.root_dir().open_file(ctx.path.as_str()) {
                        Ok(mut file) => {
                            let n = params.data.len();
                            if let Err(e) = file.seek(SeekFrom::Start(params.offset)) {
                                Err(map_fatfs_err(&e))
                            } else {
                                match file.write_all(&params.data) {
                                    Ok(()) => {
                                        if params.write_through {
                                            flush_owner(&vdx, params.fs_file_id);
                                            Ok(n)
                                        } else {
                                            Ok(n)
                                        }
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
                if let Some(ctx) = tbl.get_mut(&params.fs_file_id) {
                    let end = params.offset.saturating_add(written as u64);
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
                Err(status) => FsWriteResult {
                    written: 0,
                    error: Some(status),
                },
            };

            (DriverStatus::Success, Some(FsReply::Write(res)))
        }

        FsWork::Seek(params) => {
            let result = {
                let mut tbl = vdx.table.write();
                match tbl.get_mut(&params.fs_file_id) {
                    Some(ctx) => {
                        let size = if ctx.is_dir { 0 } else { ctx.size };

                        let base: i128 = match params.origin {
                            FsSeekWhence::Set => 0,
                            FsSeekWhence::Cur => ctx.pos as i128,
                            FsSeekWhence::End => size as i128,
                        };

                        let pos_i = base + params.offset as i128;
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

            (DriverStatus::Success, Some(FsReply::Seek(res)))
        }

        FsWork::Flush(params) => {
            vdx.current_owner.store(params.fs_file_id, Ordering::Release);
            let err = {
                let tbl = vdx.table.read();
                match tbl.get(&params.fs_file_id) {
                    None => Some(FileStatus::PathNotFound),
                    Some(ctx) if ctx.is_dir => None,
                    Some(ctx) => match fs.root_dir().open_file(ctx.path.as_str()) {
                        Ok(mut f) => f.flush().err().map(|e| map_fatfs_err(&e)),
                        Err(e) => Some(map_fatfs_err(&e)),
                    },
                }
            };
            vdx.current_owner.store(0, Ordering::Release);
            flush_owner(&vdx, params.fs_file_id);
            let res = FsFlushResult { error: err };
            (DriverStatus::Success, Some(FsReply::Flush(res)))
        }

        FsWork::Create(params) => {
            let err = match create_entry(&mut *fs, &params.path, params.dir) {
                Ok(()) => None,
                Err(e) => Some(map_fatfs_err(&e)),
            };

            let res = FsCreateResult { error: err };
            (DriverStatus::Success, Some(FsReply::Create(res)))
        }

        FsWork::Rename(params) => {
            let err = match rename_entry(&mut *fs, &params.src, &params.dst) {
                Ok(()) => {
                    let mut tbl = vdx.table.write();
                    for ctx in tbl.values_mut() {
                        if ctx.path == params.src {
                            ctx.path = params.dst.clone();
                        }
                    }
                    None
                }
                Err(e) => Some(map_fatfs_err(&e)),
            };

            let res = FsRenameResult { error: err };
            (DriverStatus::Success, Some(FsReply::Rename(res)))
        }

        FsWork::ReadDir(params) => {
            let names_or_err = list_names(&mut *fs, &params.path);

            let res = match names_or_err {
                Ok(names) => FsListDirResult { names, error: None },
                Err(e) => FsListDirResult {
                    names: Vec::new(),
                    error: Some(map_fatfs_err(&e)),
                },
            };

            (DriverStatus::Success, Some(FsReply::ReadDir(res)))
        }

        FsWork::GetInfo(params) => {
            let result = {
                let tbl = vdx.table.read();
                match tbl.get(&params.fs_file_id) {
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

            (DriverStatus::Success, Some(FsReply::GetInfo(res)))
        }

        FsWork::SetLen(params) => {
            let err = {
                let tbl = vdx.table.read();
                match tbl.get(&params.fs_file_id) {
                    None => Some(FileStatus::PathNotFound),
                    Some(ctx) if ctx.is_dir => Some(FileStatus::AccessDenied),
                    Some(ctx) => match fs.root_dir().open_file(ctx.path.as_str()) {
                        Ok(mut file) => match file.seek(SeekFrom::Start(params.new_size)) {
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
                if let Some(ctx) = tbl.get_mut(&params.fs_file_id) {
                    ctx.size = params.new_size;
                    if ctx.pos > ctx.size {
                        ctx.pos = ctx.size;
                    }
                }
            }

            let res = FsSetLenResult { error: err };
            (DriverStatus::Success, Some(FsReply::SetLen(res)))
        }

        FsWork::Append(params) => {
            vdx.current_owner.store(params.fs_file_id, Ordering::Release);
            let result: Result<(usize, u64), FileStatus> = {
                let tbl = vdx.table.read();
                match tbl.get(&params.fs_file_id) {
                    None => Err(FileStatus::PathNotFound),
                    Some(ctx) if ctx.is_dir => Err(FileStatus::AccessDenied),
                    Some(ctx) => match fs.root_dir().open_file(ctx.path.as_str()) {
                        Ok(mut file) => {
                            let start_off = ctx.size;
                            match file.seek(SeekFrom::Start(start_off)) {
                                Ok(_) => {
                                    let n = params.data.len();
                                    match file.write_all(&params.data) {
                                        Ok(()) => {
                                            if params.write_through {
                                                flush_owner(&vdx, params.fs_file_id);
                                                Ok((n, start_off + n as u64))
                                            } else {
                                                Ok((n, start_off + n as u64))
                                            }
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
                if let Some(ctx) = tbl.get_mut(&params.fs_file_id) {
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
                Err(status) => FsAppendResult {
                    written: 0,
                    new_size: 0,
                    error: Some(status),
                },
            };

            (DriverStatus::Success, Some(FsReply::Append(res)))
        }

        FsWork::ZeroRange(params) => {
            vdx.current_owner.store(params.fs_file_id, Ordering::Release);
            let err = {
                let tbl = vdx.table.read();
                match tbl.get(&params.fs_file_id) {
                    None => Some(FileStatus::PathNotFound),
                    Some(ctx) if ctx.is_dir => Some(FileStatus::AccessDenied),
                    Some(ctx) => match fs.root_dir().open_file(ctx.path.as_str()) {
                        Ok(mut file) => {
                            let file_len = file.seek(SeekFrom::End(0)).unwrap_or(0);
                            let end = params.offset.saturating_add(params.len);
                            if params.offset > file_len {
                                Some(FileStatus::BadPath)
                            } else {
                                let actual_end = end.min(file_len);
                                let zero_len = actual_end.saturating_sub(params.offset);
                                if zero_len == 0 {
                                    None
                                } else {
                                    match file.seek(SeekFrom::Start(params.offset)) {
                                        Ok(_) => {
                                            let zeros = vec![0u8; zero_len as usize];
                                            match file.write_all(&zeros) {
                                                Ok(()) => {
                                                    flush_owner(&vdx, params.fs_file_id);
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

            let res = FsZeroRangeResult { error: err };
            (DriverStatus::Success, Some(FsReply::ZeroRange(res)))
        }

        FsWork::SetInfo | FsWork::Delete => (DriverStatus::NotImplemented, None),
    }
}

fn apply_fs_reply(req: &mut RequestHandle<'_>, reply: Option<FsReply>) {
    if let Some(rep) = reply {
        let mut w = req.write();
        match rep {
            FsReply::Open(v) => w.set_data_t(v),
            FsReply::Close(v) => w.set_data_t(v),
            FsReply::Read(v) => w.set_data_t(v),
            FsReply::Write(v) => w.set_data_t(v),
            FsReply::Seek(v) => w.set_data_t(v),
            FsReply::Flush(v) => w.set_data_t(v),
            FsReply::Create(v) => w.set_data_t(v),
            FsReply::Rename(v) => w.set_data_t(v),
            FsReply::ReadDir(v) => w.set_data_t(v),
            FsReply::GetInfo(v) => w.set_data_t(v),
            FsReply::SetLen(v) => w.set_data_t(v),
            FsReply::Append(v) => w.set_data_t(v),
            FsReply::ZeroRange(v) => w.set_data_t(v),
        }
    }
}

fn handle_seek_fast(dev: &Arc<DeviceObject>, params: FsSeekParams) -> (DriverStatus, FsReply) {
    let vdx = ext_mut::<VolCtrlDevExt>(dev);
    let result = {
        let mut tbl = vdx.table.write();
        match tbl.get_mut(&params.fs_file_id) {
            Some(ctx) => {
                let size = if ctx.is_dir { 0 } else { ctx.size };

                let base: i128 = match params.origin {
                    FsSeekWhence::Set => 0,
                    FsSeekWhence::Cur => ctx.pos as i128,
                    FsSeekWhence::End => size as i128,
                };

                let pos_i = base + params.offset as i128;
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

    (DriverStatus::Success, FsReply::Seek(res))
}

async fn send_flush_dirty(volume_target: &IoTarget) -> DriverStatus {
    let mut flush_req = RequestHandle::new(
        RequestType::FlushDirty {
            should_block: false,
        },
        RequestData::empty(),
    );
    flush_req.set_traversal_policy(TraversalPolicy::ForwardLower);
    pnp_send_request(volume_target.clone(), &mut flush_req).await
}

async fn send_flush_owner(volume_target: &IoTarget, owner: u64) -> DriverStatus {
    let mut flush_req = RequestHandle::new(
        RequestType::FlushOwner {
            owner,
            should_block: false,
        },
        RequestData::empty(),
    );
    flush_req.set_traversal_policy(TraversalPolicy::ForwardLower);
    pnp_send_request(volume_target.clone(), &mut flush_req).await
}

#[request_handler]
pub async fn fs_op_dispatch<'a, 'b>(
    dev: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
) -> DriverStep {
    let (fs_arc, volume_target, flush_flag, pending_flush_owner) = {
        let vdx = ext_mut::<VolCtrlDevExt>(&dev);
        (
            vdx.fs.clone(),
            vdx.volume_target.clone(),
            vdx.should_flush.clone(),
            vdx.pending_flush_owner.clone(),
        )
    };

    let work = match parse_fs_work(req) {
        Ok(w) => w,
        Err(status) => {
            req.write().status = status;
            return DriverStep::complete(status);
        }
    };

    if let FsWork::Seek(params) = work {
        let (status, reply) = handle_seek_fast(dev, params);
        apply_fs_reply(req, Some(reply));
        req.write().status = status;
        return DriverStep::complete(status);
    }

    let dev_cloned = dev.clone();
    let join = spawn_blocking(move || execute_fs_work(&dev_cloned, &fs_arc, work));
    let (status, reply) = join.await;

    apply_fs_reply(req, reply);

    if flush_flag.swap(false, Ordering::AcqRel) {
        let owner = pending_flush_owner.swap(0, Ordering::AcqRel);
        if owner != 0 {
            let _ = send_flush_owner(&volume_target, owner).await;
        } else {
            let _ = send_flush_dirty(&volume_target).await;
        }
    }

    req.write().status = status;
    DriverStep::complete(status)
}
