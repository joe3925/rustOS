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
use kernel_api::kernel_types::async_types::AsyncMutex;
use kernel_api::kernel_types::fs::Path;
use kernel_api::println;
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
}

pub struct FileCtx {
    path: Path,
    is_dir: bool,
    pos: u64,
    size: u64,
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

fn handle_seek_request(
    dev: &Arc<DeviceObject>,
    req: &mut RequestHandle<'_>,
    _fs: &mut Fs,
) -> DriverStatus {
    let params: FsSeekParams = match take_typed_params::<FsSeekParams>(req) {
        Ok(p) => p,
        Err(st) => return st,
    };

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

    let mut r = req.write();
    match result {
        Ok(pos) => r.set_data_t(FsSeekResult { pos, error: None }),
        Err(e) => r.set_data_t(FsSeekResult {
            pos: 0,
            error: Some(e),
        }),
    }
    DriverStatus::Success
}

fn handle_fs_request(
    dev: &Arc<DeviceObject>,
    req: &mut RequestHandle<'_>,
    fs: &mut Fs,
) -> DriverStatus {
    let kind = { req.read().kind };

    match kind {
        RequestType::Fs(op) => {
            let vdx = ext_mut::<VolCtrlDevExt>(dev);

            match op {
                FsOp::Open => {
                    let params: FsOpenParams = match take_typed_params::<FsOpenParams>(req) {
                        Ok(p) => p,
                        Err(st) => return st,
                    };

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

                    let (fs_file_id, is_dir, size) = match open_res {
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
                            (id, is_dir, size)
                        }
                        Err(e) => {
                            let mut r = req.write();
                            r.set_data_t(FsOpenResult {
                                fs_file_id: 0,
                                is_dir: false,
                                size: 0,
                                error: Some(map_fatfs_err(&e)),
                            });
                            return DriverStatus::Success;
                        }
                    };

                    let mut r = req.write();
                    r.set_data_t(FsOpenResult {
                        fs_file_id,
                        is_dir,
                        size,
                        error: None,
                    });
                    DriverStatus::Success
                }

                FsOp::Close => {
                    let params: FsCloseParams = match take_typed_params::<FsCloseParams>(req) {
                        Ok(p) => p,
                        Err(st) => return st,
                    };

                    let err = {
                        let mut tbl = vdx.table.write();
                        if tbl.remove(&params.fs_file_id).is_some() {
                            None
                        } else {
                            Some(FileStatus::PathNotFound)
                        }
                    };

                    let mut r = req.write();
                    let res = FsCloseResult { error: err };
                    r.set_data_t(res);
                    DriverStatus::Success
                }

                FsOp::Read => {
                    let params: FsReadParams = match take_typed_params::<FsReadParams>(req) {
                        Ok(p) => p,
                        Err(st) => return st,
                    };

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

                    let mut r = req.write();
                    match data_or_err {
                        Ok(v) => {
                            let new_pos = params.offset.saturating_add(v.len() as u64);
                            let mut tbl = vdx.table.write();
                            if let Some(ctx) = tbl.get_mut(&params.fs_file_id) {
                                ctx.pos = new_pos;
                            }
                            r.set_data_t(FsReadResult {
                                data: v,
                                error: None,
                            })
                        }
                        Err(status) => r.set_data_t(FsReadResult {
                            data: Vec::new(),
                            error: Some(status),
                        }),
                    }
                    DriverStatus::Success
                }

                FsOp::Write => {
                    let params: FsWriteParams<'_> =
                        match take_typed_params::<FsWriteParams<'_>>(req) {
                            Ok(p) => p,
                            Err(st) => return st,
                        };

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
                                                    match file.flush() {
                                                        Ok(()) => Ok(n),
                                                        Err(e) => Err(map_fatfs_err(&e)),
                                                    }
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

                    // Update position/size on success
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

                    let mut r = req.write();
                    match write_res {
                        Ok(written) => r.set_data_t(FsWriteResult {
                            written,
                            error: None,
                        }),
                        Err(status) => r.set_data_t(FsWriteResult {
                            written: 0,
                            error: Some(status),
                        }),
                    }

                    DriverStatus::Success
                }

                FsOp::Seek => handle_seek_request(dev, req, fs),

                FsOp::Flush => {
                    let params: FsFlushParams = match take_typed_params::<FsFlushParams>(req) {
                        Ok(p) => p,
                        Err(st) => return st,
                    };

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

                    let mut r = req.write();
                    r.set_data_t(FsFlushResult { error: err });
                    DriverStatus::Success
                }

                FsOp::Create => {
                    let params: FsCreateParams = match take_typed_params::<FsCreateParams>(req) {
                        Ok(p) => p,
                        Err(st) => return st,
                    };

                    let err = {
                        match create_entry(&mut *fs, &params.path, params.dir) {
                            Ok(()) => None,
                            Err(e) => Some(map_fatfs_err(&e)),
                        }
                    };

                    let mut r = req.write();
                    r.set_data_t(FsCreateResult { error: err });
                    DriverStatus::Success
                }

                FsOp::Rename => {
                    let params: FsRenameParams = match take_typed_params::<FsRenameParams>(req) {
                        Ok(p) => p,
                        Err(st) => return st,
                    };

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

                    let mut r = req.write();
                    r.set_data_t(FsRenameResult { error: err });
                    DriverStatus::Success
                }

                FsOp::ReadDir => {
                    let params: FsListDirParams = match take_typed_params::<FsListDirParams>(req) {
                        Ok(p) => p,
                        Err(st) => return st,
                    };

                    let names_or_err = { list_names(&mut *fs, &params.path) };

                    let mut r = req.write();
                    match names_or_err {
                        Ok(names) => r.set_data_t(FsListDirResult { names, error: None }),
                        Err(e) => r.set_data_t(FsListDirResult {
                            names: Vec::new(),
                            error: Some(map_fatfs_err(&e)),
                        }),
                    }
                    DriverStatus::Success
                }

                FsOp::GetInfo => {
                    let params: FsGetInfoParams = match take_typed_params::<FsGetInfoParams>(req) {
                        Ok(p) => p,
                        Err(st) => return st,
                    };

                    let result = {
                        let tbl = vdx.table.read();
                        match tbl.get(&params.fs_file_id) {
                            None => {
                                let mut r = req.write();
                                r.set_data_t(FsGetInfoResult {
                                    size: 0,
                                    is_dir: false,
                                    attrs: 0,
                                    error: Some(FileStatus::PathNotFound),
                                });
                                return DriverStatus::Success;
                            }
                            Some(ctx) if ctx.is_dir => {
                                Ok((true, 0u64, u8::from(FileAttribute::Directory)))
                            }
                            Some(ctx) => Ok((false, ctx.size, u8::from(FileAttribute::Archive))),
                        }
                    };

                    let mut r = req.write();
                    match result {
                        Ok((is_dir, size, attrs)) => {
                            r.set_data_t(FsGetInfoResult {
                                size,
                                is_dir,
                                attrs: attrs as u32,
                                error: None,
                            });
                        }
                        Err(e) => {
                            r.set_data_t(FsGetInfoResult {
                                size: 0,
                                is_dir: false,
                                attrs: 0,
                                error: Some(e),
                            });
                        }
                    }
                    DriverStatus::Success
                }

                FsOp::SetLen => {
                    let params: FsSetLenParams = match take_typed_params::<FsSetLenParams>(req) {
                        Ok(p) => p,
                        Err(st) => return st,
                    };

                    let err = {
                        let tbl = vdx.table.read();
                        match tbl.get(&params.fs_file_id) {
                            None => Some(FileStatus::PathNotFound),
                            Some(ctx) if ctx.is_dir => Some(FileStatus::AccessDenied),
                            Some(ctx) => match fs.root_dir().open_file(ctx.path.as_str()) {
                                Ok(mut file) => match file.seek(SeekFrom::Start(params.new_size)) {
                                    Ok(_) => match file.truncate() {
                                        Ok(()) => match file.flush() {
                                            Ok(()) => None,
                                            Err(e) => Some(map_fatfs_err(&e)),
                                        },
                                        Err(e) => Some(map_fatfs_err(&e)),
                                    },
                                    Err(e) => Some(map_fatfs_err(&e)),
                                },
                                Err(e) => Some(map_fatfs_err(&e)),
                            },
                        }
                    };

                    let mut r = req.write();
                    r.set_data_t(FsSetLenResult { error: err });
                    if err.is_none() {
                        let mut tbl = vdx.table.write();
                        if let Some(ctx) = tbl.get_mut(&params.fs_file_id) {
                            ctx.size = params.new_size;
                            if ctx.pos > ctx.size {
                                ctx.pos = ctx.size;
                            }
                        }
                    }
                    DriverStatus::Success
                }

                FsOp::Append => {
                    let params: FsAppendParams<'_> =
                        match take_typed_params::<FsAppendParams<'_>>(req) {
                            Ok(p) => p,
                            Err(st) => return st,
                        };

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
                                                        match file.flush() {
                                                            Ok(()) => Ok((n, start_off + n as u64)),
                                                            Err(e) => Err(map_fatfs_err(&e)),
                                                        }
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

                    // Update position/size on success
                    if let Ok((_, new_size)) = result {
                        let mut tbl = vdx.table.write();
                        if let Some(ctx) = tbl.get_mut(&params.fs_file_id) {
                            ctx.pos = new_size;
                            ctx.size = new_size;
                        }
                    }

                    let mut r = req.write();
                    match result {
                        Ok((written, new_size)) => r.set_data_t(FsAppendResult {
                            written,
                            new_size,
                            error: None,
                        }),
                        Err(status) => r.set_data_t(FsAppendResult {
                            written: 0,
                            new_size: 0,
                            error: Some(status),
                        }),
                    }
                    DriverStatus::Success
                }

                FsOp::ZeroRange => {
                    let params: FsZeroRangeParams =
                        match take_typed_params::<FsZeroRangeParams>(req) {
                            Ok(p) => p,
                            Err(st) => return st,
                        };

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
                                                        Ok(()) => match file.flush() {
                                                            Ok(()) => None,
                                                            Err(e) => Some(map_fatfs_err(&e)),
                                                        },
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

                    let mut r = req.write();
                    r.set_data_t(FsZeroRangeResult { error: err });
                    DriverStatus::Success
                }

                FsOp::SetInfo | FsOp::Delete => DriverStatus::NotImplemented,
            }
        }
        RequestType::DeviceControl(_) => DriverStatus::NotImplemented,
        _ => DriverStatus::InvalidParameter,
    }
}

async fn send_flush_dirty(volume_target: &IoTarget) -> DriverStatus {
    let mut flush_req = RequestHandle::new(RequestType::Flush, RequestData::empty());
    flush_req.set_traversal_policy(TraversalPolicy::ForwardLower);
    pnp_send_request(volume_target.clone(), &mut flush_req).await
}

#[request_handler]
pub async fn fs_op_dispatch<'a, 'b>(
    dev: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
) -> DriverStep {
    let vdx = ext_mut::<VolCtrlDevExt>(&dev);
    let fs_arc = vdx.fs.clone();
    let volume_target = vdx.volume_target.clone();
    let mut fs_guard = fs_arc.lock();

    let status = if matches!(req.read().kind, RequestType::Fs(FsOp::Seek)) {
        handle_seek_request(&dev, req, &mut fs_guard)
    } else {
        // Todo: change this to spawn blocking when I fix request promotion
        handle_fs_request(&dev, req, &mut fs_guard)
    };

    if vdx.should_flush.swap(false, Ordering::AcqRel) {
        if matches!(req.read().kind, RequestType::Fs(FsOp::Read)) {
            // TODO: not sure why this case happens fix this at some point.
            req.write().status = status;
            return DriverStep::complete(status);
        }

        let _ = send_flush_dirty(&volume_target).await;
    }

    req.write().status = status;
    DriverStep::complete(status)
}
