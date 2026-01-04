#![no_std]

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use kernel_api::kernel_types::async_types::AsyncMutex;
use kernel_api::kernel_types::fs::Path;
use kernel_api::runtime::spawn_blocking;

use fatfs::{
    Dir as FatDirT, Error as FatError, FileSystem as FatFsT, IoBase, LossyOemCpConverter,
    NullTimeProvider, Read, Seek, SeekFrom, Write,
};

use spin::RwLock;

use kernel_api::device::DeviceObject;
use kernel_api::pnp::DriverStep;
use kernel_api::request::{Request, RequestType};
use kernel_api::status::{DriverStatus, FileStatus};
use kernel_api::{
    fs::{
        FileAttribute, FsCloseParams, FsCloseResult, FsCreateParams, FsCreateResult, FsFlushParams,
        FsFlushResult, FsGetInfoParams, FsGetInfoResult, FsListDirParams, FsListDirResult, FsOp,
        FsOpenParams, FsOpenResult, FsReadParams, FsReadResult, FsRenameParams, FsRenameResult,
        FsSeekParams, FsSeekResult, FsSeekWhence, FsWriteParams, FsWriteResult,
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
    pub fs: Arc<AsyncMutex<Fs>>,
    pub(crate) next_id: AtomicU64,
    pub(crate) table: RwLock<BTreeMap<u64, FileCtx>>,
}

pub struct FileCtx {
    path: Path,
    is_dir: bool,
    pos: u64,
}

fn take_typed_params<T: 'static>(req: &Arc<RwLock<Request>>) -> Result<T, DriverStatus> {
    let mut r = req.write();
    r.take_data::<T>().ok_or(DriverStatus::InvalidParameter)
}

fn map_fatfs_err(e: &FsError) -> FileStatus {
    use fatfs::Error::*;
    match e {
        NotFound => FileStatus::PathNotFound,
        AlreadyExists => FileStatus::FileAlreadyExist,
        InvalidInput => FileStatus::BadPath,
        NoSpace => FileStatus::NoSpace,
        CorruptedFileSystem => FileStatus::CorruptFilesystem,
    }
}

fn create_entry(fs: &mut Fs, path: &Path, dir: bool) -> Result<(), FsError> {
    let path_str = path.to_string();
    if dir {
        let _ = fs.root_dir().create_dir(&path_str)?;
    } else {
        let _ = fs.root_dir().create_file(&path_str)?;
    }
    Ok(())
}

fn rename_entry(fs: &mut Fs, src: &Path, dst: &Path) -> Result<(), FsError> {
    let dst_dir = fs.root_dir();
    fs.root_dir()
        .rename(&src.to_string(), &dst_dir, &dst.to_string())
}

fn list_names(fs: &mut Fs, path: &Path) -> Result<Vec<String>, FsError> {
    let dir: FatDir = fs.root_dir().open_dir(&path.to_string())?;
    let mut out = Vec::new();
    for r in dir.iter() {
        let e = r?;
        let name = e.file_name();
        out.push(name);
    }
    Ok(out)
}

fn get_file_len(fs: &mut Fs, path: &Path) -> Result<u64, FsError> {
    let mut file = fs.root_dir().open_file(&path.to_string())?;
    file.seek(SeekFrom::End(0))
}

fn handle_fs_request(
    dev: &Arc<DeviceObject>,
    req: &Arc<RwLock<Request>>,
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

                    let path_str = params.path.to_string();
                    let open_res = {
                        let root = fs.root_dir();

                        match root.open_file(&path_str) {
                            Ok(mut f) => match f.seek(SeekFrom::End(0)) {
                                Ok(end) => Ok((false, end)),
                                Err(e) => Err(e),
                            },
                            Err(FatError::NotFound) | Err(FatError::InvalidInput) => {
                                match root.open_dir(&path_str) {
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

                    let (path, is_dir) = {
                        let tbl = vdx.table.read();
                        match tbl.get(&params.fs_file_id) {
                            Some(ctx) => (ctx.path.clone() as Path, ctx.is_dir),
                            None => {
                                let mut r = req.write();
                            r.set_data_t(FsReadResult {
                                data: Vec::new(),
                                error: Some(FileStatus::PathNotFound),
                            });
                                return DriverStatus::Success;
                            }
                        }
                    };

                    let data_or_err = if is_dir {
                        Err(FileStatus::AccessDenied)
                    } else {
                        match fs.root_dir().open_file(&path.to_string()) {
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
                        Err(status) => {
                            r.set_data_t(FsReadResult {
                                data: Vec::new(),
                                error: Some(status),
                            })
                        }
                    }
                    DriverStatus::Success
                }

                FsOp::Write => {
                    let params: FsWriteParams = match take_typed_params::<FsWriteParams>(req) {
                        Ok(p) => p,
                        Err(st) => return st,
                    };

                    let (path, is_dir) = {
                        let tbl = vdx.table.read();
                        match tbl.get(&params.fs_file_id) {
                            Some(ctx) => (ctx.path.clone(), ctx.is_dir),
                            None => {
                                let mut r = req.write();
                                r.set_data_t(FsWriteResult {
                                    written: 0,
                                    error: Some(FileStatus::PathNotFound),
                                });
                                return DriverStatus::Success;
                            }
                        }
                    };

                    let write_res = if is_dir {
                        Err(FileStatus::AccessDenied)
                    } else {
                        match fs.root_dir().open_file(&path.to_string()) {
                            Ok(mut file) => {
                                let n = params.data.len();
                                if let Err(e) = file.seek(SeekFrom::Start(params.offset)) {
                                    Err(map_fatfs_err(&e))
                                } else {
                                    match file.write_all(&params.data) {
                                        Ok(()) => match file.flush() {
                                            Ok(()) => Ok(n),
                                            Err(e) => Err(map_fatfs_err(&e)),
                                        },
                                        Err(e) => Err(map_fatfs_err(&e)),
                                    }
                                }
                            }
                            Err(e) => Err(map_fatfs_err(&e)),
                        }
                    };

                    // Update position on success
                    if let Ok(written) = write_res {
                        let mut tbl = vdx.table.write();
                        if let Some(ctx) = tbl.get_mut(&params.fs_file_id) {
                            ctx.pos = params.offset.saturating_add(written as u64);
                        }
                    }

                    let mut r = req.write();
                    match write_res {
                        Ok(written) => {
                            r.set_data_t(FsWriteResult {
                                written,
                                error: None,
                            })
                        }
                        Err(status) => {
                            r.set_data_t(FsWriteResult {
                                written: 0,
                                error: Some(status),
                            })
                        }
                    }

                    DriverStatus::Success
                }

                FsOp::Seek => {
                    let params: FsSeekParams = match take_typed_params::<FsSeekParams>(req) {
                        Ok(p) => p,
                        Err(st) => return st,
                    };

                    let result = {
                        let mut tbl = vdx.table.write();
                        match tbl.get_mut(&params.fs_file_id) {
                            Some(ctx) => {
                                let size = if ctx.is_dir {
                                    0
                                } else {
                                    get_file_len(fs, &ctx.path).unwrap_or(0)
                                };

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
                        Ok(pos) => {
                            r.set_data_t(FsSeekResult { pos, error: None })
                        }
                        Err(e) => {
                            r.set_data_t(FsSeekResult {
                                pos: 0,
                                error: Some(e),
                            })
                        }
                    }
                    DriverStatus::Success
                }

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
                            Some(ctx) => match fs.root_dir().open_file(&ctx.path.to_string()) {
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
                        Ok(names) => {
                            r.set_data_t(FsListDirResult { names, error: None })
                        }
                        Err(e) => {
                            r.set_data_t(FsListDirResult {
                                names: Vec::new(),
                                error: Some(map_fatfs_err(&e)),
                            })
                        }
                    }
                    DriverStatus::Success
                }

                FsOp::GetInfo => {
                    let params: FsGetInfoParams = match take_typed_params::<FsGetInfoParams>(req) {
                        Ok(p) => p,
                        Err(st) => return st,
                    };

                    let (path, is_dir) = {
                        let tbl = vdx.table.read();
                        match tbl.get(&params.fs_file_id) {
                            Some(ctx) => (ctx.path.clone(), ctx.is_dir),
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
                        }
                    };

                    let result = if is_dir {
                        Ok((true, 0u64, u8::from(FileAttribute::Directory)))
                    } else {
                        let size = get_file_len(fs, &path).unwrap_or(0);
                        Ok((false, size, u8::from(FileAttribute::Archive)))
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

                FsOp::SetInfo | FsOp::Delete => DriverStatus::NotImplemented,
            }
        }
        RequestType::DeviceControl(_) => DriverStatus::NotImplemented,
        _ => DriverStatus::InvalidParameter,
    }
}

#[request_handler]
pub async fn fs_op_dispatch(dev: Arc<DeviceObject>, req: Arc<RwLock<Request>>) -> DriverStep {
    let fs_arc = {
        let vdx = ext_mut::<VolCtrlDevExt>(&dev);
        vdx.fs.clone()
    };
    let mut fs_guard = fs_arc.lock_owned().await;

    let dev2 = dev.clone();
    let req2 = req.clone();
    let res = spawn_blocking(move || {
        let fs: &mut Fs = &mut *fs_guard;
        handle_fs_request(&dev2, &req2, fs)
    })
    .await;

    DriverStep::complete(res)
}
