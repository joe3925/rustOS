#![no_std]

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use core::mem::size_of;
use core::sync::atomic::{AtomicU64, Ordering};

use fatfs::{
    Dir as FatDirT, Error as FatError, File as FatFileT, FileSystem as FatFsT, IoBase,
    LossyOemCpConverter, NullTimeProvider, Read, Seek, SeekFrom, Write,
};

use spin::{Mutex, RwLock};

use kernel_api::{
    DevExtRefMut, DeviceObject, DriverStatus, FileStatus, FsCloseParams, FsCloseResult,
    FsCreateParams, FsCreateResult, FsFlushParams, FsFlushResult, FsGetInfoParams, FsGetInfoResult,
    FsListDirParams, FsListDirResult, FsOp, FsOpenParams, FsOpenResult, FsReadParams, FsReadResult,
    FsRenameParams, FsRenameResult, FsSeekParams, FsSeekResult, FsSeekWhence, FsWriteParams,
    FsWriteResult, Request, RequestType, println,
};

use crate::block_dev::BlockDev;
use crate::control::ext_mut;

// ---- Explicit fatfs type aliases (old fatfs requires TP/OCC generics) ----
type FatDev = BlockDev;
type TP = NullTimeProvider;
type OCC = LossyOemCpConverter;

type Fs = FatFsT<FatDev, TP, OCC>;
type FatFile<'a> = FatFileT<'a, FatDev, TP, OCC>;
type FatDir<'a> = FatDirT<'a, FatDev, TP, OCC>;
type FsError = FatError<<FatDev as IoBase>::Error>; // = fatfs::Error<()>

#[repr(C)]
pub struct VolCtrlDevExt {
    pub fs: Mutex<Fs>, // <- expect a Mutex-wrapped filesystem
    pub(crate) next_id: AtomicU64,
    pub(crate) table: RwLock<BTreeMap<u64, FileCtx>>,
}

#[derive(Clone)]
pub struct FileCtx {
    path: String,
    is_dir: bool,
    pos: u64,
}

fn box_to_bytes<T>(b: Box<T>) -> Box<[u8]> {
    let len = size_of::<T>();
    let p = Box::into_raw(b) as *mut u8;
    unsafe { Box::from_raw(core::slice::from_raw_parts_mut(p, len)) }
}
unsafe fn bytes_to_box<T>(b: Box<[u8]>) -> Box<T> {
    let p = Box::into_raw(b) as *mut u8 as *mut T;
    Box::from_raw(p)
}

fn map_fatfs_err(e: &FsError) -> FileStatus {
    use fatfs::Error::*;
    match e {
        NotFound => FileStatus::PathNotFound,
        AlreadyExists => FileStatus::FileAlreadyExist,
        InvalidInput => FileStatus::BadPath,
        NoSpace => FileStatus::UnknownFail,
        CorruptedFileSystem => FileStatus::CorruptFilesystem,
    }
}

fn is_dir(fs: &mut Fs, path: &str) -> Result<bool, FsError> {
    if fs.root_dir().open_dir(path).is_ok() {
        return Ok(true);
    }
    if fs.root_dir().open_file(path).is_ok() {
        return Ok(false);
    }
    Err(FatError::NotFound)
}

fn file_len(fs: &mut Fs, path: &str) -> Result<u64, FsError> {
    let mut f = fs.root_dir().open_file(path)?;
    let end = f.seek(SeekFrom::End(0))?;
    Ok(end)
}

fn read_slice(fs: &mut Fs, path: &str, offset: u64, len: usize) -> Result<Vec<u8>, FsError> {
    let mut f = fs.root_dir().open_file(path)?;
    let _ = f.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; len];
    let n = f.read(&mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

fn open_rw_create<'fs>(fs: &'fs mut Fs, path: &str) -> Result<FatFile<'fs>, FsError> {
    match fs.root_dir().open_file(path) {
        Ok(f) => Ok(f),
        Err(e) => match e {
            FatError::NotFound => {
                fs.root_dir().create_file(path)?;
                fs.root_dir().open_file(path)
            }
            other => Err(other),
        },
    }
}

fn write_slice(fs: &mut Fs, path: &str, offset: u64, data: &[u8]) -> Result<usize, FsError> {
    let mut f = open_rw_create(fs, path)?;
    let _ = f.seek(SeekFrom::Start(offset))?;
    f.write(data)
}

fn create_entry(fs: &mut Fs, path: &str, dir: bool) -> Result<(), FsError> {
    if dir {
        let _ = fs.root_dir().create_dir(path)?;
    } else {
        let _ = fs.root_dir().create_file(path)?;
    }
    Ok(())
}

fn rename_entry(fs: &mut Fs, src: &str, dst: &str) -> Result<(), FsError> {
    let dst_dir = fs.root_dir();
    fs.root_dir().rename(src, &dst_dir, dst)
}

fn list_names(fs: &mut Fs, path: &str) -> Result<Vec<String>, FsError> {
    let dir = fs.root_dir().open_dir(path)?;
    let mut out = Vec::new();
    for r in dir.iter() {
        let e = r?;
        let name = e.file_name();
        out.push(name);
    }
    Ok(out)
}

pub extern "win64" fn fs_op_dispatch(dev: &Arc<DeviceObject>, req: Arc<RwLock<Request>>) {
    let kind = { req.read().kind };
    match kind {
        RequestType::Fs(op) => {
            let mut r = req.write();
            let vdx = ext_mut::<VolCtrlDevExt>(dev);

            // Pre-acquire everything in a fixed order
            let mut tbl_opt = Some(vdx.table.write());
            let mut fs_opt = Some(vdx.fs.lock());

            match op {
                FsOp::Open => {
                    let params: FsOpenParams = unsafe {
                        if r.data.len() != size_of::<FsOpenParams>() {
                            r.status = DriverStatus::InvalidParameter;
                            return;
                        }
                        *bytes_to_box(core::mem::replace(&mut r.data, Box::new([])))
                    };

                    // use fs
                    let (ok_dir, size_or_err) = {
                        let fs = fs_opt.as_mut().unwrap();
                        match is_dir(&mut *fs, &params.path) {
                            Ok(true) => (true, Ok(0)),
                            Ok(false) => (false, file_len(&mut *fs, &params.path)),
                            Err(e) => (false, Err(e)),
                        }
                    };

                    match size_or_err {
                        Err(e) => {
                            let res = FsOpenResult {
                                fs_file_id: 0,
                                is_dir: false,
                                size: 0,
                                error: Some(map_fatfs_err(&e)),
                            };
                            r.data = box_to_bytes(Box::new(res));
                            r.status = DriverStatus::Success;
                        }
                        Ok(size) => {
                            let id = vdx.next_id.fetch_add(1, Ordering::AcqRel).max(1);
                            let tbl = tbl_opt.as_mut().unwrap();
                            tbl.insert(
                                id,
                                FileCtx {
                                    path: params.path.clone(),
                                    is_dir: ok_dir,
                                    pos: 0,
                                },
                            );

                            let res = FsOpenResult {
                                fs_file_id: id,
                                is_dir: ok_dir,
                                size,
                                error: None,
                            };
                            r.data = box_to_bytes(Box::new(res));
                            r.status = DriverStatus::Success;
                        }
                    }
                }

                FsOp::Close => {
                    // fs not needed here
                    drop(fs_opt.take());

                    let params: FsCloseParams = unsafe {
                        if r.data.len() != size_of::<FsCloseParams>() {
                            r.status = DriverStatus::InvalidParameter;
                            return;
                        }
                        *bytes_to_box(core::mem::replace(&mut r.data, Box::new([])))
                    };

                    let removed = {
                        let tbl = tbl_opt.as_mut().unwrap();
                        tbl.remove(&params.fs_file_id).is_some()
                    };

                    let res = FsCloseResult {
                        error: if removed {
                            None
                        } else {
                            Some(FileStatus::PathNotFound)
                        },
                    };
                    r.data = box_to_bytes(Box::new(res));
                    r.status = DriverStatus::Success;
                }

                FsOp::Read => {
                    let params: FsReadParams = unsafe {
                        if r.data.len() != size_of::<FsReadParams>() {
                            r.status = DriverStatus::InvalidParameter;
                            return;
                        }
                        *bytes_to_box(core::mem::replace(&mut r.data, Box::new([])))
                    };

                    // read ctx from table
                    let ctx = {
                        let tbl = tbl_opt.as_ref().unwrap();
                        tbl.get(&params.fs_file_id).cloned()
                    };
                    if ctx.is_none() {
                        r.data = box_to_bytes(Box::new(FsReadResult {
                            data: Vec::new(),
                            error: Some(FileStatus::PathNotFound),
                        }));
                        r.status = DriverStatus::Success;
                        return;
                    }
                    let ctx = ctx.unwrap();
                    if ctx.is_dir {
                        r.data = box_to_bytes(Box::new(FsReadResult {
                            data: Vec::new(),
                            error: Some(FileStatus::PathNotFound),
                        }));
                        r.status = DriverStatus::Success;
                        return;
                    }

                    let data_or_err = {
                        let fs = fs_opt.as_mut().unwrap();
                        read_slice(&mut *fs, &ctx.path, params.offset as u64, params.len)
                    };

                    match data_or_err {
                        Ok(v) => {
                            r.data = box_to_bytes(Box::new(FsReadResult {
                                data: v,
                                error: None,
                            }))
                        }
                        Err(e) => {
                            r.data = box_to_bytes(Box::new(FsReadResult {
                                data: Vec::new(),
                                error: Some(map_fatfs_err(&e)),
                            }))
                        }
                    }
                    r.status = DriverStatus::Success;
                }

                FsOp::Write => {
                    let params: FsWriteParams = unsafe {
                        if r.data.len() != size_of::<FsWriteParams>() {
                            r.status = DriverStatus::InvalidParameter;
                            return;
                        }
                        *bytes_to_box(core::mem::replace(&mut r.data, Box::new([])))
                    };

                    let ctx = {
                        let tbl = tbl_opt.as_ref().unwrap();
                        tbl.get(&params.fs_file_id).cloned()
                    };
                    if ctx.is_none() {
                        r.data = box_to_bytes(Box::new(FsWriteResult {
                            written: 0,
                            error: Some(FileStatus::PathNotFound),
                        }));
                        r.status = DriverStatus::Success;
                        return;
                    }
                    let ctx = ctx.unwrap();
                    if ctx.is_dir {
                        r.data = box_to_bytes(Box::new(FsWriteResult {
                            written: 0,
                            error: Some(FileStatus::PathNotFound),
                        }));
                        r.status = DriverStatus::Success;
                        return;
                    }

                    let write_res = {
                        let fs = fs_opt.as_mut().unwrap();
                        write_slice(&mut *fs, &ctx.path, params.offset as u64, &params.data)
                    };

                    match write_res {
                        Ok(n) => {
                            r.data = box_to_bytes(Box::new(FsWriteResult {
                                written: n,
                                error: None,
                            }))
                        }
                        Err(e) => {
                            r.data = box_to_bytes(Box::new(FsWriteResult {
                                written: 0,
                                error: Some(map_fatfs_err(&e)),
                            }))
                        }
                    }
                    r.status = DriverStatus::Success;
                }

                FsOp::Seek => {
                    let params: FsSeekParams = unsafe {
                        if r.data.len() != size_of::<FsSeekParams>() {
                            r.status = DriverStatus::InvalidParameter;
                            return;
                        }
                        *bytes_to_box(core::mem::replace(&mut r.data, Box::new([])))
                    };

                    let snap = {
                        let tbl = tbl_opt.as_ref().unwrap();
                        tbl.get(&params.fs_file_id)
                            .map(|c| (c.path.clone(), c.is_dir, c.pos))
                    };
                    if snap.is_none() {
                        r.data = box_to_bytes(Box::new(FsSeekResult {
                            pos: 0,
                            error: Some(FileStatus::PathNotFound),
                        }));
                        r.status = DriverStatus::Success;
                        return;
                    }
                    let (path, is_dir, cur_pos) = snap.unwrap();

                    let size = if is_dir {
                        0
                    } else {
                        let fs = fs_opt.as_mut().unwrap();
                        file_len(&mut *fs, &path).unwrap_or(0)
                    };

                    let newpos_i = match params.origin {
                        FsSeekWhence::Set => params.offset as i128,
                        FsSeekWhence::Cur => cur_pos as i128 + params.offset as i128,
                        FsSeekWhence::End => size as i128 + params.offset as i128,
                    };
                    let clamped = if newpos_i < 0 { 0 } else { newpos_i as u64 };

                    {
                        let tbl = tbl_opt.as_mut().unwrap();
                        if let Some(c) = tbl.get_mut(&params.fs_file_id) {
                            c.pos = clamped;
                        } else {
                            r.data = box_to_bytes(Box::new(FsSeekResult {
                                pos: 0,
                                error: Some(FileStatus::PathNotFound),
                            }));
                            r.status = DriverStatus::Success;
                            return;
                        }
                    }

                    r.data = box_to_bytes(Box::new(FsSeekResult {
                        pos: clamped,
                        error: None,
                    }));
                    r.status = DriverStatus::Success;
                }

                FsOp::Flush => {
                    // drop locks not needed
                    drop(fs_opt.take());
                    // table not used either
                    drop(tbl_opt.take());

                    let _params: FsFlushParams = unsafe {
                        if r.data.len() != size_of::<FsFlushParams>() {
                            r.status = DriverStatus::InvalidParameter;
                            return;
                        }
                        *bytes_to_box(core::mem::replace(&mut r.data, Box::new([])))
                    };
                    r.data = box_to_bytes(Box::new(FsFlushResult { error: None }));
                    r.status = DriverStatus::Success;
                }

                FsOp::Create => {
                    // table not needed
                    drop(tbl_opt.take());

                    let params: FsCreateParams = unsafe {
                        if r.data.len() != size_of::<FsCreateParams>() {
                            r.status = DriverStatus::InvalidParameter;
                            return;
                        }
                        *bytes_to_box(core::mem::replace(&mut r.data, Box::new([])))
                    };

                    let err = {
                        let fs = fs_opt.as_mut().unwrap();
                        match create_entry(&mut *fs, &params.path, params.dir) {
                            Ok(()) => None,
                            Err(e) => Some(map_fatfs_err(&e)),
                        }
                    };

                    r.data = box_to_bytes(Box::new(FsCreateResult { error: err }));
                    r.status = DriverStatus::Success;
                }

                FsOp::Rename => {
                    // table not needed
                    drop(tbl_opt.take());

                    let params: FsRenameParams = unsafe {
                        if r.data.len() != size_of::<FsRenameParams>() {
                            r.status = DriverStatus::InvalidParameter;
                            return;
                        }
                        *bytes_to_box(core::mem::replace(&mut r.data, Box::new([])))
                    };

                    let err = {
                        let fs = fs_opt.as_mut().unwrap();
                        match rename_entry(&mut *fs, &params.src, &params.dst) {
                            Ok(()) => None,
                            Err(e) => Some(map_fatfs_err(&e)),
                        }
                    };

                    r.data = box_to_bytes(Box::new(FsRenameResult { error: err }));
                    r.status = DriverStatus::Success;
                }

                FsOp::ReadDir => {
                    // table not needed
                    drop(tbl_opt.take());

                    let params: FsListDirParams = unsafe {
                        if r.data.len() != size_of::<FsListDirParams>() {
                            r.status = DriverStatus::InvalidParameter;
                            return;
                        }
                        *bytes_to_box(core::mem::replace(&mut r.data, Box::new([])))
                    };

                    let names_or_err = {
                        let fs = fs_opt.as_mut().unwrap();
                        list_names(&mut *fs, &params.path)
                    };

                    match names_or_err {
                        Ok(names) => {
                            r.data = box_to_bytes(Box::new(FsListDirResult { names, error: None }))
                        }
                        Err(e) => {
                            r.data = box_to_bytes(Box::new(FsListDirResult {
                                names: Vec::new(),
                                error: Some(map_fatfs_err(&e)),
                            }))
                        }
                    }
                    r.status = DriverStatus::Success;
                }

                FsOp::GetInfo => {
                    let params: FsGetInfoParams = unsafe {
                        if r.data.len() != size_of::<FsGetInfoParams>() {
                            r.status = DriverStatus::InvalidParameter;
                            return;
                        }
                        *bytes_to_box(core::mem::replace(&mut r.data, Box::new([])))
                    };

                    let ctx = {
                        let tbl = tbl_opt.as_ref().unwrap();
                        tbl.get(&params.fs_file_id).cloned()
                    };
                    if ctx.is_none() {
                        r.data = box_to_bytes(Box::new(FsGetInfoResult {
                            size: 0,
                            is_dir: false,
                            attrs: 0,
                            error: Some(FileStatus::PathNotFound),
                        }));
                        r.status = DriverStatus::Success;
                        return;
                    }
                    let ctx = ctx.unwrap();

                    let (size, attrs) = if ctx.is_dir {
                        (0u64, u8::from(kernel_api::FileAttribute::Directory))
                    } else {
                        let fs = fs_opt.as_mut().unwrap();
                        (
                            file_len(&mut *fs, &ctx.path).unwrap_or(0),
                            u8::from(kernel_api::FileAttribute::Archive),
                        )
                    };

                    r.data = box_to_bytes(Box::new(FsGetInfoResult {
                        size,
                        is_dir: ctx.is_dir,
                        attrs: attrs as u32,
                        error: None,
                    }));
                    r.status = DriverStatus::Success;
                }

                FsOp::SetInfo => {
                    // nothing uses fs/table; drop both
                    drop(fs_opt.take());
                    drop(tbl_opt.take());
                    r.status = DriverStatus::NotImplemented;
                }
                FsOp::Delete => {
                    drop(fs_opt.take());
                    drop(tbl_opt.take());
                    r.status = DriverStatus::NotImplemented;
                }
            }
        }

        RequestType::DeviceControl(_code) => {
            req.write().status = DriverStatus::NotImplemented;
        }
        _ => {
            req.write().status = DriverStatus::InvalidParameter;
        }
    }
}

pub fn test_fs_readdir(dev: &Arc<DeviceObject>, path: &str) -> Result<Vec<String>, FileStatus> {
    let params = FsListDirParams {
        path: path.to_string(),
    };
    let req = Request::new(
        RequestType::Fs(FsOp::ReadDir),
        box_to_bytes(Box::new(params)),
    );

    let areq = Arc::new(RwLock::new(req));
    fs_op_dispatch(dev, areq.clone());

    let mut guard = areq.write();
    if guard.status != DriverStatus::Success {
        return Err(FileStatus::UnknownFail);
    }

    let result: FsListDirResult = unsafe {
        if guard.data.len() != core::mem::size_of::<FsListDirResult>() {
            return Err(FileStatus::CorruptFilesystem);
        }
        *bytes_to_box(core::mem::replace(&mut guard.data, Box::new([])))
    };

    match result.error {
        None => Ok(result.names),
        Some(e) => Err(e),
    }
}
