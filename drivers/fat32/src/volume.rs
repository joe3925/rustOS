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
    DevExtRefMut, DeviceObject, DriverStatus, FileAttribute, FileStatus, FsCloseParams,
    FsCloseResult, FsCreateParams, FsCreateResult, FsFlushParams, FsFlushResult, FsGetInfoParams,
    FsGetInfoResult, FsListDirParams, FsListDirResult, FsOp, FsOpenParams, FsOpenResult,
    FsReadParams, FsReadResult, FsRenameParams, FsRenameResult, FsSeekParams, FsSeekResult,
    FsSeekWhence, FsWriteParams, FsWriteResult, Request, RequestType, println,
};

use crate::block_dev::BlockDev;
use crate::control::ext_mut;

type FatDev = BlockDev;
type TP = NullTimeProvider;
type OCC = LossyOemCpConverter;

type Fs = FatFsT<FatDev, TP, OCC>;
type FatFile<'a> = FatFileT<'a, FatDev, TP, OCC>;
type FatDir<'a> = FatDirT<'a, FatDev, TP, OCC>;
type FsError = FatError<<FatDev as IoBase>::Error>;

#[repr(C)]
pub struct VolCtrlDevExt {
    pub fs: Mutex<Fs>,
    pub(crate) next_id: AtomicU64,
    pub(crate) table: RwLock<BTreeMap<u64, FileCtx>>,
}

pub struct CachedFile {
    file: FatFile<'static>,
}

unsafe impl Send for CachedFile {}
unsafe impl Sync for CachedFile {}

pub struct FileCtx {
    path: String,
    is_dir: bool,
    pos: u64,
    file: Option<CachedFile>,
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
    let dir: FatDir = fs.root_dir().open_dir(path)?;
    let mut out = Vec::new();
    for r in dir.iter() {
        let e = r?;
        let name = e.file_name();
        out.push(name);
    }
    Ok(out)
}

fn cached_file_len(file: &mut FatFile<'static>) -> Result<u64, FsError> {
    let cur = file.seek(SeekFrom::Current(0))?;
    let end = file.seek(SeekFrom::End(0))?;
    let _ = file.seek(SeekFrom::Start(cur))?;
    Ok(end)
}

pub extern "win64" fn fs_op_dispatch(
    dev: &Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
) -> DriverStatus {
    let kind = { req.read().kind };
    match kind {
        RequestType::Fs(op) => {
            let mut r = req.write();
            let vdx = ext_mut::<VolCtrlDevExt>(dev);

            let mut tbl_opt = Some(vdx.table.write());
            let mut fs_opt = Some(vdx.fs.lock());

            match op {
                FsOp::Open => {
                    let params: FsOpenParams = unsafe {
                        if r.data.len() != size_of::<FsOpenParams>() {
                            return DriverStatus::InvalidParameter;
                        }
                        *bytes_to_box(core::mem::replace(&mut r.data, Box::new([])))
                    };

                    let open_res: Result<(bool, u64, Option<CachedFile>), FsError> = {
                        let fs = fs_opt.as_mut().unwrap();
                        let root = fs.root_dir();

                        match root.open_file(&params.path) {
                            Ok(mut f) => match f.seek(SeekFrom::End(0)) {
                                Ok(end) => {
                                    let f_static: FatFile<'static> =
                                        unsafe { core::mem::transmute(f) };
                                    Ok((false, end, Some(CachedFile { file: f_static })))
                                }
                                Err(e) => Err(e),
                            },
                            Err(FatError::NotFound) | Err(FatError::InvalidInput) => {
                                match root.open_dir(&params.path) {
                                    Ok(_d) => Ok((true, 0, None)),
                                    Err(e) => Err(e),
                                }
                            }
                            Err(e) => Err(e),
                        }
                    };

                    match open_res {
                        Err(e) => {
                            let res = FsOpenResult {
                                fs_file_id: 0,
                                is_dir: false,
                                size: 0,
                                error: Some(map_fatfs_err(&e)),
                            };
                            r.data = box_to_bytes(Box::new(res));
                        }
                        Ok((is_dir, size, cached)) => {
                            let id = vdx.next_id.fetch_add(1, Ordering::AcqRel).max(1);

                            let tbl = tbl_opt.as_mut().unwrap();
                            tbl.insert(
                                id,
                                FileCtx {
                                    path: params.path.clone(),
                                    is_dir,
                                    pos: 0,
                                    file: cached,
                                },
                            );

                            let res = FsOpenResult {
                                fs_file_id: id,
                                is_dir,
                                size,
                                error: None,
                            };
                            r.data = box_to_bytes(Box::new(res));
                        }
                    }
                    DriverStatus::Success
                }

                FsOp::Close => {
                    drop(fs_opt.take());

                    let params: FsCloseParams = unsafe {
                        if r.data.len() != size_of::<FsCloseParams>() {
                            return DriverStatus::InvalidParameter;
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
                    DriverStatus::Success
                }

                FsOp::Read => {
                    let params: FsReadParams = unsafe {
                        if r.data.len() != size_of::<FsReadParams>() {
                            return DriverStatus::InvalidParameter;
                        }
                        *bytes_to_box(core::mem::replace(&mut r.data, Box::new([])))
                    };

                    let data_or_err = {
                        let tbl = tbl_opt.as_mut().unwrap();
                        let ctx = match tbl.get_mut(&params.fs_file_id) {
                            Some(c) => c,
                            None => {
                                r.data = box_to_bytes(Box::new(FsReadResult {
                                    data: Vec::new(),
                                    error: Some(FileStatus::PathNotFound),
                                }));
                                return DriverStatus::Success;
                            }
                        };

                        if ctx.is_dir {
                            r.data = box_to_bytes(Box::new(FsReadResult {
                                data: Vec::new(),
                                error: Some(FileStatus::PathNotFound),
                            }));
                            return DriverStatus::Success;
                        }

                        let _fs_guard = fs_opt.as_mut().unwrap();

                        let cached_opt = ctx.file.as_mut();
                        if cached_opt.is_none() {
                            Err(FatError::NotFound)
                        } else {
                            let file = &mut cached_opt.unwrap().file;

                            match file.seek(SeekFrom::Start(params.offset as u64)) {
                                Err(e) => Err(e),
                                Ok(_) => {
                                    let mut buf = vec![0u8; params.len];
                                    match file.read(&mut buf) {
                                        Ok(n) => {
                                            buf.truncate(n);
                                            Ok(buf)
                                        }
                                        Err(e) => Err(e),
                                    }
                                }
                            }
                        }
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
                    DriverStatus::Success
                }

                FsOp::Write => {
                    let params: FsWriteParams = unsafe {
                        if r.data.len() != size_of::<FsWriteParams>() {
                            return DriverStatus::InvalidParameter;
                        }
                        *bytes_to_box(core::mem::replace(&mut r.data, Box::new([])))
                    };

                    let write_res = {
                        let tbl = tbl_opt.as_mut().unwrap();
                        let ctx = match tbl.get_mut(&params.fs_file_id) {
                            Some(c) => c,
                            None => {
                                r.data = box_to_bytes(Box::new(FsWriteResult {
                                    written: 0,
                                    error: Some(FileStatus::PathNotFound),
                                }));
                                return DriverStatus::Success;
                            }
                        };

                        if ctx.is_dir {
                            r.data = box_to_bytes(Box::new(FsWriteResult {
                                written: 0,
                                error: Some(FileStatus::PathNotFound),
                            }));
                            return DriverStatus::Success;
                        }

                        let _fs_guard = fs_opt.as_mut().unwrap();

                        let cached_opt = ctx.file.as_mut();
                        if cached_opt.is_none() {
                            Err(FatError::NotFound)
                        } else {
                            let file = &mut cached_opt.unwrap().file;

                            match file.seek(SeekFrom::Start(params.offset as u64)) {
                                Err(e) => Err(e),
                                Ok(_) => file.write(&params.data),
                            }
                        }
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
                    DriverStatus::Success
                }

                FsOp::Seek => {
                    let params: FsSeekParams = unsafe {
                        if r.data.len() != size_of::<FsSeekParams>() {
                            return DriverStatus::InvalidParameter;
                        }
                        *bytes_to_box(core::mem::replace(&mut r.data, Box::new([])))
                    };

                    let new_pos = {
                        let tbl = tbl_opt.as_mut().unwrap();
                        let ctx = match tbl.get_mut(&params.fs_file_id) {
                            Some(c) => c,
                            None => {
                                r.data = box_to_bytes(Box::new(FsSeekResult {
                                    pos: 0,
                                    error: Some(FileStatus::PathNotFound),
                                }));
                                return DriverStatus::Success;
                            }
                        };

                        let size = if ctx.is_dir {
                            0
                        } else {
                            let _fs_guard = fs_opt.as_mut().unwrap();
                            if let Some(ref mut cached) = ctx.file {
                                match cached_file_len(&mut cached.file) {
                                    Ok(sz) => sz,
                                    Err(_) => 0,
                                }
                            } else {
                                0
                            }
                        };

                        let base: i128 = match params.origin {
                            FsSeekWhence::Set => 0,
                            FsSeekWhence::Cur => ctx.pos as i128,
                            FsSeekWhence::End => size as i128,
                        };

                        let pos_i = base + params.offset as i128;
                        let clamped = if pos_i < 0 { 0 } else { pos_i as u64 };
                        ctx.pos = clamped;
                        clamped
                    };

                    r.data = box_to_bytes(Box::new(FsSeekResult {
                        pos: new_pos,
                        error: None,
                    }));
                    DriverStatus::Success
                }

                FsOp::Flush => {
                    drop(fs_opt.take());
                    drop(tbl_opt.take());

                    let _params: FsFlushParams = unsafe {
                        if r.data.len() != size_of::<FsFlushParams>() {
                            return DriverStatus::InvalidParameter;
                        }
                        *bytes_to_box(core::mem::replace(&mut r.data, Box::new([])))
                    };
                    r.data = box_to_bytes(Box::new(FsFlushResult { error: None }));
                    DriverStatus::Success
                }

                FsOp::Create => {
                    drop(tbl_opt.take());

                    let params: FsCreateParams = unsafe {
                        if r.data.len() != size_of::<FsCreateParams>() {
                            return DriverStatus::InvalidParameter;
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
                    DriverStatus::Success
                }

                FsOp::Rename => {
                    drop(tbl_opt.take());

                    let params: FsRenameParams = unsafe {
                        if r.data.len() != size_of::<FsRenameParams>() {
                            return DriverStatus::InvalidParameter;
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
                    DriverStatus::Success
                }

                FsOp::ReadDir => {
                    drop(tbl_opt.take());

                    let params: FsListDirParams = unsafe {
                        if r.data.len() != size_of::<FsListDirParams>() {
                            return DriverStatus::InvalidParameter;
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
                    DriverStatus::Success
                }

                FsOp::GetInfo => {
                    let params: FsGetInfoParams = unsafe {
                        if r.data.len() != size_of::<FsGetInfoParams>() {
                            return DriverStatus::InvalidParameter;
                        }
                        *bytes_to_box(core::mem::replace(&mut r.data, Box::new([])))
                    };

                    let (is_dir, size, attrs) = {
                        let tbl = tbl_opt.as_mut().unwrap();
                        let ctx = match tbl.get_mut(&params.fs_file_id) {
                            None => {
                                r.data = box_to_bytes(Box::new(FsGetInfoResult {
                                    size: 0,
                                    is_dir: false,
                                    attrs: 0,
                                    error: Some(FileStatus::PathNotFound),
                                }));
                                return DriverStatus::Success;
                            }
                            Some(c) => c,
                        };

                        if ctx.is_dir {
                            (true, 0u64, u8::from(FileAttribute::Directory))
                        } else {
                            let _fs_guard = fs_opt.as_mut().unwrap();
                            let size = if let Some(ref mut cached) = ctx.file {
                                match cached_file_len(&mut cached.file) {
                                    Ok(sz) => sz,
                                    Err(_) => 0,
                                }
                            } else {
                                0
                            };
                            (false, size, u8::from(FileAttribute::Archive))
                        }
                    };

                    r.data = box_to_bytes(Box::new(FsGetInfoResult {
                        size,
                        is_dir,
                        attrs: attrs as u32,
                        error: None,
                    }));
                    DriverStatus::Success
                }

                FsOp::SetInfo => {
                    drop(fs_opt.take());
                    drop(tbl_opt.take());
                    DriverStatus::NotImplemented
                }
                FsOp::Delete => {
                    drop(fs_opt.take());
                    drop(tbl_opt.take());
                    DriverStatus::NotImplemented
                }
            }
        }

        RequestType::DeviceControl(_) => DriverStatus::NotImplemented,

        _ => DriverStatus::InvalidParameter,
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
