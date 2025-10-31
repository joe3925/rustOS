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

use spin::RwLock;

use kernel_api::{
    DeviceObject, DriverStatus, FileError, FsCloseParams, FsCloseResult, FsCreateParams,
    FsCreateResult, FsFlushParams, FsFlushResult, FsGetInfoParams, FsGetInfoResult,
    FsListDirParams, FsListDirResult, FsOp, FsOpenParams, FsOpenResult, FsReadParams, FsReadResult,
    FsRenameParams, FsRenameResult, FsSeekParams, FsSeekResult, FsSeekWhence, FsWriteParams,
    FsWriteResult, Request, RequestType,
};

use crate::block_dev::BlockDev;

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
    pub fs: Fs,
    next_id: AtomicU64,
    table: RwLock<BTreeMap<u64, FileCtx>>,
}

#[derive(Clone)]
struct FileCtx {
    path: String,
    is_dir: bool,
    pos: u64,
}

// ---- bytes <-> box helpers for your kernel message ABI ----
fn box_to_bytes<T>(b: Box<T>) -> Box<[u8]> {
    let len = size_of::<T>();
    let p = Box::into_raw(b) as *mut u8;
    unsafe { Box::from_raw(core::slice::from_raw_parts_mut(p, len)) }
}
unsafe fn bytes_to_box<T>(b: Box<[u8]>) -> Box<T> {
    let p = Box::into_raw(b) as *mut u8 as *mut T;
    Box::from_raw(p)
}

#[inline]
fn ext_mut<T>(dev: &Arc<DeviceObject>) -> &mut T {
    unsafe { &mut *((&*dev.dev_ext).as_ptr() as *const T as *mut T) }
}

// ---- map fatfs::Error<()> -> your FileError ----
fn map_fatfs_err(e: &FsError) -> FileError {
    use fatfs::Error::*;
    match e {
        NotFound => FileError::NotFound,
        AlreadyExists => FileError::AlreadyExists,
        InvalidInput => FileError::BadPath,
        NoSpace => FileError::IoError,
        CorruptedFileSystem => FileError::Corrupt,
        _ => FileError::Unknown,
    }
}

// dir? file?  Err => not found
fn is_dir(fs: &Fs, path: &str) -> Result<bool, FsError> {
    if fs.root_dir().open_dir(path).is_ok() {
        return Ok(true);
    }
    if fs.root_dir().open_file(path).is_ok() {
        return Ok(false);
    }
    Err(FatError::NotFound)
}

fn file_len(fs: &Fs, path: &str) -> Result<u64, FsError> {
    let mut f = fs.root_dir().open_file(path)?;
    let end = f.seek(SeekFrom::End(0))?;
    Ok(end)
}

fn read_slice(fs: &Fs, path: &str, offset: u64, len: usize) -> Result<Vec<u8>, FsError> {
    let mut f = fs.root_dir().open_file(path)?;
    let _ = f.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; len];
    let n = f.read(&mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

fn open_rw_create<'fs>(fs: &'fs Fs, path: &str) -> Result<FatFile<'fs>, FsError> {
    match fs.root_dir().open_file(path) {
        Ok(f) => Ok(f),
        Err(e) => {
            // open failed: if NotFound create then open; else propagate
            match e {
                FatError::NotFound => {
                    fs.root_dir().create_file(path)?;
                    fs.root_dir().open_file(path)
                }
                other => Err(other),
            }
        }
    }
}

fn write_slice(fs: &Fs, path: &str, offset: u64, data: &[u8]) -> Result<usize, FsError> {
    let mut f = open_rw_create(fs, path)?;
    let _ = f.seek(SeekFrom::Start(offset))?;
    f.write(data)
}

fn create_entry(fs: &Fs, path: &str, dir: bool) -> Result<(), FsError> {
    if dir {
        let _ = fs.root_dir().create_dir(path)?;
    } else {
        let _ = fs.root_dir().create_file(path)?;
    }
    Ok(())
}

fn rename_entry(fs: &Fs, src: &str, dst: &str) -> Result<(), FsError> {
    // old fatfs API: rename(src, &dst_dir, dst_name)
    let dst_dir = fs.root_dir();
    fs.root_dir().rename(src, &dst_dir, dst)
}

fn list_names(fs: &Fs, path: &str) -> Result<Vec<String>, FsError> {
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
            let fs = &vdx.fs;

            match op {
                FsOp::Open => {
                    let params: FsOpenParams = unsafe {
                        if r.data.len() != size_of::<FsOpenParams>() {
                            r.status = DriverStatus::InvalidParameter;
                            return;
                        }
                        *bytes_to_box(core::mem::replace(&mut r.data, Box::new([])))
                    };

                    let is_dir = match is_dir(fs, &params.path) {
                        Ok(b) => b,
                        Err(e) => {
                            let res = FsOpenResult {
                                fs_file_id: 0,
                                is_dir: false,
                                size: 0,
                                error: Some(map_fatfs_err(&e)),
                            };
                            r.data = box_to_bytes(Box::new(res));
                            r.status = DriverStatus::Success;
                            return;
                        }
                    };

                    let size = if is_dir {
                        0
                    } else {
                        file_len(fs, &params.path).unwrap_or(0)
                    };

                    let id = vdx.next_id.fetch_add(1, Ordering::AcqRel).max(1);
                    vdx.table.write().insert(
                        id,
                        FileCtx {
                            path: params.path.clone(),
                            is_dir,
                            pos: 0,
                        },
                    );

                    let res = FsOpenResult {
                        fs_file_id: id,
                        is_dir,
                        size,
                        error: None,
                    };
                    r.data = box_to_bytes(Box::new(res));
                    r.status = DriverStatus::Success;
                }

                FsOp::Close => {
                    let params: FsCloseParams = unsafe {
                        if r.data.len() != size_of::<FsCloseParams>() {
                            r.status = DriverStatus::InvalidParameter;
                            return;
                        }
                        *bytes_to_box(core::mem::replace(&mut r.data, Box::new([])))
                    };

                    let removed = vdx.table.write().remove(&params.fs_file_id).is_some();
                    let res = FsCloseResult {
                        error: if removed {
                            None
                        } else {
                            Some(FileError::NotFound)
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

                    let ctx = match vdx.table.read().get(&params.fs_file_id).cloned() {
                        Some(c) => c,
                        None => {
                            r.data = box_to_bytes(Box::new(FsReadResult {
                                data: Vec::new(),
                                error: Some(FileError::NotFound),
                            }));
                            r.status = DriverStatus::Success;
                            return;
                        }
                    };
                    if ctx.is_dir {
                        r.data = box_to_bytes(Box::new(FsReadResult {
                            data: Vec::new(),
                            error: Some(FileError::IsDirectory),
                        }));
                        r.status = DriverStatus::Success;
                        return;
                    }

                    let data = match read_slice(fs, &ctx.path, params.offset as u64, params.len) {
                        Ok(v) => v,
                        Err(e) => {
                            r.data = box_to_bytes(Box::new(FsReadResult {
                                data: Vec::new(),
                                error: Some(map_fatfs_err(&e)),
                            }));
                            r.status = DriverStatus::Success;
                            return;
                        }
                    };

                    r.data = box_to_bytes(Box::new(FsReadResult { data, error: None }));
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

                    let ctx = match vdx.table.read().get(&params.fs_file_id).cloned() {
                        Some(c) => c,
                        None => {
                            r.data = box_to_bytes(Box::new(FsWriteResult {
                                written: 0,
                                error: Some(FileError::NotFound),
                            }));
                            r.status = DriverStatus::Success;
                            return;
                        }
                    };
                    if ctx.is_dir {
                        r.data = box_to_bytes(Box::new(FsWriteResult {
                            written: 0,
                            error: Some(FileError::IsDirectory),
                        }));
                        r.status = DriverStatus::Success;
                        return;
                    }

                    match write_slice(fs, &ctx.path, params.offset as u64, &params.data) {
                        Ok(n) => {
                            r.data = box_to_bytes(Box::new(FsWriteResult {
                                written: n,
                                error: None,
                            }));
                        }
                        Err(e) => {
                            r.data = box_to_bytes(Box::new(FsWriteResult {
                                written: 0,
                                error: Some(map_fatfs_err(&e)),
                            }));
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

                    let mut tbl = vdx.table.write();
                    let Some(ctx) = tbl.get_mut(&params.fs_file_id) else {
                        r.data = box_to_bytes(Box::new(FsSeekResult {
                            pos: 0,
                            error: Some(FileError::NotFound),
                        }));
                        r.status = DriverStatus::Success;
                        return;
                    };

                    let size = if ctx.is_dir {
                        0
                    } else {
                        file_len(fs, &ctx.path).unwrap_or(0)
                    };

                    let newpos = match params.origin {
                        FsSeekWhence::Set => params.offset as i128,
                        FsSeekWhence::Cur => ctx.pos as i128 + params.offset as i128,
                        FsSeekWhence::End => size as i128 + params.offset as i128,
                    };
                    let clamped = if newpos < 0 { 0 } else { newpos as u64 };
                    ctx.pos = clamped;

                    r.data = box_to_bytes(Box::new(FsSeekResult {
                        pos: clamped,
                        error: None,
                    }));
                    r.status = DriverStatus::Success;
                }

                FsOp::Flush => {
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
                    let params: FsCreateParams = unsafe {
                        if r.data.len() != size_of::<FsCreateParams>() {
                            r.status = DriverStatus::InvalidParameter;
                            return;
                        }
                        *bytes_to_box(core::mem::replace(&mut r.data, Box::new([])))
                    };

                    let err = match create_entry(fs, &params.path, params.dir) {
                        Ok(()) => None,
                        Err(e) => Some(map_fatfs_err(&e)),
                    };

                    r.data = box_to_bytes(Box::new(FsCreateResult { error: err }));
                    r.status = DriverStatus::Success;
                }

                FsOp::Rename => {
                    let params: FsRenameParams = unsafe {
                        if r.data.len() != size_of::<FsRenameParams>() {
                            r.status = DriverStatus::InvalidParameter;
                            return;
                        }
                        *bytes_to_box(core::mem::replace(&mut r.data, Box::new([])))
                    };

                    let err = match rename_entry(fs, &params.src, &params.dst) {
                        Ok(()) => None,
                        Err(e) => Some(map_fatfs_err(&e)),
                    };
                    r.data = box_to_bytes(Box::new(FsRenameResult { error: err }));
                    r.status = DriverStatus::Success;
                }

                FsOp::ReadDir => {
                    let params: FsListDirParams = unsafe {
                        if r.data.len() != size_of::<FsListDirParams>() {
                            r.status = DriverStatus::InvalidParameter;
                            return;
                        }
                        *bytes_to_box(core::mem::replace(&mut r.data, Box::new([])))
                    };

                    match list_names(fs, &params.path) {
                        Ok(names) => {
                            r.data = box_to_bytes(Box::new(FsListDirResult { names, error: None }));
                        }
                        Err(e) => {
                            r.data = box_to_bytes(Box::new(FsListDirResult {
                                names: Vec::new(),
                                error: Some(map_fatfs_err(&e)),
                            }));
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

                    let ctx = match vdx.table.read().get(&params.fs_file_id).cloned() {
                        Some(c) => c,
                        None => {
                            r.data = box_to_bytes(Box::new(FsGetInfoResult {
                                size: 0,
                                is_dir: false,
                                attrs: 0,
                                error: Some(FileError::NotFound),
                            }));
                            r.status = DriverStatus::Success;
                            return;
                        }
                    };

                    let (size, attrs) = if ctx.is_dir {
                        (0u64, u8::from(kernel_api::FileAttribute::Directory))
                    } else {
                        (
                            file_len(fs, &ctx.path).unwrap_or(0),
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
                    r.status = DriverStatus::NotImplemented;
                }
                FsOp::Delete => {
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
