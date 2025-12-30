#![no_std]

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::mem::size_of;
use core::sync::atomic::{AtomicU64, Ordering};
use kernel_api::kernel_types::async_types::AsyncMutex;
use kernel_api::runtime::spawn_blocking;
use kernel_api::{print, println};

use fatfs::{
    Dir as FatDirT, Error as FatError, File as FatFileT, FileSystem as FatFsT, IoBase,
    LossyOemCpConverter, NullTimeProvider, Read, Seek, SeekFrom, Write,
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
type FatFile<'a> = FatFileT<'a, FatDev, TP, OCC>;
type FatDir<'a> = FatDirT<'a, FatDev, TP, OCC>;
type FsError = FatError<<FatDev as IoBase>::Error>;

#[repr(C)]
pub struct VolCtrlDevExt {
    pub fs: Arc<AsyncMutex<Fs>>,
    pub(crate) next_id: AtomicU64,
    pub(crate) table: RwLock<BTreeMap<u64, FileCtx>>,
}

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

fn get_file_len(fs: &mut Fs, path: &str) -> Result<u64, FsError> {
    let mut file = fs.root_dir().open_file(path)?;
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
                    let params: FsOpenParams = unsafe {
                        let mut r = req.write();
                        if r.data.len() != size_of::<FsOpenParams>() {
                            return DriverStatus::InvalidParameter;
                        }
                        *bytes_to_box(core::mem::replace(&mut r.data, Box::new([])))
                    };

                    let open_res = {
                        let root = fs.root_dir();

                        match root.open_file(&params.path) {
                            Ok(mut f) => match f.seek(SeekFrom::End(0)) {
                                Ok(end) => Ok((false, end)),
                                Err(e) => Err(e),
                            },
                            Err(FatError::NotFound) | Err(FatError::InvalidInput) => {
                                match root.open_dir(&params.path) {
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
                            r.data = box_to_bytes(Box::new(FsOpenResult {
                                fs_file_id: 0,
                                is_dir: false,
                                size: 0,
                                error: Some(map_fatfs_err(&e)),
                            }));
                            return DriverStatus::Success;
                        }
                    };

                    let mut r = req.write();
                    r.data = box_to_bytes(Box::new(FsOpenResult {
                        fs_file_id,
                        is_dir,
                        size,
                        error: None,
                    }));
                    DriverStatus::Success
                }

                FsOp::Close => {
                    let params: FsCloseParams = unsafe {
                        let mut r = req.write();
                        if r.data.len() != size_of::<FsCloseParams>() {
                            return DriverStatus::InvalidParameter;
                        }
                        *bytes_to_box(core::mem::replace(&mut r.data, Box::new([])))
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
                    r.data = box_to_bytes(Box::new(res));
                    DriverStatus::Success
                }

                FsOp::Read => {
                    let params: FsReadParams = unsafe {
                        let mut r = req.write();
                        if r.data.len() != size_of::<FsReadParams>() {
                            return DriverStatus::InvalidParameter;
                        }
                        *bytes_to_box(core::mem::replace(&mut r.data, Box::new([])))
                    };

                    let (path, is_dir) = {
                        let tbl = vdx.table.read();
                        match tbl.get(&params.fs_file_id) {
                            Some(ctx) => (ctx.path.clone(), ctx.is_dir),
                            None => {
                                let mut r = req.write();
                                r.data = box_to_bytes(Box::new(FsReadResult {
                                    data: Vec::new(),
                                    error: Some(FileStatus::PathNotFound),
                                }));
                                return DriverStatus::Success;
                            }
                        }
                    };

                    let data_or_err = if is_dir {
                        Ok(Vec::new())
                    } else {
                        match fs.root_dir().open_file(&path) {
                            Ok(mut file) => {
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
                            Err(e) => Err(e),
                        }
                    };

                    let mut r = req.write();
                    match data_or_err {
                        Ok(v) => {
                            r.data = box_to_bytes(Box::new(FsReadResult {
                                data: v,
                                error: None,
                            }))
                        }
                        Err(e) => {
                            let status = if matches!(e, FatError::NotFound) {
                                FileStatus::PathNotFound
                            } else {
                                map_fatfs_err(&e)
                            };

                            r.data = box_to_bytes(Box::new(FsReadResult {
                                data: Vec::new(),
                                error: Some(status),
                            }))
                        }
                    }
                    DriverStatus::Success
                }

                FsOp::Write => {
                    let params: FsWriteParams = unsafe {
                        let mut r = req.write();
                        if r.data.len() != size_of::<FsWriteParams>() {
                            return DriverStatus::InvalidParameter;
                        }
                        *bytes_to_box(core::mem::replace(&mut r.data, Box::new([])))
                    };

                    let (path, is_dir, pos) = {
                        let tbl = vdx.table.read();
                        match tbl.get(&params.fs_file_id) {
                            Some(ctx) => (ctx.path.clone(), ctx.is_dir, ctx.pos),
                            None => {
                                let mut r = req.write();
                                r.data = box_to_bytes(Box::new(FsWriteResult {
                                    written: 0,
                                    error: Some(FileStatus::PathNotFound),
                                }));
                                return DriverStatus::Success;
                            }
                        }
                    };

                    let write_res = if is_dir {
                        Ok(0usize)
                    } else {
                        match fs.root_dir().open_file(&path) {
                            Ok(mut file) => {
                                let n = params.data.len();
                                if let Err(e) = file.seek(SeekFrom::Start(pos)) {
                                    Err(e)
                                } else {
                                    match file.write_all(&params.data) {
                                        Ok(()) => match file.flush() {
                                            Ok(()) => Ok(n),
                                            Err(e) => Err(e),
                                        },
                                        Err(e) => Err(e),
                                    }
                                }
                            }
                            Err(e) => Err(e),
                        }
                    };

                    // Update position on success
                    if let Ok(written) = write_res {
                        let mut tbl = vdx.table.write();
                        if let Some(ctx) = tbl.get_mut(&params.fs_file_id) {
                            ctx.pos = ctx.pos.saturating_add(written as u64);
                        }
                    }

                    let mut r = req.write();
                    match write_res {
                        Ok(written) => {
                            r.data = box_to_bytes(Box::new(FsWriteResult {
                                written,
                                error: None,
                            }))
                        }
                        Err(e) => {
                            let status = if matches!(e, FatError::NotFound) {
                                FileStatus::PathNotFound
                            } else {
                                map_fatfs_err(&e)
                            };
                            r.data = box_to_bytes(Box::new(FsWriteResult {
                                written: 0,
                                error: Some(status),
                            }))
                        }
                    }

                    DriverStatus::Success
                }

                FsOp::Seek => {
                    let params: FsSeekParams = unsafe {
                        let mut r = req.write();
                        if r.data.len() != size_of::<FsSeekParams>() {
                            return DriverStatus::InvalidParameter;
                        }
                        *bytes_to_box(core::mem::replace(&mut r.data, Box::new([])))
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
                            r.data = box_to_bytes(Box::new(FsSeekResult { pos, error: None }))
                        }
                        Err(e) => {
                            r.data = box_to_bytes(Box::new(FsSeekResult {
                                pos: 0,
                                error: Some(e),
                            }))
                        }
                    }
                    DriverStatus::Success
                }

                FsOp::Flush => {
                    let params: FsFlushParams = unsafe {
                        let mut r = req.write();
                        if r.data.len() != size_of::<FsFlushParams>() {
                            return DriverStatus::InvalidParameter;
                        }
                        *bytes_to_box(core::mem::replace(&mut r.data, Box::new([])))
                    };

                    let err = {
                        let tbl = vdx.table.read();
                        if tbl.contains_key(&params.fs_file_id) {
                            // No cached file to flush, just verify the handle exists
                            None
                        } else {
                            Some(FileStatus::PathNotFound)
                        }
                    };

                    let mut r = req.write();
                    r.data = box_to_bytes(Box::new(FsFlushResult { error: err }));
                    DriverStatus::Success
                }

                FsOp::Create => {
                    let params: FsCreateParams = unsafe {
                        let mut r = req.write();
                        if r.data.len() != size_of::<FsCreateParams>() {
                            return DriverStatus::InvalidParameter;
                        }
                        *bytes_to_box(core::mem::replace(&mut r.data, Box::new([])))
                    };

                    let err = {
                        match create_entry(&mut *fs, &params.path, params.dir) {
                            Ok(()) => None,
                            Err(e) => Some(map_fatfs_err(&e)),
                        }
                    };

                    let mut r = req.write();
                    r.data = box_to_bytes(Box::new(FsCreateResult { error: err }));
                    DriverStatus::Success
                }

                FsOp::Rename => {
                    let params: FsRenameParams = unsafe {
                        let mut r = req.write();
                        if r.data.len() != size_of::<FsRenameParams>() {
                            return DriverStatus::InvalidParameter;
                        }
                        *bytes_to_box(core::mem::replace(&mut r.data, Box::new([])))
                    };

                    let err = {
                        match rename_entry(&mut *fs, &params.src, &params.dst) {
                            Ok(()) => None,
                            Err(e) => Some(map_fatfs_err(&e)),
                        }
                    };

                    let mut r = req.write();
                    r.data = box_to_bytes(Box::new(FsRenameResult { error: err }));
                    DriverStatus::Success
                }

                FsOp::ReadDir => {
                    let params: FsListDirParams = unsafe {
                        let mut r = req.write();
                        if r.data.len() != size_of::<FsListDirParams>() {
                            return DriverStatus::InvalidParameter;
                        }
                        *bytes_to_box(core::mem::replace(&mut r.data, Box::new([])))
                    };

                    let names_or_err = { list_names(&mut *fs, &params.path) };

                    let mut r = req.write();
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
                        let mut r = req.write();
                        if r.data.len() != size_of::<FsGetInfoParams>() {
                            return DriverStatus::InvalidParameter;
                        }
                        *bytes_to_box(core::mem::replace(&mut r.data, Box::new([])))
                    };

                    let (path, is_dir) = {
                        let tbl = vdx.table.read();
                        match tbl.get(&params.fs_file_id) {
                            Some(ctx) => (ctx.path.clone(), ctx.is_dir),
                            None => {
                                let mut r = req.write();
                                r.data = box_to_bytes(Box::new(FsGetInfoResult {
                                    size: 0,
                                    is_dir: false,
                                    attrs: 0,
                                    error: Some(FileStatus::PathNotFound),
                                }));
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
                            r.data = box_to_bytes(Box::new(FsGetInfoResult {
                                size,
                                is_dir,
                                attrs: attrs as u32,
                                error: None,
                            }));
                        }
                        Err(e) => {
                            r.data = box_to_bytes(Box::new(FsGetInfoResult {
                                size: 0,
                                is_dir: false,
                                attrs: 0,
                                error: Some(e),
                            }));
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
    println!("Request kind: {:#?}", req2.read().kind);
    let res = spawn_blocking(move || {
        let fs: &mut Fs = &mut *fs_guard;
        handle_fs_request(&dev2, &req2, fs)
    })
    .await;

    DriverStep::complete(res)
}
