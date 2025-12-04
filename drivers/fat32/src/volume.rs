#![no_std]

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::mem::size_of;
use core::sync::atomic::{AtomicU64, Ordering};
use kernel_api::task::{create_kernel_task, sleep_self, sleep_self_and_yield, wake_task};

use fatfs::{
    Dir as FatDirT, Error as FatError, File as FatFileT, FileSystem as FatFsT, IoBase,
    LossyOemCpConverter, NullTimeProvider, Read, Seek, SeekFrom, Write,
};

use spin::{Mutex, RwLock};

use kernel_api::device::DeviceObject;
use kernel_api::pnp::pnp_complete_request;
use kernel_api::request::{Request, RequestType};
use kernel_api::status::{DriverStatus, FileStatus};
use kernel_api::{
    fs::{
        FileAttribute, FsCloseParams, FsCloseResult, FsCreateParams, FsCreateResult, FsFlushParams,
        FsFlushResult, FsGetInfoParams, FsGetInfoResult, FsListDirParams, FsListDirResult, FsOp,
        FsOpenParams, FsOpenResult, FsReadParams, FsReadResult, FsRenameParams, FsRenameResult,
        FsSeekParams, FsSeekResult, FsSeekWhence, FsWriteParams, FsWriteResult,
    },
    println, request_handler,
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
    pub(crate) queue: Mutex<VecDeque<Arc<RwLock<Request>>>>,
    pub(crate) worker_task_id: AtomicU64,
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

struct FsWorkerCtx {
    dev: Arc<DeviceObject>,
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

// Called from the control module after the per-volume device is created.
pub fn start_fs_worker_for_volume(dev: Arc<DeviceObject>) {
    let vdx = ext_mut::<VolCtrlDevExt>(&dev);
    let existing = vdx.worker_task_id.load(Ordering::Acquire);
    if existing != 0 {
        return;
    }

    let ctx = Box::new(FsWorkerCtx { dev: dev.clone() });
    let raw_ctx = Box::into_raw(ctx) as usize;
    let name = alloc::format!("fat32.fs.worker.{:p}", dev.as_ref());
    let id = create_kernel_task(fs_worker_thread, raw_ctx, name);
    vdx.worker_task_id.store(id, Ordering::Release);
}

extern "win64" fn fs_worker_thread(ctx: usize) {
    let ctx_ref: &FsWorkerCtx = unsafe { &*(ctx as *const FsWorkerCtx) };

    loop {
        let req_opt = {
            let vdx = ext_mut::<VolCtrlDevExt>(&ctx_ref.dev);
            let mut q = vdx.queue.lock();
            q.pop_front()
        };

        match req_opt {
            Some(req) => {
                let status = handle_fs_request(&ctx_ref.dev, &req);
                {
                    let mut r = req.write();
                    r.status = status;
                }
                unsafe {
                    pnp_complete_request(&req);
                }
            }
            None => unsafe {
                sleep_self_and_yield();
            },
        }
    }
}

// Synchronous version of the old fs_op_dispatch body, run on the worker thread.
fn handle_fs_request(dev: &Arc<DeviceObject>, req: &Arc<RwLock<Request>>) -> DriverStatus {
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

                    let reuse_res = {
                        let mut tbl = vdx.table.write();
                        if let Some((&id, ctx)) =
                            tbl.iter_mut().find(|(_, c)| c.path == params.path)
                        {
                            let size = if ctx.is_dir {
                                0
                            } else {
                                let _fs_guard = vdx.fs.lock();
                                if let Some(ref mut cached) = ctx.file {
                                    match cached_file_len(&mut cached.file) {
                                        Ok(sz) => sz,
                                        Err(_) => 0,
                                    }
                                } else {
                                    0
                                }
                            };
                            Some((id, ctx.is_dir, size))
                        } else {
                            None
                        }
                    };

                    let (fs_file_id, is_dir, size) = if let Some((id, is_dir, size)) = reuse_res {
                        (id, is_dir, size)
                    } else {
                        let open_res = {
                            let mut fs = vdx.fs.lock();
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
                            Ok((is_dir, size, cached)) => {
                                let id = vdx.next_id.fetch_add(1, Ordering::AcqRel).max(1);
                                let mut tbl = vdx.table.write();
                                tbl.insert(
                                    id,
                                    FileCtx {
                                        path: params.path,
                                        is_dir,
                                        pos: 0,
                                        file: cached,
                                    },
                                );
                                (id, is_dir, size)
                            }
                            Err(e) => {
                                let mut r = req.write();
                                let res = FsOpenResult {
                                    fs_file_id: 0,
                                    is_dir: false,
                                    size: 0,
                                    error: Some(map_fatfs_err(&e)),
                                };
                                r.data = box_to_bytes(Box::new(res));
                                return DriverStatus::Success;
                            }
                        }
                    };

                    let mut r = req.write();
                    let res = FsOpenResult {
                        fs_file_id,
                        is_dir,
                        size,
                        error: None,
                    };
                    r.data = box_to_bytes(Box::new(res));
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
                        if let Some(mut ctx) = tbl.remove(&params.fs_file_id) {
                            if !ctx.is_dir {
                                if let Some(ref mut cached) = ctx.file {
                                    let _fs_guard = vdx.fs.lock();
                                    if let Err(e) = cached.file.flush() {
                                        Some(map_fatfs_err(&e))
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
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

                    let data_or_err = {
                        let mut tbl = vdx.table.write();

                        match tbl.get_mut(&params.fs_file_id) {
                            Some(ctx) => {
                                if ctx.is_dir {
                                    Ok(Vec::new())
                                } else {
                                    let _fs_guard = vdx.fs.lock();
                                    if let Some(ref mut cached) = ctx.file {
                                        let file = &mut cached.file;
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
                                    } else {
                                        Err(FatError::NotFound)
                                    }
                                }
                            }
                            None => Err(FatError::NotFound),
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

                    let write_res = {
                        let mut tbl = vdx.table.write();
                        match tbl.get_mut(&params.fs_file_id) {
                            Some(ctx) => {
                                if ctx.is_dir {
                                    Ok(0)
                                } else {
                                    let _fs_guard = vdx.fs.lock();
                                    if let Some(ref mut cached) = ctx.file {
                                        let file = &mut cached.file;
                                        match file.seek(SeekFrom::Start(params.offset as u64)) {
                                            Err(e) => Err(e),
                                            Ok(_) => match file.write(&params.data) {
                                                Ok(n) => match file.flush() {
                                                    Ok(()) => Ok(n),
                                                    Err(e) => Err(e),
                                                },
                                                Err(e) => Err(e),
                                            },
                                        }
                                    } else {
                                        Err(FatError::NotFound)
                                    }
                                }
                            }
                            None => Err(FatError::NotFound),
                        }
                    };

                    let mut r = req.write();
                    match write_res {
                        Ok(n) => {
                            r.data = box_to_bytes(Box::new(FsWriteResult {
                                written: n,
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
                                    let _fs_guard = vdx.fs.lock();
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

                    let flush_res = {
                        let mut tbl = vdx.table.write();
                        match tbl.get_mut(&params.fs_file_id) {
                            Some(ctx) => {
                                if ctx.is_dir {
                                    Ok(())
                                } else {
                                    let _fs_guard = vdx.fs.lock();
                                    if let Some(ref mut cached) = ctx.file {
                                        cached.file.flush()
                                    } else {
                                        Err(FatError::NotFound)
                                    }
                                }
                            }
                            None => Err(FatError::NotFound),
                        }
                    };

                    let mut r = req.write();
                    match flush_res {
                        Ok(()) => {
                            r.data = box_to_bytes(Box::new(FsFlushResult { error: None }));
                        }
                        Err(e) => {
                            let status = if matches!(e, FatError::NotFound) {
                                FileStatus::PathNotFound
                            } else {
                                map_fatfs_err(&e)
                            };
                            r.data = box_to_bytes(Box::new(FsFlushResult {
                                error: Some(status),
                            }));
                        }
                    }
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
                        let mut fs = vdx.fs.lock();
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
                        let mut fs = vdx.fs.lock();
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

                    let names_or_err = {
                        let mut fs = vdx.fs.lock();
                        list_names(&mut *fs, &params.path)
                    };

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

                    let result = {
                        let mut tbl = vdx.table.write();
                        match tbl.get_mut(&params.fs_file_id) {
                            Some(ctx) => {
                                if ctx.is_dir {
                                    Ok((true, 0u64, u8::from(FileAttribute::Directory)))
                                } else {
                                    let _fs_guard = vdx.fs.lock();
                                    let size = if let Some(ref mut cached) = ctx.file {
                                        match cached_file_len(&mut cached.file) {
                                            Ok(sz) => sz,
                                            Err(_) => 0,
                                        }
                                    } else {
                                        0
                                    };
                                    Ok((false, size, u8::from(FileAttribute::Archive)))
                                }
                            }
                            None => Err(FileStatus::PathNotFound),
                        }
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
pub async fn fs_op_dispatch(dev: Arc<DeviceObject>, req: Arc<RwLock<Request>>) -> DriverStatus {
    let kind = { req.read().kind };

    match kind {
        RequestType::Fs(_) => {
            let vdx = ext_mut::<VolCtrlDevExt>(&dev);
            {
                let mut q = vdx.queue.lock();
                q.push_back(req);
                wake_task(vdx.worker_task_id.load(Ordering::Acquire));
            }
            DriverStatus::Pending
        }
        RequestType::DeviceControl(_) => DriverStatus::NotImplemented,
        _ => DriverStatus::InvalidParameter,
    }
}
