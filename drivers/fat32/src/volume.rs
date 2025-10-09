use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::size_of;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::RwLock;

use kernel_api::{
    DeviceObject, DriverStatus, FileError, FileStatus, FsCloseParams, FsCloseResult,
    FsCreateParams, FsCreateResult, FsFlushParams, FsFlushResult, FsGetInfoParams, FsGetInfoResult,
    FsListDirParams, FsListDirResult, FsOp, FsOpenParams, FsOpenResult, FsReadParams, FsReadResult,
    FsRenameParams, FsRenameResult, FsSeekParams, FsSeekResult, FsSeekWhence, FsWriteParams,
    FsWriteResult, Request, RequestType, println,
};

use crate::fat32::Fat32;

#[repr(C)]
pub struct VolCtrlDevExt {
    pub fs: Fat32,
    next_id: AtomicU64,
    table: RwLock<BTreeMap<u64, FileCtx>>,
}

#[derive(Clone)]
struct FileCtx {
    path: String,
    is_dir: bool,
    pos: u64,
}

fn box_to_bytes<T>(b: Box<T>) -> Box<[u8]> {
    let len = size_of::<T>();
    let ptr = Box::into_raw(b) as *mut u8;
    unsafe { Box::from_raw(core::slice::from_raw_parts_mut(ptr, len)) }
}
unsafe fn bytes_to_box<T>(b: Box<[u8]>) -> Box<T> {
    assert_eq!(b.len(), size_of::<T>());
    let ptr = Box::into_raw(b) as *mut u8 as *mut T;
    Box::from_raw(ptr)
}

#[inline]
fn ext_mut<T>(dev: &Arc<DeviceObject>) -> &mut T {
    unsafe { &mut *((&*dev.dev_ext).as_ptr() as *const T as *mut T) }
}

fn fe_from_fs(s: FileStatus) -> FileError {
    match s {
        FileStatus::Success => FileError::Unknown,
        FileStatus::FileAlreadyExist => FileError::AlreadyExists,
        FileStatus::PathNotFound => FileError::NotFound,
        FileStatus::NotFat => FileError::Unsupported,
        FileStatus::DriveNotFound => FileError::NotFound,
        FileStatus::IncompatibleFlags => FileError::Unsupported,
        FileStatus::CorruptFat => FileError::Corrupt,
        FileStatus::InternalError => FileError::IoError,
        FileStatus::BadPath => FileError::BadPath,
        FileStatus::UnknownFail => FileError::Unknown,
    }
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
                        match r.data.len() {
                            n if n == size_of::<FsOpenParams>() => *bytes_to_box::<FsOpenParams>(
                                core::mem::replace(&mut r.data, Box::new([])),
                            ),
                            _ => {
                                r.status = DriverStatus::InvalidParameter;
                                return;
                            }
                        }
                    };

                    let is_dir = fs.find_dir(&params.path).is_ok();
                    let size = if is_dir {
                        0
                    } else {
                        match fs.find_file(&params.path) {
                            Ok(fe) => fe.file_size as u64,
                            Err(e) => {
                                let res = FsOpenResult {
                                    fs_file_id: 0,
                                    is_dir: false,
                                    size: 0,
                                    error: Some(fe_from_fs(e)),
                                };
                                r.data = box_to_bytes(Box::new(res));
                                r.status = DriverStatus::Success;
                                return;
                            }
                        }
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
                        *bytes_to_box::<FsCloseParams>(core::mem::replace(
                            &mut r.data,
                            Box::new([]),
                        ))
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
                        *bytes_to_box::<FsReadParams>(core::mem::replace(&mut r.data, Box::new([])))
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

                    let full = match fs.read_file(&ctx.path) {
                        Ok(v) => v,
                        Err(e) => {
                            r.data = box_to_bytes(Box::new(FsReadResult {
                                data: Vec::new(),
                                error: Some(fe_from_fs(e)),
                            }));
                            r.status = DriverStatus::Success;
                            return;
                        }
                    };

                    let off = params.offset as usize;
                    if off >= full.len() {
                        r.data = box_to_bytes(Box::new(FsReadResult {
                            data: Vec::new(),
                            error: None,
                        }));
                        r.status = DriverStatus::Success;
                        return;
                    }
                    let end = (off + params.len).min(full.len());
                    let slice = full[off..end].to_vec();

                    r.data = box_to_bytes(Box::new(FsReadResult {
                        data: slice,
                        error: None,
                    }));
                    r.status = DriverStatus::Success;
                }

                FsOp::Write => {
                    let params: FsWriteParams = unsafe {
                        if r.data.len() != size_of::<FsWriteParams>() {
                            r.status = DriverStatus::InvalidParameter;
                            return;
                        }
                        *bytes_to_box::<FsWriteParams>(core::mem::replace(
                            &mut r.data,
                            Box::new([]),
                        ))
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

                    // read-modify-write (simple)
                    let mut cur = match fs.read_file(&ctx.path) {
                        Ok(v) => v,
                        Err(FileStatus::PathNotFound) => Vec::new(),
                        Err(e) => {
                            r.data = box_to_bytes(Box::new(FsWriteResult {
                                written: 0,
                                error: Some(fe_from_fs(e)),
                            }));
                            r.status = DriverStatus::Success;
                            return;
                        }
                    };

                    let need = (params.offset as usize).saturating_add(params.data.len());
                    if cur.len() < need {
                        cur.resize(need, 0);
                    }
                    cur[params.offset as usize..params.offset as usize + params.data.len()]
                        .copy_from_slice(&params.data);

                    match fs.write_file(&cur, &ctx.path) {
                        Ok(()) => {
                            r.data = box_to_bytes(Box::new(FsWriteResult {
                                written: params.data.len(),
                                error: None,
                            }));
                        }
                        Err(e) => {
                            r.data = box_to_bytes(Box::new(FsWriteResult {
                                written: 0,
                                error: Some(fe_from_fs(e)),
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
                        *bytes_to_box::<FsSeekParams>(core::mem::replace(&mut r.data, Box::new([])))
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
                        match fs.find_file(&ctx.path) {
                            Ok(fe) => fe.file_size as u64,
                            Err(_) => 0,
                        }
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
                        *bytes_to_box::<FsFlushParams>(core::mem::replace(
                            &mut r.data,
                            Box::new([]),
                        ))
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
                        *bytes_to_box::<FsCreateParams>(core::mem::replace(
                            &mut r.data,
                            Box::new([]),
                        ))
                    };

                    let err = if params.dir {
                        match fs.create_dir(&params.path) {
                            Ok(()) => None,
                            Err(e) => Some(fe_from_fs(e)),
                        }
                    } else {
                        // split name/ext using helpers
                        let parts = crate::fat32::Fat32::file_parser(&params.path);
                        let leaf = parts.last().copied().unwrap_or("");
                        let name = Fat32::get_text_before_last_dot(leaf).to_string();
                        let ext = Fat32::get_text_after_last_dot(leaf).to_string();
                        let parent = crate::fat32::remove_file_from_path(&params.path).to_string();
                        match fs.create_file(&name, &ext, &parent) {
                            Ok(()) => None,
                            Err(e) => Some(fe_from_fs(e)),
                        }
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
                        *bytes_to_box::<FsRenameParams>(core::mem::replace(
                            &mut r.data,
                            Box::new([]),
                        ))
                    };

                    let err = match fs.move_file_nocopy(&params.src, &params.dst) {
                        Ok(()) => None,
                        Err(e) => Some(fe_from_fs(e)),
                    };
                    r.data = box_to_bytes(Box::new(FsRenameResult { error: err }));
                    r.status = DriverStatus::Success;
                }

                FsOp::ReadDir => {
                    if let FsOp::ReadDir = op {
                        let params: FsListDirParams = unsafe {
                            if r.data.len() != size_of::<FsListDirParams>() {
                                r.status = DriverStatus::InvalidParameter;
                                return;
                            }
                            *bytes_to_box::<FsListDirParams>(core::mem::replace(
                                &mut r.data,
                                Box::new([]),
                            ))
                        };

                        match fs.list_dir(&params.path) {
                            Ok(names) => {
                                r.data =
                                    box_to_bytes(Box::new(FsListDirResult { names, error: None }));
                            }
                            Err(e) => {
                                r.data = box_to_bytes(Box::new(FsListDirResult {
                                    names: Vec::new(),
                                    error: Some(fe_from_fs(e)),
                                }));
                            }
                        }
                        r.status = DriverStatus::Success;
                        return;
                    }
                }

                FsOp::GetInfo => {
                    let params: FsGetInfoParams = unsafe {
                        if r.data.len() != size_of::<FsGetInfoParams>() {
                            r.status = DriverStatus::InvalidParameter;
                            return;
                        }
                        *bytes_to_box::<FsGetInfoParams>(core::mem::replace(
                            &mut r.data,
                            Box::new([]),
                        ))
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
                        match fs.find_file(&ctx.path) {
                            Ok(fe) => (
                                fe.file_size as u64,
                                u8::from(kernel_api::FileAttribute::Archive),
                            ),
                            Err(_) => (0, 0),
                        }
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
