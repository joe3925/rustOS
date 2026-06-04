use crate::block_dev::BlockDev;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::hint::{cold_path, likely, unlikely};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use fatfs::{
    CachedFileState, Dir as FatDirT, Error as FatError, FileSystem as FatFsT, IoBase,
    LossyOemCpConverter, NullTimeProvider, Read, RenamedFileState, SeekFrom, Write,
};
use kernel_api::device::DeviceObject;
use kernel_api::kernel_types::async_types::AsyncMutex;
use kernel_api::kernel_types::fs::Path;
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
    println, request_handler,
};
use spin::Mutex;

use crate::block_dev::{flush_owner, flush_owner_blocking};
use crate::control::ext_mut;

type FatDev = BlockDev;
type TP = NullTimeProvider;
type OCC = LossyOemCpConverter;

type Fs = FatFsT<FatDev, TP, OCC>;
type FatFile<'a> = fatfs::File<'a, FatDev, TP, OCC>;
type FatDir<'a> = FatDirT<'a, FatDev, TP, OCC>;
type FsError = FatError<<FatDev as IoBase>::Error>;

pub(crate) const METADATA_OWNER_ID: u64 = 1;
pub(crate) const FIRST_FILE_OWNER_ID: u64 = METADATA_OWNER_ID + 1;
pub(crate) const FILE_HANDLE_CAPACITY: usize = 1024;
const SET_LEN_ZERO_CHUNK: usize = 64 * 1024;
static ZERO_CHUNK: [u8; SET_LEN_ZERO_CHUNK] = [0u8; SET_LEN_ZERO_CHUNK];

#[repr(C)]
pub struct VolCtrlDevExt {
    pub fs: Arc<AsyncMutex<Fs>>,
    pub(crate) handles: Mutex<FileHandleTable>,
    pub(crate) volume_target: IoTarget,
    pub should_flush: Arc<AtomicBool>,
    pub pending_flush_owner: Arc<AtomicU64>,
    pub pending_flush_block: Arc<AtomicBool>,
    pub current_owner: Arc<AtomicU64>,
}

pub struct FileCtx {
    is_dir: bool,
    pos: u64,
    size: u64,
    cached: Option<CachedFileState>,
}

struct FileSlot {
    generation: u64,
    next_free: Option<usize>,
    ctx: Option<FileCtx>,
}

pub(crate) struct FileHandleTable {
    slots: Box<[FileSlot]>,
    free_head: Option<usize>,
}

impl FileHandleTable {
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        let mut slots = Vec::with_capacity(capacity);
        for index in 0..capacity {
            let next_free = (index + 1 < capacity).then_some(index + 1);
            slots.push(FileSlot {
                generation: 0,
                next_free,
                ctx: None,
            });
        }
        Self {
            slots: slots.into_boxed_slice(),
            free_head: (capacity != 0).then_some(0),
        }
    }

    fn id_for_slot(&self, index: usize) -> u64 {
        let generation = self.slots[index].generation;
        FIRST_FILE_OWNER_ID + generation.saturating_mul(self.slots.len() as u64) + index as u64
    }

    fn index_and_generation(&self, fs_file_id: u64) -> Option<(usize, u64)> {
        if unlikely(fs_file_id < FIRST_FILE_OWNER_ID || self.slots.is_empty()) {
            cold_path();
            return None;
        }
        let raw = fs_file_id - FIRST_FILE_OWNER_ID;
        let capacity = self.slots.len() as u64;
        Some(((raw % capacity) as usize, raw / capacity))
    }

    fn slot_mut(&mut self, fs_file_id: u64) -> Option<&mut FileSlot> {
        let (index, generation) = self.index_and_generation(fs_file_id)?;
        let slot = &mut self.slots[index];
        if likely(slot.generation == generation && slot.ctx.is_some()) {
            Some(slot)
        } else {
            cold_path();
            None
        }
    }

    fn ctx_mut(&mut self, fs_file_id: u64) -> Result<&mut FileCtx, FileStatus> {
        self.slot_mut(fs_file_id)
            .and_then(|slot| slot.ctx.as_mut())
            .ok_or(FileStatus::PathNotFound)
    }

    fn ctx(&self, fs_file_id: u64) -> Result<&FileCtx, FileStatus> {
        let (index, generation) = self
            .index_and_generation(fs_file_id)
            .ok_or(FileStatus::PathNotFound)?;
        let slot = &self.slots[index];
        if slot.generation == generation {
            slot.ctx.as_ref().ok_or(FileStatus::PathNotFound)
        } else {
            Err(FileStatus::PathNotFound)
        }
    }

    fn insert(&mut self, ctx: FileCtx) -> Result<u64, FileStatus> {
        let Some(index) = self.free_head else {
            cold_path();
            return Err(FileStatus::InternalError);
        };
        self.free_head = self.slots[index].next_free.take();
        self.slots[index].ctx = Some(ctx);
        Ok(self.id_for_slot(index))
    }

    fn remove(&mut self, fs_file_id: u64) -> Result<FileCtx, FileStatus> {
        let (index, generation) = self
            .index_and_generation(fs_file_id)
            .ok_or(FileStatus::PathNotFound)?;
        let slot = &mut self.slots[index];
        if unlikely(slot.generation != generation) {
            cold_path();
            return Err(FileStatus::PathNotFound);
        }
        let Some(ctx) = slot.ctx.take() else {
            cold_path();
            return Err(FileStatus::PathNotFound);
        };
        slot.generation = slot.generation.wrapping_add(1);
        slot.next_free = self.free_head;
        self.free_head = Some(index);
        Ok(ctx)
    }

    fn take_cached_state(&mut self, fs_file_id: u64) -> Result<CachedFileState, FileStatus> {
        let ctx = self.ctx_mut(fs_file_id)?;
        if unlikely(ctx.is_dir) {
            cold_path();
            return Err(FileStatus::AccessDenied);
        }
        ctx.cached
            .take()
            .ok_or_else(|| missing_cached_file_state(fs_file_id))
    }

    fn restore_cached_state(
        &mut self,
        fs_file_id: u64,
        state: CachedFileState,
    ) -> Result<(), FileStatus> {
        self.ctx_mut(fs_file_id)?.cached = Some(state);
        Ok(())
    }

    fn update_renamed_file(&mut self, renamed: &RenamedFileState) {
        for slot in self.slots.iter_mut() {
            let Some(ctx) = slot.ctx.as_mut() else {
                continue;
            };
            let Some(state) = ctx.cached.as_mut() else {
                continue;
            };
            if state.entry_pos() == Some(renamed.old_entry_pos()) {
                state.refresh_dir_entry_from(renamed.new_state());
            }
        }
    }
}

fn map_fatfs_err(e: &FsError) -> FileStatus {
    match e {
        fatfs::Error::NotFound => FileStatus::PathNotFound,
        fatfs::Error::AlreadyExists => FileStatus::FileAlreadyExist,
        fatfs::Error::InvalidInput => FileStatus::BadPath,
        fatfs::Error::NotEnoughSpace => FileStatus::NoSpace,
        fatfs::Error::CorruptedFileSystem => FileStatus::CorruptFilesystem,
        fatfs::Error::FileTooLarge => FileStatus::FileTooLarge,
        e => {
            cold_path();
            println!("Mapping {:#?} to UnknownFail", e);
            FileStatus::UnknownFail
        }
    }
}

async fn create_entry(fs: &mut Fs, path: &Path, dir: bool) -> Result<(), FsError> {
    let path_str = path.as_str();
    if dir {
        let _ = fs.root_dir().create_dir(path_str).await?;
    } else {
        let mut file = fs.root_dir().create_file(path_str).await?;
        file.flush().await?;
    }
    Ok(())
}

async fn rename_entry(
    fs: &mut Fs,
    src: &Path,
    dst: &Path,
) -> Result<Option<RenamedFileState>, FsError> {
    let dst_dir = fs.root_dir();
    fs.root_dir()
        .rename_with_cached_file_state(src.as_str(), &dst_dir, dst.as_str())
        .await
}

async fn list_names(fs: &mut Fs, path: &Path) -> Result<Vec<String>, FsError> {
    let dir: FatDir = fs.root_dir().open_dir(path.as_str()).await?;
    let mut out = Vec::new();
    let mut iter = dir.iter();
    while let Some(r) = iter.next().await {
        let e = r?;
        let name = e.file_name();
        out.push(name);
    }
    Ok(out)
}

async fn resize_file(file: &mut FatFile<'_>, new_size: u64) -> Result<(), FsError> {
    let old_size = file.seek(SeekFrom::End(0)).await?;
    if new_size as u32 > u32::MAX {
        return Err(FsError::FileTooLarge);
    }
    if new_size <= old_size {
        file.seek(SeekFrom::Start(new_size)).await?;
        file.truncate().await?;
    } else {
        let mut remaining = new_size - old_size;
        while remaining != 0 {
            let take = remaining.min(ZERO_CHUNK.len() as u64) as usize;
            file.write_all(&ZERO_CHUNK[..take], fatfs::IoKind::Data)
                .await?;
            remaining -= take as u64;
        }
    }
    file.flush().await?;
    Ok(())
}

async fn write_file_zeros(file: &mut FatFile<'_>, mut len: u64) -> Result<(), FsError> {
    while len != 0 {
        let take = len.min(ZERO_CHUNK.len() as u64) as usize;
        file.write_all(&ZERO_CHUNK[..take], fatfs::IoKind::Data)
            .await?;
        len -= take as u64;
    }
    Ok(())
}

fn missing_cached_file_state(fs_file_id: u64) -> FileStatus {
    println!("Missing cached file state for fs_file_id {}", fs_file_id);
    FileStatus::UnknownFail
}

#[derive(Clone, Copy)]
enum LowerFlush {
    None,
    Background,
    Blocking,
}

fn take_cached_file_state(
    vdx: &VolCtrlDevExt,
    fs_file_id: u64,
) -> Result<CachedFileState, FileStatus> {
    let mut handles = vdx.handles.lock();
    handles.take_cached_state(fs_file_id)
}

fn schedule_lower_flush(vdx: &VolCtrlDevExt, fs_file_id: u64, lower_flush: LowerFlush) {
    match lower_flush {
        LowerFlush::None => {}
        LowerFlush::Background => flush_owner(vdx, fs_file_id),
        LowerFlush::Blocking => flush_owner_blocking(vdx, fs_file_id),
    }
}

fn restore_cached_file(vdx: &VolCtrlDevExt, fs_file_id: u64, file: FatFile<'_>) {
    let state = file.into_cached_state();
    let _ = vdx.handles.lock().restore_cached_state(fs_file_id, state);
}

async fn flush_cached_file(
    vdx: &VolCtrlDevExt,
    fs_file_id: u64,
    mut file: FatFile<'_>,
    lower_flush: LowerFlush,
) -> Option<FileStatus> {
    let err = file.flush().await.err().map(|e| map_fatfs_err(&e));
    restore_cached_file(vdx, fs_file_id, file);
    if likely(err.is_none()) {
        schedule_lower_flush(vdx, fs_file_id, lower_flush);
    } else {
        cold_path();
    }
    err
}

fn current_owner_for_op(op: FsOp, req: &mut RequestHandle<'_, '_>) -> Result<u64, DriverStatus> {
    match op {
        FsOp::Open | FsOp::Create | FsOp::ReadDir | FsOp::SetInfo | FsOp::Delete | FsOp::Rename => {
            Ok(METADATA_OWNER_ID)
        }
        FsOp::Close => req
            .data()
            .read_only()
            .view::<FsCloseParams>()
            .map(|p| p.fs_file_id)
            .ok_or(DriverStatus::InvalidParameter),
        FsOp::Read => req
            .data()
            .read_only()
            .view::<FsReadParams<'_>>()
            .map(|p| p.fs_file_id)
            .ok_or(DriverStatus::InvalidParameter),
        FsOp::Write => req
            .data()
            .read_only()
            .view::<FsWriteParams<'_>>()
            .map(|p| p.fs_file_id)
            .ok_or(DriverStatus::InvalidParameter),
        FsOp::Flush => req
            .data()
            .read_only()
            .view::<FsFlushParams>()
            .map(|p| p.fs_file_id)
            .ok_or(DriverStatus::InvalidParameter),
        FsOp::Seek => req
            .data()
            .read_only()
            .view::<FsSeekParams>()
            .map(|p| p.fs_file_id)
            .ok_or(DriverStatus::InvalidParameter),
        FsOp::GetInfo => req
            .data()
            .read_only()
            .view::<FsGetInfoParams>()
            .map(|p| p.fs_file_id)
            .ok_or(DriverStatus::InvalidParameter),
        FsOp::SetLen => req
            .data()
            .read_only()
            .view::<FsSetLenParams>()
            .map(|p| p.fs_file_id)
            .ok_or(DriverStatus::InvalidParameter),
        FsOp::Append => req
            .data()
            .read_only()
            .view::<FsAppendParams<'_>>()
            .map(|p| p.fs_file_id)
            .ok_or(DriverStatus::InvalidParameter),
        FsOp::ZeroRange => req
            .data()
            .read_only()
            .view::<FsZeroRangeParams>()
            .map(|p| p.fs_file_id)
            .ok_or(DriverStatus::InvalidParameter),
    }
}

async fn execute_fs_work(
    dev: &Arc<DeviceObject>,
    fs_arc: &Arc<AsyncMutex<Fs>>,
    req: &mut RequestHandle<'_, '_>,
) -> DriverStatus {
    let vdx = ext_mut::<VolCtrlDevExt>(dev);
    let mut fs = fs_arc.lock().await;

    let op = match req.read().kind {
        RequestType::Fs(op) => op,
        RequestType::DeviceControl(_) => {
            cold_path();
            return DriverStatus::NotImplemented;
        }
        _ => {
            cold_path();
            return DriverStatus::InvalidParameter;
        }
    };

    let owner = match current_owner_for_op(op, req) {
        Ok(owner) => owner,
        Err(status) => {
            cold_path();
            return status;
        }
    };
    vdx.current_owner.store(owner, Ordering::Release);

    match op {
        FsOp::Open => {
            let result = {
                let path = {
                    let data = req.data().read_only();

                    let Some(p) = data.view::<FsOpenParams>() else {
                        cold_path();
                        return DriverStatus::InvalidParameter;
                    };
                    let _ = (p.flags, p.write_through);
                    p.path.clone()
                };
                let path_str = path.as_str();
                let root = fs.root_dir();
                let open_res = match root.open_file(path_str).await {
                    Ok(mut f) => {
                        async {
                            let end = f.seek(SeekFrom::End(0)).await?;
                            f.seek(SeekFrom::Start(0)).await?;
                            Ok((false, end, Some(f.into_cached_state())))
                        }
                        .await
                    }
                    Err(FatError::NotFound) | Err(FatError::InvalidInput) => {
                        match root.open_dir(path_str).await {
                            Ok(_d) => Ok((true, 0, None)),
                            Err(e) => Err(e),
                        }
                    }
                    Err(e) => Err(e),
                };
                match open_res {
                    Ok((is_dir, size, cached)) => {
                        match vdx.handles.lock().insert(FileCtx {
                            is_dir,
                            pos: 0,
                            size,
                            cached,
                        }) {
                            Ok(id) => FsOpenResult {
                                fs_file_id: id,
                                is_dir,
                                size,
                                error: None,
                            },
                            Err(e) => FsOpenResult {
                                fs_file_id: 0,
                                is_dir: false,
                                size: 0,
                                error: Some(e),
                            },
                        }
                    }
                    Err(e) => FsOpenResult {
                        fs_file_id: 0,
                        is_dir: false,
                        size: 0,
                        error: Some(map_fatfs_err(&e)),
                    },
                }
            };

            req.write().set_data_t(result);
            DriverStatus::Success
        }

        FsOp::Close => {
            let fs_file_id = {
                let data = req.data().read_only();

                let Some(p) = data.view::<FsCloseParams>() else {
                    cold_path();
                    return DriverStatus::InvalidParameter;
                };
                p.fs_file_id
            };
            let removed_ctx = { vdx.handles.lock().remove(fs_file_id) };
            let err = match removed_ctx {
                Err(e) => Some(e),
                Ok(ctx) if ctx.is_dir => None,
                Ok(mut ctx) => match ctx.cached.take() {
                    Some(state) => {
                        let mut file = state.into_file(&*fs);
                        file.flush().await.err().map(|e| map_fatfs_err(&e))
                    }
                    None => Some(missing_cached_file_state(fs_file_id)),
                },
            };
            if err.is_none() {
                flush_owner_blocking(&vdx, fs_file_id);
            }
            req.write().set_data_t(FsCloseResult { error: err });
            DriverStatus::Success
        }

        FsOp::Read => {
            let (fs_file_id, offset, buf_ptr, buf_len) = {
                let data = req.data().read_only();

                let Some(p) = data.view::<FsReadParams<'_>>() else {
                    cold_path();
                    return DriverStatus::InvalidParameter;
                };
                (
                    p.fs_file_id,
                    p.offset,
                    p.buf.as_ptr() as *mut u8,
                    p.buf.len(),
                )
            };
            let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr, buf_len) };

            let result: Result<usize, FileStatus> = {
                let state = take_cached_file_state(&vdx, fs_file_id);
                match state {
                    Err(e) => Err(e),
                    Ok(state) => {
                        let mut file = state.into_file(&*fs);
                        let res = if let Err(e) = file.seek(SeekFrom::Start(offset)).await {
                            Err(map_fatfs_err(&e))
                        } else {
                            match file.read(buf, fatfs::IoKind::Data).await {
                                Ok(n) => Ok(n),
                                Err(e) => Err(map_fatfs_err(&e)),
                            }
                        };
                        restore_cached_file(&vdx, fs_file_id, file);
                        res
                    }
                }
            };

            let res = match result {
                Ok(n) => {
                    let new_pos = offset.saturating_add(n as u64);
                    {
                        let mut handles = vdx.handles.lock();
                        if let Ok(ctx) = handles.ctx_mut(fs_file_id) {
                            ctx.pos = new_pos;
                        }
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
                let data = req.data().read_only();

                let Some(p) = data.view::<FsWriteParams<'_>>() else {
                    cold_path();
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
            let data = unsafe { core::slice::from_raw_parts(data_ptr, data_len) };

            let write_res: Result<usize, FileStatus> = {
                let state = take_cached_file_state(&vdx, fs_file_id);
                match state {
                    Err(e) => Err(e),
                    Ok(state) => {
                        let mut file = state.into_file(&*fs);
                        let n = data.len();
                        let res = if let Err(e) = file.seek(SeekFrom::Start(offset)).await {
                            Err(map_fatfs_err(&e))
                        } else {
                            match file.write_all(data, fatfs::IoKind::Data).await {
                                Ok(()) => Ok(n),
                                Err(e) => Err(map_fatfs_err(&e)),
                            }
                        };
                        let lower_flush = if unlikely(write_through) && res.is_ok() {
                            LowerFlush::Blocking
                        } else {
                            LowerFlush::None
                        };
                        let flush_err = if unlikely(write_through) {
                            flush_cached_file(&vdx, fs_file_id, file, lower_flush).await
                        } else {
                            restore_cached_file(&vdx, fs_file_id, file);
                            None
                        };
                        match flush_err {
                            Some(e) => Err(e),
                            None => res,
                        }
                    }
                }
            };

            if let Ok(written) = write_res {
                let mut handles = vdx.handles.lock();
                if let Ok(ctx) = handles.ctx_mut(fs_file_id) {
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
                let data = req.data().read_only();

                let Some(p) = data.view::<FsFlushParams>() else {
                    cold_path();
                    return DriverStatus::InvalidParameter;
                };
                p.fs_file_id
            };
            let err = {
                let is_dir = {
                    let handles = vdx.handles.lock();
                    matches!(handles.ctx(fs_file_id), Ok(ctx) if ctx.is_dir)
                };
                if is_dir {
                    None
                } else {
                    let state = take_cached_file_state(&vdx, fs_file_id);
                    match state {
                        Err(e) => Some(e),
                        Ok(state) => {
                            let file = state.into_file(&*fs);
                            flush_cached_file(&vdx, fs_file_id, file, LowerFlush::Blocking).await
                        }
                    }
                }
            };
            req.write().set_data_t(FsFlushResult { error: err });
            DriverStatus::Success
        }

        FsOp::Create => {
            let err = {
                let (path, dir) = {
                    let data = req.data().read_only();

                    let Some(p) = data.view::<FsCreateParams>() else {
                        cold_path();
                        return DriverStatus::InvalidParameter;
                    };
                    (p.path.clone(), p.dir)
                };
                match create_entry(&mut *fs, &path, dir).await {
                    Ok(()) => None,
                    Err(e) => Some(map_fatfs_err(&e)),
                }
            };
            flush_owner_blocking(&vdx, owner);
            req.write().set_data_t(FsCreateResult { error: err });
            DriverStatus::Success
        }

        FsOp::Rename => {
            let err = {
                let (src, dst) = {
                    let data = req.data().read_only();

                    let Some(p) = data.view::<FsRenameParams>() else {
                        cold_path();
                        return DriverStatus::InvalidParameter;
                    };
                    (p.src.clone(), p.dst.clone())
                };
                match rename_entry(&mut *fs, &src, &dst).await {
                    Ok(renamed) => {
                        if let Some(renamed) = renamed {
                            vdx.handles.lock().update_renamed_file(&renamed);
                        }
                        flush_owner_blocking(&vdx, owner);
                        None
                    }
                    Err(e) => Some(map_fatfs_err(&e)),
                }
            };
            req.write().set_data_t(FsRenameResult { error: err });
            DriverStatus::Success
        }

        FsOp::ReadDir => {
            let res = {
                let path = {
                    let data = req.data().read_only();

                    let Some(p) = data.view::<FsListDirParams>() else {
                        cold_path();
                        return DriverStatus::InvalidParameter;
                    };
                    p.path.clone()
                };
                match list_names(&mut *fs, &path).await {
                    Ok(names) => FsListDirResult {
                        names: Some(names),
                        error: None,
                    },
                    Err(e) => FsListDirResult {
                        names: None,
                        error: Some(map_fatfs_err(&e)),
                    },
                }
            };
            req.write().set_data_t(res);
            DriverStatus::Success
        }

        FsOp::GetInfo => {
            let fs_file_id = {
                let data = req.data().read_only();

                let Some(p) = data.view::<FsGetInfoParams>() else {
                    cold_path();
                    return DriverStatus::InvalidParameter;
                };
                p.fs_file_id
            };
            let result = {
                let handles = vdx.handles.lock();
                match handles.ctx(fs_file_id) {
                    Err(e) => Err(e),
                    Ok(ctx) if ctx.is_dir => Ok((true, 0u64, u8::from(FileAttribute::Directory))),
                    Ok(ctx) => Ok((false, ctx.size, u8::from(FileAttribute::Archive))),
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
                let data = req.data().read_only();

                let Some(p) = data.view::<FsSetLenParams>() else {
                    cold_path();
                    return DriverStatus::InvalidParameter;
                };
                (p.fs_file_id, p.new_size)
            };
            let err = {
                let state = take_cached_file_state(&vdx, fs_file_id);
                match state {
                    Err(e) => Some(e),
                    Ok(state) => {
                        let mut file = state.into_file(&*fs);
                        let err = resize_file(&mut file, new_size)
                            .await
                            .err()
                            .map(|e| map_fatfs_err(&e));
                        restore_cached_file(&vdx, fs_file_id, file);
                        err
                    }
                }
            };
            if err.is_none() {
                flush_owner_blocking(&vdx, fs_file_id);
            }
            if err.is_none() {
                let mut handles = vdx.handles.lock();
                if let Ok(ctx) = handles.ctx_mut(fs_file_id) {
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
                let data = req.data().read_only();

                let Some(p) = data.view::<FsAppendParams<'_>>() else {
                    cold_path();
                    return DriverStatus::InvalidParameter;
                };
                (p.fs_file_id, p.write_through, p.data.as_ptr(), p.data.len())
            };
            let data = unsafe { core::slice::from_raw_parts(data_ptr, data_len) };

            let result: Result<(usize, u64), FileStatus> = {
                let start_off = {
                    let handles = vdx.handles.lock();
                    match handles.ctx(fs_file_id) {
                        Ok(ctx) if ctx.is_dir => Err(FileStatus::AccessDenied),
                        Ok(ctx) => Ok(ctx.size),
                        Err(e) => Err(e),
                    }
                };
                match start_off {
                    Err(e) => Err(e),
                    Ok(start_off) => {
                        let state = take_cached_file_state(&vdx, fs_file_id);
                        match state {
                            Err(e) => Err(e),
                            Ok(state) => {
                                let mut file = state.into_file(&*fs);
                                let res = match file.seek(SeekFrom::Start(start_off)).await {
                                    Ok(_) => {
                                        let n = data.len();
                                        match file.write_all(data, fatfs::IoKind::Data).await {
                                            Ok(()) => Ok((n, start_off + n as u64)),
                                            Err(e) => Err(map_fatfs_err(&e)),
                                        }
                                    }
                                    Err(e) => Err(map_fatfs_err(&e)),
                                };
                                let lower_flush = if unlikely(write_through) && res.is_ok() {
                                    LowerFlush::Blocking
                                } else {
                                    LowerFlush::None
                                };
                                let flush_err = if unlikely(write_through) {
                                    flush_cached_file(&vdx, fs_file_id, file, lower_flush).await
                                } else {
                                    restore_cached_file(&vdx, fs_file_id, file);
                                    None
                                };
                                match flush_err {
                                    Some(e) => Err(e),
                                    None => res,
                                }
                            }
                        }
                    }
                }
            };

            if let Ok((_, new_size)) = result {
                let mut handles = vdx.handles.lock();
                if let Ok(ctx) = handles.ctx_mut(fs_file_id) {
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
                let data = req.data().read_only();

                let Some(p) = data.view::<FsZeroRangeParams>() else {
                    cold_path();
                    return DriverStatus::InvalidParameter;
                };
                (p.fs_file_id, p.offset, p.len)
            };
            let err = {
                let state = take_cached_file_state(&vdx, fs_file_id);
                match state {
                    Err(e) => Some(e),
                    Ok(state) => {
                        let mut file = state.into_file(&*fs);
                        let file_len = file.seek(SeekFrom::End(0)).await.unwrap_or(0);
                        let end = offset.saturating_add(len);
                        let (op_err, lower_flush) = if offset > file_len {
                            (Some(FileStatus::BadPath), LowerFlush::None)
                        } else {
                            let actual_end = end.min(file_len);
                            let zero_len = actual_end.saturating_sub(offset);
                            if zero_len == 0 {
                                (None, LowerFlush::None)
                            } else {
                                match file.seek(SeekFrom::Start(offset)).await {
                                    Ok(_) => match write_file_zeros(&mut file, zero_len).await {
                                        Ok(()) => (None, LowerFlush::Background),
                                        Err(e) => (Some(map_fatfs_err(&e)), LowerFlush::None),
                                    },
                                    Err(e) => (Some(map_fatfs_err(&e)), LowerFlush::None),
                                }
                            }
                        };
                        let flush_err =
                            if op_err.is_none() && !matches!(lower_flush, LowerFlush::None) {
                                flush_cached_file(&vdx, fs_file_id, file, lower_flush).await
                            } else {
                                restore_cached_file(&vdx, fs_file_id, file);
                                None
                            };
                        flush_err.or(op_err)
                    }
                }
            };
            req.write().set_data_t(FsZeroRangeResult { error: err });
            DriverStatus::Success
        }

        FsOp::Seek => handle_seek_fast(dev, req),

        FsOp::SetInfo | FsOp::Delete => DriverStatus::NotImplemented,
    }
}

fn handle_seek_fast(dev: &Arc<DeviceObject>, req: &mut RequestHandle<'_, '_>) -> DriverStatus {
    let (fs_file_id, origin, offset) = {
        let data = req.data().read_only();

        let Some(p) = data.view::<FsSeekParams>() else {
            cold_path();
            return DriverStatus::InvalidParameter;
        };
        (p.fs_file_id, p.origin, p.offset)
    };
    let vdx = ext_mut::<VolCtrlDevExt>(dev);
    let result = {
        let mut handles = vdx.handles.lock();
        match handles.ctx_mut(fs_file_id) {
            Ok(ctx) => {
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
            Err(e) => Err(e),
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
pub async fn fs_op_dispatch(
    dev: &Arc<DeviceObject>,
    req: &mut RequestHandle<'_, '_>,
) -> DriverStep {
    if unlikely(matches!(req.read().kind, RequestType::Fs(FsOp::Seek))) {
        let status = handle_seek_fast(dev, req);
        req.write().status = status.clone();
        return DriverStep::complete(status);
    }

    let flush_metadata_after_op =
        matches!(req.read().kind, RequestType::Fs(FsOp::Close | FsOp::Flush));

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

    let status = execute_fs_work(dev, &fs_arc, req).await;

    if unlikely(flush_flag.swap(false, Ordering::AcqRel)) {
        let owner = pending_flush_owner.swap(0, Ordering::AcqRel);
        let should_block = pending_flush_block.swap(false, Ordering::AcqRel);
        if likely(owner != 0) {
            let _ = send_flush_owner(volume_target.clone(), owner, should_block).await;
        } else {
            cold_path();
        }
    }

    if unlikely(flush_metadata_after_op) {
        let _ = send_flush_owner(volume_target, METADATA_OWNER_ID, true).await;
    }

    req.write().status = status.clone();
    DriverStep::complete(status)
}
