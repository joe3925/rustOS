use crate::block_dev::{BlockDev, FatIoError};
use crate::control::ext_mut;
use crate::reader_pool::{ReaderLease, ReaderPool, ReaderSlot};
use alloc::{
    boxed::Box,
    collections::BTreeMap,
    string::String,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::ops::Deref;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use fatfs::{
    CachedFileState, Error as FatError, FileSystem as FatFsT, IoBase, LossyOemCpConverter,
    NullTimeProvider, SeekFrom, Write,
};
use kernel_api::device::DeviceObject;
use kernel_api::error::{DriverErrorKind, FileErrorKind, KernelError, error};
use kernel_api::kernel_types::dma::{
    IoBuffer, IoBufferBacking, IoBufferBackingConfig, IoBufferBackingDesc, ToDevice,
};
use kernel_api::kernel_types::io::{FileSystem, IoTarget};
use kernel_api::pnp::{DriverStep, io};
use kernel_api::request::{
    FlushOwner, Fs as FsRequest, FsAppend, FsClose, FsCreate, FsDelete, FsFlush, FsGetInfo, FsOpen,
    FsRead, FsReadDir, FsRemoveDir, FsRename, FsSeek, FsSetLen, FsWrite, FsZeroRange,
};
use kernel_api::{
    fs::{
        FileAttribute, FsAppendResult, FsCloseResult, FsCreateResult, FsDeleteResult,
        FsFlushResult, FsGetInfoResult, FsListDirResult, FsOpenResult, FsReadResult,
        FsRemoveDirResult, FsRenameResult, FsSeekResult, FsSeekWhence, FsSetLenResult,
        FsWriteResult, FsZeroRangeResult,
    },
    request_handler,
};
use kernel_sync::locks::AsyncRwLock;
use spin::{Mutex, Once};

type Fs = FatFsT<BlockDev, NullTimeProvider, LossyOemCpConverter>;
type FatFile<'a> = fatfs::File<'a, BlockDev, NullTimeProvider, LossyOemCpConverter>;
type FsError = FatError<<BlockDev as IoBase>::Error>;

pub(crate) const METADATA_OWNER_ID: u64 = 1;
pub(crate) const FIRST_FILE_OWNER_ID: u64 = METADATA_OWNER_ID + 1;
pub(crate) const FILE_HANDLE_CAPACITY: usize = 1024;
const ZERO_CHUNK_BYTES: usize = 64 * 1024;

#[repr(C)]
pub struct VolCtrlDevExt {
    mounted: Once<MountedFat32>,
}

pub struct MountedFat32 {
    pub fs: Arc<Fs>,
    pub(crate) metadata: AsyncRwLock<()>,
    pub(crate) namespace: AsyncRwLock<()>,
    pub(crate) readers: ReaderPool,
    pub(crate) handles: Mutex<FileHandleTable>,
    pub(crate) files: Mutex<BTreeMap<u64, Weak<FileNode>>>,
    pub(crate) next_owner: AtomicU64,
    pub(crate) volume_target: IoTarget,
    pub(crate) sector_size: u16,
    pub(crate) total_sectors: u64,
}

impl Default for VolCtrlDevExt {
    fn default() -> Self {
        Self {
            mounted: Once::new(),
        }
    }
}

impl VolCtrlDevExt {
    pub fn mount(&self, mounted: MountedFat32) -> Result<(), MountedFat32> {
        if self.mounted.get().is_some() {
            return Err(mounted);
        }
        self.mounted.call_once(|| mounted);
        Ok(())
    }
}

impl Deref for VolCtrlDevExt {
    type Target = MountedFat32;
    fn deref(&self) -> &Self::Target {
        self.mounted
            .get()
            .expect("FAT32 device used before StartDevice completed")
    }
}

pub(crate) struct FileNode {
    owner: u64,
    state: AsyncRwLock<FileState>,
}

struct FileState {
    cached: CachedFileState,
    revision: u64,
    unavailable: bool,
}

impl FileState {
    fn check(&self) -> Result<(), KernelError> {
        if self.unavailable {
            Err(error(FileErrorKind::AccessDenied)
                .with_context("accessing an unavailable FAT32 file"))
        } else {
            Ok(())
        }
    }
}

struct FileCtx {
    file: Option<Arc<FileNode>>,
    pos: AtomicU64,
    active: AtomicBool,
}

impl FileCtx {
    fn check(&self) -> Result<(), KernelError> {
        if !self.active.load(Ordering::Acquire) {
            return Err(
                error(FileErrorKind::PathNotFound).with_context("accessing a closed FAT32 handle")
            );
        }
        Ok(())
    }

    fn file(&self) -> Result<&Arc<FileNode>, KernelError> {
        self.file.as_ref().ok_or_else(|| {
            error(FileErrorKind::AccessDenied)
                .with_context("using a directory handle as a FAT32 file")
        })
    }
}

struct FileSlot {
    generation: u64,
    next_free: Option<usize>,
    ctx: Option<Arc<FileCtx>>,
    cursor: Option<(u64, CachedFileState)>,
}

pub(crate) struct FileHandleTable {
    slots: Box<[FileSlot]>,
    free_head: Option<usize>,
}

impl FileHandleTable {
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        let mut slots = Vec::with_capacity(capacity);
        for index in 0..capacity {
            slots.push(FileSlot {
                generation: 0,
                next_free: (index + 1 < capacity).then_some(index + 1),
                ctx: None,
                cursor: None,
            });
        }
        Self {
            slots: slots.into_boxed_slice(),
            free_head: (capacity != 0).then_some(0),
        }
    }

    fn index_and_generation(&self, id: u64) -> Result<(usize, u64), KernelError> {
        let raw = id
            .checked_sub(FIRST_FILE_OWNER_ID)
            .ok_or_else(|| error(FileErrorKind::PathNotFound))?;
        let capacity = self.slots.len() as u64;
        if capacity == 0 {
            return Err(error(FileErrorKind::PathNotFound));
        }
        Ok(((raw % capacity) as usize, raw / capacity))
    }

    fn slot(&self, id: u64) -> Result<&FileSlot, KernelError> {
        let (index, generation) = self.index_and_generation(id)?;
        let slot = &self.slots[index];
        if slot.generation != generation || slot.ctx.is_none() {
            return Err(error(FileErrorKind::PathNotFound));
        }
        Ok(slot)
    }

    fn ctx(&self, id: u64) -> Result<Arc<FileCtx>, KernelError> {
        Ok(self.slot(id)?.ctx.as_ref().unwrap().clone())
    }

    fn insert(&mut self, ctx: FileCtx) -> Result<u64, KernelError> {
        let index = self
            .free_head
            .ok_or_else(|| error(DriverErrorKind::InsufficientResources))?;
        self.free_head = self.slots[index].next_free.take();
        self.slots[index].ctx = Some(Arc::new(ctx));
        Ok(FIRST_FILE_OWNER_ID
            + self.slots[index].generation * self.slots.len() as u64
            + index as u64)
    }

    fn remove(&mut self, id: u64) -> Result<Arc<FileCtx>, KernelError> {
        let (index, generation) = self.index_and_generation(id)?;
        let slot = &mut self.slots[index];
        if slot.generation != generation {
            return Err(error(FileErrorKind::PathNotFound));
        }
        let ctx = slot
            .ctx
            .take()
            .ok_or_else(|| error(FileErrorKind::PathNotFound))?;
        slot.cursor = None;
        slot.generation = slot.generation.wrapping_add(1);
        slot.next_free = self.free_head;
        self.free_head = Some(index);
        Ok(ctx)
    }
}

impl MountedFat32 {
    async fn resolve_file(&self, path: &str) -> Result<Arc<FileNode>, FsError> {
        let _metadata = self.metadata.write().await;
        let cached = self
            .fs
            .root_dir()
            .open_file(path)
            .await?
            .into_cached_state();
        let entry = cached.entry_pos().ok_or(FsError::InvalidInput)?;
        let mut files = self.files.lock();
        if let Some(file) = files.get(&entry).and_then(Weak::upgrade) {
            return Ok(file);
        }
        let owner = self
            .next_owner
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |owner| {
                owner.checked_add(1)
            })
            .map_err(|_| FsError::NotEnoughSpace)?;
        let file = Arc::new(FileNode {
            owner,
            state: AsyncRwLock::new(FileState {
                cached,
                revision: 0,
                unavailable: false,
            }),
        });
        files.retain(|_, node| node.strong_count() != 0);
        files.insert(entry, Arc::downgrade(&file));
        Ok(file)
    }

    fn acquire_io(&self, owner: u64) -> Result<ReaderLease<'_>, KernelError> {
        let mut lease = ReaderLease {
            pool: &self.readers,
            slot: self.readers.take(false),
            pending: false,
        };
        if let Some(slot) = lease.slot.as_mut() {
            let next = core::mem::take(&mut slot.next);
            if next != 0 {
                self.readers
                    .put(unsafe { Box::from_raw(core::ptr::with_exposed_provenance_mut(next)) });
            }
            slot.reader.owner = owner;
        } else {
            lease.slot = Some(Box::new(ReaderSlot {
                reader: BlockDev::new(
                    self.volume_target.clone(),
                    self.sector_size,
                    self.total_sectors,
                    owner,
                )?,
                next: 0,
            }));
        }
        Ok(lease)
    }
}

fn map_fatfs_err(err: &FsError) -> KernelError {
    match err {
        FatError::Io(err) => err.0.clone(),
        FatError::NotFound => error(FileErrorKind::PathNotFound),
        FatError::AlreadyExists => error(FileErrorKind::AlreadyExists),
        FatError::InvalidInput => error(FileErrorKind::BadPath),
        FatError::NotEnoughSpace => error(FileErrorKind::NoSpace),
        FatError::CorruptedFileSystem => error(FileErrorKind::CorruptFilesystem),
        FatError::FileTooLarge => error(FileErrorKind::FileTooLarge),
        _ => error(FileErrorKind::UnknownFailure),
    }
}

async fn send_flush_owner(vdx: &MountedFat32, owner: u64) -> Result<(), KernelError> {
    let mut request = FlushOwner {
        owner,
        should_block: true,
    };
    io::send_down_stack(vdx.volume_target.clone(), &mut request)
        .await
        .map(|_| ())
}

async fn flush_file(
    vdx: &MountedFat32,
    state: &mut FileState,
    owner: u64,
) -> Result<(), KernelError> {
    send_flush_owner(vdx, owner).await?;
    {
        let _metadata = vdx.metadata.write().await;
        let mut file = state.cached.clone().into_file(&vdx.fs);
        let result = file.flush().await;
        state.cached = file.into_cached_state();
        result.map_err(|err| map_fatfs_err(&err))?;
    }
    send_flush_owner(vdx, METADATA_OWNER_ID).await
}

async fn write_file_zeros(
    file: &mut FatFile<'_>,
    block: &mut BlockDev,
    mut len: u64,
) -> Result<(), FsError> {
    if len == 0 {
        return Ok(());
    }
    let buffer_len = len.min(ZERO_CHUNK_BYTES as u64) as usize;
    let mut zeros = Vec::new();
    zeros
        .try_reserve_exact(buffer_len)
        .map_err(|_| FsError::NotEnoughSpace)?;
    zeros.resize(buffer_len, 0u8);
    let map_buffer_error = |cause| {
        FsError::Io(FatIoError(
            error(DriverErrorKind::InsufficientResources)
                .with_context(alloc::format!("preparing FAT32 zero buffer: {cause:?}")),
        ))
    };
    let backing = IoBufferBacking::new(
        IoBufferBackingDesc::Slice(&zeros),
        IoBufferBackingConfig {
            lease_capacity: 1,
            ..IoBufferBackingConfig::default()
        },
    )
    .map_err(map_buffer_error)?;
    let factory = backing
        .create_to_device_factory(0, buffer_len)
        .map_err(map_buffer_error)?;
    while len != 0 {
        let take = len.min(buffer_len as u64) as usize;
        let buffer = factory.create(0, take).map_err(map_buffer_error)?;
        let written = file
            .write_iobuffer_with(block, buffer, fatfs::IoKind::Data)
            .await?;
        if written != take {
            return Err(FsError::WriteZero);
        }
        len -= written as u64;
    }
    Ok(())
}

async fn trim_file(
    vdx: &MountedFat32,
    state: &mut FileState,
    owner: u64,
    size: u64,
) -> Result<(), KernelError> {
    send_flush_owner(vdx, owner).await?;
    let _metadata = vdx.metadata.write().await;
    let mut file = state.cached.clone().into_file(&vdx.fs);
    let result = async {
        file.seek(SeekFrom::Start(size)).await?;
        file.truncate().await?;
        file.flush().await
    }
    .await;
    state.cached = file.into_cached_state();
    state.revision = state.revision.wrapping_add(1);
    if result.is_err() {
        state.unavailable = true;
    }
    result.map_err(|err| map_fatfs_err(&err))
}

async fn write_cached_file<'buffer>(
    vdx: &MountedFat32,
    ctx: &FileCtx,
    offset: Option<u64>,
    buffer: IoBuffer<'buffer, 'buffer, ToDevice>,
    write_through: bool,
) -> Result<(usize, u64), KernelError> {
    let node = ctx.file()?;
    let mut state = node.state.write().await;
    state.check()?;
    ctx.check()?;
    let old_size = state.cached.size();
    let offset = offset.unwrap_or(old_size);
    if buffer.is_empty() {
        ctx.pos.store(offset, Ordering::Release);
        return Ok((0, old_size));
    }
    let end = offset
        .checked_add(buffer.len() as u64)
        .filter(|end| *end <= u32::MAX as u64)
        .ok_or_else(|| error(FileErrorKind::FileTooLarge))?;
    let mut lease = vdx.acquire_io(node.owner)?;
    let block = &mut lease.slot.as_mut().unwrap().reader;
    let mut file = state.cached.clone().into_file(&vdx.fs);
    let result = async {
        if end > old_size {
            let _metadata = vdx.metadata.write().await;
            file.reserve_len(end).await?;
        }
        if offset > old_size {
            file.seek_with(block, SeekFrom::End(0)).await?;
            write_file_zeros(&mut file, block, offset - old_size).await?;
        } else {
            file.seek_with(block, SeekFrom::Start(offset)).await?;
        }
        file.write_iobuffer_with(block, buffer, fatfs::IoKind::Data)
            .await
    }
    .await;
    state.cached = file.into_cached_state();
    if end > old_size {
        state.revision = state.revision.wrapping_add(1);
    }
    let written = match result {
        Ok(written) => {
            if end > old_size && offset.saturating_add(written as u64) < end {
                let size = old_size.max(offset.saturating_add(written as u64));
                trim_file(vdx, &mut state, node.owner, size).await?;
            }
            written
        }
        Err(err) => {
            if end > old_size {
                trim_file(vdx, &mut state, node.owner, old_size).await?;
            }
            return Err(map_fatfs_err(&err));
        }
    };
    ctx.pos.store(offset + written as u64, Ordering::Release);
    if write_through {
        flush_file(vdx, &mut state, node.owner).await?;
    }
    Ok((written, state.cached.size()))
}

pub struct Fat32Fs;

impl FileSystem for Fat32Fs {
    #[request_handler]
    async fn open<'req, 'data, 'b>(
        dev: &Arc<DeviceObject>,
        req: &'b mut FsRequest<'data, FsOpen>,
    ) -> Result<DriverStep, KernelError> {
        let vdx = ext_mut::<VolCtrlDevExt>(dev);
        let result = async {
            let _namespace = vdx.namespace.write().await;
            let path = req.payload.params.path.as_str();
            let file = match vdx.resolve_file(path).await {
                Ok(file) => Some(file),
                Err(FatError::NotFound | FatError::InvalidInput) => {
                    let _metadata = vdx.metadata.write().await;
                    vdx.fs
                        .root_dir()
                        .open_dir(path)
                        .await
                        .map_err(|err| map_fatfs_err(&err))?;
                    None
                }
                Err(err) => return Err(map_fatfs_err(&err)),
            };
            let size = if let Some(file) = &file {
                let state = file.state.read().await;
                state.check()?;
                state.cached.size()
            } else {
                0
            };
            let is_dir = file.is_none();
            let id = vdx.handles.lock().insert(FileCtx {
                file,
                pos: AtomicU64::new(0),
                active: AtomicBool::new(true),
            })?;
            Ok((id, is_dir, size))
        }
        .await;
        req.payload.result = Some(match result {
            Ok((fs_file_id, is_dir, size)) => FsOpenResult {
                fs_file_id,
                is_dir,
                size,
                error: None,
            },
            Err(err) => FsOpenResult {
                fs_file_id: 0,
                is_dir: false,
                size: 0,
                error: Some(err),
            },
        });
        Ok(DriverStep::Complete)
    }

    #[request_handler]
    async fn close<'req, 'data, 'b>(
        dev: &Arc<DeviceObject>,
        req: &'b mut FsRequest<'data, FsClose>,
    ) -> Result<DriverStep, KernelError> {
        let vdx = ext_mut::<VolCtrlDevExt>(dev);
        let result = async {
            let ctx = { vdx.handles.lock().remove(req.payload.params.fs_file_id)? };
            ctx.active.store(false, Ordering::Release);
            if let Some(node) = &ctx.file {
                let mut state = node.state.write().await;
                if !state.unavailable {
                    flush_file(&vdx, &mut state, node.owner).await?;
                }
            }
            Ok::<(), KernelError>(())
        }
        .await;
        req.payload.result = Some(FsCloseResult {
            error: result.err(),
        });
        Ok(DriverStep::Complete)
    }

    #[request_handler]
    async fn read<'req, 'data, 'b>(
        dev: &Arc<DeviceObject>,
        req: &'b mut FsRequest<'data, FsRead>,
    ) -> Result<DriverStep, KernelError> {
        let vdx = ext_mut::<VolCtrlDevExt>(dev);
        let params = &mut req.payload.params;
        let result = async {
            let (ctx, cursor) = {
                let handles = vdx.handles.lock();
                let slot = handles.slot(params.fs_file_id)?;
                (slot.ctx.as_ref().unwrap().clone(), slot.cursor.clone())
            };
            let node = ctx.file()?;
            let state = node.state.read().await;
            state.check()?;
            ctx.check()?;
            let buffer = params
                .buffer
                .take()
                .ok_or_else(|| error(FileErrorKind::NoBuffer))?;
            if params.offset >= state.cached.size() || buffer.is_empty() {
                ctx.pos.store(params.offset, Ordering::Release);
                return Ok(0);
            }
            let cached = {
                let mut cached = match cursor {
                    Some((revision, cached)) if revision == state.revision => cached,
                    _ => state.cached.clone(),
                };
                cached.refresh_dir_entry_from(&state.cached);
                cached
            };
            let mut file = cached.into_file(&vdx.fs);
            let mut lease = vdx.acquire_io(node.owner)?;
            let block = &mut lease.slot.as_mut().unwrap().reader;
            let read = async {
                file.seek_with(block, SeekFrom::Start(params.offset))
                    .await?;
                file.read_iobuffer_with(block, buffer, fatfs::IoKind::Data)
                    .await
            }
            .await;
            {
                let mut handles = vdx.handles.lock();
                if let Ok((index, generation)) = handles.index_and_generation(params.fs_file_id) {
                    let slot = &mut handles.slots[index];
                    if slot.generation == generation && slot.ctx.is_some() {
                        slot.cursor = Some((state.revision, file.into_cached_state()));
                    }
                }
            }
            let bytes = read.map_err(|err| map_fatfs_err(&err))?;
            ctx.pos
                .store(params.offset + bytes as u64, Ordering::Release);
            Ok(bytes)
        }
        .await;
        req.payload.result = Some(match result {
            Ok(bytes_read) => FsReadResult {
                bytes_read,
                error: None,
            },
            Err(err) => FsReadResult {
                bytes_read: 0,
                error: Some(err),
            },
        });
        Ok(DriverStep::Complete)
    }

    #[request_handler]
    async fn write<'req, 'data, 'b>(
        dev: &Arc<DeviceObject>,
        req: &'b mut FsRequest<'data, FsWrite>,
    ) -> Result<DriverStep, KernelError> {
        let vdx = ext_mut::<VolCtrlDevExt>(dev);
        let params = &mut req.payload.params;
        let result = async {
            let ctx = { vdx.handles.lock().ctx(params.fs_file_id)? };
            let buffer = params
                .buffer
                .take()
                .ok_or_else(|| error(FileErrorKind::NoBuffer))?;
            write_cached_file(
                &vdx,
                &ctx,
                Some(params.offset),
                buffer,
                params.write_through,
            )
            .await
        }
        .await;
        req.payload.result = Some(match result {
            Ok((written, _)) => FsWriteResult {
                written,
                error: None,
            },
            Err(err) => FsWriteResult {
                written: 0,
                error: Some(err),
            },
        });
        Ok(DriverStep::Complete)
    }

    #[request_handler]
    async fn flush<'req, 'data, 'b>(
        dev: &Arc<DeviceObject>,
        req: &'b mut FsRequest<'data, FsFlush>,
    ) -> Result<DriverStep, KernelError> {
        let vdx = ext_mut::<VolCtrlDevExt>(dev);
        let result = async {
            let ctx = { vdx.handles.lock().ctx(req.payload.params.fs_file_id)? };
            ctx.check()?;
            if let Some(node) = &ctx.file {
                let mut state = node.state.write().await;
                state.check()?;
                ctx.check()?;
                flush_file(&vdx, &mut state, node.owner).await?;
            } else {
                send_flush_owner(&vdx, METADATA_OWNER_ID).await?;
            }
            Ok::<(), KernelError>(())
        }
        .await;
        req.payload.result = Some(FsFlushResult {
            error: result.err(),
        });
        Ok(DriverStep::Complete)
    }

    #[request_handler]
    async fn seek<'req, 'data, 'b>(
        dev: &Arc<DeviceObject>,
        req: &'b mut FsRequest<'data, FsSeek>,
    ) -> Result<DriverStep, KernelError> {
        let vdx = ext_mut::<VolCtrlDevExt>(dev);
        let params = &req.payload.params;
        let result = async {
            let ctx = { vdx.handles.lock().ctx(params.fs_file_id)? };
            let state = match &ctx.file {
                Some(file) => Some(file.state.read().await),
                None => None,
            };
            if let Some(state) = &state {
                state.check()?;
            }
            ctx.check()?;
            let size = state.as_ref().map_or(0, |state| state.cached.size());
            let calculate = |old| {
                let base = match params.origin {
                    FsSeekWhence::Set => 0,
                    FsSeekWhence::Cur => old,
                    FsSeekWhence::End => size,
                };
                (base as i128 + params.offset as i128).clamp(0, u64::MAX as i128) as u64
            };
            let old = ctx
                .pos
                .try_update(Ordering::AcqRel, Ordering::Acquire, |old| {
                    Some(calculate(old))
                })
                .unwrap();
            Ok::<u64, KernelError>(calculate(old))
        }
        .await;
        req.payload.result = Some(match result {
            Ok(pos) => FsSeekResult { pos, error: None },
            Err(err) => FsSeekResult {
                pos: 0,
                error: Some(err),
            },
        });
        Ok(DriverStep::Complete)
    }

    #[request_handler]
    async fn create<'req, 'data, 'b>(
        dev: &Arc<DeviceObject>,
        req: &'b mut FsRequest<'data, FsCreate>,
    ) -> Result<DriverStep, KernelError> {
        let vdx = ext_mut::<VolCtrlDevExt>(dev);
        let result = async {
            {
                let _namespace = vdx.namespace.write().await;
                let _metadata = vdx.metadata.write().await;
                let params = &req.payload.params;
                if params.dir {
                    vdx.fs
                        .root_dir()
                        .create_dir(params.path.as_str())
                        .await
                        .map_err(|err| map_fatfs_err(&err))?;
                } else {
                    let mut file = vdx
                        .fs
                        .root_dir()
                        .create_file(params.path.as_str())
                        .await
                        .map_err(|err| map_fatfs_err(&err))?;
                    file.flush().await.map_err(|err| map_fatfs_err(&err))?;
                }
            }
            send_flush_owner(&vdx, METADATA_OWNER_ID).await
        }
        .await;
        req.payload.result = Some(FsCreateResult {
            error: result.err(),
        });
        Ok(DriverStep::Complete)
    }

    #[request_handler]
    async fn remove_dir<'req, 'data, 'b>(
        dev: &Arc<DeviceObject>,
        req: &'b mut FsRequest<'data, FsRemoveDir>,
    ) -> Result<DriverStep, KernelError> {
        let vdx = ext_mut::<VolCtrlDevExt>(dev);
        let result = async {
            {
                let _namespace = vdx.namespace.write().await;
                let _metadata = vdx.metadata.write().await;
                let path = req.payload.params.path.as_str();
                vdx.fs
                    .root_dir()
                    .open_dir(path)
                    .await
                    .map_err(|err| map_fatfs_err(&err))?;
                vdx.fs
                    .root_dir()
                    .remove(path)
                    .await
                    .map_err(|err| map_fatfs_err(&err))?;
            }
            send_flush_owner(&vdx, METADATA_OWNER_ID).await
        }
        .await;
        req.payload.result = Some(FsRemoveDirResult {
            error: result.err(),
        });
        Ok(DriverStep::Complete)
    }

    #[request_handler]
    async fn delete<'req, 'data, 'b>(
        dev: &Arc<DeviceObject>,
        req: &'b mut FsRequest<'data, FsDelete>,
    ) -> Result<DriverStep, KernelError> {
        let vdx = ext_mut::<VolCtrlDevExt>(dev);
        let result = async {
            {
                let _namespace = vdx.namespace.write().await;
                let path = req.payload.params.path.as_str();
                let node = vdx
                    .resolve_file(path)
                    .await
                    .map_err(|err| map_fatfs_err(&err))?;
                let mut state = node.state.write().await;
                state.check()?;
                flush_file(&vdx, &mut state, node.owner).await?;
                let _metadata = vdx.metadata.write().await;
                state.unavailable = true;
                vdx.fs
                    .root_dir()
                    .remove(path)
                    .await
                    .map_err(|err| map_fatfs_err(&err))?;
                if let Some(entry) = state.cached.entry_pos() {
                    vdx.files.lock().remove(&entry);
                }
            }
            send_flush_owner(&vdx, METADATA_OWNER_ID).await
        }
        .await;
        req.payload.result = Some(FsDeleteResult {
            error: result.err(),
        });
        Ok(DriverStep::Complete)
    }

    #[request_handler]
    async fn rename<'req, 'data, 'b>(
        dev: &Arc<DeviceObject>,
        req: &'b mut FsRequest<'data, FsRename>,
    ) -> Result<DriverStep, KernelError> {
        let vdx = ext_mut::<VolCtrlDevExt>(dev);
        let result = async {
            {
                let _namespace = vdx.namespace.write().await;
                let params = &req.payload.params;
                let node = match vdx.resolve_file(params.src.as_str()).await {
                    Ok(node) => Some(node),
                    Err(FatError::NotFound | FatError::InvalidInput) => None,
                    Err(err) => return Err(map_fatfs_err(&err)),
                };
                let mut state = match &node {
                    Some(node) => Some(node.state.write().await),
                    None => None,
                };
                if let (Some(node), Some(state)) = (&node, state.as_mut()) {
                    state.check()?;
                    flush_file(&vdx, state, node.owner).await?;
                }
                let _metadata = vdx.metadata.write().await;
                let renamed = vdx
                    .fs
                    .root_dir()
                    .rename_with_cached_file_state(
                        params.src.as_str(),
                        &vdx.fs.root_dir(),
                        params.dst.as_str(),
                    )
                    .await;
                match renamed {
                    Ok(Some(renamed)) => {
                        if let (Some(node), Some(state)) = (&node, state.as_mut()) {
                            state.cached.refresh_dir_entry_from(renamed.new_state());
                            let mut files = vdx.files.lock();
                            files.remove(&renamed.old_entry_pos());
                            if let Some(entry) = state.cached.entry_pos() {
                                files.insert(entry, Arc::downgrade(node));
                            }
                        }
                    }
                    Ok(None) => {}
                    Err(err) => {
                        if !matches!(
                            err,
                            FatError::AlreadyExists | FatError::NotFound | FatError::InvalidInput
                        ) {
                            if let Some(state) = state.as_mut() {
                                state.unavailable = true;
                            }
                        }
                        return Err(map_fatfs_err(&err));
                    }
                }
            }
            send_flush_owner(&vdx, METADATA_OWNER_ID).await
        }
        .await;
        req.payload.result = Some(FsRenameResult {
            error: result.err(),
        });
        Ok(DriverStep::Complete)
    }

    #[request_handler]
    async fn read_dir<'req, 'data, 'b>(
        dev: &Arc<DeviceObject>,
        req: &'b mut FsRequest<'data, FsReadDir>,
    ) -> Result<DriverStep, KernelError> {
        let vdx = ext_mut::<VolCtrlDevExt>(dev);
        let result = async {
            let _namespace = vdx.namespace.read().await;
            let _metadata = vdx.metadata.write().await;
            let dir = vdx
                .fs
                .root_dir()
                .open_dir(req.payload.params.path.as_str())
                .await?;
            let mut names = Vec::<String>::new();
            let mut entries = dir.iter();
            while let Some(entry) = entries.next().await {
                names.push(entry?.file_name());
            }
            Ok::<_, FsError>(names)
        }
        .await;
        req.payload.result = Some(match result {
            Ok(names) => FsListDirResult {
                names: Some(names),
                error: None,
            },
            Err(err) => FsListDirResult {
                names: None,
                error: Some(map_fatfs_err(&err)),
            },
        });
        Ok(DriverStep::Complete)
    }

    #[request_handler]
    async fn get_info<'req, 'data, 'b>(
        dev: &Arc<DeviceObject>,
        req: &'b mut FsRequest<'data, FsGetInfo>,
    ) -> Result<DriverStep, KernelError> {
        let vdx = ext_mut::<VolCtrlDevExt>(dev);
        let result = async {
            let ctx = { vdx.handles.lock().ctx(req.payload.params.fs_file_id)? };
            ctx.check()?;
            match &ctx.file {
                Some(node) => {
                    let state = node.state.read().await;
                    state.check()?;
                    ctx.check()?;
                    Ok((state.cached.size(), false, u8::from(FileAttribute::Archive)))
                }
                None => Ok::<_, KernelError>((0, true, u8::from(FileAttribute::Directory))),
            }
        }
        .await;
        req.payload.result = Some(match result {
            Ok((size, is_dir, attrs)) => FsGetInfoResult {
                size,
                is_dir,
                attrs: attrs as u32,
                error: None,
            },
            Err(err) => FsGetInfoResult {
                size: 0,
                is_dir: false,
                attrs: 0,
                error: Some(err),
            },
        });
        Ok(DriverStep::Complete)
    }

    #[request_handler]
    async fn set_len<'req, 'data, 'b>(
        dev: &Arc<DeviceObject>,
        req: &'b mut FsRequest<'data, FsSetLen>,
    ) -> Result<DriverStep, KernelError> {
        let vdx = ext_mut::<VolCtrlDevExt>(dev);
        let params = &req.payload.params;
        let result = async {
            let ctx = { vdx.handles.lock().ctx(params.fs_file_id)? };
            let node = ctx.file()?;
            let mut state = node.state.write().await;
            state.check()?;
            ctx.check()?;
            if params.new_size > u32::MAX as u64 {
                return Err(error(FileErrorKind::FileTooLarge));
            }
            let old_size = state.cached.size();
            if params.new_size <= old_size {
                trim_file(&vdx, &mut state, node.owner, params.new_size).await?;
            } else {
                let mut lease = vdx.acquire_io(node.owner)?;
                let block = &mut lease.slot.as_mut().unwrap().reader;
                let mut file = state.cached.clone().into_file(&vdx.fs);
                let result = async {
                    {
                        let _metadata = vdx.metadata.write().await;
                        file.reserve_len(params.new_size).await?;
                    }
                    file.seek_with(block, SeekFrom::End(0)).await?;
                    write_file_zeros(&mut file, block, params.new_size - old_size).await
                }
                .await;
                state.cached = file.into_cached_state();
                state.revision = state.revision.wrapping_add(1);
                if let Err(err) = result {
                    trim_file(&vdx, &mut state, node.owner, old_size).await?;
                    return Err(map_fatfs_err(&err));
                }
            }
            ctx.pos.fetch_min(params.new_size, Ordering::AcqRel);
            flush_file(&vdx, &mut state, node.owner).await
        }
        .await;
        req.payload.result = Some(FsSetLenResult {
            error: result.err(),
        });
        Ok(DriverStep::Complete)
    }

    #[request_handler]
    async fn append<'req, 'data, 'b>(
        dev: &Arc<DeviceObject>,
        req: &'b mut FsRequest<'data, FsAppend>,
    ) -> Result<DriverStep, KernelError> {
        let vdx = ext_mut::<VolCtrlDevExt>(dev);
        let params = &mut req.payload.params;
        let result = async {
            let ctx = { vdx.handles.lock().ctx(params.fs_file_id)? };
            let buffer = params
                .buffer
                .take()
                .ok_or_else(|| error(FileErrorKind::NoBuffer))?;
            write_cached_file(&vdx, &ctx, None, buffer, params.write_through).await
        }
        .await;
        req.payload.result = Some(match result {
            Ok((written, new_size)) => FsAppendResult {
                written,
                new_size,
                error: None,
            },
            Err(err) => FsAppendResult {
                written: 0,
                new_size: 0,
                error: Some(err),
            },
        });
        Ok(DriverStep::Complete)
    }

    #[request_handler]
    async fn zero_range<'req, 'data, 'b>(
        dev: &Arc<DeviceObject>,
        req: &'b mut FsRequest<'data, FsZeroRange>,
    ) -> Result<DriverStep, KernelError> {
        let vdx = ext_mut::<VolCtrlDevExt>(dev);
        let params = &req.payload.params;
        let result = async {
            let ctx = { vdx.handles.lock().ctx(params.fs_file_id)? };
            let node = ctx.file()?;
            let mut state = node.state.write().await;
            state.check()?;
            ctx.check()?;
            let size = state.cached.size();
            if params.offset > size {
                return Err(error(FileErrorKind::BadPath));
            }
            let len = params.len.min(size - params.offset);
            let mut file = state.cached.clone().into_file(&vdx.fs);
            let mut lease = vdx.acquire_io(node.owner)?;
            let block = &mut lease.slot.as_mut().unwrap().reader;
            let result = async {
                file.seek_with(block, SeekFrom::Start(params.offset))
                    .await?;
                write_file_zeros(&mut file, block, len).await
            }
            .await;
            state.cached = file.into_cached_state();
            result.map_err(|err| map_fatfs_err(&err))?;
            flush_file(&vdx, &mut state, node.owner).await
        }
        .await;
        req.payload.result = Some(FsZeroRangeResult {
            error: result.err(),
        });
        Ok(DriverStep::Complete)
    }
}
