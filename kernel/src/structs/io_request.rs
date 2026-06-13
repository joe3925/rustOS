use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};

use kernel_types::fs::{OpenFlags, Path};
use kernel_types::status::FileStatus;
use spin::Mutex;

use crate::executable::program::{Message, ProgramHandle, QueueHandle, UserHandle};
use crate::file_system::file::File;
use crate::memory::paging::{base_page_size, kernel_space_base};
use crate::object_manager::{OBJECT_MANAGER, Object, ObjectPayload};
use crate::platform;
use crate::util::generate_guid;

pub type RequestId = u64;

pub const IO_STATUS_SUCCESS: u64 = 0;
pub const IO_STATUS_CANCELLED: u64 = 0xC000_0120;
pub const IO_STATUS_INVALID_PARAMETER: u64 = 0xC000_000D;
pub const IO_STATUS_INVALID_HANDLE: u64 = 0xC000_0008;
pub const IO_STATUS_BUFFER_TOO_SMALL: u64 = 0xC000_0023;
pub const IO_STATUS_NO_MEMORY: u64 = 0xC000_0017;
pub const IO_STATUS_FILE_ERROR_BASE: u64 = 0x0003_0000;
pub const IO_STATUS_MESSAGE_ERROR_BASE: u64 = 0x0004_0000;

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoOpcode {
    FileOpen = 1,
    FileRead = 2,
    FileWrite = 3,
    FileDelete = 4,
    ListDir = 5,
    ChangeDirectory = 6,
    MqReceive = 7,

    SocketRecv = 64,
    SocketSend = 65,
    TimerWait = 66,
    ProcessWait = 67,
    Ioctl = 68,
}

impl IoOpcode {
    pub fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            1 => Some(Self::FileOpen),
            2 => Some(Self::FileRead),
            3 => Some(Self::FileWrite),
            4 => Some(Self::FileDelete),
            5 => Some(Self::ListDir),
            6 => Some(Self::ChangeDirectory),
            7 => Some(Self::MqReceive),
            64 => Some(Self::SocketRecv),
            65 => Some(Self::SocketSend),
            66 => Some(Self::TimerWait),
            67 => Some(Self::ProcessWait),
            68 => Some(Self::Ioctl),
            _ => None,
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoRequestState {
    Free = 0,
    Submitted = 1,
    Running = 2,
    CancelRequested = 3,
    CompleteQueued = 4,
    Reaped = 5,
}

impl IoRequestState {
    #[inline]
    pub fn from_u8(raw: u8) -> Self {
        match raw {
            0 => Self::Free,
            1 => Self::Submitted,
            2 => Self::Running,
            3 => Self::CancelRequested,
            4 => Self::CompleteQueued,
            5 => Self::Reaped,
            _ => Self::Free,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UserIoOp {
    pub opcode: u32,
    pub flags: u32,
    pub target_handle: UserHandle,
    pub user_token: u64,
    pub buffer: u64,
    pub length: u64,
    pub offset: u64,
    pub extra0: u64,
    pub extra1: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct UserIoCompletion {
    pub request_id: RequestId,
    pub user_token: u64,
    pub opcode: u32,
    pub reserved: u32,
    pub status: u64,
    pub result: u64,
    pub extra: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct IoRequestOutput {
    pub status: u64,
    pub result: u64,
    pub extra: u64,
}

impl IoRequestOutput {
    #[inline]
    pub const fn success(result: u64, extra: u64) -> Self {
        Self {
            status: IO_STATUS_SUCCESS,
            result,
            extra,
        }
    }

    #[inline]
    pub const fn error(status: u64) -> Self {
        Self {
            status,
            result: 0,
            extra: 0,
        }
    }
}

pub type IoRequestFuture = Pin<Box<dyn Future<Output = IoRequestOutput> + Send + 'static>>;

struct FileObjectState {
    file: Option<File>,
    waiters: Vec<Waker>,
}

pub struct FileObject {
    state: Mutex<FileObjectState>,
}

impl core::fmt::Debug for FileObject {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FileObject").finish_non_exhaustive()
    }
}

impl FileObject {
    pub fn new(file: File) -> Self {
        Self {
            state: Mutex::new(FileObjectState {
                file: Some(file),
                waiters: Vec::new(),
            }),
        }
    }

    pub fn take(self: &Arc<Self>) -> TakeFileFuture {
        TakeFileFuture {
            object: self.clone(),
        }
    }

    fn put(&self, file: File) {
        let waiters = {
            let mut state = self.state.lock();
            state.file = Some(file);
            core::mem::take(&mut state.waiters)
        };

        for waiter in waiters {
            waiter.wake();
        }
    }
}

pub struct FileLease {
    object: Arc<FileObject>,
    file: Option<File>,
}

impl FileLease {
    #[inline]
    pub fn file(&self) -> &File {
        self.file.as_ref().expect("file lease missing file")
    }

    #[inline]
    pub fn file_mut(&mut self) -> &mut File {
        self.file.as_mut().expect("file lease missing file")
    }
}

impl Drop for FileLease {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            self.object.put(file);
        }
    }
}

pub struct TakeFileFuture {
    object: Arc<FileObject>,
}

impl Future for TakeFileFuture {
    type Output = FileLease;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = self.object.state.lock();
        if let Some(file) = state.file.take() {
            return Poll::Ready(FileLease {
                object: self.object.clone(),
                file: Some(file),
            });
        }

        if state
            .waiters
            .iter()
            .all(|waiter| !waiter.will_wake(cx.waker()))
        {
            state.waiters.push(cx.waker().clone());
        }

        Poll::Pending
    }
}

pub enum KernelIoOp {
    FileOpen {
        owner_pid: u64,
        owner: ProgramHandle,
        path: Path,
        flags: Vec<OpenFlags>,
        user_token: u64,
    },
    FileRead {
        owner: ProgramHandle,
        file: Arc<FileObject>,
        buffer: u64,
        length: usize,
        offset: u64,
        user_token: u64,
    },
    FileWrite {
        file: Arc<FileObject>,
        data: Vec<u8>,
        offset: u64,
        user_token: u64,
    },
    FileDeleteHandle {
        file: Arc<FileObject>,
        user_token: u64,
    },
    FileDeletePath {
        path: Path,
        user_token: u64,
    },
    ListDir {
        owner: ProgramHandle,
        path: Path,
        user_token: u64,
    },
    ChangeDirectory {
        owner: ProgramHandle,
        path: Path,
        user_token: u64,
    },
    MqReceive {
        owner: ProgramHandle,
        queue: QueueHandle,
        buffer: u64,
        length: usize,
        user_token: u64,
    },
}

impl KernelIoOp {
    #[inline]
    pub fn opcode(&self) -> IoOpcode {
        match self {
            Self::FileOpen { .. } => IoOpcode::FileOpen,
            Self::FileRead { .. } => IoOpcode::FileRead,
            Self::FileWrite { .. } => IoOpcode::FileWrite,
            Self::FileDeleteHandle { .. } | Self::FileDeletePath { .. } => IoOpcode::FileDelete,
            Self::ListDir { .. } => IoOpcode::ListDir,
            Self::ChangeDirectory { .. } => IoOpcode::ChangeDirectory,
            Self::MqReceive { .. } => IoOpcode::MqReceive,
        }
    }

    #[inline]
    pub fn user_token(&self) -> u64 {
        match self {
            Self::FileOpen { user_token, .. }
            | Self::FileRead { user_token, .. }
            | Self::FileWrite { user_token, .. }
            | Self::FileDeleteHandle { user_token, .. }
            | Self::FileDeletePath { user_token, .. }
            | Self::ListDir { user_token, .. }
            | Self::ChangeDirectory { user_token, .. }
            | Self::MqReceive { user_token, .. } => *user_token,
        }
    }

    pub fn into_future(self) -> IoRequestFuture {
        match self {
            Self::FileOpen {
                owner_pid,
                owner,
                path,
                flags,
                ..
            } => Box::pin(async move { run_file_open(owner_pid, owner, path, flags).await }),
            Self::FileRead {
                owner,
                file,
                buffer,
                length,
                offset,
                ..
            } => Box::pin(async move { run_file_read(owner, file, buffer, length, offset).await }),
            Self::FileWrite {
                file, data, offset, ..
            } => Box::pin(async move { run_file_write(file, data, offset).await }),
            Self::FileDeleteHandle { file, .. } => {
                Box::pin(async move { run_file_delete_handle(file).await })
            }
            Self::FileDeletePath { path, .. } => {
                Box::pin(async move { run_file_delete_path(path).await })
            }
            Self::ListDir { owner, path, .. } => {
                Box::pin(async move { run_list_dir(owner, path).await })
            }
            Self::ChangeDirectory { owner, path, .. } => {
                Box::pin(async move { run_change_directory(owner, path).await })
            }
            Self::MqReceive {
                owner,
                queue,
                buffer,
                length,
                ..
            } => Box::pin(MqReceiveFuture {
                owner,
                queue,
                buffer,
                length,
            }),
        }
    }
}

pub struct IoRequestSlot {
    pub request_id: core::sync::atomic::AtomicU64,
    pub state: core::sync::atomic::AtomicU8,
    pub waker: Mutex<Option<Waker>>,
}

impl IoRequestSlot {
    pub fn new() -> Self {
        Self {
            request_id: core::sync::atomic::AtomicU64::new(0),
            state: core::sync::atomic::AtomicU8::new(IoRequestState::Free as u8),
            waker: Mutex::new(None),
        }
    }
}

pub struct IoRequestTable {
    slots: Vec<IoRequestSlot>,
    next_request_id: core::sync::atomic::AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestTableError {
    Full,
    NotFound,
    AlreadyComplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompleteTransition {
    Normal,
    Cancelled,
}

impl IoRequestTable {
    pub fn new(capacity: usize) -> Self {
        let mut slots = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            slots.push(IoRequestSlot::new());
        }

        Self {
            slots,
            next_request_id: core::sync::atomic::AtomicU64::new(1),
        }
    }

    pub fn capacity(&self) -> usize {
        self.slots.len()
    }

    pub fn allocate(&self) -> Result<RequestId, RequestTableError> {
        use core::sync::atomic::Ordering;

        for slot in &self.slots {
            if slot
                .state
                .compare_exchange(
                    IoRequestState::Free as u8,
                    IoRequestState::Submitted as u8,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                continue;
            }

            let request_id = self.next_request_id.fetch_add(1, Ordering::AcqRel);
            slot.request_id.store(request_id, Ordering::Release);
            *slot.waker.lock() = None;
            return Ok(request_id);
        }

        Err(RequestTableError::Full)
    }

    pub fn mark_running_or_cancelled(
        &self,
        request_id: RequestId,
    ) -> Result<CompleteTransition, RequestTableError> {
        use core::sync::atomic::Ordering;

        let slot = self.find_slot(request_id)?;

        loop {
            let state = IoRequestState::from_u8(slot.state.load(Ordering::Acquire));
            match state {
                IoRequestState::Submitted => {
                    if slot
                        .state
                        .compare_exchange(
                            IoRequestState::Submitted as u8,
                            IoRequestState::Running as u8,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        return Ok(CompleteTransition::Normal);
                    }
                }
                IoRequestState::Running => return Ok(CompleteTransition::Normal),
                IoRequestState::CancelRequested => return Ok(CompleteTransition::Cancelled),
                IoRequestState::CompleteQueued | IoRequestState::Reaped | IoRequestState::Free => {
                    return Err(RequestTableError::AlreadyComplete);
                }
            }
        }
    }

    pub fn complete(&self, request_id: RequestId) -> Result<CompleteTransition, RequestTableError> {
        use core::sync::atomic::Ordering;

        let slot = self.find_slot(request_id)?;
        loop {
            let state = IoRequestState::from_u8(slot.state.load(Ordering::Acquire));
            let transition = match state {
                IoRequestState::Submitted | IoRequestState::Running => CompleteTransition::Normal,
                IoRequestState::CancelRequested => CompleteTransition::Cancelled,
                IoRequestState::CompleteQueued | IoRequestState::Reaped | IoRequestState::Free => {
                    return Err(RequestTableError::AlreadyComplete);
                }
            };

            if slot
                .state
                .compare_exchange(
                    state as u8,
                    IoRequestState::CompleteQueued as u8,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                *slot.waker.lock() = None;
                return Ok(transition);
            }
        }
    }

    pub fn cancel(&self, request_id: RequestId) -> Result<(), RequestTableError> {
        use core::sync::atomic::Ordering;

        let slot = self.find_slot(request_id)?;
        loop {
            let state = IoRequestState::from_u8(slot.state.load(Ordering::Acquire));
            match state {
                IoRequestState::Submitted | IoRequestState::Running => {
                    if slot
                        .state
                        .compare_exchange(
                            state as u8,
                            IoRequestState::CancelRequested as u8,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        if let Some(waker) = slot.waker.lock().take() {
                            waker.wake();
                        }
                        return Ok(());
                    }
                }
                IoRequestState::CancelRequested => return Ok(()),
                IoRequestState::CompleteQueued | IoRequestState::Reaped | IoRequestState::Free => {
                    return Err(RequestTableError::AlreadyComplete);
                }
            }
        }
    }

    pub fn set_waker(&self, request_id: RequestId, waker: &Waker) {
        if let Ok(slot) = self.find_slot(request_id) {
            let mut guard = slot.waker.lock();
            if guard
                .as_ref()
                .is_none_or(|current| !current.will_wake(waker))
            {
                *guard = Some(waker.clone());
            }
        }
    }

    pub fn reap(&self, request_id: RequestId) {
        use core::sync::atomic::Ordering;

        let Ok(slot) = self.find_slot(request_id) else {
            return;
        };

        if slot
            .state
            .compare_exchange(
                IoRequestState::CompleteQueued as u8,
                IoRequestState::Reaped as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            slot.request_id.store(0, Ordering::Release);
            *slot.waker.lock() = None;
            slot.state
                .store(IoRequestState::Free as u8, Ordering::Release);
        }
    }

    fn find_slot(&self, request_id: RequestId) -> Result<&IoRequestSlot, RequestTableError> {
        use core::sync::atomic::Ordering;

        for slot in &self.slots {
            if slot.request_id.load(Ordering::Acquire) == request_id {
                return Ok(slot);
            }
        }

        Err(RequestTableError::NotFound)
    }
}

fn file_status(status: FileStatus) -> u64 {
    IO_STATUS_FILE_ERROR_BASE | status as u64
}

#[inline(always)]
fn is_user_addr(addr: u64) -> bool {
    (base_page_size()..kernel_space_base().as_u64()).contains(&addr)
}

#[inline(always)]
fn user_ptr_range_ok(addr: u64, bytes: usize) -> bool {
    if bytes == 0 {
        return true;
    }

    is_user_addr(addr)
        && addr
            .checked_add(bytes as u64)
            .is_some_and(|end| is_user_addr(end - 1))
}

fn with_process_address_space<T>(owner: &ProgramHandle, f: impl FnOnce() -> T) -> T {
    let process_address_space_root = owner.read().address_space_root;
    let old_address_space_root = crate::memory::paging::current_address_space_root();

    platform::with_interrupts_disabled(|| {
        unsafe {
            crate::memory::paging::switch_address_space_root(process_address_space_root);
        }
        let result = f();
        unsafe {
            crate::memory::paging::switch_address_space_root(old_address_space_root);
        }
        result
    })
}

fn copy_to_user_bytes(owner: &ProgramHandle, dst: u64, bytes: &[u8]) -> Result<(), u64> {
    if !user_ptr_range_ok(dst, bytes.len()) {
        return Err(IO_STATUS_INVALID_PARAMETER);
    }

    with_process_address_space(owner, || unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), dst as *mut u8, bytes.len());
    });

    Ok(())
}

fn copy_to_user_value<T: Clone>(owner: &ProgramHandle, dst: u64, value: &T) -> Result<(), u64> {
    if !user_ptr_range_ok(dst, core::mem::size_of::<T>()) {
        return Err(IO_STATUS_INVALID_PARAMETER);
    }

    let cloned = value.clone();
    with_process_address_space(owner, || unsafe {
        core::ptr::write_unaligned(dst as *mut T, cloned);
    });

    Ok(())
}

fn alloc_user_bytes(owner: &ProgramHandle, bytes: &[u8]) -> Result<u64, u64> {
    let dst = owner
        .read()
        .virtual_map_auto_alloc(bytes.len())
        .map_err(|_| IO_STATUS_NO_MEMORY)?;
    copy_to_user_bytes(owner, dst.as_u64(), bytes)?;
    Ok(dst.as_u64())
}

#[inline]
fn guid_to_string(g: &[u8; 16]) -> String {
    let d1 = u32::from_le_bytes([g[0], g[1], g[2], g[3]]);
    let d2 = u16::from_le_bytes([g[4], g[5]]);
    let d3 = u16::from_le_bytes([g[6], g[7]]);
    alloc::format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        d1,
        d2,
        d3,
        g[8],
        g[9],
        g[10],
        g[11],
        g[12],
        g[13],
        g[14],
        g[15]
    )
}

fn create_file_handle(
    owner_pid: u64,
    owner: &ProgramHandle,
    file: File,
) -> Result<UserHandle, u64> {
    let dir = alloc::format!("\\Process\\{}\\Files", owner_pid);
    OBJECT_MANAGER
        .mkdir_p(dir.clone())
        .map_err(|_| IO_STATUS_INVALID_PARAMETER)?;

    let name = guid_to_string(&generate_guid());
    let file_object = Arc::new(FileObject::new(file));
    let object = Object::with_name(
        kernel_types::object_manager::ObjectTag::File,
        name.clone(),
        ObjectPayload::File(file_object),
    );
    OBJECT_MANAGER
        .link(alloc::format!("{}\\{}", dir, name), &object)
        .map_err(|_| IO_STATUS_INVALID_PARAMETER)?;

    Ok(owner.read().create_user_handle_for_object(object))
}

async fn run_file_open(
    owner_pid: u64,
    owner: ProgramHandle,
    path: Path,
    flags: Vec<OpenFlags>,
) -> IoRequestOutput {
    match File::open(&path, &flags).await {
        Ok(file) => match create_file_handle(owner_pid, &owner, file) {
            Ok(handle) => IoRequestOutput::success(handle, 0),
            Err(status) => IoRequestOutput::error(status),
        },
        Err(status) => IoRequestOutput::error(file_status(status)),
    }
}

async fn run_file_read(
    owner: ProgramHandle,
    file: Arc<FileObject>,
    buffer: u64,
    length: usize,
    offset: u64,
) -> IoRequestOutput {
    if length == 0 {
        return IoRequestOutput::success(0, 0);
    }

    let lease = file.take().await;
    let mut data = alloc::vec![0u8; length];
    let n = match lease.file().read_at(offset, &mut data).await {
        Ok(n) => n,
        Err(status) => return IoRequestOutput::error(file_status(status)),
    };
    data.truncate(n);
    drop(lease);

    if let Err(status) = copy_to_user_bytes(&owner, buffer, &data) {
        return IoRequestOutput::error(status);
    }

    IoRequestOutput::success(data.len() as u64, 0)
}

async fn run_file_write(file: Arc<FileObject>, data: Vec<u8>, offset: u64) -> IoRequestOutput {
    if data.is_empty() {
        return IoRequestOutput::success(0, 0);
    }

    let mut lease = file.take().await;
    match lease.file_mut().write_at(offset, &data).await {
        Ok(written) => IoRequestOutput::success(written as u64, 0),
        Err(status) => IoRequestOutput::error(file_status(status)),
    }
}

async fn run_file_delete_handle(file: Arc<FileObject>) -> IoRequestOutput {
    let mut lease = file.take().await;
    match lease.file_mut().delete().await {
        Ok(()) => IoRequestOutput::success(0, 0),
        Err(status) => IoRequestOutput::error(file_status(status)),
    }
}

async fn run_file_delete_path(path: Path) -> IoRequestOutput {
    let mut file = match File::open(&path, &[OpenFlags::Open, OpenFlags::ReadWrite]).await {
        Ok(file) => file,
        Err(status) => return IoRequestOutput::error(file_status(status)),
    };

    match file.delete().await {
        Ok(()) => IoRequestOutput::success(0, 0),
        Err(status) => IoRequestOutput::error(file_status(status)),
    }
}

async fn run_list_dir(owner: ProgramHandle, path: Path) -> IoRequestOutput {
    let entries = match File::list_dir(&path).await {
        Ok(entries) => entries,
        Err(status) => return IoRequestOutput::error(file_status(status)),
    };

    let joined = if entries.is_empty() {
        String::new()
    } else {
        entries.join("\n")
    };
    let mut bytes = joined.into_bytes();
    bytes.push(0);

    match alloc_user_bytes(&owner, &bytes) {
        Ok(ptr) => IoRequestOutput::success(ptr, bytes.len() as u64),
        Err(status) => IoRequestOutput::error(status),
    }
}

async fn run_change_directory(owner: ProgramHandle, path: Path) -> IoRequestOutput {
    if let Err(status) = File::list_dir(&path).await {
        return IoRequestOutput::error(file_status(status));
    }

    owner.write().working_dir = path;
    IoRequestOutput::success(0, 0)
}

pub struct MqReceiveFuture {
    owner: ProgramHandle,
    queue: QueueHandle,
    buffer: u64,
    length: usize,
}

impl Future for MqReceiveFuture {
    type Output = IoRequestOutput;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut queue = this.queue.write();

        if let Some(message) = queue.try_pop_message() {
            drop(queue);

            let message_size = core::mem::size_of::<Message>();
            if this.length < message_size {
                return Poll::Ready(IoRequestOutput::error(IO_STATUS_BUFFER_TOO_SMALL));
            }

            return Poll::Ready(
                match copy_to_user_value(&this.owner, this.buffer, &message) {
                    Ok(()) => IoRequestOutput::success(message_size as u64, 0),
                    Err(status) => IoRequestOutput::error(status),
                },
            );
        }

        queue.register_waker(cx.waker());
        Poll::Pending
    }
}
