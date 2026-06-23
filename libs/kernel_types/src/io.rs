use crate::async_ffi::FfiFuture;
use crate::device::DeviceObject;
use crate::irq::IrqSafeMutex;
use crate::pnp::DriverStep;
use crate::request::{
    DeviceControl, Flush, FlushDirty, FlushOwner, Fs as FsRequest, FsAppend, FsClose, FsCreate,
    FsFlush, FsGetInfo, FsOpen, FsRead, FsReadDir, FsRename, FsSeek, FsSetLen, FsWrite,
    FsZeroRange, Read, RequestHandle, Write,
};
use crate::{
    EvtFsAppend, EvtFsClose, EvtFsCreate, EvtFsFlush, EvtFsGetInfo, EvtFsOpen, EvtFsRead,
    EvtFsReadDir, EvtFsRename, EvtFsSeek, EvtFsSetLen, EvtFsWrite, EvtFsZeroRange,
    EvtIoDeviceControl, EvtIoFlush, EvtIoFlushDirty, EvtIoFlushOwner, EvtIoRead, EvtIoWrite,
};
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ptr;
use core::ptr::NonNull;
use core::sync::atomic::AtomicPtr;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;
use core::task::Waker;

#[repr(C)]
struct TreiberNode<T> {
    data: UnsafeCell<MaybeUninit<T>>,
    next: AtomicPtr<TreiberNode<T>>,
}

#[repr(C)]
pub struct TreiberStack<T> {
    head: AtomicPtr<TreiberNode<T>>,
    retired: AtomicPtr<TreiberNode<T>>,
    len: AtomicUsize,
    op_lock: IrqSafeMutex<()>,
}

unsafe impl<T: Send> Send for TreiberStack<T> {}
unsafe impl<T: Send> Sync for TreiberStack<T> {}

impl<T> TreiberStack<T> {
    pub const fn new() -> Self {
        Self {
            head: AtomicPtr::new(ptr::null_mut()),
            retired: AtomicPtr::new(ptr::null_mut()),
            len: AtomicUsize::new(0),
            op_lock: IrqSafeMutex::new(()),
        }
    }

    pub fn len(&self) -> usize {
        self.len.load(Ordering::Acquire)
    }

    pub fn is_empty(&self) -> bool {
        self.head.load(Ordering::Acquire).is_null()
    }

    pub fn push(&self, data: T) {
        let node = Box::into_raw(Box::new(TreiberNode {
            data: UnsafeCell::new(MaybeUninit::new(data)),
            next: AtomicPtr::new(ptr::null_mut()),
        }));

        let _guard = self.op_lock.lock();
        self.len.fetch_add(1, Ordering::Release);
        unsafe { Self::push_raw(&self.head, node) };
    }

    pub fn pop(&self) -> Option<T> {
        let _guard = self.op_lock.lock();
        let node = unsafe { Self::pop_raw(&self.head)? };

        self.len.fetch_sub(1, Ordering::AcqRel);

        let data = unsafe {
            let data = (*(*node).data.get()).assume_init_read();
            Self::push_raw(&self.retired, node);
            data
        };

        Some(data)
    }

    pub fn drain_fifo<F>(&self, mut f: F)
    where
        F: FnMut(T),
    {
        let _guard = self.op_lock.lock();
        let mut list = self.head.swap(ptr::null_mut(), Ordering::AcqRel);
        let mut reversed = ptr::null_mut();
        let mut count = 0usize;

        while !list.is_null() {
            unsafe {
                let next = (*list).next.load(Ordering::Relaxed);
                (*list).next.store(reversed, Ordering::Relaxed);
                reversed = list;
                list = next;
            }

            count += 1;
        }

        if count != 0 {
            self.len.fetch_sub(count, Ordering::AcqRel);
        }

        while !reversed.is_null() {
            let node = reversed;

            unsafe {
                let next = (*node).next.load(Ordering::Relaxed);
                let data = (*(*node).data.get()).assume_init_read();

                Self::push_raw(&self.retired, node);

                reversed = next;
                f(data);
            }
        }
    }

    pub fn remove_one_by<F>(&self, mut pred: F) -> Option<T>
    where
        F: FnMut(&T) -> bool,
    {
        let _guard = self.op_lock.lock();
        let mut list = self.head.swap(ptr::null_mut(), Ordering::AcqRel);
        let mut keep = ptr::null_mut();
        let mut removed = None;

        while !list.is_null() {
            unsafe {
                let node = list;
                let next = (*node).next.load(Ordering::Relaxed);

                if removed.is_none() && pred((*(*node).data.get()).assume_init_ref()) {
                    let data = (*(*node).data.get()).assume_init_read();
                    Self::push_raw(&self.retired, node);
                    removed = Some(data);
                } else {
                    (*node).next.store(keep, Ordering::Relaxed);
                    keep = node;
                }

                list = next;
            }
        }

        while !keep.is_null() {
            unsafe {
                let node = keep;
                let next = (*node).next.load(Ordering::Relaxed);

                Self::push_raw(&self.head, node);

                keep = next;
            }
        }

        if removed.is_some() {
            self.len.fetch_sub(1, Ordering::AcqRel);
        }

        removed
    }

    unsafe fn push_raw(stack: &AtomicPtr<TreiberNode<T>>, node: *mut TreiberNode<T>) {
        loop {
            let head = stack.load(Ordering::Acquire);

            unsafe {
                (*node).next.store(head, Ordering::Relaxed);
            }

            if stack
                .compare_exchange_weak(head, node, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
        }
    }

    unsafe fn pop_raw(stack: &AtomicPtr<TreiberNode<T>>) -> Option<*mut TreiberNode<T>> {
        loop {
            let head = stack.load(Ordering::Acquire);

            if head.is_null() {
                return None;
            }

            let next = unsafe { (*head).next.load(Ordering::Acquire) };

            if stack
                .compare_exchange_weak(head, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(head);
            }
        }
    }

    unsafe fn free_retired(&mut self) {
        let mut node = self.retired.swap(ptr::null_mut(), Ordering::AcqRel);

        while !node.is_null() {
            unsafe {
                let next = (*node).next.load(Ordering::Relaxed);
                drop(Box::from_raw(node));
                node = next;
            }
        }
    }
}

impl<T> Drop for TreiberStack<T> {
    fn drop(&mut self) {
        while self.pop().is_some() {}

        unsafe {
            self.free_retired();
        }
    }
}

impl<T> Default for TreiberStack<T> {
    fn default() -> Self {
        Self::new()
    }
}

const NULL_INDEX: u32 = u32::MAX;

#[repr(C)]
struct BoundedTreiberNode<T> {
    data: UnsafeCell<MaybeUninit<T>>,
    next: AtomicU32,
}

#[repr(C)]
pub struct BoundedTreiberStack<T> {
    head: AtomicU64,
    free: AtomicU64,
    nodes: Vec<BoundedTreiberNode<T>>,
    len: AtomicUsize,
}

unsafe impl<T: Send> Send for BoundedTreiberStack<T> {}
unsafe impl<T: Send> Sync for BoundedTreiberStack<T> {}

impl<T> BoundedTreiberStack<T> {
    pub fn new(capacity: usize) -> Self {
        if capacity >= NULL_INDEX as usize {
            panic!("BoundedTreiberStack capacity too large");
        }

        let mut nodes = Vec::with_capacity(capacity);

        let mut i = 0usize;
        while i < capacity {
            let next = if i + 1 < capacity {
                (i + 1) as u32
            } else {
                NULL_INDEX
            };

            nodes.push(BoundedTreiberNode {
                data: UnsafeCell::new(MaybeUninit::uninit()),
                next: AtomicU32::new(next),
            });

            i += 1;
        }

        let free = if capacity == 0 { NULL_INDEX } else { 0 };

        Self {
            head: AtomicU64::new(Self::pack(NULL_INDEX, 0)),
            free: AtomicU64::new(Self::pack(free, 0)),
            nodes,
            len: AtomicUsize::new(0),
        }
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.nodes.len()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len.load(Ordering::Acquire)
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        let packed = self.head.load(Ordering::Acquire);
        let (idx, _) = Self::unpack(packed);

        idx == NULL_INDEX
    }

    #[inline]
    pub fn try_push(&self, data: T) -> Result<(), T> {
        let idx = match self.pop_index(&self.free) {
            Some(idx) => idx,
            None => return Err(data),
        };

        unsafe {
            (*self.nodes.get_unchecked(idx as usize).data.get()).write(data);
        }

        self.len.fetch_add(1, Ordering::Release);
        self.push_index(&self.head, idx);

        Ok(())
    }

    #[inline]
    pub fn push(&self, data: T) {
        if self.try_push(data).is_err() {
            panic!("BoundedTreiberStack full");
        }
    }

    #[inline]
    pub fn pop(&self) -> Option<T> {
        let idx = self.pop_index(&self.head)?;

        self.len.fetch_sub(1, Ordering::AcqRel);

        let data =
            unsafe { (*self.nodes.get_unchecked(idx as usize).data.get()).assume_init_read() };

        self.push_index(&self.free, idx);

        Some(data)
    }

    pub fn drain_fifo<F>(&self, mut f: F)
    where
        F: FnMut(T),
    {
        let mut list = self.take_all_indices();
        let mut reversed = NULL_INDEX;
        let mut count = 0usize;

        while list != NULL_INDEX {
            let idx = list;

            unsafe {
                let node = self.nodes.get_unchecked(idx as usize);
                list = node.next.load(Ordering::Relaxed);
                node.next.store(reversed, Ordering::Relaxed);
            }

            reversed = idx;
            count += 1;
        }

        if count != 0 {
            self.len.fetch_sub(count, Ordering::AcqRel);
        }

        while reversed != NULL_INDEX {
            let idx = reversed;

            let data = unsafe {
                let node = self.nodes.get_unchecked(idx as usize);
                reversed = node.next.load(Ordering::Relaxed);
                (*node.data.get()).assume_init_read()
            };

            self.push_index(&self.free, idx);
            f(data);
        }
    }

    pub fn remove_one_by<F>(&self, mut pred: F) -> Option<T>
    where
        F: FnMut(&T) -> bool,
    {
        let mut list = self.take_all_indices();
        let mut keep = NULL_INDEX;
        let mut removed = None;

        while list != NULL_INDEX {
            let idx = list;

            unsafe {
                let node = self.nodes.get_unchecked(idx as usize);
                let next = node.next.load(Ordering::Relaxed);

                if removed.is_none() && pred((*node.data.get()).assume_init_ref()) {
                    let data = (*node.data.get()).assume_init_read();
                    self.push_index(&self.free, idx);
                    removed = Some(data);
                } else {
                    node.next.store(keep, Ordering::Relaxed);
                    keep = idx;
                }

                list = next;
            }
        }

        while keep != NULL_INDEX {
            let idx = keep;

            unsafe {
                let node = self.nodes.get_unchecked(idx as usize);
                keep = node.next.load(Ordering::Relaxed);
            }

            self.push_index(&self.head, idx);
        }

        if removed.is_some() {
            self.len.fetch_sub(1, Ordering::AcqRel);
        }

        removed
    }

    #[inline]
    fn push_index(&self, stack: &AtomicU64, idx: u32) {
        loop {
            let old = stack.load(Ordering::Acquire);
            let (old_idx, old_tag) = Self::unpack(old);

            unsafe {
                self.nodes
                    .get_unchecked(idx as usize)
                    .next
                    .store(old_idx, Ordering::Relaxed);
            }

            let new = Self::pack(idx, old_tag.wrapping_add(1));

            if stack
                .compare_exchange_weak(old, new, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
        }
    }

    #[inline]
    fn pop_index(&self, stack: &AtomicU64) -> Option<u32> {
        loop {
            let old = stack.load(Ordering::Acquire);
            let (idx, old_tag) = Self::unpack(old);

            if idx == NULL_INDEX {
                return None;
            }

            let next = unsafe {
                self.nodes
                    .get_unchecked(idx as usize)
                    .next
                    .load(Ordering::Acquire)
            };

            let new = Self::pack(next, old_tag.wrapping_add(1));

            if stack
                .compare_exchange_weak(old, new, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(idx);
            }
        }
    }

    #[inline]
    fn take_all_indices(&self) -> u32 {
        loop {
            let old = self.head.load(Ordering::Acquire);
            let (_, old_tag) = Self::unpack(old);
            let new = Self::pack(NULL_INDEX, old_tag.wrapping_add(1));

            if self
                .head
                .compare_exchange_weak(old, new, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                let (idx, _) = Self::unpack(old);
                return idx;
            }
        }
    }

    #[inline]
    const fn pack(idx: u32, tag: u32) -> u64 {
        ((tag as u64) << 32) | idx as u64
    }

    #[inline]
    const fn unpack(value: u64) -> (u32, u32) {
        (value as u32, (value >> 32) as u32)
    }
}

impl<T> Drop for BoundedTreiberStack<T> {
    fn drop(&mut self) {
        while self.pop().is_some() {}
    }
}
pub type IoTarget = Arc<DeviceObject>;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct GptHeader {
    pub signature: [u8; 8],
    pub revision: u32,
    pub header_size: u32,
    pub header_crc32: u32,
    pub _reserved: u32,
    pub _current_lba: u64,
    pub _backup_lba: u64,
    pub first_usable_lba: u64,
    pub last_usable_lba: u64,
    pub disk_guid: [u8; 16],
    pub partition_entry_lba: u64,
    pub num_partition_entries: u32,
    pub partition_entry_size: u32,
    pub _partition_crc32: u32,
    pub_reserved_block: [u8; 420],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, kernel_macros::RequestPayload)]
pub struct DiskInfo {
    pub logical_block_size: u32,
    pub physical_block_size: u32,
    pub total_logical_blocks: u64,
    pub total_bytes_low: u64,
    pub total_bytes_high: u64,
}

#[repr(C)]
#[derive(Debug, Clone, kernel_macros::RequestPayload)]
pub struct PartitionInfo {
    pub disk: DiskInfo,
    pub gpt_header: Option<GptHeader>,
    pub gpt_entry: Option<GptPartitionEntry>,
}

#[repr(C)]
#[derive(kernel_macros::RequestPayload)]
pub struct FsIdentify {
    pub volume_fdo: IoTarget,
    pub mount_device: Option<Arc<DeviceObject>>,
    pub can_mount: bool,
}

#[repr(C)]
#[derive(Clone, Copy, kernel_macros::RequestPayload)]
pub struct BlkRead {
    pub lba: u64,
    pub sectors: u32,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct GptPartitionEntry {
    pub partition_type_guid: [u8; 16],
    pub unique_partition_guid: [u8; 16],
    pub first_lba: u64,
    pub last_lba: u64,
    pub _attr: u64,
    pub name_utf16: [u16; 36],
}

#[repr(C)]
pub struct IoHandler<T> {
    pub handler: T,
    /// 0 = unlimited, 1 = serialized, >1 = bounded async queue depth
    pub depth: usize,
    pub running_request: AtomicU64,
    pub waiters: TreiberStack<Waker>,
}

impl<T> core::fmt::Debug for IoHandler<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IoHandler")
            .field("depth", &self.depth)
            .finish()
    }
}

impl<T> IoHandler<T> {
    #[inline]
    pub fn new(handler: T, depth: u32) -> Self {
        IoHandler {
            handler,
            depth: depth as usize,
            running_request: AtomicU64::new(0),
            waiters: TreiberStack::<Waker>::new(),
        }
    }
}

pub trait DeviceRead {
    const DEPTH: u32 = 0;

    extern "C" fn handler<'req, 'io, 'b>(
        dev: &Arc<DeviceObject>,
        req: &'b mut RequestHandle<'req, Read<'io>>,
    ) -> FfiFuture<DriverStep>;
}

pub trait DeviceWrite {
    const DEPTH: u32 = 0;

    extern "C" fn handler<'req, 'io, 'b>(
        dev: &Arc<DeviceObject>,
        req: &'b mut RequestHandle<'req, Write<'io>>,
    ) -> FfiFuture<DriverStep>;
}

pub trait DeviceFlush {
    const DEPTH: u32 = 0;

    extern "C" fn handler<'req, 'b>(
        dev: &Arc<DeviceObject>,
        req: &'b mut RequestHandle<'req, Flush>,
    ) -> FfiFuture<DriverStep>;
}

pub trait DeviceFlushDirty {
    const DEPTH: u32 = 0;

    extern "C" fn handler<'req, 'b>(
        dev: &Arc<DeviceObject>,
        req: &'b mut RequestHandle<'req, FlushDirty>,
    ) -> FfiFuture<DriverStep>;
}

pub trait DeviceFlushOwner {
    const DEPTH: u32 = 0;

    extern "C" fn handler<'req, 'b>(
        dev: &Arc<DeviceObject>,
        req: &'b mut RequestHandle<'req, FlushOwner>,
    ) -> FfiFuture<DriverStep>;
}

pub trait DeviceControlHandler {
    const DEPTH: u32 = 0;

    extern "C" fn handler<'req, 'data, 'b>(
        dev: &Arc<DeviceObject>,
        req: &'b mut RequestHandle<'req, DeviceControl<'data>>,
    ) -> FfiFuture<DriverStep>;
}

pub trait FileSystem {
    const OPEN_DEPTH: u32 = 0;
    const CLOSE_DEPTH: u32 = 0;
    const READ_DEPTH: u32 = 0;
    const WRITE_DEPTH: u32 = 0;
    const FLUSH_DEPTH: u32 = 1;
    const SEEK_DEPTH: u32 = 0;
    const CREATE_DEPTH: u32 = 0;
    const RENAME_DEPTH: u32 = 0;
    const READ_DIR_DEPTH: u32 = 0;
    const GET_INFO_DEPTH: u32 = 0;
    const SET_LEN_DEPTH: u32 = 0;
    const APPEND_DEPTH: u32 = 0;
    const ZERO_RANGE_DEPTH: u32 = 0;

    extern "C" fn open<'req, 'data, 'b>(
        dev: &Arc<DeviceObject>,
        req: &'b mut RequestHandle<'req, FsRequest<'data, FsOpen>>,
    ) -> FfiFuture<DriverStep>;

    extern "C" fn close<'req, 'data, 'b>(
        dev: &Arc<DeviceObject>,
        req: &'b mut RequestHandle<'req, FsRequest<'data, FsClose>>,
    ) -> FfiFuture<DriverStep>;

    extern "C" fn read<'req, 'data, 'b>(
        dev: &Arc<DeviceObject>,
        req: &'b mut RequestHandle<'req, FsRequest<'data, FsRead>>,
    ) -> FfiFuture<DriverStep>;

    extern "C" fn write<'req, 'data, 'b>(
        dev: &Arc<DeviceObject>,
        req: &'b mut RequestHandle<'req, FsRequest<'data, FsWrite>>,
    ) -> FfiFuture<DriverStep>;

    extern "C" fn flush<'req, 'data, 'b>(
        dev: &Arc<DeviceObject>,
        req: &'b mut RequestHandle<'req, FsRequest<'data, FsFlush>>,
    ) -> FfiFuture<DriverStep>;

    extern "C" fn seek<'req, 'data, 'b>(
        dev: &Arc<DeviceObject>,
        req: &'b mut RequestHandle<'req, FsRequest<'data, FsSeek>>,
    ) -> FfiFuture<DriverStep>;

    extern "C" fn create<'req, 'data, 'b>(
        dev: &Arc<DeviceObject>,
        req: &'b mut RequestHandle<'req, FsRequest<'data, FsCreate>>,
    ) -> FfiFuture<DriverStep>;

    extern "C" fn rename<'req, 'data, 'b>(
        dev: &Arc<DeviceObject>,
        req: &'b mut RequestHandle<'req, FsRequest<'data, FsRename>>,
    ) -> FfiFuture<DriverStep>;

    extern "C" fn read_dir<'req, 'data, 'b>(
        dev: &Arc<DeviceObject>,
        req: &'b mut RequestHandle<'req, FsRequest<'data, FsReadDir>>,
    ) -> FfiFuture<DriverStep>;

    extern "C" fn get_info<'req, 'data, 'b>(
        dev: &Arc<DeviceObject>,
        req: &'b mut RequestHandle<'req, FsRequest<'data, FsGetInfo>>,
    ) -> FfiFuture<DriverStep>;

    extern "C" fn set_len<'req, 'data, 'b>(
        dev: &Arc<DeviceObject>,
        req: &'b mut RequestHandle<'req, FsRequest<'data, FsSetLen>>,
    ) -> FfiFuture<DriverStep>;

    extern "C" fn append<'req, 'data, 'b>(
        dev: &Arc<DeviceObject>,
        req: &'b mut RequestHandle<'req, FsRequest<'data, FsAppend>>,
    ) -> FfiFuture<DriverStep>;

    extern "C" fn zero_range<'req, 'data, 'b>(
        dev: &Arc<DeviceObject>,
        req: &'b mut RequestHandle<'req, FsRequest<'data, FsZeroRange>>,
    ) -> FfiFuture<DriverStep>;
}

macro_rules! define_device_slot {
    ($slot:ident, $handler:ty, $trait:path) => {
        #[repr(C)]
        #[derive(Debug)]
        pub struct $slot {
            handler: Option<IoHandler<$handler>>,
        }

        impl $slot {
            #[inline]
            pub const fn empty() -> Self {
                Self { handler: None }
            }

            #[inline]
            pub fn as_handler(&self) -> Option<&IoHandler<$handler>> {
                self.handler.as_ref()
            }

            #[inline]
            pub fn register<T>(&mut self)
            where
                T: $trait + 'static,
            {
                self.handler = Some(IoHandler::new(T::handler, T::DEPTH));
            }

            #[inline]
            pub fn clear(&mut self) {
                self.handler = None;
            }
        }
    };
}

macro_rules! define_fs_slot {
    ($slot:ident, $handler:ty) => {
        #[repr(C)]
        #[derive(Debug)]
        pub struct $slot {
            handler: Option<IoHandler<$handler>>,
        }

        impl $slot {
            #[inline]
            pub const fn empty() -> Self {
                Self { handler: None }
            }

            #[inline]
            pub fn as_handler(&self) -> Option<&IoHandler<$handler>> {
                self.handler.as_ref()
            }

            #[inline]
            fn set(&mut self, handler: $handler, depth: u32) {
                self.handler = Some(IoHandler::new(handler, depth));
            }

            #[inline]
            pub fn clear(&mut self) {
                self.handler = None;
            }
        }
    };
}

define_device_slot!(ReadSlot, EvtIoRead, DeviceRead);
define_device_slot!(WriteSlot, EvtIoWrite, DeviceWrite);
define_device_slot!(FlushSlot, EvtIoFlush, DeviceFlush);
define_device_slot!(FlushDirtySlot, EvtIoFlushDirty, DeviceFlushDirty);
define_device_slot!(FlushOwnerSlot, EvtIoFlushOwner, DeviceFlushOwner);
define_device_slot!(DeviceControlSlot, EvtIoDeviceControl, DeviceControlHandler);

define_fs_slot!(FsOpenSlot, EvtFsOpen);
define_fs_slot!(FsCloseSlot, EvtFsClose);
define_fs_slot!(FsReadSlot, EvtFsRead);
define_fs_slot!(FsWriteSlot, EvtFsWrite);
define_fs_slot!(FsFlushSlot, EvtFsFlush);
define_fs_slot!(FsSeekSlot, EvtFsSeek);
define_fs_slot!(FsCreateSlot, EvtFsCreate);
define_fs_slot!(FsRenameSlot, EvtFsRename);
define_fs_slot!(FsReadDirSlot, EvtFsReadDir);
define_fs_slot!(FsGetInfoSlot, EvtFsGetInfo);
define_fs_slot!(FsSetLenSlot, EvtFsSetLen);
define_fs_slot!(FsAppendSlot, EvtFsAppend);
define_fs_slot!(FsZeroRangeSlot, EvtFsZeroRange);

#[repr(C)]
#[derive(Debug)]
pub struct FsOps {
    pub open: FsOpenSlot,
    pub close: FsCloseSlot,
    pub read: FsReadSlot,
    pub write: FsWriteSlot,
    pub flush: FsFlushSlot,
    pub seek: FsSeekSlot,
    pub create: FsCreateSlot,
    pub rename: FsRenameSlot,
    pub read_dir: FsReadDirSlot,
    pub get_info: FsGetInfoSlot,
    pub set_len: FsSetLenSlot,
    pub append: FsAppendSlot,
    pub zero_range: FsZeroRangeSlot,
}

impl FsOps {
    pub const fn empty() -> Self {
        Self {
            open: FsOpenSlot::empty(),
            close: FsCloseSlot::empty(),
            read: FsReadSlot::empty(),
            write: FsWriteSlot::empty(),
            flush: FsFlushSlot::empty(),
            seek: FsSeekSlot::empty(),
            create: FsCreateSlot::empty(),
            rename: FsRenameSlot::empty(),
            read_dir: FsReadDirSlot::empty(),
            get_info: FsGetInfoSlot::empty(),
            set_len: FsSetLenSlot::empty(),
            append: FsAppendSlot::empty(),
            zero_range: FsZeroRangeSlot::empty(),
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct FsSlot {
    ops: Option<FsOps>,
}

impl FsSlot {
    #[inline]
    pub const fn empty() -> Self {
        Self { ops: None }
    }

    #[inline]
    pub fn as_ops(&self) -> Option<&FsOps> {
        self.ops.as_ref()
    }

    #[inline]
    pub fn register<T>(&mut self)
    where
        T: FileSystem + 'static,
    {
        let mut ops = FsOps::empty();

        ops.open.set(T::open, T::OPEN_DEPTH);
        ops.close.set(T::close, T::CLOSE_DEPTH);
        ops.read.set(T::read, T::READ_DEPTH);
        ops.write.set(T::write, T::WRITE_DEPTH);
        ops.flush.set(T::flush, T::FLUSH_DEPTH);
        ops.seek.set(T::seek, T::SEEK_DEPTH);
        ops.create.set(T::create, T::CREATE_DEPTH);
        ops.rename.set(T::rename, T::RENAME_DEPTH);
        ops.read_dir.set(T::read_dir, T::READ_DIR_DEPTH);
        ops.get_info.set(T::get_info, T::GET_INFO_DEPTH);
        ops.set_len.set(T::set_len, T::SET_LEN_DEPTH);
        ops.append.set(T::append, T::APPEND_DEPTH);
        ops.zero_range.set(T::zero_range, T::ZERO_RANGE_DEPTH);

        self.ops = Some(ops);
    }

    #[inline]
    pub fn clear(&mut self) {
        self.ops = None;
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct DeviceOps {
    pub read: ReadSlot,
    pub write: WriteSlot,
    pub flush: FlushSlot,
    pub flush_dirty: FlushDirtySlot,
    pub flush_owner: FlushOwnerSlot,
    pub device_control: DeviceControlSlot,
    pub fs: FsSlot,
}

impl DeviceOps {
    pub const fn empty() -> Self {
        Self {
            read: ReadSlot::empty(),
            write: WriteSlot::empty(),
            flush: FlushSlot::empty(),
            flush_dirty: FlushDirtySlot::empty(),
            flush_owner: FlushOwnerSlot::empty(),
            device_control: DeviceControlSlot::empty(),
            fs: FsSlot::empty(),
        }
    }
}
