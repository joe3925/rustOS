use crate::async_ffi::FfiFuture;
use crate::device::DeviceObject;
use crate::irq::IrqSafeMutex;
use crate::pnp::DriverStep;
use crate::status::DriverStatus;
use crate::request::{
    DeviceControl, Flush, FlushDirty, FlushOwner, Fs as FsRequest, FsAppend, FsClose, FsCreate,
    FsFlush, FsGetInfo, FsOpen, FsRead, FsReadDir, FsRename, FsSeek, FsSetLen, FsWrite,
    FsZeroRange, Read, Write,
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

    extern "C" fn handler<'a, 'io>(
        dev: &'a Arc<DeviceObject>,
        req: &'a mut Read<'io>,
    ) -> FfiFuture<DriverStep>;
}

pub trait DeviceWrite {
    const DEPTH: u32 = 0;

    extern "C" fn handler<'a, 'io>(
        dev: &'a Arc<DeviceObject>,
        req: &'a mut Write<'io>,
    ) -> FfiFuture<DriverStep>;
}

pub trait DeviceFlush {
    const DEPTH: u32 = 0;

    extern "C" fn handler<'a>(
        dev: &'a Arc<DeviceObject>,
        req: &'a mut Flush,
    ) -> FfiFuture<DriverStep>;
}

pub trait DeviceFlushDirty {
    const DEPTH: u32 = 0;

    extern "C" fn handler<'a>(
        dev: &'a Arc<DeviceObject>,
        req: &'a mut FlushDirty,
    ) -> FfiFuture<DriverStep>;
}

pub trait DeviceFlushOwner {
    const DEPTH: u32 = 0;

    extern "C" fn handler<'a>(
        dev: &'a Arc<DeviceObject>,
        req: &'a mut FlushOwner,
    ) -> FfiFuture<DriverStep>;
}

pub trait DeviceControlHandler {
    const DEPTH: u32 = 0;

    extern "C" fn handler<'a, 'data>(
        dev: &'a Arc<DeviceObject>,
        req: &'a mut DeviceControl<'data>,
    ) -> FfiFuture<DriverStep>;
}

#[repr(C)]
#[derive(Debug)]
pub struct HandlerSlot<T> {
    handler: Option<IoHandler<T>>,
}

impl<T> HandlerSlot<T> {
    #[inline]
    pub const fn empty() -> Self {
        Self { handler: None }
    }

    #[inline]
    pub fn as_handler(&self) -> Option<&IoHandler<T>> {
        self.handler.as_ref()
    }

    #[inline]
    pub fn set(&mut self, handler: T) {
        self.set_with_depth(handler, 0);
    }

    #[inline]
    pub fn set_with_depth(&mut self, handler: T, depth: u32) {
        self.handler = Some(IoHandler::new(handler, depth));
    }

    #[inline]
    pub fn clear(&mut self) {
        self.handler = None;
    }
}

macro_rules! define_fs_io_operations {
    (
        $(
            $field:ident {
                op: $op:ident,
                params: $params:ty,
                result: $result:ty,
                handler: $handler:ty,
                method: $method:ident,
                depth: $depth:ident = $default_depth:expr
            }
        ),+ $(,)?
    ) => {
        pub trait FileSystem {
            $(
                const $depth: u32 = $default_depth;

                extern "C" fn $method<'a, 'data>(
                    dev: &'a Arc<DeviceObject>,
                    req: &'a mut FsRequest<'data, $op>,
                ) -> FfiFuture<DriverStep>;
            )+
        }

        #[repr(C)]
        #[derive(Debug)]
        pub struct FsOps {
            $(pub $field: HandlerSlot<$handler>,)+
        }

        impl FsOps {
            pub const fn empty() -> Self {
                Self {
                    $($field: HandlerSlot::empty(),)+
                }
            }
        }

        impl Default for FsOps {
            fn default() -> Self {
                Self::empty()
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
                $(ops.$field.set_with_depth(T::$method, T::$depth);)+
                self.ops = Some(ops);
            }

            #[inline]
            pub fn clear(&mut self) {
                self.ops = None;
            }
        }

        impl Default for FsSlot {
            fn default() -> Self {
                Self::empty()
            }
        }
    };
}

crate::for_each_fs_operation!(define_fs_io_operations);

macro_rules! define_device_ops {
    (
        $(
            $field:ident {
                op: $op:ident,
                slot: $slot:ident,
                handler: $handler:ty,
                trait: $trait:path
            }
        ),+ $(,)?
    ) => {
        $(
            pub enum $op {}
            pub type $slot = HandlerSlot<$handler>;
        )+

        #[derive(Debug)]
        #[repr(C)]
        pub struct DeviceOps {
            $(pub $field: $slot,)+
            pub fs: FsSlot,
        }

        pub trait DeviceOpRegistration<Op, T> {
            fn register_op(&mut self);
        }

        pub trait DeviceOpHandlerRegistration<Op, H> {
            fn set_op_handler(&mut self, handler: H, depth: u32);
        }

        impl DeviceOps {
            pub const fn empty() -> Self {
                Self {
                    $($field: HandlerSlot::empty(),)+
                    fs: FsSlot::empty(),
                }
            }

            #[inline]
            pub fn register<Op, T>(&mut self)
            where
                Self: DeviceOpRegistration<Op, T>,
            {
                <Self as DeviceOpRegistration<Op, T>>::register_op(self);
            }

            #[inline]
            pub fn set_handler<Op, H>(&mut self, handler: H)
            where
                Self: DeviceOpHandlerRegistration<Op, H>,
            {
                <Self as DeviceOpHandlerRegistration<Op, H>>::set_op_handler(self, handler, 0);
            }

            #[inline]
            pub fn set_handler_with_depth<Op, H>(&mut self, handler: H, depth: u32)
            where
                Self: DeviceOpHandlerRegistration<Op, H>,
            {
                <Self as DeviceOpHandlerRegistration<Op, H>>::set_op_handler(self, handler, depth);
            }
        }

        impl Default for DeviceOps {
            fn default() -> Self {
                Self::empty()
            }
        }

        $(
            impl<T> DeviceOpRegistration<$op, T> for DeviceOps
            where
                T: $trait + 'static,
            {
                #[inline]
                fn register_op(&mut self) {
                    self.$field.set_with_depth(T::handler, T::DEPTH);
                }
            }

            impl DeviceOpHandlerRegistration<$op, $handler> for DeviceOps {
                #[inline]
                fn set_op_handler(&mut self, handler: $handler, depth: u32) {
                    self.$field.set_with_depth(handler, depth);
                }
            }
        )+
    };
}

define_device_ops! {
    read {
        op: DeviceReadOp,
        slot: ReadSlot,
        handler: EvtIoRead,
        trait: DeviceRead
    },
    write {
        op: DeviceWriteOp,
        slot: WriteSlot,
        handler: EvtIoWrite,
        trait: DeviceWrite
    },
    flush {
        op: DeviceFlushOp,
        slot: FlushSlot,
        handler: EvtIoFlush,
        trait: DeviceFlush
    },
    flush_dirty {
        op: DeviceFlushDirtyOp,
        slot: FlushDirtySlot,
        handler: EvtIoFlushDirty,
        trait: DeviceFlushDirty
    },
    flush_owner {
        op: DeviceFlushOwnerOp,
        slot: FlushOwnerSlot,
        handler: EvtIoFlushOwner,
        trait: DeviceFlushOwner
    },
    device_control {
        op: DeviceControlOp,
        slot: DeviceControlSlot,
        handler: EvtIoDeviceControl,
        trait: DeviceControlHandler
    }
}

use crate::device::{Protocol, ProtocolId, ProtocolVersion};

#[repr(C)]
pub struct DiskInfoProtocolVTable {
    pub query: extern "C" fn(&Arc<DeviceObject>) -> Result<DiskInfo, DriverStatus>,
}

pub enum DiskInfoProtocol {}

unsafe impl Protocol for DiskInfoProtocol {
    const ID: ProtocolId = ProtocolId(0x10000000000000000000000000000001);
    const VERSION: ProtocolVersion = ProtocolVersion::new(1, 0);

    type VTable = DiskInfoProtocolVTable;
}

#[repr(C)]
pub struct PartitionInfoProtocolVTable {
    pub query: extern "C" fn(&Arc<DeviceObject>) -> Result<PartitionInfo, DriverStatus>,
}

pub enum PartitionInfoProtocol {}

unsafe impl Protocol for PartitionInfoProtocol {
    const ID: ProtocolId = ProtocolId(0x10000000000000000000000000000002);
    const VERSION: ProtocolVersion = ProtocolVersion::new(1, 0);

    type VTable = PartitionInfoProtocolVTable;
}

#[repr(C)]
pub struct VolmgrProtocolVTable {
    pub partition_info: extern "C" fn(&Arc<DeviceObject>) -> Result<PartitionInfo, DriverStatus>,
}

pub enum VolmgrProtocol {}

unsafe impl Protocol for VolmgrProtocol {
    const ID: ProtocolId = ProtocolId(0x10000000000000000000000000000003);
    const VERSION: ProtocolVersion = ProtocolVersion::new(1, 0);

    type VTable = VolmgrProtocolVTable;
}
