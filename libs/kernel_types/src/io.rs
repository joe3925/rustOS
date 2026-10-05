use crate::async_ffi::AbiFuture;
use crate::device::DeviceObject;
use crate::pnp::DriverStep;
use kernel_sync::queues::waiter_queue::RawWaiterQueue;
use crate::request::{
    DeviceControl, Flush, FlushDirty, FlushOwner, Fs as FsRequest, FsAppend, FsClose, FsCreate,
    FsDelete, FsFlush, FsGetInfo, FsOpen, FsRead, FsReadDir, FsRemoveDir, FsRename, FsSeek,
    FsSetLen, FsWrite, FsZeroRange, Read, Write,
};
use crate::{
    EvtFsAppend, EvtFsClose, EvtFsCreate, EvtFsDelete, EvtFsFlush, EvtFsGetInfo, EvtFsOpen,
    EvtFsRead, EvtFsReadDir, EvtFsRemoveDir, EvtFsRename, EvtFsSeek, EvtFsSetLen, EvtFsWrite,
    EvtFsZeroRange, EvtIoDeviceControl, EvtIoFlush, EvtIoFlushDirty, EvtIoFlushOwner, EvtIoRead,
    EvtIoWrite,
};
use alloc::sync::Arc;
use core::sync::atomic::AtomicU64;

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
    pub waiters: RawWaiterQueue,
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
            waiters: RawWaiterQueue::new(),
        }
    }
}

pub trait DeviceRead {
    const DEPTH: u32 = 0;

    extern "C" fn handler<'a, 'io>(
        dev: &'a Arc<DeviceObject>,
        req: &'a mut Read<'io>,
    ) -> AbiFuture<Result<DriverStep, crate::error::KernelError>>;
}

pub trait DeviceWrite {
    const DEPTH: u32 = 0;

    extern "C" fn handler<'a, 'io>(
        dev: &'a Arc<DeviceObject>,
        req: &'a mut Write<'io>,
    ) -> AbiFuture<Result<DriverStep, crate::error::KernelError>>;
}

pub trait DeviceFlush {
    const DEPTH: u32 = 0;

    extern "C" fn handler<'a>(
        dev: &'a Arc<DeviceObject>,
        req: &'a mut Flush,
    ) -> AbiFuture<Result<DriverStep, crate::error::KernelError>>;
}

pub trait DeviceFlushDirty {
    const DEPTH: u32 = 0;

    extern "C" fn handler<'a>(
        dev: &'a Arc<DeviceObject>,
        req: &'a mut FlushDirty,
    ) -> AbiFuture<Result<DriverStep, crate::error::KernelError>>;
}

pub trait DeviceFlushOwner {
    const DEPTH: u32 = 0;

    extern "C" fn handler<'a>(
        dev: &'a Arc<DeviceObject>,
        req: &'a mut FlushOwner,
    ) -> AbiFuture<Result<DriverStep, crate::error::KernelError>>;
}

pub trait DeviceControlHandler {
    const DEPTH: u32 = 0;

    extern "C" fn handler<'a, 'data>(
        dev: &'a Arc<DeviceObject>,
        req: &'a mut DeviceControl<'data>,
    ) -> AbiFuture<Result<DriverStep, crate::error::KernelError>>;
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
                ) -> AbiFuture<Result<DriverStep, crate::error::KernelError>>;
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
