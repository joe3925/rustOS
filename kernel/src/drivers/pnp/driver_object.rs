use crate::{
    alloc::vec,
    drivers::pnp::{device::DevNode, driver_index::DriverRuntime, request::CompletionRoutine},
    util::random_number,
};
use alloc::{
    boxed::Box,
    collections::vec_deque::VecDeque,
    string::String,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{
    any::{type_name, Any, TypeId},
    marker::PhantomData,
    mem,
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicBool, AtomicU32, AtomicU64},
};
use spin::{Mutex, RwLock};
use strum::Display;

#[repr(i32)]
#[derive(Display, Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverStatus {
    Success = 0x0000_0000,
    Pending = 0x0000_0103,
    NotImplemented = 0xC000_0002u32 as i32,
    InvalidParameter = 0xC000_000Du32 as i32,
    InsufficientResources = 0xC000_009Au32 as i32,
    NoSuchDevice = 0xC000_000Eu32 as i32,
    NoSuchFile = 0xC000_000Fu32 as i32,
    DeviceNotReady = 0xC000_00A3u32 as i32,
    Unsuccessful = 0xC000_0001u32 as i32,
}
#[repr(C)]
pub struct ReqJob {
    pub(crate) dev: Arc<DeviceObject>,
    pub(crate) req: Arc<RwLock<Request>>,
}

#[derive(Debug)]
#[repr(C)]

pub struct DeviceObject {
    pub lower_device: Option<Arc<DeviceObject>>,
    pub upper_device: RwLock<Option<alloc::sync::Weak<DeviceObject>>>,
    dev_ext: DevExtBox,
    pub dev_init: DeviceInit,
    pub queue: Mutex<VecDeque<Arc<RwLock<Request>>>>,
    pub dispatch_tickets: AtomicU32,
    pub dev_node: Weak<DevNode>,
    pub in_queue: AtomicBool,
}
impl DeviceObject {
    pub fn new(mut init: DeviceInit) -> Arc<Self> {
        let dev_ext = match (init.dev_ext_type, init.dev_ext_factory) {
            (Some(ty), Some(f)) => DevExtBox::from_factory(f, ty),
            _ => DevExtBox::none(),
        };

        Arc::new(Self {
            lower_device: None,
            upper_device: RwLock::new(None),
            dev_ext,
            dev_init: init,
            queue: Mutex::new(VecDeque::new()),
            dispatch_tickets: AtomicU32::new(0),
            dev_node: Weak::new(),
            in_queue: AtomicBool::new(false),
        })
    }

    pub fn set_lower_upper(this: &Arc<Self>, lower: Option<Arc<DeviceObject>>) {
        {
            let me = unsafe { &mut *(Arc::as_ptr(this) as *mut DeviceObject) };
            me.lower_device = lower.clone();
        }
        if let Some(low) = lower {
            *low.upper_device.write() = Some(Arc::downgrade(this));
        }
    }

    #[inline]
    pub fn upper(&self) -> Option<Arc<DeviceObject>> {
        self.upper_device.read().as_ref().and_then(|w| w.upgrade())
    }

    #[inline]
    pub fn bottom_from(start: &Arc<DeviceObject>) -> Arc<DeviceObject> {
        let mut cur = start.clone();
        while let Some(next) = cur.lower_device.clone() {
            cur = next;
        }
        cur
    }

    #[inline]
    pub fn top_from(start: &Arc<DeviceObject>) -> Arc<DeviceObject> {
        let mut cur = start.clone();
        loop {
            let up = cur.upper_device.read().as_ref().and_then(|w| w.upgrade());
            if let Some(next) = up {
                cur = next;
            } else {
                return cur;
            }
        }
    }

    pub fn try_devext<'a, T: 'static>(&'a self) -> Result<DevExtRef<'a, T>, DevExtError> {
        if self.dev_ext.ty != TypeId::of::<T>() {
            return Err(DevExtError::TypeMismatch {
                expected: type_name::<T>(),
            });
        }
        let r = self.dev_ext.inner.downcast_ref::<T>().unwrap();
        Ok(DevExtRef {
            inner: r,
            _lt: PhantomData,
        })
    }

    pub fn try_devext_mut<'a, T: 'static>(
        &'a mut self,
    ) -> Result<DevExtRefMut<'a, T>, DevExtError> {
        if self.dev_ext.ty != TypeId::of::<T>() {
            return Err(DevExtError::TypeMismatch {
                expected: type_name::<T>(),
            });
        }
        let r = self.dev_ext.inner.downcast_mut::<T>().unwrap();
        Ok(DevExtRefMut {
            inner: r,
            _lt: PhantomData,
        })
    }

    pub fn devext<'a, T: 'static>(&'a self) -> DevExtRef<'a, T> {
        self.try_devext::<T>().ok().unwrap()
    }

    pub fn devext_mut<'a, T: 'static>(&'a mut self) -> DevExtRefMut<'a, T> {
        self.try_devext_mut::<T>().ok().unwrap()
    }
}
fn self_arc(this: &DeviceObject) -> Arc<DeviceObject> {
    unsafe { Arc::from_raw(Arc::as_ptr(&Arc::new_uninit().assume_init())) }
}
pub type ClassAddCallback =
    extern "win64" fn(node: &Arc<DevNode>, listener_dev: &Arc<DeviceObject>);

pub type EvtDriverDeviceAdd =
    extern "win64" fn(driver: &Arc<DriverObject>, init: &mut DeviceInit) -> DriverStatus;

pub type EvtDriverUnload = extern "win64" fn(driver: &Arc<DriverObject>);

pub type EvtIoRead = extern "win64" fn(&Arc<DeviceObject>, Arc<RwLock<Request>>, usize);
pub type EvtIoWrite = extern "win64" fn(&Arc<DeviceObject>, Arc<RwLock<Request>>, usize);
pub type EvtIoDeviceControl = extern "win64" fn(&Arc<DeviceObject>, Arc<RwLock<Request>>);
pub type EvtDevicePrepareHardware = extern "win64" fn(&Arc<DeviceObject>) -> DriverStatus;
pub type EvtDeviceEnumerateDevices =
    extern "win64" fn(&Arc<DeviceObject>, Arc<RwLock<Request>>) -> DriverStatus;
pub type EvtIoFs = extern "win64" fn(&Arc<DeviceObject>, Arc<RwLock<Request>>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]

pub enum DeviceRelationType {
    BusRelations,
    EjectionRelations,
    RemovalRelations,
    TargetDeviceRelation,
    PowerRelations,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum QueryIdType {
    DeviceId,
    HardwareIds,
    CompatibleIds,
    InstanceId,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ResourceKind {
    Memory = 1,
    Port = 2,
    Interrupt = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PnpMinorFunction {
    StartDevice,
    QueryDeviceRelations,
    QueryId,
    QueryResources,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct PnpRequest {
    pub minor_function: PnpMinorFunction,
    pub relation: DeviceRelationType,
    pub id_type: QueryIdType,

    pub ids_out: Vec<String>,
    pub blob_out: Vec<u8>,
}
pub type PnpMinorCallback =
    extern "win64" fn(&Arc<DeviceObject>, Arc<RwLock<Request>>) -> DriverStatus;

#[repr(C)]
#[derive(Debug)]
pub struct PnpVtable {
    pub handlers: Vec<Option<PnpMinorCallback>>,
}

impl PnpVtable {
    #[inline]
    pub fn new() -> Self {
        let n = core::mem::variant_count::<PnpMinorFunction>();
        Self {
            handlers: alloc::vec![None; n],
        }
    }

    #[inline]
    pub fn set(&mut self, m: PnpMinorFunction, cb: PnpMinorCallback) {
        let i = m as usize;
        if i < self.handlers.len() {
            self.handlers[i] = Some(cb);
        }
    }

    #[inline]
    pub fn get(&self, m: PnpMinorFunction) -> Option<PnpMinorCallback> {
        let i = m as usize;
        if i < self.handlers.len() {
            self.handlers[i]
        } else {
            None
        }
    }
}
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub enum RequestType {
    Read { offset: u64, len: usize },
    Write { offset: u64, len: usize },
    DeviceControl(u32),
    Fs(FsOp),
    Pnp,

    Dummy,
}
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub enum FsOp {
    /// data = UTF-8 path bytes; flags in Request.flags (bitfield), length may carry mode/perm
    Create,
    /// data = UTF-8 path bytes; flags in Request.flags (bitfield)
    Open,
    /// uses Request.handle
    Close,
    /// uses Request.handle + Request.offset/length; returns bytes in Request.data
    Read,
    /// uses Request.handle + Request.offset; bytes to write in Request.data
    Write,
    /// uses Request.handle; ensure durable
    Flush,
    /// uses Request.handle + Request.offset (absolute)
    Seek,
    /// uses Request.handle; returns serialized dir entries in Request.data
    ReadDir,
    /// uses Request.handle; returns serialized stat/attributes in Request.data
    GetInfo,
    /// uses Request.handle; takes serialized attrs in Request.data
    SetInfo,
    /// data = UTF-8 path bytes (or uses Request.handle if nonzero)
    Delete,
    /// data = "old\0new" UTF-8 bytes
    Rename,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub enum IoType {
    Read(EvtIoRead),
    Write(EvtIoWrite),
    DeviceControl(EvtIoDeviceControl),
    Fs(EvtIoFs),
}
impl IoType {
    #[inline]
    pub fn slot(&self) -> usize {
        match self {
            IoType::Read(_) => 0,
            IoType::Write(_) => 1,
            IoType::DeviceControl(_) => 2,
            IoType::Fs(_) => 3,
        }
    }

    #[inline]
    pub fn invoke(&self, dev: &Arc<DeviceObject>, req: Arc<RwLock<Request>>) {
        match *self {
            IoType::Read(h) | IoType::Write(h) => {
                let len = req.read().data.len();
                h(dev, req, len);
            }
            IoType::DeviceControl(h) => h(dev, req),
            IoType::Fs(h) => h(dev, req),
        }
    }

    #[inline]
    pub fn slot_for_request(r: &RequestType) -> Option<usize> {
        match r {
            RequestType::Read { .. } => Some(0),
            RequestType::Write { .. } => Some(1),
            RequestType::DeviceControl(_) => Some(2),
            RequestType::Fs(_) => Some(3),
            _ => None,
        }
    }
}
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum Synchronization {
    Sync,
    Async,
    FireAndForget,
}
#[repr(C)]
#[derive(Debug, Clone)]
pub struct IoHandler {
    pub handler: IoType,
    pub synchronization: Synchronization,
    pub depth: usize,
    pub running_request: Arc<AtomicU64>,
}
#[repr(C)]
#[derive(Debug)]
pub struct IoVtable {
    pub handlers: Vec<Option<IoHandler>>,
}

impl IoVtable {
    #[inline]
    pub fn new() -> Self {
        let n = core::mem::variant_count::<IoType>();
        Self {
            handlers: alloc::vec![None; n],
        }
    }

    #[inline]
    pub fn set(&mut self, cb: IoType, synchronization: Synchronization, depth: usize) {
        let i = cb.slot();
        if i < self.handlers.len() {
            self.handlers[i] = Some(IoHandler {
                handler: cb,
                synchronization,
                depth,
                running_request: Arc::new(AtomicU64::new(0)),
            });
        }
    }

    #[inline]
    pub fn get_for(&self, r: &RequestType) -> Option<IoHandler> {
        IoType::slot_for_request(r).and_then(|i| self.handlers.get(i).cloned().flatten())
    }
}
pub struct ClassListener {
    pub class: String,
    pub dev: Arc<DeviceObject>,
    pub cb: ClassAddCallback,
}
#[derive(Debug)]
#[repr(C)]
pub struct Request {
    pub id: u64,
    pub kind: RequestType,
    pub data: Box<[u8]>,
    pub completed: bool,
    pub status: DriverStatus,

    pub pnp: Option<PnpRequest>,

    pub completion_routine: Option<CompletionRoutine>,
    pub completion_context: usize,
}

impl Request {
    #[inline]
    pub fn new(kind: RequestType, data: Box<[u8]>) -> Self {
        Self {
            id: random_number(),
            kind,
            data,
            completed: false,
            status: DriverStatus::Pending,
            pnp: None,
            completion_routine: None,
            completion_context: 0,
        }
    }
    #[inline]
    pub fn empty() -> Self {
        let dummy_kind = RequestType::Dummy;

        Self {
            id: 0,
            kind: dummy_kind,
            data: Box::new([]),
            completed: true,
            status: DriverStatus::Success,
            pnp: None,
            completion_routine: None,
            completion_context: 0,
        }
    }
    pub fn set_completion(&mut self, routine: CompletionRoutine, context: usize) {
        self.completion_routine = Some(routine);
        self.completion_context = context;
    }
}
#[derive(Debug)]
pub struct DeviceInit {
    pub dev_ext_size: usize,
    pub io_vtable: IoVtable,
    pub pnp_vtable: Option<PnpVtable>,
    dev_ext_factory: Option<fn() -> Box<dyn Any + Send + Sync>>,
    dev_ext_type: Option<TypeId>,
}

impl DeviceInit {
    pub fn new() -> Self {
        Self {
            dev_ext_size: 0,
            io_vtable: IoVtable::new(),
            pnp_vtable: None,
            dev_ext_factory: None,
            dev_ext_type: None,
        }
    }

    pub fn set_dev_ext_default<T>(&mut self)
    where
        T: Default + 'static + Send + Sync,
    {
        self.dev_ext_size = core::mem::size_of::<T>();
        self.dev_ext_type = Some(TypeId::of::<T>());
        self.dev_ext_factory = Some(|| Box::new(T::default()));
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct DriverObject {
    pub runtime: Arc<DriverRuntime>,
    pub driver_name: String,
    pub flags: u32,

    pub evt_device_add: Option<EvtDriverDeviceAdd>,
    pub evt_driver_unload: Option<EvtDriverUnload>,
}

impl DriverObject {
    pub fn allocate(runtime: Arc<DriverRuntime>, driver_name: String) -> Arc<Self> {
        Arc::new(Self {
            runtime,
            driver_name,
            flags: 0,
            evt_device_add: None,
            evt_driver_unload: None,
        })
    }

    pub fn configure<F: FnOnce(&mut DriverConfig)>(this: &Arc<Self>, f: F) {
        let mut cfg = DriverConfig {
            driver: Arc::as_ptr(this),
        };
        f(&mut cfg);
    }

    pub unsafe fn configure_raw<F: FnOnce(&mut DriverConfig)>(
        driver_ptr: *const DriverObject,
        f: F,
    ) {
        let mut cfg = DriverConfig { driver: driver_ptr };
        f(&mut cfg);
    }
}

pub struct DriverConfig {
    driver: *const DriverObject,
}

impl DriverConfig {
    pub fn on_device_add(&mut self, cb: EvtDriverDeviceAdd) -> &mut Self {
        unsafe {
            (*(self.driver as *mut DriverObject)).evt_device_add = Some(cb);
        }
        self
    }
    pub fn on_unload(&mut self, cb: EvtDriverUnload) -> &mut Self {
        unsafe {
            (*(self.driver as *mut DriverObject)).evt_driver_unload = Some(cb);
        }
        self
    }
}

pub enum DevExtError {
    NotPresent,
    TypeMismatch { expected: &'static str },
}

pub struct DevExtRef<'a, T: 'static> {
    inner: &'a T,
    _lt: PhantomData<&'a T>,
}
impl<'a, T: 'static> Deref for DevExtRef<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.inner
    }
}

pub struct DevExtRefMut<'a, T: 'static> {
    inner: &'a mut T,
    _lt: PhantomData<&'a mut T>,
}
impl<'a, T: 'static> Deref for DevExtRefMut<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.inner
    }
}
impl<'a, T: 'static> DerefMut for DevExtRefMut<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.inner
    }
}

#[derive(Default)]
struct NoDevExt;
#[derive(Debug)]
struct DevExtBox {
    ty: TypeId,
    inner: Box<dyn Any + Send + Sync>,
    present: bool,
}

impl DevExtBox {
    fn none() -> Self {
        Self {
            ty: TypeId::of::<NoDevExt>(),
            inner: Box::new(NoDevExt::default()),
            present: false,
        }
    }
    fn from_factory(f: fn() -> Box<dyn Any + Send + Sync>, ty: TypeId) -> Self {
        Self {
            ty,
            inner: f(),
            present: true,
        }
    }
}
