use crate::{
    alloc::vec,
    drivers::pnp::{device::DevNode, driver_index::DriverRuntime, request::CompletionRoutine},
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
    ops::{ControlFlow, FromResidual, Try},
    pin::Pin,
    ptr::{self, NonNull},
    sync::atomic::{AtomicBool, AtomicU32, AtomicU64},
    task::{Context, Poll, Waker},
};
use core::{cell::OnceCell, future::Future};
use spin::{Mutex, Once, RwLock};
use strum::Display;

#[repr(i32)]
#[derive(Display, Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverStatus {
    Success = 0x0000_0000,
    Pending = 0x0000_0103,
    Continue = 0x0000_0203,
    NotImplemented = 0xC000_0002u32 as i32,
    InvalidParameter = 0xC000_000Du32 as i32,
    InsufficientResources = 0xC000_009Au32 as i32,
    NoSuchDevice = 0xC000_000Eu32 as i32,
    NoSuchFile = 0xC000_000Fu32 as i32,
    DeviceNotReady = 0xC000_00A3u32 as i32,
    Unsuccessful = 0xC000_0001u32 as i32,
}

impl Try for DriverStatus {
    type Output = ();
    type Residual = DriverStatus;
    #[inline]
    fn from_output((): Self::Output) -> Self {
        DriverStatus::Success
    }
    #[inline]
    fn branch(self) -> ControlFlow<Self::Residual, Self::Output> {
        if self == DriverStatus::Success {
            ControlFlow::Continue(())
        } else {
            ControlFlow::Break(self)
        }
    }
}
impl<T> FromResidual<DriverStatus> for Result<T, DriverStatus> {
    #[inline]
    fn from_residual(r: DriverStatus) -> Self {
        Err(r)
    }
}
impl FromResidual<DriverStatus> for DriverStatus {
    #[inline]
    fn from_residual(r: DriverStatus) -> Self {
        r
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum TraversalPolicy {
    ForwardLower,
    FailIfUnhandled,
    ForwardUpper,
}

/// Common type for futures returned by I/O handlers.
pub type BoxedIoFuture = Pin<Box<dyn Future<Output = DriverStatus> + Send + 'static>>;

#[derive(Debug)]
#[repr(C)]
pub struct DeviceObject {
    pub lower_device: Once<Arc<DeviceObject>>,
    pub upper_device: Once<alloc::sync::Weak<DeviceObject>>,
    dev_ext: DevExtBox,
    pub dev_init: DeviceInit,
    pub queue: Mutex<VecDeque<Arc<RwLock<Request>>>>,
    pub dispatch_tickets: AtomicU32,
    pub dev_node: Once<Weak<DevNode>>,
    pub in_queue: AtomicBool,
}

impl DeviceObject {
    pub fn new(mut init: DeviceInit) -> Arc<Self> {
        let dev_ext = init.dev_ext_ready.take().unwrap_or_else(DevExtBox::none);
        Arc::new(Self {
            lower_device: Once::new(),
            upper_device: Once::new(),
            dev_ext,
            dev_init: init,
            queue: Mutex::new(VecDeque::new()),
            dispatch_tickets: AtomicU32::new(0),
            dev_node: Once::new(),
            in_queue: AtomicBool::new(false),
        })
    }
    pub fn try_devext<'a, T: 'static>(&'a self) -> Result<DevExtRef<'a, T>, DevExtError> {
        if !self.dev_ext.present {
            return Err(DevExtError::NotPresent);
        }
        if self.dev_ext.ty != TypeId::of::<T>() {
            return Err(DevExtError::TypeMismatch {
                expected: type_name::<T>(),
            });
        }
        let p = NonNull::new(self.dev_ext.as_const_ptr::<T>() as *mut T).unwrap();
        Ok(DevExtRef {
            ptr: p,
            _lt: PhantomData,
            _nosend: PhantomData,
        })
    }
    pub fn set_lower_upper(this: &Arc<Self>, lower: Arc<DeviceObject>) {
        this.lower_device.call_once(|| lower.clone());
        lower
            .upper_device
            .call_once(|| Arc::downgrade(this).clone());
    }
    pub fn attach_devnode(&self, dn: &Arc<DevNode>) {
        self.dev_node.call_once(|| Arc::downgrade(dn));
    }
}

pub type ClassAddCallback = extern "win64" fn(node: Arc<DevNode>, listener_dev: &Arc<DeviceObject>);
pub type EvtDriverDeviceAdd =
    extern "win64" fn(driver: Arc<DriverObject>, init: &mut DeviceInit) -> DriverStatus;
pub type EvtDriverUnload = extern "win64" fn(driver: Arc<DriverObject>) -> DriverStatus;

// Async Handler Types - Note: These are Rust function pointers, not extern "C"
pub type EvtIoRead = fn(Arc<DeviceObject>, Arc<RwLock<Request>>, usize) -> BoxedIoFuture;
pub type EvtIoWrite = fn(Arc<DeviceObject>, Arc<RwLock<Request>>, usize) -> BoxedIoFuture;
pub type EvtIoDeviceControl = fn(Arc<DeviceObject>, Arc<RwLock<Request>>) -> BoxedIoFuture;
pub type EvtIoFs = fn(Arc<DeviceObject>, Arc<RwLock<Request>>) -> BoxedIoFuture;

pub type EvtDevicePrepareHardware = extern "win64" fn(Arc<DeviceObject>) -> DriverStatus;

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
pub enum PnpMinorFunction {
    StartDevice,
    QueryDeviceRelations,
    QueryId,
    QueryResources,
    SurpriseRemoval,
    RemoveDevice,
    StopDevice,
}
impl PnpMinorFunction {
    pub fn default_status_for_unhandled(&self) -> DriverStatus {
        match self {
            Self::StartDevice
            | Self::QueryDeviceRelations
            | Self::SurpriseRemoval
            | Self::RemoveDevice
            | Self::StopDevice => DriverStatus::Success,
            Self::QueryId | Self::QueryResources => DriverStatus::NotImplemented,
        }
    }
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
    extern "win64" fn(Arc<DeviceObject>, Arc<RwLock<Request>>) -> DriverStatus;

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
            handlers: vec![None; n],
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum RequestType {
    Read { offset: u64, len: usize },
    Write { offset: u64, len: usize },
    DeviceControl(u32),
    Fs(FsOp),
    Pnp,
    Dummy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum FsOp {
    Create,
    Open,
    Close,
    Read,
    Write,
    Flush,
    Seek,
    ReadDir,
    GetInfo,
    SetInfo,
    Delete,
    Rename,
}

#[derive(Clone, Copy)]
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
    pub fn invoke(&self, dev: Arc<DeviceObject>, req: Arc<RwLock<Request>>) -> BoxedIoFuture {
        match *self {
            IoType::Read(h) | IoType::Write(h) => {
                let len = req.read().data.len();
                h(dev, req, len)
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

#[derive(Clone)]
#[repr(C)]
pub struct IoHandler {
    pub handler: IoType,
    pub synchronization: Synchronization,
    pub depth: usize,
    pub running_request: Arc<AtomicU64>,
}

// Custom debug impl to avoid printing function pointers
impl core::fmt::Debug for IoHandler {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IoHandler")
            .field("synchronization", &self.synchronization)
            .finish()
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct IoVtable {
    pub handlers: Vec<Option<IoHandler>>,
}
impl IoVtable {
    #[inline]
    pub fn new() -> Self {
        let n = 4; // Read, Write, DC, Fs
        Self {
            handlers: vec![None; n],
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

#[repr(C)]
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
    pub traversal_policy: TraversalPolicy,
    pub pnp: Option<PnpRequest>,
    pub completion_routine: Option<CompletionRoutine>,
    pub completion_context: usize,
    pub waker: Option<Waker>,
}

impl Request {
    #[inline]
    pub fn new(kind: RequestType, data: Box<[u8]>) -> Self {
        if matches!(kind, RequestType::Pnp) {
            panic!("Use Request::new_pnp for PnP requests.");
        }
        Self {
            id: unsafe { crate::util::random_number() },
            kind,
            data,
            completed: false,
            status: DriverStatus::Continue,
            traversal_policy: TraversalPolicy::FailIfUnhandled,
            pnp: None,
            completion_routine: None,
            completion_context: 0,
            waker: None,
        }
    }
    #[inline]
    pub fn set_traversal_policy(mut self, policy: TraversalPolicy) -> Self {
        self.traversal_policy = policy;
        self
    }
    #[inline]
    pub fn new_pnp(pnp: PnpRequest, data: Box<[u8]>) -> Self {
        Self {
            id: unsafe { crate::util::random_number() },
            kind: RequestType::Pnp,
            data,
            completed: false,
            status: DriverStatus::Continue,
            traversal_policy: TraversalPolicy::ForwardLower,
            pnp: Some(pnp),
            completion_routine: None,
            completion_context: 0,
            waker: None,
        }
    }
    pub fn set_completion(&mut self, routine: CompletionRoutine, context: usize) {
        self.completion_routine = Some(routine);
        self.completion_context = context;
    }
}

pub struct RequestFuture {
    pub req: Arc<RwLock<Request>>,
}

impl Future for RequestFuture {
    type Output = DriverStatus;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut req = self.req.write();
        if req.completed {
            Poll::Ready(req.status)
        } else {
            req.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct DeviceInit {
    pub io_vtable: IoVtable,
    pub pnp_vtable: Option<PnpVtable>,
    pub(crate) dev_ext_type: Option<TypeId>,
    pub(crate) dev_ext_size: usize,
    pub(crate) dev_ext_ready: Option<DevExtBox>,
}

impl DeviceInit {
    pub fn new(io_vtable: IoVtable, pnp_vtable: Option<PnpVtable>) -> Self {
        Self {
            io_vtable,
            pnp_vtable,
            dev_ext_type: None,
            dev_ext_size: 0,
            dev_ext_ready: None,
        }
    }
    pub fn set_dev_ext_from<T: 'static + Send + Sync>(&mut self, value: T) {
        self.dev_ext_size = core::mem::size_of::<T>();
        self.dev_ext_type = Some(TypeId::of::<T>());
        self.dev_ext_ready = Some(DevExtBox::from_value(value));
    }
    pub fn set_dev_ext_default<T: Default + 'static + Send + Sync>(&mut self) {
        self.set_dev_ext_from::<T>(T::default());
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
}

#[repr(C)]
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

#[repr(u32)]
pub enum DevExtError {
    NotPresent,
    TypeMismatch { expected: &'static str },
}

#[repr(C)]
pub struct DevExtRef<'a, T: 'static> {
    ptr: NonNull<T>,
    _lt: PhantomData<&'a T>,
    _nosend: PhantomData<*mut T>,
}
impl<'a, T: 'static> core::ops::Deref for DevExtRef<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { self.ptr.as_ref() }
    }
}

#[repr(C)]
#[derive(Debug)]
struct DevExtBox {
    inner: Once<Box<dyn Any + Send + Sync>>,
    ty: TypeId,
    present: bool,
}
impl DevExtBox {
    fn none() -> Self {
        Self {
            inner: Once::new(),
            ty: TypeId::of::<()>(),
            present: false,
        }
    }
    fn from_value<T: 'static + Send + Sync>(v: T) -> Self {
        let mut b = Self {
            inner: Once::new(),
            ty: TypeId::of::<T>(),
            present: true,
        };
        b.inner.call_once(|| Box::new(v));
        b
    }
    fn as_const_ptr<T: 'static>(&self) -> *const T {
        self.inner
            .get()
            .map(|b| {
                (&**b as &dyn Any)
                    .downcast_ref::<T>()
                    .map(|r| r as *const T)
                    .unwrap_or(ptr::null())
            })
            .unwrap_or(ptr::null())
    }
}
