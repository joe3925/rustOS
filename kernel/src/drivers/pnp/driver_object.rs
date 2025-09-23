use crate::{alloc::vec, util::random_number};
use alloc::{
    boxed::Box,
    collections::vec_deque::VecDeque,
    string::String,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{
    mem,
    sync::atomic::{AtomicBool, AtomicU32, AtomicU64},
};
use spin::{Mutex, RwLock};
use strum::Display;

use super::pnp_manager::{CompletionRoutine, DevNode, DriverRuntime};

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
    pub dev_ext: Box<[u8]>,
    pub dev_init: DeviceInit,
    pub queue: Mutex<VecDeque<Arc<RwLock<Request>>>>,

    pub dispatch_tickets: AtomicU32,
    pub dev_node: Weak<DevNode>,
}

impl DeviceObject {
    pub fn new(dev_ext_size: usize) -> Arc<Self> {
        let dev_ext = vec![0u8; dev_ext_size].into_boxed_slice();
        Arc::new(Self {
            lower_device: None,
            upper_device: RwLock::new(None),
            dev_ext,
            dev_init: DeviceInit::new(),
            queue: Mutex::new(VecDeque::new()),
            dispatch_tickets: AtomicU32::new(0),
            dev_node: Weak::new(),
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

    #[inline]
    pub fn devext_mut<T>(&mut self) -> &mut T {
        assert!(self.dev_ext.len() >= mem::size_of::<T>());
        unsafe { &mut *(self.dev_ext.as_mut_ptr() as *mut T) }
    }

    #[inline]
    pub fn devext_ref<T>(&self) -> &T {
        assert!(self.dev_ext.len() >= mem::size_of::<T>());
        unsafe { &*(self.dev_ext.as_ptr() as *const T) }
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

    Pnp,

    Dummy,
}
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub enum IoType {
    Read(EvtIoRead),
    Write(EvtIoWrite),
    DeviceControl(EvtIoDeviceControl),
}
impl IoType {
    #[inline]
    pub fn slot(&self) -> usize {
        match self {
            IoType::Read(_) => 0,
            IoType::Write(_) => 1,
            IoType::DeviceControl(_) => 2,
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
        }
    }

    #[inline]
    pub fn slot_for_request(r: &RequestType) -> Option<usize> {
        match r {
            RequestType::Read { .. } => Some(0),
            RequestType::Write { .. } => Some(1),
            RequestType::DeviceControl(_) => Some(2),
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
//TODO: do something better
#[repr(C)]
#[derive(Debug)]
pub struct DeviceInit {
    pub dev_ext_size: usize,
    pub io_vtable: IoVtable,
    pub pnp_vtable: Option<PnpVtable>,
}

impl DeviceInit {
    pub fn new() -> Self {
        Self {
            dev_ext_size: 0,
            io_vtable: IoVtable::new(),
            pnp_vtable: None,
        }
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
