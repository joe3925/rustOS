use alloc::boxed::Box;
use alloc::collections::vec_deque::VecDeque;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::{Any, TypeId, type_name};
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
use spin::{Mutex, Once, RwLock};

use crate::io::IoVtable;
use crate::memory::Module;
use crate::pnp::{BootType, DeviceIds, PnpVtable};
use crate::request::Request;
use crate::{EvtDriverDeviceAdd, EvtDriverUnload};

pub type ModuleHandle = Arc<RwLock<Module>>;
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevNodeState {
    Empty,
    Initialized,
    DriversBound,
    Started,
    Stopped,
    SurpriseRemoved,
    Deleted,
    Faulted,
}
#[repr(C)]
#[derive(Debug, Clone)]
pub struct DriverPackage {
    pub name: String,
    pub image_path: String,
    pub toml_path: String,
    pub start: BootType,
    pub hwids: Vec<String>,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DriverState {
    Loaded,
    Continue,
    Started,
    Stopped,
    Failed,
}
#[repr(C)]
#[derive(Debug)]
pub struct DriverRuntime {
    pub pkg: Arc<DriverPackage>,
    pub module: ModuleHandle,
    pub state: AtomicU8,
    pub refcnt: AtomicU32,
}
impl DriverRuntime {
    pub fn set_state(&self, s: DriverState) {
        self.state.store(s as u8, Ordering::Release);
    }
    pub fn get_state(&self) -> DriverState {
        unsafe { core::mem::transmute(self.state.load(Ordering::Acquire) as u32) }
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
#[derive(Debug, Clone)]
pub struct StackLayer {
    pub driver: Arc<DriverObject>,
    pub devobj: Option<Arc<DeviceObject>>,
}
#[repr(C)]
#[derive(Debug)]
pub struct DeviceStack {
    pub pdo_bus_service: Option<String>,
    pub lower: Vec<StackLayer>,
    pub function: Option<StackLayer>,
    pub upper: Vec<StackLayer>,
}

impl DeviceStack {
    pub fn new() -> Self {
        Self {
            pdo_bus_service: None,
            lower: Vec::new(),
            function: None,
            upper: Vec::new(),
        }
    }
    pub fn get_top_device_object(&self) -> Option<Arc<DeviceObject>> {
        self.upper
            .last()
            .and_then(|l| l.devobj.clone())
            .or_else(|| self.function.as_ref().and_then(|l| l.devobj.clone()))
            .or_else(|| self.lower.last().and_then(|l| l.devobj.clone()))
    }
}
#[derive(Debug)]
#[repr(C)]
pub struct DevNode {
    pub name: String,
    pub parent: Once<Weak<DevNode>>,
    pub children: RwLock<Vec<Arc<DevNode>>>,
    pub instance_path: String,
    pub ids: DeviceIds,
    pub class: Option<String>,
    pub state: AtomicU8,
    pub pdo: RwLock<Option<Arc<DeviceObject>>>,
    pub stack: RwLock<Option<DeviceStack>>,
}

#[derive(Debug)]
#[repr(C)]
pub struct DeviceObject {
    pub lower_device: Once<Arc<DeviceObject>>,
    pub upper_device: Once<Weak<DeviceObject>>,
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

#[derive(Debug)]
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
impl<'a, T: 'static> Deref for DevExtRef<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { self.ptr.as_ref() }
    }
}
unsafe impl<'a, T: Sync> Send for DevExtRef<'a, T> {}
unsafe impl<'a, T: Sync> Sync for DevExtRef<'a, T> {}

#[repr(C)]
pub struct DevExtRefMut<'a, T: 'static> {
    ptr: NonNull<T>,
    _lt: PhantomData<&'a mut T>,
    _nosend: PhantomData<*mut T>,
}
impl<'a, T: 'static> Deref for DevExtRefMut<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { self.ptr.as_ref() }
    }
}
impl<'a, T: 'static> DerefMut for DevExtRefMut<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { self.ptr.as_mut() }
    }
}

#[repr(C)]
#[derive(Debug)]
pub(crate) struct DevExtBox {
    inner: Once<Box<dyn Any + Send + Sync>>,
    ty: TypeId,
    present: bool,
}

impl DevExtBox {
    #[inline]
    pub fn none() -> Self {
        Self {
            inner: Once::new(),
            ty: TypeId::of::<()>(),
            present: false,
        }
    }

    #[inline]
    pub fn from_value<T: 'static + Send + Sync>(v: T) -> Self {
        let b = Self {
            inner: Once::new(),
            ty: TypeId::of::<T>(),
            present: true,
        };
        b.inner
            .call_once(|| Box::new(v) as Box<dyn Any + Send + Sync>);
        b
    }

    #[inline]
    pub fn as_const_ptr<T: 'static>(&self) -> *const T {
        match self.inner.get() {
            Some(b) => {
                let a: &dyn Any = &**b;
                a.downcast_ref::<T>()
                    .map(|r| r as *const T)
                    .unwrap_or(ptr::null())
            }
            None => ptr::null(),
        }
    }
}
