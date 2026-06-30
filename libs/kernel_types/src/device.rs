use crate::fs::Path;
use crate::io::DeviceOps;
use crate::memory::Module;
use crate::pnp::{BootType, DeviceIds, PnpOps};
use crate::status::DriverStatus;
use crate::{EvtDriverDeviceAdd, EvtDriverUnload};
use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::{Any, TypeId, type_name};
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
use spin::{Once, RwLock};

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
    pub image_path: Path,
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
        match self.state.load(Ordering::Acquire) {
            0 => DriverState::Loaded,
            1 => DriverState::Continue,
            2 => DriverState::Started,
            3 => DriverState::Stopped,
            4 => DriverState::Failed,
            _ => DriverState::Failed,
        }
    }
}

pub struct DriverConfig<'a> {
    driver: &'a DriverObject,
}

impl DriverConfig<'_> {
    pub fn on_device_add(&mut self, cb: EvtDriverDeviceAdd) -> &mut Self {
        *self.driver.evt_device_add.write() = Some(cb);
        self
    }

    pub fn on_unload(&mut self, cb: EvtDriverUnload) -> &mut Self {
        *self.driver.evt_driver_unload.write() = Some(cb);
        self
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct DriverObject {
    pub runtime: Arc<DriverRuntime>,
    pub driver_name: String,
    pub flags: u32,
    pub evt_device_add: RwLock<Option<EvtDriverDeviceAdd>>,
    pub evt_driver_unload: RwLock<Option<EvtDriverUnload>>,
}

impl DriverObject {
    pub fn allocate(runtime: Arc<DriverRuntime>, driver_name: String) -> Arc<Self> {
        Arc::new(Self {
            runtime,
            driver_name,
            flags: 0,
            evt_device_add: RwLock::new(None),
            evt_driver_unload: RwLock::new(None),
        })
    }

    pub fn configure<F: FnOnce(&mut DriverConfig)>(this: &Arc<Self>, f: F) {
        let mut cfg = DriverConfig { driver: this };

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
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicProtocol {
    pub id: ProtocolId,
    pub major: u16,
}

#[repr(C)]
#[derive(Debug)]
pub struct DeviceStack {
    pub pdo_bus_service: Option<String>,
    pub lower: Vec<StackLayer>,
    pub function: Option<StackLayer>,
    pub upper: Vec<StackLayer>,
    pub public_protocols: Vec<PublicProtocol>,
}

impl Default for DeviceStack {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceStack {
    pub fn new() -> Self {
        Self {
            pdo_bus_service: None,
            lower: Vec::new(),
            function: None,
            upper: Vec::new(),
            public_protocols: Vec::new(),
        }
    }

    #[inline]
    pub fn has_public_protocol<P: Protocol>(&self) -> bool {
        self.public_protocols
            .iter()
            .any(|p| p.id == P::ID && p.major == P::VERSION.major)
    }

    #[inline]
    pub fn publish_protocol<P: Protocol>(&mut self) -> bool {
        if self.has_public_protocol::<P>() {
            return false;
        }

        self.public_protocols.push(PublicProtocol {
            id: P::ID,
            major: P::VERSION.major,
        });

        true
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

impl DevNode {
    #[inline]
    pub fn state(&self) -> DevNodeState {
        match self.state.load(Ordering::Acquire) {
            0 => DevNodeState::Empty,
            1 => DevNodeState::Initialized,
            2 => DevNodeState::DriversBound,
            3 => DevNodeState::Started,
            4 => DevNodeState::Stopped,
            5 => DevNodeState::SurpriseRemoved,
            6 => DevNodeState::Deleted,
            7 => DevNodeState::Faulted,
            _ => DevNodeState::Faulted,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ProtocolId(pub u128);

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

impl ProtocolVersion {
    #[inline]
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    #[inline]
    pub const fn is_compatible_with(self, required: ProtocolVersion) -> bool {
        self.major == required.major && self.minor >= required.minor
    }
}

/// Safety: for a given `ID` and major version, `VTable` must always be the same ABI layout.
pub unsafe trait Protocol: 'static {
    const ID: ProtocolId;
    const VERSION: ProtocolVersion;

    type VTable: Sync + 'static;
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
struct ErasedProtocolVtable {
    ptr: NonNull<()>,
}

impl ErasedProtocolVtable {
    #[inline]
    fn from_static<T: Sync + 'static>(vtable: &'static T) -> Self {
        Self {
            ptr: NonNull::from(vtable).cast(),
        }
    }

    #[inline]
    unsafe fn as_static<T: Sync + 'static>(self) -> &'static T {
        unsafe { self.ptr.cast::<T>().as_ref() }
    }
}

unsafe impl Send for ErasedProtocolVtable {}
unsafe impl Sync for ErasedProtocolVtable {}

#[derive(Debug, Clone, Copy)]
struct ProtocolEntry {
    id: ProtocolId,
    version: ProtocolVersion,
    vtable: ErasedProtocolVtable,
    generation: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProtocolRef<P: Protocol> {
    vtable: &'static P::VTable,
    version: ProtocolVersion,
    generation: u64,
    _protocol: PhantomData<P>,
}

impl<P: Protocol> ProtocolRef<P> {
    #[inline]
    pub fn vtable(&self) -> &'static P::VTable {
        self.vtable
    }

    #[inline]
    pub fn version(&self) -> ProtocolVersion {
        self.version
    }

    #[inline]
    pub fn version_major(&self) -> u16 {
        self.version.major
    }

    #[inline]
    pub fn version_minor(&self) -> u16 {
        self.version.minor
    }

    #[inline]
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

impl<P: Protocol> Deref for ProtocolRef<P> {
    type Target = P::VTable;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.vtable
    }
}

pub struct ProtocolHandle<P: Protocol> {
    provider: Arc<DeviceObject>,
    vtable: &'static P::VTable,
    version: ProtocolVersion,
    provider_generation: u64,
    protocol_generation: u64,
    entry_generation: u64,
    _protocol: PhantomData<P>,
}

impl<P: Protocol> ProtocolHandle<P> {
    #[inline]
    pub fn provider(&self) -> &Arc<DeviceObject> {
        &self.provider
    }

    #[inline]
    pub fn vtable(&self) -> &'static P::VTable {
        self.vtable
    }

    #[inline]
    pub fn version(&self) -> ProtocolVersion {
        self.version
    }

    #[inline]
    pub fn version_major(&self) -> u16 {
        self.version.major
    }

    #[inline]
    pub fn version_minor(&self) -> u16 {
        self.version.minor
    }

    #[inline]
    pub fn entry_generation(&self) -> u64 {
        self.entry_generation
    }

    #[inline]
    pub fn validate(&self) -> Result<(), DriverStatus> {
        if self.provider.is_removed() {
            return Err(DriverStatus::NoSuchDevice);
        }

        if self.provider.generation() != self.provider_generation {
            return Err(DriverStatus::NoSuchDevice);
        }

        if self.provider.protocol_generation() != self.protocol_generation {
            return Err(DriverStatus::NoSuchDevice);
        }

        Ok(())
    }
}

impl<P: Protocol> Deref for ProtocolHandle<P> {
    type Target = P::VTable;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.vtable
    }
}

pub fn register_protocol<P: Protocol>(
    device: &Arc<DeviceObject>,
    vtable: &'static P::VTable,
) -> DriverStatus {
    if device.is_removed() {
        return DriverStatus::NoSuchDevice;
    }

    if device.register_protocol::<P>(vtable) {
        DriverStatus::Success
    } else {
        DriverStatus::InvalidParameter
    }
}

pub fn open_protocol_to_next_lower<P: Protocol>(
    device: &Arc<DeviceObject>,
) -> Result<ProtocolHandle<P>, DriverStatus> {
    let mut current = device.lower_device.get().cloned();

    while let Some(dev) = current {
        if let Some(handle) = try_open_protocol_on_device::<P>(&dev) {
            return Ok(handle);
        }

        current = dev.lower_device.get().cloned();
    }

    Err(DriverStatus::NotImplemented)
}

pub fn open_protocol_at_stack_top<P: Protocol>(
    node: &Arc<DevNode>,
) -> Result<ProtocolHandle<P>, DriverStatus> {
    let top = {
        let stack = node.stack.read();

        stack
            .as_ref()
            .and_then(|stack| stack.get_top_device_object())
    }
    .or_else(|| node.pdo.read().clone())
    .ok_or(DriverStatus::NoSuchDevice)?;

    let mut current = Some(top);

    while let Some(dev) = current {
        if let Some(handle) = try_open_protocol_on_device::<P>(&dev) {
            return Ok(handle);
        }

        current = dev.lower_device.get().cloned();
    }

    Err(DriverStatus::NotImplemented)
}

fn try_open_protocol_on_device<P: Protocol>(
    device: &Arc<DeviceObject>,
) -> Option<ProtocolHandle<P>> {
    if device.is_removed() {
        return None;
    }

    let protocol = device.find_protocol::<P>(P::VERSION.minor)?;

    Some(ProtocolHandle {
        provider: device.clone(),
        vtable: protocol.vtable(),
        version: protocol.version(),
        provider_generation: device.generation(),
        protocol_generation: device.protocol_generation(),
        entry_generation: protocol.generation(),
        _protocol: PhantomData,
    })
}

#[derive(Debug)]
#[repr(C)]
pub struct DeviceObject {
    pub lower_device: Once<Arc<DeviceObject>>,
    pub upper_device: Once<Weak<DeviceObject>>,
    dev_ext: DevExtBox,
    pub ops: DeviceOps,
    pub pnp_ops: Option<PnpOps>,
    pub dispatch_tickets: AtomicU32,
    pub dev_node: Once<Weak<DevNode>>,
    pub in_queue: AtomicBool,
    protocols: RwLock<Vec<ProtocolEntry>>,
    protocol_generation: AtomicU64,
    generation: AtomicU64,
}

impl DeviceObject {
    pub fn new(mut init: DeviceInit) -> Arc<Self> {
        let dev_ext = init.dev_ext_ready.take().unwrap_or_else(DevExtBox::none);

        Arc::new(Self {
            lower_device: Once::new(),
            upper_device: Once::new(),
            dev_ext,
            ops: init.ops,
            pnp_ops: init.pnp_ops,
            dispatch_tickets: AtomicU32::new(0),
            dev_node: Once::new(),
            in_queue: AtomicBool::new(false),
            protocols: RwLock::new(Vec::new()),
            protocol_generation: AtomicU64::new(1),
            generation: AtomicU64::new(1),
        })
    }

    /// Note: because of `TypeId`, devext is only accessible from the driver binary that created it.
    pub fn try_devext<'a, T: 'static>(&'a self) -> Result<DevExtRef<'a, T>, DevExtError> {
        if !self.dev_ext.present {
            return Err(DevExtError::NotPresent);
        }

        if self.dev_ext.ty != TypeId::of::<T>() {
            return Err(DevExtError::TypeMismatch {
                expected: type_name::<T>(),
            });
        }

        let p = NonNull::new(self.dev_ext.as_const_ptr::<T>() as *mut T)
            .ok_or(DevExtError::NotPresent)?;

        Ok(DevExtRef {
            ptr: p,
            _lt: PhantomData,
            _nosend: PhantomData,
        })
    }

    pub fn set_lower_upper(this: &Arc<Self>, lower: Arc<DeviceObject>) {
        this.lower_device.call_once(|| lower.clone());
        lower.upper_device.call_once(|| Arc::downgrade(this));
    }

    pub fn attach_devnode(&self, dn: &Arc<DevNode>) {
        self.dev_node.call_once(|| Arc::downgrade(dn));
    }

    #[inline]
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    #[inline]
    pub fn protocol_generation(&self) -> u64 {
        self.protocol_generation.load(Ordering::Acquire)
    }

    #[inline]
    fn bump_protocol_generation(&self) -> u64 {
        self.protocol_generation.fetch_add(1, Ordering::AcqRel) + 1
    }

    #[inline]
    pub fn is_removed(&self) -> bool {
        self.dev_node
            .get()
            .and_then(Weak::upgrade)
            .is_some_and(|dn| {
                matches!(
                    dn.state(),
                    DevNodeState::SurpriseRemoved | DevNodeState::Deleted
                )
            })
    }

    pub fn register_protocol<P>(&self, vtable: &'static P::VTable) -> bool
    where
        P: Protocol,
    {
        let mut protocols = self.protocols.write();

        if protocols
            .iter()
            .any(|entry| entry.id == P::ID && entry.version.major == P::VERSION.major)
        {
            return false;
        }

        let generation = self.bump_protocol_generation();

        protocols.push(ProtocolEntry {
            id: P::ID,
            version: P::VERSION,
            vtable: ErasedProtocolVtable::from_static(vtable),
            generation,
        });

        true
    }

    pub fn find_protocol<P>(&self, min_version_minor: u16) -> Option<ProtocolRef<P>>
    where
        P: Protocol,
    {
        let required = ProtocolVersion::new(P::VERSION.major, min_version_minor);

        self.protocols
            .read()
            .iter()
            .copied()
            .find(|entry| entry.id == P::ID && entry.version.is_compatible_with(required))
            .map(|entry| {
                let vtable = unsafe { entry.vtable.as_static::<P::VTable>() };

                ProtocolRef {
                    vtable,
                    version: entry.version,
                    generation: entry.generation,
                    _protocol: PhantomData,
                }
            })
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct DeviceInit {
    pub ops: DeviceOps,
    pub pnp_ops: Option<PnpOps>,
    pub(crate) dev_ext_type: Option<TypeId>,
    pub(crate) dev_ext_size: usize,
    pub(crate) dev_ext_ready: Option<DevExtBox>,
}

impl DeviceInit {
    pub fn new() -> Self {
        Self {
            ops: DeviceOps::empty(),
            pnp_ops: None,
            dev_ext_type: None,
            dev_ext_size: 0,
            dev_ext_ready: None,
        }
    }

    pub fn with_pnp(pnp_ops: Option<PnpOps>) -> Self {
        let mut init = Self::new();
        init.pnp_ops = pnp_ops;
        init
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

impl Default for DeviceInit {
    fn default() -> Self {
        Self::new()
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

impl<P: Protocol> ProtocolHandle<P> {
    #[inline]
    pub fn open_next_lower(&self) -> Result<ProtocolHandle<P>, DriverStatus> {
        open_protocol_to_next_lower::<P>(&self.provider)
    }
}

pub fn publish_stack_protocol<P: Protocol>(node: &Arc<DevNode>) -> DriverStatus {
    let mut stack = node.stack.write();

    let Some(stack) = stack.as_mut() else {
        return DriverStatus::NoSuchDevice;
    };

    if stack.publish_protocol::<P>() {
        DriverStatus::Success
    } else {
        DriverStatus::InvalidParameter
    }
}

pub fn open_public_protocol<P: Protocol>(
    node: &Arc<DevNode>,
) -> Result<ProtocolHandle<P>, DriverStatus> {
    open_protocol_at_stack_top::<P>(node)
}
