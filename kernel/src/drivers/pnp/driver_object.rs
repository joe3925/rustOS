/* -------------------------------------------------------------------------- */
/* Status codes                                                               */
/* -------------------------------------------------------------------------- */

use core::sync::atomic::AtomicU32;

use alloc::{string::String, sync::Arc};

use super::pnp_manager::DriverRuntime;

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

pub struct DeviceObject;
pub struct Request;

pub type EvtDriverDeviceAdd = fn(driver: &Arc<DriverObject>, init: &mut DeviceInit) -> DriverStatus;
pub type EvtDriverUnload = fn(driver: &Arc<DriverObject>);

pub type EvtIoRead = fn(device: &Arc<DeviceObject>, request: &mut Request, length: usize);
pub type EvtIoWrite = fn(device: &Arc<DeviceObject>, request: &mut Request, length: usize);
pub type EvtIoDeviceControl =
    fn(device: &Arc<DeviceObject>, request: &mut Request, control_code: u32);

pub struct DeviceInit {
    pub io_read: Option<EvtIoRead>,
    pub io_write: Option<EvtIoWrite>,
    pub io_device_control: Option<EvtIoDeviceControl>,
}

impl DeviceInit {
    pub fn new() -> Self {
        Self {
            io_read: None,
            io_write: None,
            io_device_control: None,
        }
    }
}

#[repr(C)]
pub struct DriverObject {
    pub runtime: Arc<DriverRuntime>,
    pub driver_name: String,
    pub flags: u32,
    pub refcnt: AtomicU32,

    /* Framework callbacks */
    pub evt_device_add: Option<EvtDriverDeviceAdd>,
    pub evt_driver_unload: Option<EvtDriverUnload>,
}

impl DriverObject {
    pub fn allocate(runtime: Arc<DriverRuntime>, driver_name: String) -> Arc<Self> {
        Arc::new(Self {
            runtime,
            driver_name,
            flags: 0,
            refcnt: AtomicU32::new(1),
            evt_device_add: None,
            evt_driver_unload: None,
        })
    }

    pub fn configure<F: FnOnce(&mut DriverConfig)>(this: &Arc<Self>, f: F) {
        let mut cfg = DriverConfig {
            driver: this.clone(),
        };
        f(&mut cfg);
    }
}

/* -------------------------------------------------------------------------- */
/* DriverConfig - fluent API to set callbacks                                 */
/* -------------------------------------------------------------------------- */

pub struct DriverConfig {
    driver: Arc<DriverObject>,
}

impl DriverConfig {
    pub fn on_device_add(mut self, cb: EvtDriverDeviceAdd) -> Self {
        let me = unsafe { &mut *(Arc::as_ptr(&self.driver) as *mut DriverObject) };
        me.evt_device_add = Some(cb);
        self
    }

    pub fn on_unload(mut self, cb: EvtDriverUnload) -> Self {
        let me = unsafe { &mut *(Arc::as_ptr(&self.driver) as *mut DriverObject) };
        me.evt_driver_unload = Some(cb);
        self
    }
}

pub fn framework_call_device_add(
    driver: &Arc<DriverObject>,
    init: &mut DeviceInit,
) -> DriverStatus {
    if let Some(cb) = driver.evt_device_add {
        cb(driver, init)
    } else {
        DriverStatus::NotImplemented
    }
}

pub fn framework_call_unload(driver: &Arc<DriverObject>) {
    if let Some(cb) = driver.evt_driver_unload {
        cb(driver)
    }
}
