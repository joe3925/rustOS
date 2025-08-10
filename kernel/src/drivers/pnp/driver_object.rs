/* -------------------------------------------------------------------------- */
/* Status codes                                                               */
/* -------------------------------------------------------------------------- */

use crate::{alloc::vec, util::random_number};
use alloc::{boxed::Box, collections::vec_deque::VecDeque, string::String, sync::Arc};
use core::{
    mem,
    sync::atomic::{AtomicBool, AtomicU32},
};
use spin::{Mutex, RwLock};
use strum::Display;

use super::pnp_manager::DriverRuntime;

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

#[derive(Debug)]

pub struct DeviceObject {
    pub lower_device: Option<Arc<DeviceObject>>,
    pub upper_device: RwLock<Option<alloc::sync::Weak<DeviceObject>>>,
    pub dev_ext: Box<[u8]>,
    pub dev_init: DeviceInit,
    pub queue: Mutex<VecDeque<Arc<spin::Mutex<Request>>>>,

    pub dispatch_scheduled: AtomicBool,
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
            dispatch_scheduled: AtomicBool::new(false),
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

    /// Dev_ext casts
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
pub type EvtDriverDeviceAdd = fn(driver: &Arc<DriverObject>, init: &mut DeviceInit) -> DriverStatus;
pub type EvtDriverUnload = fn(driver: &Arc<DriverObject>);

pub type EvtIoRead = fn(&Arc<DeviceObject>, &mut Request, usize);
pub type EvtIoWrite = fn(&Arc<DeviceObject>, &mut Request, usize);
pub type EvtIoDeviceControl = fn(&Arc<DeviceObject>, &mut Request, u32);
#[derive(Debug, Clone, Copy)]
pub enum RequestType {
    Read(fn(&Arc<DeviceObject>, &mut Request)),
    Write(fn(&Arc<DeviceObject>, &mut Request)),
    DeviceControl(fn(&Arc<DeviceObject>, &mut Request)),
}

#[derive(Debug)]
pub struct Request {
    pub id: u64,
    pub kind: RequestType,
    pub data: Box<[u8]>,
    pub ioctl_code: Option<u32>,
    pub completed: bool,
    pub status: DriverStatus,
}

impl Request {
    #[inline]
    pub fn new(kind: RequestType, data: Box<[u8]>, ioctl_code: Option<u32>) -> Self {
        Self {
            id: random_number(),
            kind,
            data,
            ioctl_code,
            completed: false,
            status: DriverStatus::Pending,
        }
    }
}
//TODO: do something better
#[derive(Debug)]
pub struct DeviceInit {
    pub dev_ext_size: usize,
    pub io_read: Option<EvtIoRead>,
    pub io_write: Option<EvtIoWrite>,
    pub io_device_control: Option<EvtIoDeviceControl>,
}

impl DeviceInit {
    pub fn new() -> Self {
        Self {
            dev_ext_size: 0,
            io_read: None,
            io_write: None,
            io_device_control: None,
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
