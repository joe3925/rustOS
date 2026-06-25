#![no_std]

extern crate alloc;

use alloc::sync::Arc;
use core::marker::PhantomData;

use kernel_types::device::{DevNode, DeviceObject};
use kernel_types::status::DriverStatus;

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
}

pub trait DriverProtocol {
    const ID: ProtocolId;
    const VERSION: ProtocolVersion;

    type VTable: 'static;
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RegisteredProtocol {
    pub id: ProtocolId,
    pub version: ProtocolVersion,
    pub vtable: *const (),
    pub generation: u64,
}

pub struct ProtocolHandle<P: DriverProtocol> {
    provider: Arc<DeviceObject>,
    vtable: &'static P::VTable,
    provider_generation: u64,
    protocol_generation: u64,
    _protocol: PhantomData<P>,
}

impl<P: DriverProtocol> ProtocolHandle<P> {
    #[inline]
    pub fn provider(&self) -> &Arc<DeviceObject> {
        &self.provider
    }

    #[inline]
    pub fn vtable(&self) -> &'static P::VTable {
        self.vtable
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

pub fn register_protocol<P: DriverProtocol>(
    device: &Arc<DeviceObject>,
    vtable: &'static P::VTable,
) -> DriverStatus {
    if device.register_protocol_entry(
        P::ID.0,
        P::VERSION.major,
        P::VERSION.minor,
        vtable as *const P::VTable as *const (),
    ) {
        DriverStatus::Success
    } else {
        DriverStatus::InvalidParameter
    }
}

pub fn open_protocol_to_next_lower<P: DriverProtocol>(
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

pub fn open_protocol_at_stack_top<P: DriverProtocol>(
    node: &Arc<DevNode>,
) -> Result<ProtocolHandle<P>, DriverStatus> {
    let top = node
        .stack
        .read()
        .as_ref()
        .and_then(|stack| stack.get_top_device_object())
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

pub fn open_protocol_to_next_upper<P: DriverProtocol>(
    device: &Arc<DeviceObject>,
) -> Result<ProtocolHandle<P>, DriverStatus> {
    let mut current = device.upper_device.get().and_then(|upper| upper.upgrade());

    while let Some(dev) = current {
        if let Some(handle) = try_open_protocol_on_device::<P>(&dev) {
            return Ok(handle);
        }

        current = dev.upper_device.get().and_then(|upper| upper.upgrade());
    }

    Err(DriverStatus::NotImplemented)
}

fn try_open_protocol_on_device<P: DriverProtocol>(
    device: &Arc<DeviceObject>,
) -> Option<ProtocolHandle<P>> {
    let entry = find_protocol::<P>(device)?;
    let vtable = typed_vtable::<P>(&entry);

    Some(ProtocolHandle {
        provider: device.clone(),
        vtable,
        provider_generation: device.generation(),
        protocol_generation: device.protocol_generation(),
        _protocol: PhantomData,
    })
}

fn find_protocol<P: DriverProtocol>(device: &DeviceObject) -> Option<RegisteredProtocol> {
    device
        .find_protocol_entry(P::ID.0, P::VERSION.major, P::VERSION.minor)
        .map(|entry| RegisteredProtocol {
            id: ProtocolId(entry.id),
            version: ProtocolVersion::new(entry.version_major, entry.version_minor),
            vtable: entry.vtable,
            generation: entry.generation,
        })
}

#[inline]
fn typed_vtable<P: DriverProtocol>(entry: &RegisteredProtocol) -> &'static P::VTable {
    debug_assert_eq!(entry.id, P::ID);
    debug_assert!(entry.version.major == P::VERSION.major);
    debug_assert!(entry.version.minor >= P::VERSION.minor);

    // Safety: register_protocol::<P> stores only static P::VTable pointers for
    // P::ID. If the id and compatible version match, this erased pointer came
    // from that registration path and is valid for the lifetime of the kernel.
    unsafe { &*(entry.vtable as *const P::VTable) }
}
