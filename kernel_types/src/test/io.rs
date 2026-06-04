use alloc::sync::Arc;

use crate::async_ffi::{FfiFuture, FutureExt};
use crate::device::DeviceObject;
use crate::dma::{Described, FromDevice, IoBuffer};
use crate::io::{IoType, IoVtable, TreiberStack};
use crate::pnp::DriverStep;
use crate::request::{DeviceControl, Flush, Fs, Read, RequestData, RequestHandle, Write};
use crate::status::DriverStatus;

extern "win64" fn read_handler(
    _dev: &Arc<DeviceObject>,
    _handle: &mut RequestHandle<'_, Read<'_>>,
    len: usize,
) -> FfiFuture<DriverStep> {
    async move {
        if len == 4 {
            DriverStep::complete(DriverStatus::Success)
        } else {
            DriverStep::complete(DriverStatus::InvalidParameter)
        }
    }
    .into_ffi()
}

extern "win64" fn write_handler(
    _dev: &Arc<DeviceObject>,
    _handle: &mut RequestHandle<'_, Write<'_>>,
    _len: usize,
) -> FfiFuture<DriverStep> {
    async { DriverStep::Continue }.into_ffi()
}

extern "win64" fn device_control_handler(
    _dev: &Arc<DeviceObject>,
    _handle: &mut RequestHandle<'_, DeviceControl<'_>>,
) -> FfiFuture<DriverStep> {
    async { DriverStep::complete(DriverStatus::Success) }.into_ffi()
}

extern "win64" fn fs_handler(
    _dev: &Arc<DeviceObject>,
    _handle: &mut RequestHandle<'_, Fs<'_>>,
) -> FfiFuture<DriverStep> {
    async { DriverStep::complete(DriverStatus::Success) }.into_ffi()
}

extern "win64" fn flush_handler(
    _dev: &Arc<DeviceObject>,
    _handle: &mut RequestHandle<'_, Flush>,
) -> FfiFuture<DriverStep> {
    async { DriverStep::complete(DriverStatus::Success) }.into_ffi()
}

#[test]
fn treiber_stack_is_lifo_and_tracks_length() {
    let stack = TreiberStack::new();
    assert!(stack.is_empty());
    assert_eq!(stack.pop(), None);

    stack.push(10);
    stack.push(20);
    stack.push(30);

    assert_eq!(stack.len(), 3);
    assert_eq!(stack.pop(), Some(30));
    assert_eq!(stack.pop(), Some(20));
    assert_eq!(stack.pop(), Some(10));
    assert_eq!(stack.pop(), None);
    assert!(stack.is_empty());
}

#[test]
fn io_type_slots_match_request_kinds() {
    assert_eq!(IoType::Read(read_handler).slot(), 0);
    assert_eq!(IoType::Write(write_handler).slot(), 1);
    assert_eq!(IoType::Flush(flush_handler).slot(), 2);
    assert_eq!(IoType::DeviceControl(device_control_handler).slot(), 5);
    assert_eq!(IoType::Fs(fs_handler).slot(), 6);
}

#[test]
fn io_vtable_installs_each_handler_once() {
    let mut vtable = IoVtable::new();

    assert!(vtable.read.is_none());
    vtable.set(IoType::Read(read_handler), 1);
    vtable.set(IoType::Read(read_handler), 99);
    vtable.set(IoType::Write(write_handler), 0);

    assert_eq!(vtable.read.as_ref().unwrap().depth, 1);
    assert_eq!(vtable.write.as_ref().unwrap().depth, 0);
    assert!(vtable.device_control.is_none());

    let mut buffer = [0u8; 4];
    let handle = RequestHandle::new(Read {
        offset: 0,
        len: 4,
        no_buffer: false,
        buffer: IoBuffer::<Described, FromDevice>::new(&mut buffer).into(),
    });
    assert_eq!(handle.read().body.offset, 0);
    assert_eq!(handle.read().body.len, 4);

    let dc = RequestHandle::new(DeviceControl::new(0xCAFE, RequestData::empty()));
    assert_eq!(dc.read().body.code, 0xCAFE);
}
