use alloc::sync::Arc;

use crate::async_ffi::{FfiFuture, FutureExt};
use crate::device::DeviceObject;
use crate::io::{IoType, IoVtable, TreiberStack};
use crate::pnp::DriverStep;
use crate::request::{RequestData, RequestHandle, RequestType};
use crate::status::DriverStatus;

extern "win64" fn read_handler(
    _dev: &Arc<DeviceObject>,
    _handle: &mut RequestHandle<'_, '_>,
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
    _handle: &mut RequestHandle<'_, '_>,
    _len: usize,
) -> FfiFuture<DriverStep> {
    async { DriverStep::Continue }.into_ffi()
}

extern "win64" fn simple_handler(
    _dev: &Arc<DeviceObject>,
    _handle: &mut RequestHandle<'_, '_>,
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
    assert_eq!(IoType::DeviceControl(simple_handler).slot(), 2);
    assert_eq!(IoType::Fs(simple_handler).slot(), 3);
    assert_eq!(IoType::Flush(simple_handler).slot(), 4);

    assert_eq!(
        IoType::slot_for_request(&RequestType::Read {
            offset: 0,
            len: 4,
            no_buffer: false
        }),
        Some(0)
    );
    assert_eq!(
        IoType::slot_for_request(&RequestType::Write {
            offset: 0,
            len: 4,
            no_buffer: false,
            owner: 9
        }),
        Some(1)
    );
    assert_eq!(
        IoType::slot_for_request(&RequestType::DeviceControl(1)),
        Some(2)
    );
    assert_eq!(IoType::slot_for_request(&RequestType::Dummy), None);
}

#[test]
fn io_vtable_installs_each_handler_once() {
    let vtable = IoVtable::new();
    let read = RequestType::Read {
        offset: 0,
        len: 4,
        no_buffer: false,
    };
    let write = RequestType::Write {
        offset: 0,
        len: 9,
        no_buffer: false,
        owner: 0,
    };

    assert!(vtable.get_for(&read).is_none());
    vtable.set(IoType::Read(read_handler), 1);
    vtable.set(IoType::Read(read_handler), 99);
    vtable.set(IoType::Write(write_handler), 0);

    assert_eq!(vtable.get_for(&read).unwrap().depth, 1);
    assert_eq!(vtable.get_for(&write).unwrap().depth, 0);
    assert!(
        vtable
            .get_for(&RequestType::DeviceControl(0xCAFE))
            .is_none()
    );

    let handle = RequestHandle::new(read, RequestData::empty());
    assert_eq!(handle.read().kind, read);
}
