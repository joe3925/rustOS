use alloc::sync::Arc;

use crate::async_ffi::{FfiFuture, FutureExt};
use crate::device::DeviceObject;
use crate::dma::{Described, FromDevice, IoBuffer};
use crate::io::{
    DeviceControlHandler, DeviceFlush, DeviceOps, DeviceRead, DeviceWrite, TreiberStack,
};
use crate::pnp::DriverStep;
use crate::request::{DeviceControl, Flush, Read, RequestData, RequestHandle, Write};
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

extern "win64" fn flush_handler(
    _dev: &Arc<DeviceObject>,
    _handle: &mut RequestHandle<'_, Flush>,
) -> FfiFuture<DriverStep> {
    async { DriverStep::complete(DriverStatus::Success) }.into_ffi()
}

struct TestRead;

impl DeviceRead for TestRead {
    const DEPTH: u32 = 1;

    extern "win64" fn handler<'req, 'data, 'b>(
        dev: &Arc<DeviceObject>,
        handle: &'b mut RequestHandle<'req, Read<'data>>,
        len: usize,
    ) -> FfiFuture<DriverStep> {
        read_handler(dev, handle, len)
    }
}

struct TestWrite;

impl DeviceWrite for TestWrite {
    extern "win64" fn handler<'req, 'data, 'b>(
        dev: &Arc<DeviceObject>,
        handle: &'b mut RequestHandle<'req, Write<'data>>,
        len: usize,
    ) -> FfiFuture<DriverStep> {
        write_handler(dev, handle, len)
    }
}

struct TestFlush;

impl DeviceFlush for TestFlush {
    extern "win64" fn handler<'req, 'b>(
        dev: &Arc<DeviceObject>,
        handle: &'b mut RequestHandle<'req, Flush>,
    ) -> FfiFuture<DriverStep> {
        flush_handler(dev, handle)
    }
}

struct TestDeviceControl;

impl DeviceControlHandler for TestDeviceControl {
    extern "win64" fn handler<'req, 'data, 'b>(
        dev: &Arc<DeviceObject>,
        handle: &'b mut RequestHandle<'req, DeviceControl<'data>>,
    ) -> FfiFuture<DriverStep> {
        device_control_handler(dev, handle)
    }
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
fn device_ops_registers_typed_handlers() {
    let mut ops = DeviceOps::empty();

    assert!(ops.read.as_handler().is_none());
    ops.read.register::<TestRead>();
    ops.write.register::<TestWrite>();
    ops.flush.register::<TestFlush>();
    ops.device_control.register::<TestDeviceControl>();

    assert_eq!(ops.read.as_handler().unwrap().depth, 1);
    assert_eq!(ops.write.as_handler().unwrap().depth, 0);
    assert_eq!(ops.flush.as_handler().unwrap().depth, 0);
    assert!(ops.device_control.as_handler().is_some());

    let mut buffer = [0u8; 4];
    let handle = RequestHandle::new(Read {
        offset: 0,
        len: 4,
        no_buffer: false,
        buffer: IoBuffer::<Described, FromDevice>::from_slice_mut(&mut buffer),
    });
    assert_eq!(handle.read().body.offset, 0);
    assert_eq!(handle.read().body.len, 4);

    let dc = RequestHandle::new(DeviceControl::new(0xCAFE, RequestData::empty()));
    assert_eq!(dc.read().body.code, 0xCAFE);
}
