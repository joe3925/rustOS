use alloc::sync::Arc;

use crate::async_ffi::{FfiFuture, FutureExt};
use crate::device::DeviceObject;
use crate::dma::{IoBufferBacking, IoBufferBackingConfig, IoBufferBackingDesc};
use crate::error::{DriverErrorKind, KernelError};
use crate::io::{
    DeviceControlHandler, DeviceControlOp, DeviceFlush, DeviceFlushOp, DeviceOps, DeviceRead,
    DeviceReadOp, DeviceWrite, DeviceWriteOp, TreiberStack,
};
use crate::pnp::DriverStep;
use crate::request::{DeviceControl, Flush, IoctlData, Read, Write};

extern "C" fn read_handler(
    _dev: &Arc<DeviceObject>,
    _request: &mut Read<'_>,
    len: usize,
) -> FfiFuture<Result<DriverStep, KernelError>> {
    async move {
        if len == 4 {
            Ok(DriverStep::Complete)
        } else {
            Err(KernelError::from_parts(
                DriverErrorKind::InvalidParameter.into(),
                None,
                None,
            ))
        }
    }
    .into_ffi()
}

extern "C" fn write_handler(
    _dev: &Arc<DeviceObject>,
    _request: &mut Write<'_>,
    _len: usize,
) -> FfiFuture<Result<DriverStep, KernelError>> {
    async { Ok(DriverStep::Continue) }.into_ffi()
}

extern "C" fn device_control_handler(
    _dev: &Arc<DeviceObject>,
    _request: &mut DeviceControl<'_>,
) -> FfiFuture<Result<DriverStep, KernelError>> {
    async { Ok(DriverStep::Complete) }.into_ffi()
}

extern "C" fn flush_handler(
    _dev: &Arc<DeviceObject>,
    _request: &mut Flush,
) -> FfiFuture<Result<DriverStep, KernelError>> {
    async { Ok(DriverStep::Complete) }.into_ffi()
}

struct TestRead;

impl DeviceRead for TestRead {
    const DEPTH: u32 = 1;

    extern "C" fn handler<'a, 'data>(
        dev: &'a Arc<DeviceObject>,
        request: &'a mut Read<'data>,
    ) -> FfiFuture<Result<DriverStep, KernelError>> {
        let len = request.len;
        read_handler(dev, request, len)
    }
}

struct TestWrite;

impl DeviceWrite for TestWrite {
    extern "C" fn handler<'a, 'data>(
        dev: &'a Arc<DeviceObject>,
        request: &'a mut Write<'data>,
    ) -> FfiFuture<Result<DriverStep, KernelError>> {
        let len = request.len;
        write_handler(dev, request, len)
    }
}

struct TestFlush;

impl DeviceFlush for TestFlush {
    extern "C" fn handler<'a>(
        dev: &'a Arc<DeviceObject>,
        request: &'a mut Flush,
    ) -> FfiFuture<Result<DriverStep, KernelError>> {
        flush_handler(dev, request)
    }
}

struct TestDeviceControl;

impl DeviceControlHandler for TestDeviceControl {
    extern "C" fn handler<'a, 'data>(
        dev: &'a Arc<DeviceObject>,
        request: &'a mut DeviceControl<'data>,
    ) -> FfiFuture<Result<DriverStep, KernelError>> {
        device_control_handler(dev, request)
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
    ops.register::<DeviceReadOp, TestRead>();
    ops.register::<DeviceWriteOp, TestWrite>();
    ops.register::<DeviceFlushOp, TestFlush>();
    ops.register::<DeviceControlOp, TestDeviceControl>();

    assert_eq!(ops.read.as_handler().unwrap().depth, 1);
    assert_eq!(ops.write.as_handler().unwrap().depth, 0);
    assert_eq!(ops.flush.as_handler().unwrap().depth, 0);
    assert!(ops.device_control.as_handler().is_some());

    let mut buffer = [0u8; 4];
    let backing = IoBufferBacking::new(
        IoBufferBackingDesc::SliceMut(&mut buffer),
        IoBufferBackingConfig::default(),
    )
    .unwrap();
    let io_buffer = backing.create_from_device(0, 4).unwrap();
    let request = Read::new(0, 4, false, Some(io_buffer));
    assert_eq!(request.offset, 0);
    assert_eq!(request.len, 4);

    let dc = DeviceControl::new(0xCAFE, IoctlData::empty());
    assert_eq!(dc.code, 0xCAFE);
}
