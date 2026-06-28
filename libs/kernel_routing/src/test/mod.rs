extern crate std;

use alloc::{sync::Arc, vec::Vec};
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use kernel_types::arch::{PhysAddr, VirtAddr};
use kernel_types::async_ffi::{FfiFuture, FutureExt};
use kernel_types::device::{DeviceInit, DeviceObject};
use kernel_types::dma::{IoBufferBacking, IoBufferBackingConfig, IoBufferBackingDesc};
use kernel_types::io::{DeviceOps, DeviceRead};
use kernel_types::pnp::{DriverStep, PnpOps, QueryId, QueryIdType, StartDevice};
use kernel_types::request::Read;
use kernel_types::status::DriverStatus;

use crate::{io, pnp};

#[unsafe(export_name = "resolve_virtual_range_frame")]
extern "C" fn hosted_resolve_virtual_range_frame(addr: VirtAddr) -> Option<(u64, PhysAddr)> {
    Some((4096, PhysAddr::new(addr.as_u64())))
}

fn noop_waker() -> Waker {
    unsafe fn clone(_: *const ()) -> RawWaker {
        RawWaker::new(core::ptr::null(), &VTABLE)
    }
    unsafe fn wake(_: *const ()) {}
    unsafe fn wake_by_ref(_: *const ()) {}
    unsafe fn drop(_: *const ()) {}
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop);
    unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) }
}

fn block_on_ready<F: Future>(mut future: F) -> F::Output {
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    match unsafe { Pin::new_unchecked(&mut future) }.poll(&mut cx) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("test future unexpectedly returned Pending"),
    }
}

fn device_with_ops(ops: DeviceOps) -> Arc<DeviceObject> {
    let mut init = DeviceInit::new();
    init.ops = ops;
    DeviceObject::new(init)
}

extern "C" fn read_handler<'a, 'io>(
    _dev: &'a Arc<DeviceObject>,
    request: &'a mut Read<'io>,
) -> FfiFuture<DriverStep> {
    async move {
        if let Some(buffer) = request.buffer.as_mut() {
            let out = buffer.try_as_mut_slice().unwrap();
            out[0] = request.len as u8;
        }
        DriverStep::complete(DriverStatus::Success)
    }
    .into_ffi()
}

extern "C" fn continue_handler<'a, 'io>(
    _dev: &'a Arc<DeviceObject>,
    _request: &'a mut Read<'io>,
) -> FfiFuture<DriverStep> {
    async { DriverStep::Continue }.into_ffi()
}

struct TestRead;
impl DeviceRead for TestRead {
    extern "C" fn handler<'a, 'io>(
        dev: &'a Arc<DeviceObject>,
        request: &'a mut Read<'io>,
    ) -> FfiFuture<DriverStep> {
        read_handler(dev, request)
    }
}

struct ContinueRead;
impl DeviceRead for ContinueRead {
    extern "C" fn handler<'a, 'io>(
        dev: &'a Arc<DeviceObject>,
        request: &'a mut Read<'io>,
    ) -> FfiFuture<DriverStep> {
        continue_handler(dev, request)
    }
}

#[test]
fn typed_read_updates_buffer() {
    let mut ops = DeviceOps::empty();
    ops.read.register::<TestRead>();
    let device = device_with_ops(ops);
    let mut out = [0u8; 1];
    let status = {
        let backing = IoBufferBacking::new(
            IoBufferBackingDesc::SliceMut(&mut out),
            IoBufferBackingConfig::worst_case_for_len(1),
        )
        .unwrap();
        let buffer = backing.create_from_device(0, 1).unwrap();
        let mut request = Read::new(0, 7, false, Some(buffer));
        block_on_ready(io::send_to_device(device, &mut request))
    };
    assert_eq!(status, DriverStatus::Success);
    assert_eq!(out, [7]);
}

#[test]
fn continue_traverses_to_lower_device() {
    let mut upper_ops = DeviceOps::empty();
    upper_ops.read.register::<ContinueRead>();
    let upper = device_with_ops(upper_ops);
    let mut lower_ops = DeviceOps::empty();
    lower_ops.read.register::<TestRead>();
    let lower = device_with_ops(lower_ops);
    DeviceObject::set_lower_upper(&upper, lower);

    let mut out = [0u8; 1];
    let status = {
        let backing = IoBufferBacking::new(
            IoBufferBackingDesc::SliceMut(&mut out),
            IoBufferBackingConfig::worst_case_for_len(1),
        )
        .unwrap();
        let buffer = backing.create_from_device(0, 1).unwrap();
        let mut request = Read::new(0, 3, false, Some(buffer));
        block_on_ready(io::send_down_stack(upper, &mut request))
    };
    assert_eq!(status, DriverStatus::Success);
    assert_eq!(out, [3]);
}

#[test]
fn typed_pnp_uses_operation_default_when_unhandled() {
    let device = DeviceObject::new(DeviceInit::with_pnp(Some(PnpOps::new())));
    let mut query = QueryId {
        id_type: QueryIdType::DeviceId,
        ids: Vec::new(),
    };
    assert_eq!(
        block_on_ready(pnp::send_down_stack(device.clone(), &mut query)),
        DriverStatus::NotImplemented
    );

    let mut start = StartDevice {
        resources: Vec::new(),
    };
    assert_eq!(
        block_on_ready(pnp::send_down_stack(device, &mut start)),
        DriverStatus::Success
    );
}
