extern crate std;

use alloc::{sync::Arc, vec::Vec};
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use kernel_types::async_ffi::{FfiFuture, FutureExt};
use kernel_types::device::{DeviceInit, DeviceObject};
use kernel_types::dma::{IoBufferBacking, IoBufferBackingConfig, IoBufferBackingDesc};
use kernel_types::io::{DeviceOps, DeviceRead, DeviceWrite};
use kernel_types::pnp::{
    DeviceRelationType, DriverStep, PnpMinorFunction, PnpRequest, PnpVtable, QueryIdType,
};
use kernel_types::request::{Dummy, Pnp, Read, Request, RequestData, RequestHandle, Write};
use kernel_types::status::DriverStatus;

use crate::{complete_request, io, pnp};

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

fn device_without_io() -> Arc<DeviceObject> {
    DeviceObject::new(DeviceInit::new())
}

fn device_with_pnp(vtable: PnpVtable) -> Arc<DeviceObject> {
    DeviceObject::new(DeviceInit::with_pnp(Some(vtable)))
}

extern "C" fn read_handler(
    _dev: &Arc<DeviceObject>,
    handle: &mut RequestHandle<'_, Read<'_>>,
) -> FfiFuture<DriverStep> {
    async move {
        let len = handle.read().body.len;
        if let Some(buffer) = handle.get_mut().body.buffer.as_mut() {
            let out = buffer.try_as_mut_slice().unwrap();
            if out.len() >= 2 {
                out[0] = len as u8;
                out[1] = 0xAA;
            }
        }
        DriverStep::complete(DriverStatus::Success)
    }
    .into_ffi()
}

extern "C" fn write_handler(
    _dev: &Arc<DeviceObject>,
    _handle: &mut RequestHandle<'_, Write<'_>>,
) -> FfiFuture<DriverStep> {
    async { DriverStep::complete(DriverStatus::Success) }.into_ffi()
}

extern "C" fn continue_handler(
    _dev: &Arc<DeviceObject>,
    _handle: &mut RequestHandle<'_, Read<'_>>,
) -> FfiFuture<DriverStep> {
    async { DriverStep::Continue }.into_ffi()
}

struct TestRead;

impl DeviceRead for TestRead {
    extern "C" fn handler<'req, 'data, 'b>(
        dev: &Arc<DeviceObject>,
        handle: &'b mut RequestHandle<'req, Read<'data>>,
    ) -> FfiFuture<DriverStep> {
        read_handler(dev, handle)
    }
}

struct ContinueRead;

impl DeviceRead for ContinueRead {
    extern "C" fn handler<'req, 'data, 'b>(
        dev: &Arc<DeviceObject>,
        handle: &'b mut RequestHandle<'req, Read<'data>>,
    ) -> FfiFuture<DriverStep> {
        continue_handler(dev, handle)
    }
}

struct TestWrite;

impl DeviceWrite for TestWrite {
    extern "C" fn handler<'req, 'data, 'b>(
        dev: &Arc<DeviceObject>,
        handle: &'b mut RequestHandle<'req, Write<'data>>,
    ) -> FfiFuture<DriverStep> {
        write_handler(dev, handle)
    }
}

static COMPLETION_SUM: AtomicUsize = AtomicUsize::new(0);

extern "C" fn completion_success(_request: &mut Request<Dummy>, ctx: usize) -> DriverStatus {
    COMPLETION_SUM.fetch_add(ctx, Ordering::AcqRel);
    DriverStatus::Success
}

extern "C" fn completion_timeout(_request: &mut Request<Dummy>, ctx: usize) -> DriverStatus {
    COMPLETION_SUM.fetch_add(ctx, Ordering::AcqRel);
    DriverStatus::Timeout
}

fn pnp_request(minor_function: PnpMinorFunction) -> PnpRequest<'static> {
    PnpRequest {
        minor_function,
        relation: DeviceRelationType::BusRelations,
        id_type: QueryIdType::DeviceId,
        ids_out: Vec::new(),
        data_out: RequestData::empty(),
    }
}

#[test]
fn complete_request_runs_chained_completions_once() {
    let before = COMPLETION_SUM.load(Ordering::Acquire);
    let mut handle = RequestHandle::new(Dummy);

    handle.get_mut().add_completion(completion_success, 10);
    handle.get_mut().add_completion(completion_timeout, 20);
    handle.get_mut().add_completion(completion_success, 5);

    assert_eq!(complete_request(&mut handle), DriverStatus::Success);
    assert_eq!(handle.status(), DriverStatus::Success);
    assert_eq!(COMPLETION_SUM.load(Ordering::Acquire), before + 35);

    assert_eq!(complete_request(&mut handle), DriverStatus::Success);
    assert_eq!(COMPLETION_SUM.load(Ordering::Acquire), before + 35);
}

#[test]
fn read_request_invokes_matching_io_handler_and_updates_buffer() {
    let mut ops = DeviceOps::empty();
    ops.read.register::<TestRead>();
    let dev = device_with_ops(ops);
    let mut out = [0u8; 2];
    let status = {
        let out_len = out.len();
        let backing = IoBufferBacking::new(
            IoBufferBackingDesc::SliceMut(&mut out),
            IoBufferBackingConfig::worst_case_for_len(out_len),
        )
        .unwrap();
        let buffer = backing.create_from_device(0, out_len).unwrap();
        let mut handle = RequestHandle::new(Read::new(5, 12, false, Some(buffer)));

        block_on_ready(io::send_to_device(dev, &mut handle))
    };

    assert_eq!(status, DriverStatus::Success);
    assert_eq!(out, [12, 0xAA]);
}

#[test]
fn unhandled_io_is_not_implemented_or_explicitly_forwarded_lower() {
    let upper = device_without_io();
    let input = [0u8; 4];
    let backing = IoBufferBacking::new(
        IoBufferBackingDesc::Slice(&input[..1]),
        IoBufferBackingConfig::worst_case_for_len(1),
    )
    .unwrap();
    let buffer = backing.create_to_device(0, 1).unwrap();
    let mut handle = RequestHandle::new(Write::new(0, 1, false, 0, Some(buffer)));

    assert_eq!(
        block_on_ready(io::send_to_device(upper.clone(), &mut handle)),
        DriverStatus::NotImplemented
    );

    let mut ops = DeviceOps::empty();
    ops.write.register::<TestWrite>();
    let lower = device_with_ops(ops);
    DeviceObject::set_lower_upper(&upper, lower);

    let backing = IoBufferBacking::new(
        IoBufferBackingDesc::Slice(&input),
        IoBufferBackingConfig::worst_case_for_len(input.len()),
    )
    .unwrap();
    let buffer = backing.create_to_device(0, input.len()).unwrap();
    let mut handle = RequestHandle::new(Write::new(0, 4, false, 0, Some(buffer)));
    assert_eq!(
        block_on_ready(io::send_next_lower(upper, &mut handle)),
        DriverStatus::Success
    );
}

#[test]
fn next_lower_reports_missing_link() {
    let dev = device_without_io();
    let input = [0u8; 1];
    let backing = IoBufferBacking::new(
        IoBufferBackingDesc::Slice(&input),
        IoBufferBackingConfig::worst_case_for_len(input.len()),
    )
    .unwrap();
    let buffer = backing.create_to_device(0, input.len()).unwrap();
    let mut handle = RequestHandle::new(Write::new(0, 1, false, 0, Some(buffer)));

    assert_eq!(
        block_on_ready(io::send_next_lower(dev, &mut handle)),
        DriverStatus::NoSuchDevice
    );
}

#[test]
fn pnp_query_without_handler_continues_to_success_at_bottom_of_stack() {
    let dev = device_with_pnp(PnpVtable::new());
    let mut handle = RequestHandle::new(Pnp {
        request: pnp_request(PnpMinorFunction::QueryId),
    });

    let status = block_on_ready(pnp::send_down_stack(dev, &mut handle));

    assert_eq!(status, DriverStatus::Success);
}

#[test]
fn io_continue_completes_not_implemented_without_forwarding() {
    let mut upper_ops = DeviceOps::empty();
    upper_ops.read.register::<ContinueRead>();
    let upper = device_with_ops(upper_ops);

    let mut lower_ops = DeviceOps::empty();
    lower_ops.read.register::<TestRead>();
    let lower = device_with_ops(lower_ops);
    DeviceObject::set_lower_upper(&upper, lower);

    let mut out = [0u8; 2];
    let status = {
        let out_len = out.len();
        let backing = IoBufferBacking::new(
            IoBufferBackingDesc::SliceMut(&mut out),
            IoBufferBackingConfig::worst_case_for_len(out_len),
        )
        .unwrap();
        let buffer = backing.create_from_device(0, out_len).unwrap();
        let mut handle = RequestHandle::new(Read::new(0, 3, false, Some(buffer)));
        block_on_ready(io::send_down_stack(upper, &mut handle))
    };

    assert_eq!(status, DriverStatus::NotImplemented);
    assert_eq!(out, [0, 0]);
}
