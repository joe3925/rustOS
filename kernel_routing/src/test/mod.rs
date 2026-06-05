extern crate std;

use alloc::{sync::Arc, vec::Vec};
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use kernel_types::async_ffi::{FfiFuture, FutureExt};
use kernel_types::device::{DeviceInit, DeviceObject};
use kernel_types::dma::{Described, FromDevice, IoBuffer, ToDevice};
use kernel_types::io::{DeviceOps, DeviceRead, DeviceWrite};
use kernel_types::pnp::{
    DeviceRelationType, DriverStep, PnpMinorFunction, PnpRequest, PnpVtable, QueryIdType,
};
use kernel_types::request::{
    Dummy, Pnp, Read, Request, RequestData, RequestHandle, TraversalPolicy, Write,
};
use kernel_types::status::DriverStatus;

use crate::{
    complete_request, send_request, send_request_to_next_lower, send_request_to_next_upper,
};

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

extern "win64" fn read_handler(
    _dev: &Arc<DeviceObject>,
    handle: &mut RequestHandle<'_, Read<'_>>,
    len: usize,
) -> FfiFuture<DriverStep> {
    async move {
        let out = handle.write().body.buffer.as_inner_mut().as_mut_slice();
        if out.len() >= 2 {
            out[0] = len as u8;
            out[1] = 0xAA;
        }
        DriverStep::complete(DriverStatus::Success)
    }
    .into_ffi()
}

extern "win64" fn write_handler(
    _dev: &Arc<DeviceObject>,
    _handle: &mut RequestHandle<'_, Write<'_>>,
    _len: usize,
) -> FfiFuture<DriverStep> {
    async { DriverStep::complete(DriverStatus::Success) }.into_ffi()
}

extern "win64" fn continue_handler(
    _dev: &Arc<DeviceObject>,
    _handle: &mut RequestHandle<'_, Read<'_>>,
    _len: usize,
) -> FfiFuture<DriverStep> {
    async { DriverStep::Continue }.into_ffi()
}

struct TestRead;

impl DeviceRead for TestRead {
    extern "win64" fn handler<'req, 'data, 'b>(
        dev: &Arc<DeviceObject>,
        handle: &'b mut RequestHandle<'req, Read<'data>>,
        len: usize,
    ) -> FfiFuture<DriverStep> {
        read_handler(dev, handle, len)
    }
}

struct ContinueRead;

impl DeviceRead for ContinueRead {
    extern "win64" fn handler<'req, 'data, 'b>(
        dev: &Arc<DeviceObject>,
        handle: &'b mut RequestHandle<'req, Read<'data>>,
        len: usize,
    ) -> FfiFuture<DriverStep> {
        continue_handler(dev, handle, len)
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

extern "win64" fn not_implemented_pnp(
    _dev: &Arc<DeviceObject>,
    _handle: &mut RequestHandle<'_, Pnp<'_>>,
) -> FfiFuture<DriverStep> {
    async { DriverStep::complete(DriverStatus::NotImplemented) }.into_ffi()
}

static COMPLETION_SUM: AtomicUsize = AtomicUsize::new(0);

extern "win64" fn completion_success(_request: &mut Request<Dummy>, ctx: usize) -> DriverStatus {
    COMPLETION_SUM.fetch_add(ctx, Ordering::AcqRel);
    DriverStatus::Success
}

extern "win64" fn completion_timeout(_request: &mut Request<Dummy>, ctx: usize) -> DriverStatus {
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

    handle.write().add_completion(completion_success, 10);
    handle.write().add_completion(completion_timeout, 20);
    handle.write().add_completion(completion_success, 5);

    assert_eq!(complete_request(&mut handle), DriverStatus::Success);
    assert_eq!(handle.status(), DriverStatus::Success);
    assert_eq!(COMPLETION_SUM.load(Ordering::Acquire), before + 35);

    assert_eq!(complete_request(&mut handle), DriverStatus::Success);
    assert_eq!(COMPLETION_SUM.load(Ordering::Acquire), before + 35);
}

#[test]
fn dummy_request_completes_without_requiring_a_handler() {
    let dev = device_without_io();
    let mut handle = RequestHandle::new(Dummy);

    let status = block_on_ready(send_request(dev, &mut handle));

    assert_eq!(status, DriverStatus::Success);
    assert!(handle.read().completed);
}

#[test]
fn read_request_invokes_matching_io_handler_and_updates_buffer() {
    let mut ops = DeviceOps::empty();
    ops.read.register::<TestRead>();
    let dev = device_with_ops(ops);
    let mut out = [0u8; 2];
    let mut handle = RequestHandle::new(Read {
        offset: 5,
        len: 12,
        no_buffer: false,
        buffer: IoBuffer::<Described, FromDevice>::from_slice_mut(&mut out),
    });

    let status = block_on_ready(send_request(dev, &mut handle));

    assert_eq!(status, DriverStatus::Success);
    assert_eq!(out, [12, 0xAA]);
}

#[test]
fn unhandled_io_follows_policy_to_not_implemented_or_next_lower() {
    let upper = device_without_io();
    let input = [0u8; 4];
    let mut handle = RequestHandle::new(Write {
        offset: 0,
        len: 1,
        no_buffer: false,
        owner: 0,
        buffer: IoBuffer::<Described, ToDevice>::from_slice(&input[..1]),
    });

    assert_eq!(
        block_on_ready(send_request(upper.clone(), &mut handle)),
        DriverStatus::NotImplemented
    );

    let mut ops = DeviceOps::empty();
    ops.write.register::<TestWrite>();
    let lower = device_with_ops(ops);
    DeviceObject::set_lower_upper(&upper, lower);

    let mut handle = RequestHandle::new(Write {
        offset: 0,
        len: 4,
        no_buffer: false,
        owner: 0,
        buffer: IoBuffer::<Described, ToDevice>::from_slice(&input),
    });
    handle.set_traversal_policy(TraversalPolicy::ForwardLower);

    assert_eq!(
        block_on_ready(send_request_to_next_lower(upper, &mut handle)),
        DriverStatus::Success
    );
}

#[test]
fn next_upper_and_next_lower_report_missing_links() {
    let dev = device_without_io();
    let mut handle = RequestHandle::new(Dummy);

    assert_eq!(
        block_on_ready(send_request_to_next_lower(dev.clone(), &mut handle)),
        DriverStatus::NoSuchDevice
    );
    assert_eq!(
        block_on_ready(send_request_to_next_upper(dev, &mut handle)),
        DriverStatus::NoSuchDevice
    );
}

#[test]
fn pnp_not_implemented_lifecycle_handler_maps_to_default_success() {
    let vtable = PnpVtable::new();
    vtable.set(PnpMinorFunction::StartDevice, not_implemented_pnp);
    let dev = device_with_pnp(vtable);
    let mut handle = RequestHandle::new(Pnp {
        request: pnp_request(PnpMinorFunction::StartDevice),
    });

    let status = block_on_ready(send_request(dev, &mut handle));

    assert_eq!(status, DriverStatus::Success);
}

#[test]
fn pnp_query_without_handler_continues_to_success_at_bottom_of_stack() {
    let dev = device_with_pnp(PnpVtable::new());
    let mut handle = RequestHandle::new(Pnp {
        request: pnp_request(PnpMinorFunction::QueryId),
    });

    let status = block_on_ready(send_request(dev, &mut handle));

    assert_eq!(status, DriverStatus::Success);
}

#[test]
fn continuing_handler_can_forward_to_lower_handler() {
    let mut upper_ops = DeviceOps::empty();
    upper_ops.read.register::<ContinueRead>();
    let upper = device_with_ops(upper_ops);

    let mut lower_ops = DeviceOps::empty();
    lower_ops.read.register::<TestRead>();
    let lower = device_with_ops(lower_ops);
    DeviceObject::set_lower_upper(&upper, lower);

    let mut out = [0u8; 2];
    let mut handle = RequestHandle::new(Read {
        offset: 0,
        len: 3,
        no_buffer: false,
        buffer: IoBuffer::<Described, FromDevice>::from_slice_mut(&mut out),
    });
    handle.set_traversal_policy(TraversalPolicy::ForwardLower);

    let status = block_on_ready(send_request(upper, &mut handle));

    assert_eq!(status, DriverStatus::Success);
    assert_eq!(out, [3, 0xAA]);
}
