use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use crate::async_ffi::{FfiPoll, FutureExt};

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

fn poll_once<F: Future + Unpin>(future: &mut F) -> Poll<F::Output> {
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    Pin::new(future).poll(&mut cx)
}

#[test]
fn ffi_poll_round_trips_core_poll_values() {
    let pending = FfiPoll::<u32>::from(Poll::Pending);
    assert!(pending.is_pending());
    assert!(!pending.is_ready());
    assert!(matches!(unsafe { pending.into_poll() }, Poll::Pending));

    let ready = FfiPoll::from(Poll::Ready(123u32));
    assert!(ready.is_ready());
    assert!(matches!(unsafe { ready.into_poll() }, Poll::Ready(123)));
}

#[test]
fn owned_ffi_future_polls_ready_future_and_consumes_result() {
    let mut future = async { 77u32 }.into_ffi();
    assert!(!future.is_null());

    match poll_once(&mut future) {
        Poll::Ready(value) => assert_eq!(value, 77),
        Poll::Pending => panic!("ready async block returned pending"),
    }
}

#[test]
fn owned_ffi_future_with_null_waker_reports_pending() {
    let mut future = async { 1u32 }.into_ffi();
    let poll = unsafe { future.poll(core::ptr::null()) };
    assert!(poll.is_pending());
}
