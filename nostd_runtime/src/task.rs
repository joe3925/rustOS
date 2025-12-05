use alloc::boxed::Box;
use alloc::sync::Arc;
use core::any::TypeId;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use spin::Mutex;

use crate::waker::TaskWaker;
#[repr(C)]
pub struct FutureTask {
    future: Mutex<Pin<Box<dyn Future<Output = ()> + Send + 'static>>>,
}
// TODO: get rid of this alloc should be possible as the future task is only seen by the ffi side that called spawn
impl FutureTask {
    pub fn new(future: impl Future<Output = ()> + Send + 'static) -> Self {
        Self {
            future: Mutex::new(Box::pin(future)),
        }
    }
}
#[inline(never)]
pub extern "win64" fn poll_trampoline<T: 'static>(ctx: usize) {
    unsafe {
        let id = TypeId::of::<T>();
        core::ptr::read_volatile(&id as *const _ as *const u8);
    }
    if ctx < 0x1000 {
        panic!("ctx passed is null ptr");
    }
    let task: Arc<FutureTask> = unsafe {
        let raw = ctx as *const FutureTask;

        // Borrow the Arc behind `ctx` without consuming that owner.
        let tmp = Arc::from_raw(raw);
        let cloned = tmp.clone();
        core::mem::forget(tmp);

        cloned
    };
    let waker = TaskWaker::create_waker(task.clone());
    let mut context = Context::from_waker(&waker);

    let mut future_guard = task.future.lock();
    match future_guard.as_mut().poll(&mut context) {
        Poll::Ready(()) => {}
        Poll::Pending => {}
    }
}
