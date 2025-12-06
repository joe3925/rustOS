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
    let raw = ctx as *const FutureTask;
    let task: Arc<FutureTask> = unsafe { Arc::from_raw(raw) };
    let waker = TaskWaker::create_waker(task.clone());
    let mut context = Context::from_waker(&waker);

    let mut future_guard = task.future.lock();
    match future_guard.as_mut().poll(&mut context) {
        Poll::Ready(()) => {}
        Poll::Pending => {}
    }
}
