use alloc::boxed::Box;
use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use spin::Mutex;

use crate::waker::TaskWaker;
#[repr(C)]
pub struct FutureTask {
    future: Mutex<Pin<Box<dyn Future<Output = ()> + Send + 'static>>>,
}

impl FutureTask {
    pub fn new(future: impl Future<Output = ()> + Send + 'static) -> Self {
        Self {
            future: Mutex::new(Box::pin(future)),
        }
    }
}
#[no_mangle]
#[inline(never)]
pub extern "C" fn poll_trampoline(ctx: usize) {
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
        Poll::Ready(()) => {
            // Task finished. At this point:
            // - `task` is dropped at function end (decrement refcount)
            // - Wakers you'll drop will decrement their refs.
            // When no wakers remain, the final `Arc` will be dropped and free the Task.
        }
        Poll::Pending => {
            // Do nothing. Ownership is now *only* via wakers and the `ctx` raw pointer.
        }
    }
}
