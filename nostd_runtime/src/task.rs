use alloc::boxed::Box;
use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use spin::Mutex;

use crate::waker::TaskWaker;

pub struct Task {
    future: Mutex<Pin<Box<dyn Future<Output = ()> + Send + 'static>>>,
}

impl Task {
    pub fn new(future: impl Future<Output = ()> + Send + 'static) -> Self {
        Self {
            future: Mutex::new(Box::pin(future)),
        }
    }

    pub extern "win64" fn poll_trampoline(ctx: usize) {
        let task = unsafe { Arc::from_raw(ctx as *const Task) };

        let waker = TaskWaker::create_waker(task.clone());
        let mut context = Context::from_waker(&waker);

        let mut future_guard = task.future.lock();
        match future_guard.as_mut().poll(&mut context) {
            Poll::Ready(()) => {
                // The Future is complete.
                // We do nothing.
                // - `task` (the Arc we reconstructed) drops here.
                // - `waker` drops here.
                // If this was the last reference, the memory is freed.
            }
            Poll::Pending => {
                // The Future is waiting for something (e.g., IO, Timer).
                // - `task` drops here (decrementing the count we claimed from the scheduler).
                //
                // CRITICAL: The Future only returns Pending if it has stored a clone
                // of our `waker` somewhere (e.g. in the IO Driver).
                // That stored `waker` holds a reference to `Task`, keeping it alive.
            }
        }
    }
}
