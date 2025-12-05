use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::task::Wake;
use core::future::Future;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll, Waker};

use crate::task_yield;

#[repr(C)]
struct ThreadNotify {
    ready: AtomicBool,
}

impl ThreadNotify {
    fn new() -> Self {
        Self {
            ready: AtomicBool::new(false),
        }
    }
}

// We implement the standard Wake trait to easily create a Waker from an Arc.
impl Wake for ThreadNotify {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        // Signal that the future is ready to proceed.

        self.ready.store(true, Ordering::Release);
    }
}

/// Runs a future to completion on the current thread.
///
/// This function will block the caller until the given future has resolved.
/// It yields the CPU (via `hlt`) while waiting for interrupts/signals.
///
pub fn block_on<F: Future>(future: F) -> F::Output {
    let mut pinned_future = Box::pin(future);

    let notify = Arc::new(ThreadNotify::new());
    let waker = Waker::from(notify.clone());

    let mut cx = Context::from_waker(&waker);

    loop {
        match pinned_future.as_mut().poll(&mut cx) {
            Poll::Ready(output) => {
                return output;
            }
            Poll::Pending => {
                while !notify.ready.swap(false, Ordering::Acquire) {
                    //unsafe { task_yield() };
                }
            }
        }
    }
}
