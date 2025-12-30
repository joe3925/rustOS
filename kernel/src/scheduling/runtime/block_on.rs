use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::task::Wake;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll, Waker};

use crate::scheduling::runtime::runtime::{try_steal_blocking_one, yield_now};

pub struct ThreadNotify {
    ready: AtomicBool,
}

impl ThreadNotify {
    pub fn new() -> Self {
        Self {
            ready: AtomicBool::new(false),
        }
    }

    pub fn take_ready(&self) -> bool {
        self.ready.swap(false, Ordering::AcqRel)
    }
}

impl Wake for ThreadNotify {
    fn wake(self: Arc<Self>) {
        self.ready.store(true, Ordering::Release);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.ready.store(true, Ordering::Release);
    }
}

pub fn block_on<F: Future>(future: F) -> F::Output {
    let mut pinned = Box::pin(future);
    let notify = Arc::new(ThreadNotify::new());
    let waker = Waker::from(notify.clone());
    let mut cx = Context::from_waker(&waker);

    loop {
        match Pin::new(&mut pinned).as_mut().poll(&mut cx) {
            Poll::Ready(out) => return out,
            Poll::Pending => {
                if !notify.take_ready() {
                    if !try_steal_blocking_one() {}
                    //yield_now();
                }
            }
        }
    }
}
