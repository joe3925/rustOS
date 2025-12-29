use alloc::boxed::Box;
use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll};

use spin::Mutex;

use crate::scheduling::runtime::runtime::submit_global;
use crate::scheduling::runtime::waker;

pub struct FutureTask {
    future: Mutex<Option<Pin<Box<dyn Future<Output = ()> + Send + 'static>>>>,
    queued: AtomicBool,
    completed: AtomicBool,
}

impl FutureTask {
    pub fn new(future: impl Future<Output = ()> + Send + 'static) -> Self {
        Self {
            future: Mutex::new(Some(Box::pin(future))),
            queued: AtomicBool::new(false),
            completed: AtomicBool::new(false),
        }
    }

    pub fn enqueue(self: &Arc<Self>) {
        if self.completed.load(Ordering::Acquire) {
            return;
        }

        if self.queued.swap(true, Ordering::AcqRel) {
            return;
        }

        let ptr = Arc::into_raw(self.clone()) as usize;
        submit_global(poll_trampoline, ptr);
    }

    fn poll_once(self: &Arc<Self>) {
        self.queued.store(false, Ordering::Release);

        if self.completed.load(Ordering::Acquire) {
            return;
        }

        let w = waker::create(self.clone());
        let mut cx = Context::from_waker(&w);

        let poll_res = {
            let mut guard = self.future.lock();
            let Some(fut) = guard.as_mut() else {
                self.completed.store(true, Ordering::Release);
                return;
            };
            fut.as_mut().poll(&mut cx)
        };

        if let Poll::Ready(()) = poll_res {
            let mut guard = self.future.lock();
            *guard = None;
            self.completed.store(true, Ordering::Release);
        }
    }
}

#[inline(never)]
pub extern "win64" fn poll_trampoline(ctx: usize) {
    let task = unsafe { Arc::from_raw(ctx as *const FutureTask) };
    task.poll_once();
}
