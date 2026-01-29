use alloc::sync::Arc;
use alloc::task::Wake;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll, Waker};
use spin::Mutex;

use kernel_types::async_ffi::FfiFuture;

use crate::global_async::GlobalAsyncExecutor;

pub struct FfiTask {
    future: Mutex<Option<FfiFuture<()>>>,
    queued: AtomicBool,
    completed: AtomicBool,
}

impl FfiTask {
    pub fn new(fut: FfiFuture<()>) -> Self {
        Self {
            future: Mutex::new(Some(fut)),
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

        let ctx = Arc::into_raw(self.clone()) as usize;
        GlobalAsyncExecutor::global().submit(poll_trampoline, ctx);
    }

    fn poll_once(self: &Arc<Self>) {
        self.queued.store(false, Ordering::Release);

        if self.completed.load(Ordering::Acquire) {
            return;
        }

        let waker = task_waker(self.clone());
        let mut cx = Context::from_waker(&waker);

        let mut done = false;

        {
            let mut g = self.future.lock();
            let Some(fut) = g.as_mut() else {
                self.completed.store(true, Ordering::Release);
                return;
            };

            let poll_res = Pin::new(fut).poll(&mut cx);
            if let Poll::Ready(()) = poll_res {
                *g = None;
                done = true;
            }
        }

        if done {
            self.completed.store(true, Ordering::Release);
        }
    }
}

#[inline(never)]
pub extern "win64" fn poll_trampoline(ctx: usize) {
    let task = unsafe { Arc::from_raw(ctx as *const FfiTask) };
    task.poll_once();
}

struct TaskWake {
    task: Arc<FfiTask>,
}

impl Wake for TaskWake {
    fn wake(self: Arc<Self>) {
        self.task.enqueue();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.task.enqueue();
    }
}

fn task_waker(task: Arc<FfiTask>) -> Waker {
    Waker::from(Arc::new(TaskWake { task }))
}

#[no_mangle]
pub extern "win64" fn kernel_spawn_ffi_internal(fut: FfiFuture<()>) {
    let task = Arc::new(FfiTask::new(fut));
    task.enqueue();
}
