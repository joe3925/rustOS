use alloc::sync::Arc;
use alloc::task::Wake;
use core::future::Future;
use core::mem;
use core::pin::Pin;
use core::sync::atomic::{AtomicU8, Ordering};
use core::task::{Context, Poll, Waker};
use spin::Mutex;

use kernel_types::async_ffi::FfiFuture;

use crate::global_async::GlobalAsyncExecutor;

/// Task states for the FfiTask state machine.
/// IDLE: not queued, not running. A wake transitions to QUEUED.
/// QUEUED: submitted to executor, waiting to run. Wakes are absorbed.
/// POLLING: currently being polled. A wake transitions to NOTIFIED.
/// NOTIFIED: a wake arrived during poll. poll_once will re-enqueue.
const STATE_IDLE: u8 = 0;
const STATE_QUEUED: u8 = 1;
const STATE_POLLING: u8 = 2;
const STATE_NOTIFIED: u8 = 3;
const STATE_COMPLETED: u8 = 4;

pub struct FfiTask {
    future: Mutex<Option<FfiFuture<()>>>,
    state: AtomicU8,
}

impl FfiTask {
    pub fn new(fut: FfiFuture<()>) -> Self {
        Self {
            future: Mutex::new(Some(fut)),
            state: AtomicU8::new(STATE_IDLE),
        }
    }

    pub fn enqueue(self: &Arc<Self>) {
        loop {
            let s = self.state.load(Ordering::Acquire);
            match s {
                STATE_COMPLETED | STATE_QUEUED | STATE_NOTIFIED => return,
                STATE_POLLING => {
                    // Currently being polled — upgrade to NOTIFIED so
                    // poll_once knows to re-enqueue when it finishes.
                    if self
                        .state
                        .compare_exchange_weak(
                            STATE_POLLING,
                            STATE_NOTIFIED,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        return;
                    }
                    // CAS failed — state changed, retry.
                    continue;
                }
                STATE_IDLE => {
                    if self
                        .state
                        .compare_exchange_weak(
                            STATE_IDLE,
                            STATE_QUEUED,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        let ctx = Arc::into_raw(self.clone()) as usize;
                        GlobalAsyncExecutor::global().submit(poll_trampoline, ctx);
                        return;
                    }
                    continue;
                }
                _ => return,
            }
        }
    }

    fn poll_once(self: &Arc<Self>) {
        // Transition QUEUED -> POLLING
        if self
            .state
            .compare_exchange(STATE_QUEUED, STATE_POLLING, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }

        let waker = task_waker(self.clone());
        let mut cx = Context::from_waker(&waker);

        let mut done = false;

        {
            let mut g = self.future.lock();
            let Some(fut) = g.as_mut() else {
                self.state.store(STATE_COMPLETED, Ordering::Release);
                return;
            };

            let poll_res = Pin::new(fut).poll(&mut cx);
            if let Poll::Ready(()) = poll_res {
                *g = None;
                done = true;
            }
        }

        if done {
            self.state.store(STATE_COMPLETED, Ordering::Release);
            return;
        }

        // Try POLLING -> IDLE. If a wake arrived during poll, state
        // is NOTIFIED and we must re-enqueue instead of going idle.
        match self.state.compare_exchange(
            STATE_POLLING,
            STATE_IDLE,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                // Successfully went idle. If a wake arrives now,
                // enqueue() will transition IDLE -> QUEUED and submit.
            }
            Err(STATE_NOTIFIED) => {
                // A wake arrived during poll — re-enqueue.
                self.state.store(STATE_QUEUED, Ordering::Release);
                let ctx = Arc::into_raw(self.clone()) as usize;
                GlobalAsyncExecutor::global().submit(poll_trampoline, ctx);
            }
            Err(_) => {}
        }
    }
}

#[inline(never)]
pub extern "win64" fn poll_trampoline(ctx: usize) {
    let task = unsafe { Arc::from_raw(ctx as *const FfiTask) };
    task.poll_once();
    // If the future is still pending we must keep the Arc alive; otherwise the
    // executor would drop the last ref and free a still-running task.
    if task.state.load(Ordering::Acquire) != STATE_COMPLETED {
        mem::forget(task);
    }
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
