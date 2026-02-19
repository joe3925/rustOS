extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::task::Wake;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll, Waker};
use spin::Mutex;

use kernel_sys::{
    kernel_spawn_blocking_raw, kernel_spawn_detached_ffi, kernel_spawn_ffi,
    try_steal_blocking_one as sys_try_steal_blocking_one,
};
use kernel_types::async_ffi::{FfiWaker, FfiWakerVTable, FutureExt};

/// Spawn an async task on the kernel executor (shared singleton in the kernel).
pub fn spawn<F>(future: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    unsafe { kernel_spawn_ffi(future.into_ffi()) };
}

/// Spawn a detached async task (fire-and-forget).
pub fn spawn_detached<F>(future: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    unsafe { kernel_spawn_detached_ffi(future.into_ffi()) };
}

/// Block the current thread until the future completes 
pub fn block_on<F: Future>(future: F) -> F::Output {
    let mut ffi_fut = future.into_ffi();
    let ready = AtomicBool::new(false);

    let vtable: &'static FfiWakerVTable = &BLOCK_ON_WAKER_VTABLE;
    let ffi_waker = FfiWaker {
        data: &ready as *const AtomicBool as *const (),
        vtable,
    };

    loop {
        let poll = unsafe { ffi_fut.poll(&ffi_waker as *const FfiWaker) };
        if poll.is_ready() {
            // SAFETY: we just checked is_ready
            match unsafe { poll.into_poll() } {
                Poll::Ready(v) => return v,
                Poll::Pending => unreachable!(),
            }
        }
        if !ready.swap(false, Ordering::AcqRel) {
            let _ = unsafe { sys_try_steal_blocking_one() };
        }
    }
}

/// Static vtable for the block_on FfiWaker. The data pointer is a raw pointer
/// to a stack-local AtomicBool, so clone just copies the pointer (no refcount needed
/// since the bool outlives all waker copies within block_on).
static BLOCK_ON_WAKER_VTABLE: FfiWakerVTable = FfiWakerVTable {
    clone: block_on_waker_clone,
    wake: block_on_waker_wake,
    wake_by_ref: block_on_waker_wake_by_ref,
    drop: block_on_waker_drop,
};

unsafe extern "win64" fn block_on_waker_clone(data: *const ()) -> FfiWaker {
    FfiWaker {
        data,
        vtable: &BLOCK_ON_WAKER_VTABLE,
    }
}

unsafe extern "win64" fn block_on_waker_wake(data: *const ()) {
    unsafe {
        let ready = &*(data as *const AtomicBool);
        ready.store(true, Ordering::Release);
    }
}

unsafe extern "win64" fn block_on_waker_wake_by_ref(data: *const ()) {
    unsafe {
        let ready = &*(data as *const AtomicBool);
        ready.store(true, Ordering::Release);
    }
}

unsafe extern "win64" fn block_on_waker_drop(_data: *const ()) {
    // No-op: the AtomicBool lives on the block_on stack frame.
}

/// Minimal blocking join handle executed on the kernel blocking pool.
pub struct BlockingJoin<R> {
    state: Arc<BlockingState<R>>,
}

struct BlockingState<R> {
    result: Mutex<Option<R>>,
    ready: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

impl<R> BlockingState<R> {
    fn new() -> Self {
        Self {
            result: Mutex::new(None),
            ready: AtomicBool::new(false),
            waker: Mutex::new(None),
        }
    }

    fn store(&self, value: R) {
        *self.result.lock() = Some(value);
        self.ready.store(true, Ordering::Release);
        if let Some(w) = self.waker.lock().take() {
            w.wake();
        }
    }
}

impl<R> Future for BlockingJoin<R> {
    type Output = R;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<R> {
        if self.state.ready.load(Ordering::Acquire) {
            if let Some(v) = self.state.result.lock().take() {
                return Poll::Ready(v);
            }
        }
        *self.state.waker.lock() = Some(cx.waker().clone());
        Poll::Pending
    }
}

extern "win64" fn blocking_trampoline<F, R>(ctx: usize)
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let ptr = ctx as *mut (Arc<BlockingState<R>>, Option<F>);
    let boxed = unsafe { Box::from_raw(ptr) };
    let (state, func_opt) = *boxed;
    if let Some(f) = func_opt {
        let res = f();
        state.store(res);
    }
}

pub fn spawn_blocking<F, R>(func: F) -> BlockingJoin<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let state = Arc::new(BlockingState::new());
    let pair = Box::new((state.clone(), Some(func)));
    let ctx = Box::into_raw(pair) as usize;
    unsafe {
        kernel_spawn_blocking_raw(blocking_trampoline::<F, R>, ctx);
    }
    BlockingJoin { state }
}

pub fn spawn_blocking_many<F, R>(funcs: Vec<F>) -> Vec<BlockingJoin<R>>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    if funcs.is_empty() {
        return Vec::new();
    }
    let mut joins = Vec::with_capacity(funcs.len());
    for f in funcs {
        joins.push(spawn_blocking(f));
    }
    joins
}

/// Best-effort steal of one blocking task from the kernel blocking pool.
pub fn try_steal_blocking_one() -> bool {
    unsafe { sys_try_steal_blocking_one() }
}

