extern crate alloc;

use crate::kernel_types::runtime::Stopwatch;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::task::Wake;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll, Waker};
use core::time::Duration;
use kernel_sys::{elapsed, kernel_cycle_counter, kernel_cycle_counter_frequency_hz, stopwatch_new};
use kernel_types::arch::{Platform, PlatformInfo};
use spin::Mutex;

use kernel_sys::{
    kernel_block_on_thread_state, kernel_spawn_blocking_raw, kernel_spawn_detached_ffi,
    kernel_spawn_joinable_ffi, try_steal_blocking_one as sys_try_steal_blocking_one,
};
use kernel_types::async_ffi::{FfiFuture, FutureExt, WakerExt};
use kernel_types::runtime::BlockOnThreadState;

/// Spawn an async task on the kernel executor (shared singleton in the kernel) and
/// return a join handle that can be awaited for completion.
pub fn spawn<F>(future: F) -> FfiFuture<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    unsafe { kernel_spawn_joinable_ffi(future.into_ffi()) }
}

/// Spawn a detached async task (fire-and-forget).
pub fn spawn_detached<F>(future: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    unsafe { kernel_spawn_detached_ffi(future.into_ffi()) };
}

struct BlockOnActiveGuard<'a> {
    state: &'a BlockOnThreadState,
}

impl<'a> BlockOnActiveGuard<'a> {
    fn new(state: &'a BlockOnThreadState) -> Self {
        Self { state }
    }
}

impl Drop for BlockOnActiveGuard<'_> {
    fn drop(&mut self) {
        self.state.exit();
    }
}

struct BlockOnWaker {
    state: Arc<BlockOnThreadState>,
}

impl Wake for BlockOnWaker {
    fn wake(self: Arc<Self>) {
        self.state.mark_ready();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.state.mark_ready();
    }
}

pub fn block_on<F: Future + Send>(future: F) -> F::Output {
    let mut ffi_fut = future.into_ffi();
    let state = unsafe { kernel_block_on_thread_state() };

    if !state.try_enter() {
        panic!("reentrant kernel_api::runtime::block_on is not supported");
    }

    let _active = BlockOnActiveGuard::new(&state);
    state.clear_ready();

    let waker = Waker::from(Arc::new(BlockOnWaker {
        state: state.clone(),
    }));
    let ffi_waker = waker.into_ffi();

    loop {
        let poll = unsafe { ffi_fut.poll(&ffi_waker as *const _) };

        if poll.is_ready() {
            match unsafe { poll.into_poll() } {
                Poll::Ready(v) => return v,
                Poll::Pending => unreachable!(),
            }
        }

        if !state.take_ready() {}
    }
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

        if self.state.ready.load(Ordering::Acquire) {
            if let Some(v) = self.state.result.lock().take() {
                return Poll::Ready(v);
            }
        }

        Poll::Pending
    }
}

extern "C" fn blocking_trampoline<F, R>(ctx: usize)
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

#[inline(always)]
pub fn cycle_counter() -> u64 {
    <Platform as PlatformInfo>::cycle_counter()
}

#[inline(always)]
pub fn cycle_counter_frequency_hz() -> u64 {
    unsafe { kernel_cycle_counter_frequency_hz() }
}

pub struct KernelStopwatch {
    inner: Stopwatch,
}

impl KernelStopwatch {
    #[inline(always)]
    pub fn start() -> Self {
        Self {
            inner: unsafe { stopwatch_new() },
        }
    }

    #[inline(always)]
    pub fn elapsed(&self) -> Duration {
        unsafe { elapsed(&self.inner) }
    }

    #[inline(always)]
    pub fn start_cycles(&self) -> u64 {
        self.inner.start_cycles()
    }

    #[inline(always)]
    pub fn cycle_counter_frequency_hz(&self) -> u64 {
        self.inner.cycle_counter_frequency_hz()
    }
}
