use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::arch::asm;

use alloc::sync::Arc;
use core::future::Future;
use core::hint::black_box;
use core::mem::ManuallyDrop;
use core::ops::{Deref, DerefMut};
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};

use spin::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
use x86_64::instructions::interrupts;

/// IRQ handle shared across kernel/driver boundary.
/// Safe to pass over FFI (win64); both sides must be compiled with the same Rust version.
pub type IrqHandle = Arc<IrqHandleInner>;

/// ISR function signature (win64 ABI).
/// Returns true if the interrupt was claimed/handled by this handler.
pub type IrqIsrFn = extern "win64" fn(
    vector: u8,
    cpu: u32,
    frame: &mut x86_64::structures::idt::InterruptStackFrame,
    handle: IrqHandle,
    ctx: usize,
) -> bool;

/// Metadata passed when signaling an IRQ
/// Carries additional information from the ISR to waiters.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct IrqMeta {
    /// Tag value for identifying signal type
    pub tag: u64,
    /// Additional data slots
    pub data: [u64; 3],
}

impl IrqMeta {
    /// Create a new empty metadata struct
    pub const fn new() -> Self {
        Self {
            tag: 0,
            data: [0; 3],
        }
    }

    /// Create metadata with a specific tag
    pub const fn with_tag(tag: u64) -> Self {
        Self { tag, data: [0; 3] }
    }

    /// Create metadata with tag and single data value
    pub const fn with_data(tag: u64, d0: u64) -> Self {
        Self {
            tag,
            data: [d0, 0, 0],
        }
    }

    /// Create metadata with tag and multiple data values
    pub const fn with_data3(tag: u64, d0: u64, d1: u64, d2: u64) -> Self {
        Self {
            tag,
            data: [d0, d1, d2],
        }
    }
}

/// Result codes for IRQ wait operations
pub const IRQ_WAIT_OK: u32 = 0;
pub const IRQ_WAIT_CLOSED: u32 = 1;
pub const IRQ_WAIT_NULL: u32 = 2;
pub const IRQ_WAIT_TIMEOUT: u32 = 3;
pub const IRQ_RESCUE_WAKEUP: u32 = 4;

/// Result of waiting on an IRQ
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct IrqWaitResult {
    /// Result code (IRQ_WAIT_*)
    pub code: u32,
    /// Number of signals consumed (usually 1)
    pub count: u32,
    /// Metadata from the signal
    pub meta: IrqMeta,
}

impl IrqWaitResult {
    /// Create a successful result with metadata
    pub const fn ok(meta: IrqMeta) -> Self {
        Self {
            code: IRQ_WAIT_OK,
            count: 1,
            meta,
        }
    }

    /// Create a successful result with count
    pub const fn ok_n(meta: IrqMeta, count: u32) -> Self {
        Self {
            code: IRQ_WAIT_OK,
            count,
            meta,
        }
    }

    /// Create a closed result (handle was unregistered)
    pub const fn closed() -> Self {
        Self {
            code: IRQ_WAIT_CLOSED,
            count: 0,
            meta: IrqMeta::new(),
        }
    }

    /// Create a null result (null handle passed)
    pub const fn null() -> Self {
        Self {
            code: IRQ_WAIT_NULL,
            count: 0,
            meta: IrqMeta::new(),
        }
    }

    /// Create a timeout result
    pub const fn timeout() -> Self {
        Self {
            code: IRQ_WAIT_TIMEOUT,
            count: 0,
            meta: IrqMeta::new(),
        }
    }
    pub const fn rescue() -> Self {
        Self {
            code: IRQ_RESCUE_WAKEUP,
            count: 0,
            meta: IrqMeta::new(),
        }
    }

    /// Check if wait succeeded
    pub fn is_ok(&self) -> bool {
        self.code == IRQ_WAIT_OK
    }

    /// Check if handle was closed
    pub fn is_closed(&self) -> bool {
        self.code == IRQ_WAIT_CLOSED
    }

    /// Check if null handle was passed
    pub fn is_null(&self) -> bool {
        self.code == IRQ_WAIT_NULL
    }

    /// Check if wait timed out
    pub fn is_timeout(&self) -> bool {
        self.code == IRQ_WAIT_TIMEOUT
    }
}

impl Default for IrqWaitResult {
    fn default() -> Self {
        Self::null()
    }
}

// =============================================================================
// IRQ HANDLE (safe, Arc-based)
// =============================================================================
#[repr(C)]
struct Waiter {
    waker: IrqSafeMutex<Option<Waker>>,
    result: IrqSafeMutex<Option<IrqWaitResult>>,
    enqueued: AtomicBool,
}

impl Waiter {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            waker: IrqSafeMutex::new(None),
            result: IrqSafeMutex::new(None),
            enqueued: AtomicBool::new(false),
        })
    }

    fn set_waker(&self, w: &Waker) {
        let mut g = self.waker.lock();
        let update = match g.as_ref() {
            Some(existing) => !existing.will_wake(w),
            None => true,
        };
        if update {
            *g = Some(w.clone());
        }
    }

    fn take_result(&self) -> Option<IrqWaitResult> {
        self.result.lock().take()
    }

    fn store_result(&self, r: IrqWaitResult) {
        *self.result.lock() = Some(r);
    }

    fn wake(&self) {
        if let Some(w) = self.waker.lock().take() {
            w.wake();
        }
    }

    fn clear(&self) {
        self.enqueued.store(false, Ordering::Release);
        *self.waker.lock() = None;
        *self.result.lock() = None;
    }
}

struct WaitState {
    waiters: VecDeque<Arc<Waiter>>,
    pending_signals: usize,
    last_meta: IrqMeta,
}

impl WaitState {
    const fn new() -> Self {
        Self {
            waiters: VecDeque::new(),
            pending_signals: 0,
            last_meta: IrqMeta::new(),
        }
    }

    fn pop_waiter(&mut self) -> Option<Arc<Waiter>> {
        self.waiters.pop_front()
    }

    fn push_waiter(&mut self, w: Arc<Waiter>) {
        self.waiters.push_back(w);
    }

    fn remove_waiter(&mut self, target: &Arc<Waiter>) -> bool {
        let before = self.waiters.len();
        self.waiters.retain(|w| !Arc::ptr_eq(w, target));
        before != self.waiters.len()
    }
}

#[repr(C)]
pub struct IrqHandleInner {
    drop_hook: Mutex<Option<DropHook>>,
    closed: AtomicBool,
    user_ctx: AtomicUsize,
    state: IrqSafeMutex<WaitState>,
}

impl IrqHandleInner {
    pub fn new(drop_hook: DropHook) -> IrqHandle {
        Arc::new(Self {
            drop_hook: Mutex::new(Some(drop_hook)),
            closed: AtomicBool::new(false),
            user_ctx: AtomicUsize::new(0),
            state: IrqSafeMutex::new(WaitState::new()),
        })
    }

    #[inline]
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    pub fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }

        let waiters = {
            let mut st = self.state.lock();
            st.pending_signals = 0;

            let mut drained = Vec::with_capacity(st.waiters.len());
            while let Some(waiter) = st.pop_waiter() {
                waiter.enqueued.store(false, Ordering::Release);
                drained.push(waiter);
            }
            drained
        };

        for waiter in waiters {
            waiter.store_result(IrqWaitResult::closed());
            waiter.wake();
        }
    }

    pub fn signal_one(&self, meta: IrqMeta) {
        if self.is_closed() {
            return;
        }

        let waiter_opt = {
            let mut st = self.state.lock();
            st.last_meta = meta;

            if let Some(waiter) = st.pop_waiter() {
                waiter.enqueued.store(false, Ordering::Release);
                Some(waiter)
            } else {
                st.pending_signals = st.pending_signals.saturating_add(1);

                None
            }
        };

        if let Some(waiter) = waiter_opt {
            waiter.store_result(IrqWaitResult::ok_n(meta, 1));
            waiter.wake();
        }
    }

    pub fn ensure_signal_exactly_one(&self, meta: IrqMeta) {
        if self.is_closed() {
            return;
        }

        let waiter_opt = {
            let mut st = self.state.lock();
            st.last_meta = meta;

            if let Some(waiter) = st.pop_waiter() {
                waiter.enqueued.store(false, Ordering::Release);
                Some(waiter)
            } else {
                st.pending_signals = 1;
                None
            }
        };

        if let Some(waiter) = waiter_opt {
            waiter.store_result(IrqWaitResult::ok_n(meta, 1));
            waiter.wake();
        }
    }

    pub fn signal_n(&self, meta: IrqMeta, n: usize) -> usize {
        if n == 0 || self.is_closed() {
            return 0;
        }

        let waiters = {
            let mut st = self.state.lock();
            st.last_meta = meta;

            let mut drained = Vec::with_capacity(n.min(st.waiters.len()));
            for _ in 0..n {
                let Some(waiter) = st.pop_waiter() else { break };
                waiter.enqueued.store(false, Ordering::Release);
                drained.push(waiter);
            }

            if drained.len() < n {
                st.pending_signals = st.pending_signals.saturating_add(n - drained.len());
            }

            drained
        };

        let woken = waiters.len();
        for waiter in waiters.iter() {
            waiter.store_result(IrqWaitResult::ok_n(meta, 1));
            waiter.wake();
        }

        woken
    }

    pub fn signal_all(&self, meta: IrqMeta) -> usize {
        if self.is_closed() {
            return 0;
        }

        let mut woken = 0;
        loop {
            let waiter_opt = {
                let mut st = self.state.lock();
                st.last_meta = meta;
                st.pop_waiter().map(|w| {
                    w.enqueued.store(false, Ordering::Release);
                    w
                })
            };

            let Some(waiter) = waiter_opt else { break };
            waiter.store_result(IrqWaitResult::ok_n(meta, 1));
            waiter.wake();
            woken += 1;
        }

        if woken == 0 {
            self.signal_one(meta);
        }
        woken
    }

    pub fn cancel_waiter(&self, waiter: &Arc<Waiter>) {
        let mut st = self.state.lock();
        if st.remove_waiter(waiter) {
            waiter.enqueued.store(false, Ordering::Release);
        }
    }

    pub fn set_user_ctx(&self, v: usize) {
        self.user_ctx.store(v, Ordering::Release);
    }

    pub fn user_ctx(&self) -> usize {
        self.user_ctx.load(Ordering::Acquire)
    }

    pub fn wait_future(self: &Arc<Self>) -> IrqWaitFuture {
        IrqWaitFuture {
            handle: Arc::clone(self),
            waiter: Waiter::new(),
            test_wakeup: AtomicUsize::new(0),
        }
    }
}

impl Drop for IrqHandleInner {
    fn drop(&mut self) {
        if let Some(h) = self.drop_hook.lock().take() {
            h.invoke();
        }
    }
}

pub struct IrqWaitFuture {
    handle: IrqHandle,
    //TODO: Remove this
    test_wakeup: AtomicUsize,
    waiter: Arc<Waiter>,
}

impl Future for IrqWaitFuture {
    type Output = IrqWaitResult;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.as_ref().get_ref();

        if let Some(r) = this.waiter.take_result() {
            return Poll::Ready(r);
        }
        if self.test_wakeup.load(Ordering::Relaxed) > 500_000 {
            return Poll::Ready(IrqWaitResult::rescue());
        }
        if this.handle.is_closed() {
            return Poll::Ready(IrqWaitResult::closed());
        }

        {
            let mut st = this.handle.state.lock();

            this.waiter.set_waker(cx.waker());

            if st.pending_signals > 0 {
                st.pending_signals -= 1;
                let meta = st.last_meta;
                return Poll::Ready(IrqWaitResult::ok_n(meta, 1));
            }

            if !this.waiter.enqueued.swap(true, Ordering::AcqRel) {
                st.push_waiter(this.waiter.clone());
            }
        }
        self.test_wakeup.fetch_add(1, Ordering::Relaxed);
        Poll::Pending
    }
}

impl Drop for IrqWaitFuture {
    fn drop(&mut self) {
        self.handle.cancel_waiter(&self.waiter);
        self.waiter.clear();
    }
}

/// Drop hook for automatic cleanup when handle is dropped.
/// Called when the last reference to an IRQ handle is released.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DropHook {
    /// Function to call on drop
    pub func: extern "win64" fn(usize),
    /// Argument to pass to the function
    pub arg: usize,
}

impl DropHook {
    /// Create a new drop hook
    pub const fn new(func: extern "win64" fn(usize), arg: usize) -> Self {
        Self { func, arg }
    }

    /// Invoke the drop hook
    pub fn invoke(self) {
        (self.func)(self.arg);
    }
}

impl core::fmt::Debug for DropHook {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DropHook")
            .field("func", &(self.func as usize))
            .field("arg", &self.arg)
            .finish()
    }
}

pub struct IrqSafeMutex<T> {
    inner: Mutex<T>,
}

pub struct IrqSafeMutexGuard<'a, T> {
    guard: ManuallyDrop<MutexGuard<'a, T>>,
    restore_interrupts: bool,
}

impl<T> IrqSafeMutex<T> {
    pub const fn new(value: T) -> Self {
        Self {
            inner: Mutex::new(value),
        }
    }

    #[inline(always)]
    pub fn lock(&self) -> IrqSafeMutexGuard<'_, T> {
        let restore_interrupts = interrupts::are_enabled();

        loop {
            if restore_interrupts {
                interrupts::disable();
            }

            if let Some(guard) = self.inner.try_lock() {
                return IrqSafeMutexGuard {
                    guard: ManuallyDrop::new(guard),
                    restore_interrupts,
                };
            }

            if restore_interrupts {
                interrupts::enable_and_hlt();
            } else {
                core::hint::spin_loop();
            }
        }
    }

    #[inline(always)]
    pub fn try_lock(&self) -> Option<IrqSafeMutexGuard<'_, T>> {
        let restore_interrupts = interrupts::are_enabled();
        if restore_interrupts {
            interrupts::disable();
        }

        match self.inner.try_lock() {
            Some(guard) => Some(IrqSafeMutexGuard {
                guard: ManuallyDrop::new(guard),
                restore_interrupts,
            }),
            None => {
                if restore_interrupts {
                    interrupts::enable();
                }
                None
            }
        }
    }
}

impl<'a, T> Deref for IrqSafeMutexGuard<'a, T> {
    type Target = T;

    #[inline(always)]
    fn deref(&self) -> &T {
        &self.guard
    }
}

impl<'a, T> DerefMut for IrqSafeMutexGuard<'a, T> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut T {
        &mut self.guard
    }
}

impl<'a, T> Drop for IrqSafeMutexGuard<'a, T> {
    #[inline(always)]
    fn drop(&mut self) {
        unsafe { ManuallyDrop::drop(&mut self.guard) };
        if self.restore_interrupts {
            interrupts::enable();
        }
    }
}

pub struct IrqSafeRwLock<T> {
    inner: RwLock<T>,
}

pub struct IrqSafeRwLockReadGuard<'a, T> {
    guard: ManuallyDrop<RwLockReadGuard<'a, T>>,
    restore_interrupts: bool,
}

pub struct IrqSafeRwLockWriteGuard<'a, T> {
    guard: ManuallyDrop<RwLockWriteGuard<'a, T>>,
    restore_interrupts: bool,
}

impl<T> IrqSafeRwLock<T> {
    #[inline(always)]
    pub const fn new(value: T) -> Self {
        Self {
            inner: RwLock::new(value),
        }
    }

    #[inline(always)]
    pub fn read(&self) -> IrqSafeRwLockReadGuard<'_, T> {
        let restore_interrupts = interrupts::are_enabled();

        loop {
            if restore_interrupts {
                interrupts::disable();
            }

            if let Some(guard) = self.inner.try_read() {
                return IrqSafeRwLockReadGuard {
                    guard: ManuallyDrop::new(guard),
                    restore_interrupts,
                };
            }

            if restore_interrupts {
                interrupts::enable_and_hlt();
            } else {
                core::hint::spin_loop();
            }
        }
    }

    #[inline(always)]
    pub fn try_read(&self) -> Option<IrqSafeRwLockReadGuard<'_, T>> {
        let restore_interrupts = interrupts::are_enabled();
        if restore_interrupts {
            interrupts::disable();
        }

        match self.inner.try_read() {
            Some(guard) => Some(IrqSafeRwLockReadGuard {
                guard: ManuallyDrop::new(guard),
                restore_interrupts,
            }),
            None => {
                if restore_interrupts {
                    interrupts::enable();
                }
                None
            }
        }
    }

    #[inline(always)]
    pub fn write(&self) -> IrqSafeRwLockWriteGuard<'_, T> {
        let restore_interrupts = interrupts::are_enabled();

        loop {
            if restore_interrupts {
                interrupts::disable();
            }

            if let Some(guard) = self.inner.try_write() {
                return IrqSafeRwLockWriteGuard {
                    guard: ManuallyDrop::new(guard),
                    restore_interrupts,
                };
            }

            if restore_interrupts {
                interrupts::enable_and_hlt();
            } else {
                core::hint::spin_loop();
            }
        }
    }

    #[inline(always)]
    pub fn try_write(&self) -> Option<IrqSafeRwLockWriteGuard<'_, T>> {
        let restore_interrupts = interrupts::are_enabled();
        if restore_interrupts {
            interrupts::disable();
        }

        match self.inner.try_write() {
            Some(guard) => Some(IrqSafeRwLockWriteGuard {
                guard: ManuallyDrop::new(guard),
                restore_interrupts,
            }),
            None => {
                if restore_interrupts {
                    interrupts::enable();
                }
                None
            }
        }
    }
}

impl<'a, T> Deref for IrqSafeRwLockReadGuard<'a, T> {
    type Target = T;

    #[inline(always)]
    fn deref(&self) -> &T {
        &self.guard
    }
}

impl<'a, T> Drop for IrqSafeRwLockReadGuard<'a, T> {
    #[inline(always)]
    fn drop(&mut self) {
        unsafe { ManuallyDrop::drop(&mut self.guard) };
        if self.restore_interrupts {
            interrupts::enable();
        }
    }
}

impl<'a, T> Deref for IrqSafeRwLockWriteGuard<'a, T> {
    type Target = T;

    #[inline(always)]
    fn deref(&self) -> &T {
        &self.guard
    }
}

impl<'a, T> DerefMut for IrqSafeRwLockWriteGuard<'a, T> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut T {
        &mut self.guard
    }
}

impl<'a, T> Drop for IrqSafeRwLockWriteGuard<'a, T> {
    #[inline(always)]
    fn drop(&mut self) {
        unsafe { ManuallyDrop::drop(&mut self.guard) };
        if self.restore_interrupts {
            interrupts::enable();
        }
    }
}
