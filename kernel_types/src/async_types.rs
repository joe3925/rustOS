use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::future::Future;
use core::hint::spin_loop;
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::ops::{Deref, DerefMut};
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicIsize, AtomicU8, Ordering};
use core::task::{Context, Poll, Waker};
use spin::Mutex as SpinMutex;

fn push_waker(list: &mut Vec<Waker>, w: &Waker) {
    for slot in list.iter_mut() {
        if slot.will_wake(w) {
            *slot = w.clone();
            return;
        }
    }
    list.push(w.clone());
}

fn remove_waker(list: &mut Vec<Waker>, w: &Waker) {
    let mut i = 0usize;
    while i < list.len() {
        if list[i].will_wake(w) {
            list.swap_remove(i);
            return;
        }
        i += 1;
    }
}

fn wake_one(list: &mut Vec<Waker>) {
    if let Some(w) = list.pop() {
        w.wake();
    }
}

fn wake_all(list: &mut Vec<Waker>) {
    while let Some(w) = list.pop() {
        w.wake();
    }
}
#[repr(C)]

pub struct AsyncMutex<T> {
    locked: AtomicBool,
    waiters: SpinMutex<Vec<Waker>>,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Sync for AsyncMutex<T> {}
unsafe impl<T: Send> Send for AsyncMutex<T> {}
#[repr(C)]

pub struct AsyncMutexGuard<'a, T> {
    m: &'a AsyncMutex<T>,
    _pd: PhantomData<&'a mut T>,
}
#[repr(C)]

pub struct AsyncMutexLockFuture<'a, T> {
    m: &'a AsyncMutex<T>,
}

impl<T> AsyncMutex<T> {
    pub const fn new(value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            waiters: SpinMutex::new(Vec::new()),
            data: UnsafeCell::new(value),
        }
    }

    /// Returns a raw pointer to the underlying data.
    /// SAFETY: Caller must ensure proper synchronization. Only use this for
    /// accessing fields that are already atomic/thread-safe.
    #[inline]
    pub fn as_ptr(&self) -> *mut T {
        self.data.get()
    }

    pub fn try_lock(&self) -> Option<AsyncMutexGuard<'_, T>> {
        if self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(AsyncMutexGuard {
                m: self,
                _pd: PhantomData,
            })
        } else {
            None
        }
    }

    pub fn lock(&self) -> AsyncMutexLockFuture<'_, T> {
        AsyncMutexLockFuture { m: self }
    }
    #[inline]
    pub fn lock_blocking(&self) -> AsyncMutexGuard<'_, T> {
        loop {
            if let Some(g) = self.try_lock() {
                return g;
            }
            core::hint::spin_loop();
        }
    }
    fn unlock(&self) {
        self.unlock_and_wake_one();
    }

    pub fn unlock_and_wake_one(&self) {
        self.locked.store(false, Ordering::Release);
        let mut w = self.waiters.lock();
        wake_one(&mut w);
    }

    pub async fn lock_owned(self: Arc<Self>) -> AsyncMutexOwnedGuard<T> {
        let g = self.lock().await;
        core::mem::forget(g);
        AsyncMutexOwnedGuard { m: self }
    }
}

impl<'a, T> Deref for AsyncMutexGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.m.data.get() }
    }
}

impl<'a, T> DerefMut for AsyncMutexGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.m.data.get() }
    }
}

impl<'a, T> Drop for AsyncMutexGuard<'a, T> {
    fn drop(&mut self) {
        self.m.unlock();
    }
}

impl<'a, T> Future for AsyncMutexLockFuture<'a, T> {
    type Output = AsyncMutexGuard<'a, T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(g) = self.m.try_lock() {
            return Poll::Ready(g);
        }

        {
            let mut w = self.m.waiters.lock();
            push_waker(&mut w, cx.waker());
        }

        if let Some(g) = self.m.try_lock() {
            let mut w = self.m.waiters.lock();
            remove_waker(&mut w, cx.waker());
            return Poll::Ready(g);
        }

        Poll::Pending
    }
}
#[repr(C)]

pub struct AsyncMutexOwnedGuard<T> {
    m: Arc<AsyncMutex<T>>,
}

impl<T> Deref for AsyncMutexOwnedGuard<T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.m.data.get() }
    }
}

impl<T> DerefMut for AsyncMutexOwnedGuard<T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.m.data.get() }
    }
}

impl<T> Drop for AsyncMutexOwnedGuard<T> {
    fn drop(&mut self) {
        self.m.unlock_and_wake_one();
    }
}

unsafe impl<T: Send> Send for AsyncMutexOwnedGuard<T> {}
unsafe impl<T: Send> Sync for AsyncMutexOwnedGuard<T> {}
#[repr(C)]

pub struct AsyncRwLock<T> {
    state: AtomicIsize, // -1 = writer, 0 = free, >0 = readers
    r_waiters: SpinMutex<Vec<Waker>>,
    w_waiters: SpinMutex<Vec<Waker>>,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send + Sync> Sync for AsyncRwLock<T> {}
unsafe impl<T: Send> Send for AsyncRwLock<T> {}
#[repr(C)]

pub struct AsyncRwLockReadGuard<'a, T> {
    l: &'a AsyncRwLock<T>,
    _pd: PhantomData<&'a T>,
}
#[repr(C)]

pub struct AsyncRwLockWriteGuard<'a, T> {
    l: &'a AsyncRwLock<T>,
    _pd: PhantomData<&'a mut T>,
}
#[repr(C)]

pub struct AsyncRwLockReadFuture<'a, T> {
    l: &'a AsyncRwLock<T>,
}
#[repr(C)]
pub struct AsyncRwLockWriteFuture<'a, T> {
    l: &'a AsyncRwLock<T>,
}

impl<T> AsyncRwLock<T> {
    pub const fn new(value: T) -> Self {
        Self {
            state: AtomicIsize::new(0),
            r_waiters: SpinMutex::new(Vec::new()),
            w_waiters: SpinMutex::new(Vec::new()),
            data: UnsafeCell::new(value),
        }
    }

    pub fn try_read(&self) -> Option<AsyncRwLockReadGuard<'_, T>> {
        if !self.w_waiters.lock().is_empty() {
            return None;
        }

        let mut cur = self.state.load(Ordering::Acquire);
        loop {
            if cur < 0 {
                return None;
            }
            let next = cur + 1;
            match self
                .state
                .compare_exchange(cur, next, Ordering::Acquire, Ordering::Relaxed)
            {
                Ok(_) => {
                    return Some(AsyncRwLockReadGuard {
                        l: self,
                        _pd: PhantomData,
                    });
                }
                Err(v) => cur = v,
            }
        }
    }

    pub fn try_write(&self) -> Option<AsyncRwLockWriteGuard<'_, T>> {
        if self
            .state
            .compare_exchange(0, -1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(AsyncRwLockWriteGuard {
                l: self,
                _pd: PhantomData,
            })
        } else {
            None
        }
    }

    pub fn read(&self) -> AsyncRwLockReadFuture<'_, T> {
        AsyncRwLockReadFuture { l: self }
    }

    pub fn write(&self) -> AsyncRwLockWriteFuture<'_, T> {
        AsyncRwLockWriteFuture { l: self }
    }

    fn read_unlock(&self) {
        self.read_unlock_and_wake_one();
    }

    fn write_unlock(&self) {
        self.write_unlock_and_wake_one();
    }

    pub fn read_unlock_and_wake_one(&self) {
        let prev = self.state.fetch_sub(1, Ordering::Release);
        let now = prev - 1;

        if now == 0 {
            let mut ww = self.w_waiters.lock();
            if !ww.is_empty() {
                wake_one(&mut ww);
            }
        }
    }

    pub fn write_unlock_and_wake_one(&self) {
        self.state.store(0, Ordering::Release);

        {
            let mut ww = self.w_waiters.lock();
            if !ww.is_empty() {
                wake_one(&mut ww);
                return;
            }
        }

        let mut rw = self.r_waiters.lock();
        wake_all(&mut rw);
    }

    pub async fn read_owned(self: Arc<Self>) -> AsyncRwLockOwnedReadGuard<T> {
        let g = self.read().await;
        core::mem::forget(g);
        AsyncRwLockOwnedReadGuard { l: self }
    }

    pub async fn write_owned(self: Arc<Self>) -> AsyncRwLockOwnedWriteGuard<T> {
        let g = self.write().await;
        core::mem::forget(g);
        AsyncRwLockOwnedWriteGuard { l: self }
    }
}

impl<'a, T> Deref for AsyncRwLockReadGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.l.data.get() }
    }
}

impl<'a, T> Drop for AsyncRwLockReadGuard<'a, T> {
    fn drop(&mut self) {
        self.l.read_unlock();
    }
}

impl<'a, T> Deref for AsyncRwLockWriteGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.l.data.get() }
    }
}

impl<'a, T> DerefMut for AsyncRwLockWriteGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.l.data.get() }
    }
}

impl<'a, T> Drop for AsyncRwLockWriteGuard<'a, T> {
    fn drop(&mut self) {
        self.l.write_unlock();
    }
}

impl<'a, T> Future for AsyncRwLockReadFuture<'a, T> {
    type Output = AsyncRwLockReadGuard<'a, T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(g) = self.l.try_read() {
            // Clean up any stale waker we might have enqueued on a previous poll.
            let mut rw = self.l.r_waiters.lock();
            remove_waker(&mut rw, cx.waker());
            return Poll::Ready(g);
        }

        {
            let mut rw = self.l.r_waiters.lock();
            push_waker(&mut rw, cx.waker());
        }

        if let Some(g) = self.l.try_read() {
            let mut rw = self.l.r_waiters.lock();
            remove_waker(&mut rw, cx.waker());
            return Poll::Ready(g);
        }

        Poll::Pending
    }
}

impl<'a, T> Future for AsyncRwLockWriteFuture<'a, T> {
    type Output = AsyncRwLockWriteGuard<'a, T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(g) = self.l.try_write() {
            // Clean up any stale waker we might have enqueued on a previous poll.
            let mut ww = self.l.w_waiters.lock();
            remove_waker(&mut ww, cx.waker());
            return Poll::Ready(g);
        }

        {
            let mut ww = self.l.w_waiters.lock();
            push_waker(&mut ww, cx.waker());
        }

        if let Some(g) = self.l.try_write() {
            let mut ww = self.l.w_waiters.lock();
            remove_waker(&mut ww, cx.waker());
            return Poll::Ready(g);
        }

        Poll::Pending
    }
}
#[repr(C)]

pub struct AsyncRwLockOwnedReadGuard<T> {
    l: Arc<AsyncRwLock<T>>,
}
#[repr(C)]

pub struct AsyncRwLockOwnedWriteGuard<T> {
    l: Arc<AsyncRwLock<T>>,
}

impl<T> Deref for AsyncRwLockOwnedReadGuard<T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.l.data.get() }
    }
}

impl<T> Drop for AsyncRwLockOwnedReadGuard<T> {
    fn drop(&mut self) {
        self.l.read_unlock_and_wake_one();
    }
}

impl<T> Deref for AsyncRwLockOwnedWriteGuard<T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.l.data.get() }
    }
}

impl<T> DerefMut for AsyncRwLockOwnedWriteGuard<T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.l.data.get() }
    }
}

impl<T> Drop for AsyncRwLockOwnedWriteGuard<T> {
    fn drop(&mut self) {
        self.l.write_unlock_and_wake_one();
    }
}

unsafe impl<T: Sync> Send for AsyncRwLockOwnedReadGuard<T> {}
unsafe impl<T: Sync> Sync for AsyncRwLockOwnedReadGuard<T> {}

unsafe impl<T: Send> Send for AsyncRwLockOwnedWriteGuard<T> {}
unsafe impl<T: Send> Sync for AsyncRwLockOwnedWriteGuard<T> {}

const EMPTY: u8 = 0;
const WRITING: u8 = 1;
const READY: u8 = 2;
const CLOSED: u8 = 3;
const TAKEN: u8 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Canceled;

pub struct Oneshot<T> {
    state: AtomicU8,
    value: UnsafeCell<MaybeUninit<T>>,
    waker: WakerSlot,
}

pub struct Sender<'a, T> {
    chan: &'a Oneshot<T>,
    finished: bool,
}

pub struct Receiver<'a, T> {
    chan: &'a Oneshot<T>,
    finished: bool,
}

struct WakerSlot {
    locked: AtomicBool,
    waker: UnsafeCell<Option<Waker>>,
}

struct WakerGuard<'a> {
    slot: &'a WakerSlot,
}

unsafe impl<T: Send> Send for Oneshot<T> {}
unsafe impl<T: Send> Sync for Oneshot<T> {}

unsafe impl Send for WakerSlot {}
unsafe impl Sync for WakerSlot {}

impl<T> Oneshot<T> {
    pub const fn new() -> Self {
        Self {
            state: AtomicU8::new(EMPTY),
            value: UnsafeCell::new(MaybeUninit::uninit()),
            waker: WakerSlot::new(),
        }
    }

    pub fn split(&mut self) -> (Sender<'_, T>, Receiver<'_, T>) {
        self.reset();

        let chan = &*self;

        (
            Sender {
                chan,
                finished: false,
            },
            Receiver {
                chan,
                finished: false,
            },
        )
    }

    fn reset(&mut self) {
        let state = self.state.load(Ordering::Acquire);

        if state == READY {
            unsafe {
                self.value.get_mut().assume_init_drop();
            }
        }

        self.waker.clear_mut();
        self.state.store(EMPTY, Ordering::Release);
    }

    fn send(&self, value: T) -> Result<(), T> {
        let result =
            self.state
                .compare_exchange(EMPTY, WRITING, Ordering::AcqRel, Ordering::Acquire);

        if result.is_err() {
            return Err(value);
        }

        unsafe {
            (*self.value.get()).write(value);
        }

        self.state.store(READY, Ordering::Release);
        self.waker.wake();

        Ok(())
    }

    fn recv(&self, cx: &mut Context<'_>) -> Poll<Result<T, Canceled>> {
        loop {
            let state = self.state.load(Ordering::Acquire);

            match state {
                READY => {
                    let result = self.state.compare_exchange(
                        READY,
                        TAKEN,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    );

                    if result.is_ok() {
                        self.waker.clear();

                        let value = unsafe { (*self.value.get()).assume_init_read() };

                        return Poll::Ready(Ok(value));
                    }
                }
                EMPTY => {
                    self.waker.register(cx.waker());

                    if self.state.load(Ordering::Acquire) == EMPTY {
                        return Poll::Pending;
                    }
                }
                WRITING => {
                    spin_loop();
                }
                CLOSED | TAKEN => {
                    self.waker.clear();
                    return Poll::Ready(Err(Canceled));
                }
                _ => unreachable!(),
            }
        }
    }

    fn try_recv(&self) -> Result<Option<T>, Canceled> {
        loop {
            let state = self.state.load(Ordering::Acquire);

            match state {
                READY => {
                    let result = self.state.compare_exchange(
                        READY,
                        TAKEN,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    );

                    if result.is_ok() {
                        self.waker.clear();

                        let value = unsafe { (*self.value.get()).assume_init_read() };

                        return Ok(Some(value));
                    }
                }
                EMPTY | WRITING => return Ok(None),
                CLOSED | TAKEN => return Err(Canceled),
                _ => unreachable!(),
            }
        }
    }

    fn close_sender(&self) {
        let result =
            self.state
                .compare_exchange(EMPTY, CLOSED, Ordering::AcqRel, Ordering::Acquire);

        if result.is_ok() {
            self.waker.wake();
        }
    }

    fn close_receiver(&self) {
        loop {
            let state = self.state.load(Ordering::Acquire);

            match state {
                EMPTY => {
                    let result = self.state.compare_exchange(
                        EMPTY,
                        CLOSED,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    );

                    if result.is_ok() {
                        self.waker.clear();
                        return;
                    }
                }
                WRITING => {
                    spin_loop();
                }
                READY => {
                    let result = self.state.compare_exchange(
                        READY,
                        TAKEN,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    );

                    if result.is_ok() {
                        unsafe {
                            (*self.value.get()).assume_init_drop();
                        }

                        self.waker.clear();
                        return;
                    }
                }
                CLOSED | TAKEN => {
                    self.waker.clear();
                    return;
                }
                _ => unreachable!(),
            }
        }
    }
}

impl<T> Drop for Oneshot<T> {
    fn drop(&mut self) {
        if self.state.load(Ordering::Acquire) == READY {
            unsafe {
                self.value.get_mut().assume_init_drop();
            }
        }

        self.waker.clear_mut();
    }
}

impl<'a, T> Sender<'a, T> {
    pub fn send(mut self, value: T) -> Result<(), T> {
        let result = self.chan.send(value);
        self.finished = true;
        result
    }

    pub fn is_canceled(&self) -> bool {
        self.chan.state.load(Ordering::Acquire) == CLOSED
    }
}

impl<T> Drop for Sender<'_, T> {
    fn drop(&mut self) {
        if !self.finished {
            self.chan.close_sender();
            self.finished = true;
        }
    }
}

impl<'a, T> Receiver<'a, T> {
    pub fn try_recv(&mut self) -> Result<Option<T>, Canceled> {
        let result = self.chan.try_recv();

        if !matches!(result, Ok(None)) {
            self.finished = true;
        }

        result
    }

    pub fn close(&mut self) {
        if !self.finished {
            self.chan.close_receiver();
            self.finished = true;
        }
    }
}

impl<T> Future for Receiver<'_, T> {
    type Output = Result<T, Canceled>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        if this.finished {
            return Poll::Ready(Err(Canceled));
        }

        let result = this.chan.recv(cx);

        if result.is_ready() {
            this.finished = true;
        }

        result
    }
}

impl<T> Drop for Receiver<'_, T> {
    fn drop(&mut self) {
        if !self.finished {
            self.chan.close_receiver();
            self.finished = true;
        }
    }
}

impl<T> Unpin for Sender<'_, T> {}
impl<T> Unpin for Receiver<'_, T> {}

impl WakerSlot {
    const fn new() -> Self {
        Self {
            locked: AtomicBool::new(false),
            waker: UnsafeCell::new(None),
        }
    }

    fn register(&self, waker: &Waker) {
        let mut guard = self.lock();
        let slot = guard.get_mut();

        match slot {
            Some(old) if old.will_wake(waker) => {}
            _ => *slot = Some(waker.clone()),
        }
    }

    fn wake(&self) {
        let waker = {
            let mut guard = self.lock();
            guard.get_mut().take()
        };

        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn clear(&self) {
        let mut guard = self.lock();
        guard.get_mut().take();
    }

    fn clear_mut(&mut self) {
        *self.waker.get_mut() = None;
        self.locked.store(false, Ordering::Relaxed);
    }

    fn lock(&self) -> WakerGuard<'_> {
        while self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            spin_loop();
        }

        WakerGuard { slot: self }
    }
}

impl<'a> WakerGuard<'a> {
    fn get_mut(&mut self) -> &mut Option<Waker> {
        unsafe { &mut *self.slot.waker.get() }
    }
}

impl Drop for WakerGuard<'_> {
    fn drop(&mut self) {
        self.slot.locked.store(false, Ordering::Release);
    }
}
