use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::future::Future;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
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

pub struct AsyncMutex<T> {
    locked: AtomicBool,
    waiters: SpinMutex<Vec<Waker>>,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Sync for AsyncMutex<T> {}
unsafe impl<T: Send> Send for AsyncMutex<T> {}

pub struct AsyncMutexGuard<'a, T> {
    m: &'a AsyncMutex<T>,
    _pd: PhantomData<&'a mut T>,
}

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
        wake_one(&mut *w);
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
            push_waker(&mut *w, cx.waker());
        }

        if let Some(g) = self.m.try_lock() {
            let mut w = self.m.waiters.lock();
            remove_waker(&mut *w, cx.waker());
            return Poll::Ready(g);
        }

        Poll::Pending
    }
}

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

pub struct AsyncRwLock<T> {
    state: AtomicIsize, // -1 = writer, 0 = free, >0 = readers
    r_waiters: SpinMutex<Vec<Waker>>,
    w_waiters: SpinMutex<Vec<Waker>>,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send + Sync> Sync for AsyncRwLock<T> {}
unsafe impl<T: Send> Send for AsyncRwLock<T> {}

pub struct AsyncRwLockReadGuard<'a, T> {
    l: &'a AsyncRwLock<T>,
    _pd: PhantomData<&'a T>,
}

pub struct AsyncRwLockWriteGuard<'a, T> {
    l: &'a AsyncRwLock<T>,
    _pd: PhantomData<&'a mut T>,
}

pub struct AsyncRwLockReadFuture<'a, T> {
    l: &'a AsyncRwLock<T>,
}

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
                wake_one(&mut *ww);
            }
        }
    }

    pub fn write_unlock_and_wake_one(&self) {
        self.state.store(0, Ordering::Release);

        {
            let mut ww = self.w_waiters.lock();
            if !ww.is_empty() {
                wake_one(&mut *ww);
                return;
            }
        }

        let mut rw = self.r_waiters.lock();
        wake_all(&mut *rw);
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
            return Poll::Ready(g);
        }

        {
            let mut rw = self.l.r_waiters.lock();
            push_waker(&mut *rw, cx.waker());
        }

        if let Some(g) = self.l.try_read() {
            let mut rw = self.l.r_waiters.lock();
            remove_waker(&mut *rw, cx.waker());
            return Poll::Ready(g);
        }

        Poll::Pending
    }
}

impl<'a, T> Future for AsyncRwLockWriteFuture<'a, T> {
    type Output = AsyncRwLockWriteGuard<'a, T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(g) = self.l.try_write() {
            return Poll::Ready(g);
        }

        {
            let mut ww = self.l.w_waiters.lock();
            push_waker(&mut *ww, cx.waker());
        }

        if let Some(g) = self.l.try_write() {
            let mut ww = self.l.w_waiters.lock();
            remove_waker(&mut *ww, cx.waker());
            return Poll::Ready(g);
        }

        Poll::Pending
    }
}

pub struct AsyncRwLockOwnedReadGuard<T> {
    l: Arc<AsyncRwLock<T>>,
}

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
