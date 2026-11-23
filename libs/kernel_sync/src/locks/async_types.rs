use crate::queues::waiter_queue::{WaitRegistration, WaiterQueue};
use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::future::Future;
use core::hint::spin_loop;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
use core::task::{Context, Poll};

use core::mem;
use core::sync::atomic::AtomicUsize;

#[repr(C)]
pub struct AsyncMutex<T> {
    locked: AtomicBool,
    waiters: WaiterQueue,
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
    waiter: WaitRegistration<'a>,
}

#[repr(C)]
pub struct AsyncMutexOwnedGuard<T> {
    m: Arc<AsyncMutex<T>>,
}

impl<T> AsyncMutex<T> {
    pub const fn new(value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            waiters: WaiterQueue::new(),
            data: UnsafeCell::new(value),
        }
    }

    #[inline]
    pub fn as_ptr(&self) -> *mut T {
        self.data.get()
    }

    #[inline]
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

    #[inline]
    pub fn lock(&self) -> AsyncMutexLockFuture<'_, T> {
        AsyncMutexLockFuture {
            m: self,
            waiter: self.waiters.registration(),
        }
    }

    #[inline]
    #[cfg_attr(irq_check, irq::forbidden)]
    pub fn lock_blocking(&self) -> AsyncMutexGuard<'_, T> {
        loop {
            if let Some(g) = self.try_lock() {
                return g;
            }

            spin_loop();
        }
    }

    fn unlock_and_wake_one(&self) {
        let was_locked = self.locked.swap(false, Ordering::Release);
        debug_assert!(was_locked);
        self.waiters.notify_one();
    }

    pub async fn lock_owned(self: Arc<Self>) -> AsyncMutexOwnedGuard<T> {
        let g = self.lock().await;
        mem::forget(g);
        AsyncMutexOwnedGuard { m: self }
    }
}

impl<'a, T> Future for AsyncMutexLockFuture<'a, T> {
    type Output = AsyncMutexGuard<'a, T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };
        let mut waiter = unsafe { Pin::new_unchecked(&mut this.waiter) };
        if let Some(guard) = this.m.try_lock() {
            waiter.as_mut().remove();
            return Poll::Ready(guard);
        }
        waiter.as_mut().register(cx.waker());
        if let Some(guard) = this.m.try_lock() {
            waiter.as_mut().remove();
            return Poll::Ready(guard);
        }
        Poll::Pending
    }
}

impl<T> Drop for AsyncMutexLockFuture<'_, T> {
    fn drop(&mut self) {
        let notified = unsafe { Pin::new_unchecked(&mut self.waiter) }.remove();
        if notified && !self.m.locked.load(Ordering::Acquire) {
            self.m.waiters.notify_one();
        }
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
        self.m.unlock_and_wake_one();
    }
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
unsafe impl<T: Send + Sync> Sync for AsyncMutexOwnedGuard<T> {}

#[repr(C)]
pub struct AsyncRwLock<T> {
    state: AtomicIsize,
    waiting_writers: AtomicUsize,
    r_waiters: WaiterQueue,
    w_waiters: WaiterQueue,
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
    waiter: WaitRegistration<'a>,
}

#[repr(C)]
pub struct AsyncRwLockWriteFuture<'a, T> {
    l: &'a AsyncRwLock<T>,
    waiter: WaitRegistration<'a>,
    counted: bool,
}

#[repr(C)]
pub struct AsyncRwLockOwnedReadGuard<T> {
    l: Arc<AsyncRwLock<T>>,
}

#[repr(C)]
pub struct AsyncRwLockOwnedWriteGuard<T> {
    l: Arc<AsyncRwLock<T>>,
}

impl<T> AsyncRwLock<T> {
    pub const fn new(value: T) -> Self {
        Self {
            state: AtomicIsize::new(0),
            waiting_writers: AtomicUsize::new(0),
            r_waiters: WaiterQueue::new(),
            w_waiters: WaiterQueue::new(),
            data: UnsafeCell::new(value),
        }
    }

    pub fn try_read(&self) -> Option<AsyncRwLockReadGuard<'_, T>> {
        if self.waiting_writers.load(Ordering::Acquire) != 0 {
            return None;
        }

        let mut cur = self.state.load(Ordering::Acquire);

        loop {
            if cur < 0 {
                return None;
            }

            if cur == isize::MAX {
                return None;
            }

            match self
                .state
                .compare_exchange(cur, cur + 1, Ordering::Acquire, Ordering::Relaxed)
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

    #[inline]
    pub fn read(&self) -> AsyncRwLockReadFuture<'_, T> {
        AsyncRwLockReadFuture {
            l: self,
            waiter: self.r_waiters.registration(),
        }
    }

    #[inline]
    pub fn write(&self) -> AsyncRwLockWriteFuture<'_, T> {
        AsyncRwLockWriteFuture {
            l: self,
            waiter: self.w_waiters.registration(),
            counted: false,
        }
    }

    fn read_unlock_and_wake_one(&self) {
        let prev = self.state.fetch_sub(1, Ordering::Release);
        debug_assert!(prev > 0);

        if prev == 1 {
            self.wake_after_state_became_free();
        }
    }

    fn write_unlock_and_wake_one(&self) {
        let prev = self.state.swap(0, Ordering::Release);
        debug_assert!(prev == -1);

        self.wake_after_state_became_free();
    }

    fn wake_after_state_became_free(&self) {
        if self.state.load(Ordering::Acquire) != 0 {
            return;
        }
        if self.waiting_writers.load(Ordering::Acquire) != 0 {
            self.w_waiters.notify_one();
        } else {
            self.r_waiters.notify_all();
        }
    }

    pub async fn read_owned(self: Arc<Self>) -> AsyncRwLockOwnedReadGuard<T> {
        let g = self.read().await;
        mem::forget(g);
        AsyncRwLockOwnedReadGuard { l: self }
    }

    pub async fn write_owned(self: Arc<Self>) -> AsyncRwLockOwnedWriteGuard<T> {
        let g = self.write().await;
        mem::forget(g);
        AsyncRwLockOwnedWriteGuard { l: self }
    }
}

impl<'a, T> Future for AsyncRwLockReadFuture<'a, T> {
    type Output = AsyncRwLockReadGuard<'a, T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };
        let mut waiter = unsafe { Pin::new_unchecked(&mut this.waiter) };
        if let Some(guard) = this.l.try_read() {
            waiter.as_mut().remove();
            return Poll::Ready(guard);
        }
        waiter.as_mut().register(cx.waker());
        if let Some(guard) = this.l.try_read() {
            waiter.as_mut().remove();
            return Poll::Ready(guard);
        }
        Poll::Pending
    }
}

impl<T> AsyncRwLockWriteFuture<'_, T> {
    fn unregister_waiter(&mut self) {
        unsafe { Pin::new_unchecked(&mut self.waiter) }.remove();
        if self.counted {
            self.counted = false;
            let previous = self.l.waiting_writers.fetch_sub(1, Ordering::AcqRel);
            debug_assert!(previous > 0);
        }
    }
}

impl<'a, T> Future for AsyncRwLockWriteFuture<'a, T> {
    type Output = AsyncRwLockWriteGuard<'a, T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };
        if let Some(guard) = this.l.try_write() {
            this.unregister_waiter();
            return Poll::Ready(guard);
        }
        if !this.counted {
            this.l.waiting_writers.fetch_add(1, Ordering::AcqRel);
            this.counted = true;
        }
        unsafe { Pin::new_unchecked(&mut this.waiter) }.register(cx.waker());
        if let Some(guard) = this.l.try_write() {
            this.unregister_waiter();
            return Poll::Ready(guard);
        }
        Poll::Pending
    }
}

impl<T> Drop for AsyncRwLockWriteFuture<'_, T> {
    fn drop(&mut self) {
        if self.counted {
            self.unregister_waiter();
            self.l.wake_after_state_became_free();
        }
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
        self.l.read_unlock_and_wake_one();
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
        self.l.write_unlock_and_wake_one();
    }
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

unsafe impl<T: Send + Sync> Send for AsyncRwLockOwnedReadGuard<T> {}
unsafe impl<T: Send + Sync> Sync for AsyncRwLockOwnedReadGuard<T> {}

unsafe impl<T: Send + Sync> Send for AsyncRwLockOwnedWriteGuard<T> {}
unsafe impl<T: Send + Sync> Sync for AsyncRwLockOwnedWriteGuard<T> {}
