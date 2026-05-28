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

use core::mem;
use core::sync::atomic::AtomicUsize;

struct Waiter {
    id: usize,
    waker: Waker,
}

fn push_or_update_waiter(list: &mut Vec<Waiter>, id: usize, waker: &Waker) {
    for waiter in list.iter_mut() {
        if waiter.id == id {
            waiter.waker = waker.clone();
            return;
        }
    }

    list.push(Waiter {
        id,
        waker: waker.clone(),
    });
}

fn remove_waiter(list: &mut Vec<Waiter>, id: usize) -> bool {
    let mut i = 0usize;
    while i < list.len() {
        if list[i].id == id {
            list.swap_remove(i);
            return true;
        }
        i += 1;
    }

    false
}

fn pop_waiter(list: &mut Vec<Waiter>) -> Option<Waker> {
    list.pop().map(|waiter| waiter.waker)
}

#[repr(C)]
pub struct AsyncMutex<T> {
    locked: AtomicBool,
    waiters: SpinMutex<Vec<Waiter>>,
    next_waiter_id: AtomicUsize,
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
    waiter_id: usize,
    registered: bool,
}

#[repr(C)]
pub struct AsyncMutexOwnedGuard<T> {
    m: Arc<AsyncMutex<T>>,
}

impl<T> AsyncMutex<T> {
    pub const fn new(value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            waiters: SpinMutex::new(Vec::new()),
            next_waiter_id: AtomicUsize::new(0),
            data: UnsafeCell::new(value),
        }
    }

    #[inline]
    pub fn as_ptr(&self) -> *mut T {
        self.data.get()
    }

    #[inline]
    fn next_waiter_id(&self) -> usize {
        loop {
            let id = self
                .next_waiter_id
                .fetch_add(1, Ordering::Relaxed)
                .wrapping_add(1);

            if id != 0 {
                return id;
            }
        }
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
            waiter_id: 0,
            registered: false,
        }
    }

    #[inline]
    pub fn lock_blocking(&self) -> AsyncMutexGuard<'_, T> {
        loop {
            if let Some(g) = self.try_lock() {
                return g;
            }

            spin_loop();
        }
    }

    #[inline]
    fn unlock(&self) {
        self.unlock_and_wake_one();
    }

    pub fn unlock_and_wake_one(&self) {
        let was_locked = self.locked.swap(false, Ordering::Release);
        debug_assert!(was_locked);

        self.wake_one_waiter();
    }

    fn wake_one_waiter(&self) -> bool {
        let waiter = {
            let mut waiters = self.waiters.lock();
            pop_waiter(&mut waiters)
        };

        if let Some(waker) = waiter {
            waker.wake();
            true
        } else {
            false
        }
    }

    fn wake_one_if_unlocked(&self) {
        if !self.locked.load(Ordering::Acquire) {
            self.wake_one_waiter();
        }
    }

    pub async fn lock_owned(self: Arc<Self>) -> AsyncMutexOwnedGuard<T> {
        let g = self.lock().await;
        mem::forget(g);
        AsyncMutexOwnedGuard { m: self }
    }
}

impl<'a, T> AsyncMutexLockFuture<'a, T> {
    fn register_waiter(&mut self, cx: &Context<'_>) {
        if self.waiter_id == 0 {
            self.waiter_id = self.m.next_waiter_id();
        }

        let mut waiters = self.m.waiters.lock();
        push_or_update_waiter(&mut waiters, self.waiter_id, cx.waker());
        self.registered = true;
    }

    fn unregister_waiter(&mut self) -> bool {
        if !self.registered {
            return false;
        }

        let removed = {
            let mut waiters = self.m.waiters.lock();
            remove_waiter(&mut waiters, self.waiter_id)
        };

        self.registered = false;
        removed
    }
}

impl<'a, T> Future for AsyncMutexLockFuture<'a, T> {
    type Output = AsyncMutexGuard<'a, T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        if let Some(g) = this.m.try_lock() {
            this.unregister_waiter();
            return Poll::Ready(g);
        }

        this.register_waiter(cx);

        if let Some(g) = this.m.try_lock() {
            this.unregister_waiter();
            return Poll::Ready(g);
        }

        Poll::Pending
    }
}

impl<'a, T> Drop for AsyncMutexLockFuture<'a, T> {
    fn drop(&mut self) {
        if self.registered {
            let removed = self.unregister_waiter();

            if !removed {
                self.m.wake_one_if_unlocked();
            }
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
        self.m.unlock();
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
    r_waiters: SpinMutex<Vec<Waiter>>,
    w_waiters: SpinMutex<Vec<Waiter>>,
    next_waiter_id: AtomicUsize,
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
    waiter_id: usize,
    registered: bool,
}

#[repr(C)]
pub struct AsyncRwLockWriteFuture<'a, T> {
    l: &'a AsyncRwLock<T>,
    waiter_id: usize,
    registered: bool,
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
            r_waiters: SpinMutex::new(Vec::new()),
            w_waiters: SpinMutex::new(Vec::new()),
            next_waiter_id: AtomicUsize::new(0),
            data: UnsafeCell::new(value),
        }
    }

    #[inline]
    fn next_waiter_id(&self) -> usize {
        loop {
            let id = self
                .next_waiter_id
                .fetch_add(1, Ordering::Relaxed)
                .wrapping_add(1);

            if id != 0 {
                return id;
            }
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
            waiter_id: 0,
            registered: false,
        }
    }

    #[inline]
    pub fn write(&self) -> AsyncRwLockWriteFuture<'_, T> {
        AsyncRwLockWriteFuture {
            l: self,
            waiter_id: 0,
            registered: false,
        }
    }

    #[inline]
    fn read_unlock(&self) {
        self.read_unlock_and_wake_one();
    }

    #[inline]
    fn write_unlock(&self) {
        self.write_unlock_and_wake_one();
    }

    pub fn read_unlock_and_wake_one(&self) {
        let prev = self.state.fetch_sub(1, Ordering::Release);
        debug_assert!(prev > 0);

        if prev == 1 {
            self.wake_after_state_became_free();
        }
    }

    pub fn write_unlock_and_wake_one(&self) {
        let prev = self.state.swap(0, Ordering::Release);
        debug_assert!(prev == -1);

        self.wake_after_state_became_free();
    }

    fn wake_after_state_became_free(&self) {
        if self.state.load(Ordering::Acquire) != 0 {
            return;
        }

        if self.wake_one_writer() {
            return;
        }

        if self.waiting_writers.load(Ordering::Acquire) == 0 {
            self.wake_all_readers();
        }
    }

    fn wake_one_writer(&self) -> bool {
        let waiter = {
            let mut waiters = self.w_waiters.lock();
            pop_waiter(&mut waiters)
        };

        if let Some(waker) = waiter {
            waker.wake();
            true
        } else {
            false
        }
    }

    fn wake_all_readers(&self) -> bool {
        let waiters = {
            let mut waiters = self.r_waiters.lock();
            mem::take(&mut *waiters)
        };

        if waiters.is_empty() {
            return false;
        }

        for waiter in waiters {
            waiter.waker.wake();
        }

        true
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

impl<'a, T> AsyncRwLockReadFuture<'a, T> {
    fn register_waiter(&mut self, cx: &Context<'_>) {
        if self.waiter_id == 0 {
            self.waiter_id = self.l.next_waiter_id();
        }

        let mut waiters = self.l.r_waiters.lock();
        push_or_update_waiter(&mut waiters, self.waiter_id, cx.waker());
        self.registered = true;
    }

    fn unregister_waiter(&mut self) -> bool {
        if !self.registered {
            return false;
        }

        let removed = {
            let mut waiters = self.l.r_waiters.lock();
            remove_waiter(&mut waiters, self.waiter_id)
        };

        self.registered = false;
        removed
    }
}

impl<'a, T> Future for AsyncRwLockReadFuture<'a, T> {
    type Output = AsyncRwLockReadGuard<'a, T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        if let Some(g) = this.l.try_read() {
            this.unregister_waiter();
            return Poll::Ready(g);
        }

        this.register_waiter(cx);

        if let Some(g) = this.l.try_read() {
            this.unregister_waiter();
            return Poll::Ready(g);
        }

        Poll::Pending
    }
}

impl<'a, T> Drop for AsyncRwLockReadFuture<'a, T> {
    fn drop(&mut self) {
        self.unregister_waiter();
    }
}

impl<'a, T> AsyncRwLockWriteFuture<'a, T> {
    fn register_waiter(&mut self, cx: &Context<'_>) {
        if self.waiter_id == 0 {
            self.waiter_id = self.l.next_waiter_id();
        }

        let was_registered = self.registered;

        {
            let mut waiters = self.l.w_waiters.lock();
            push_or_update_waiter(&mut waiters, self.waiter_id, cx.waker());
        }

        if !was_registered {
            self.registered = true;
            self.l.waiting_writers.fetch_add(1, Ordering::AcqRel);
        }
    }

    fn unregister_waiter(&mut self) -> bool {
        if !self.registered {
            return false;
        }

        let removed = {
            let mut waiters = self.l.w_waiters.lock();
            remove_waiter(&mut waiters, self.waiter_id)
        };

        self.registered = false;

        let prev = self.l.waiting_writers.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(prev > 0);

        removed
    }
}

impl<'a, T> Future for AsyncRwLockWriteFuture<'a, T> {
    type Output = AsyncRwLockWriteGuard<'a, T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        if let Some(g) = this.l.try_write() {
            this.unregister_waiter();
            return Poll::Ready(g);
        }

        this.register_waiter(cx);

        if let Some(g) = this.l.try_write() {
            this.unregister_waiter();
            return Poll::Ready(g);
        }

        Poll::Pending
    }
}

impl<'a, T> Drop for AsyncRwLockWriteFuture<'a, T> {
    fn drop(&mut self) {
        if self.registered {
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
