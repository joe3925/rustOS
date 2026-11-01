use core::marker::PhantomData;
use core::mem::ManuallyDrop;
use core::ops::{Deref, DerefMut};
use spin::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::platform::contract::Platform;

pub struct IrqSafeMutex<P: Platform, T> {
    inner: Mutex<T>,
    _platform: PhantomData<P>,
}

pub struct IrqSafeMutexGuard<'a, P: Platform, T> {
    guard: ManuallyDrop<MutexGuard<'a, T>>,
    restore_interrupts: bool,
    _platform: PhantomData<P>,
}

impl<P: Platform, T> IrqSafeMutex<P, T> {
    pub const fn new(value: T) -> Self {
        Self {
            inner: Mutex::new(value),
            _platform: PhantomData,
        }
    }

    #[inline(always)]
    pub fn lock(&self) -> IrqSafeMutexGuard<'_, P, T> {
        let restore_interrupts = P::interrupts_enabled();

        loop {
            if restore_interrupts {
                P::disable_interrupts();
            }

            if let Some(guard) = self.inner.try_lock() {
                return IrqSafeMutexGuard {
                    guard: ManuallyDrop::new(guard),
                    restore_interrupts,
                    _platform: PhantomData,
                };
            }

            core::hint::spin_loop();
        }
    }

    #[inline(always)]
    pub fn try_lock(&self) -> Option<IrqSafeMutexGuard<'_, P, T>> {
        let restore_interrupts = P::interrupts_enabled();

        if restore_interrupts {
            P::disable_interrupts();
        }

        match self.inner.try_lock() {
            Some(guard) => Some(IrqSafeMutexGuard {
                guard: ManuallyDrop::new(guard),
                restore_interrupts,
                _platform: PhantomData,
            }),
            None => {
                if restore_interrupts {
                    P::enable_interrupts();
                }

                None
            }
        }
    }
}

impl<'a, P: Platform, T> Deref for IrqSafeMutexGuard<'a, P, T> {
    type Target = T;

    #[inline(always)]
    fn deref(&self) -> &T {
        &self.guard
    }
}

impl<'a, P: Platform, T> DerefMut for IrqSafeMutexGuard<'a, P, T> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut T {
        &mut self.guard
    }
}

impl<'a, P: Platform, T> Drop for IrqSafeMutexGuard<'a, P, T> {
    #[inline(always)]
    fn drop(&mut self) {
        unsafe {
            ManuallyDrop::drop(&mut self.guard);
        }

        if self.restore_interrupts {
            P::enable_interrupts();
        }
    }
}

pub struct IrqSafeRwLock<P: Platform, T> {
    inner: RwLock<T>,
    _platform: PhantomData<P>,
}

pub struct IrqSafeRwLockReadGuard<'a, P: Platform, T> {
    guard: ManuallyDrop<RwLockReadGuard<'a, T>>,
    restore_interrupts: bool,
    _platform: PhantomData<P>,
}

pub struct IrqSafeRwLockWriteGuard<'a, P: Platform, T> {
    guard: ManuallyDrop<RwLockWriteGuard<'a, T>>,
    restore_interrupts: bool,
    _platform: PhantomData<P>,
}

impl<P: Platform, T> IrqSafeRwLock<P, T> {
    #[inline(always)]
    pub const fn new(value: T) -> Self {
        Self {
            inner: RwLock::new(value),
            _platform: PhantomData,
        }
    }

    #[inline(always)]
    pub fn read(&self) -> IrqSafeRwLockReadGuard<'_, P, T> {
        let restore_interrupts = P::interrupts_enabled();

        loop {
            if restore_interrupts {
                P::disable_interrupts();
            }

            if let Some(guard) = self.inner.try_read() {
                return IrqSafeRwLockReadGuard {
                    guard: ManuallyDrop::new(guard),
                    restore_interrupts,
                    _platform: PhantomData,
                };
            }

            core::hint::spin_loop();
        }
    }

    #[inline(always)]
    pub fn try_read(&self) -> Option<IrqSafeRwLockReadGuard<'_, P, T>> {
        let restore_interrupts = P::interrupts_enabled();

        if restore_interrupts {
            P::disable_interrupts();
        }

        match self.inner.try_read() {
            Some(guard) => Some(IrqSafeRwLockReadGuard {
                guard: ManuallyDrop::new(guard),
                restore_interrupts,
                _platform: PhantomData,
            }),
            None => {
                if restore_interrupts {
                    P::enable_interrupts();
                }

                None
            }
        }
    }

    #[inline(always)]
    pub fn write(&self) -> IrqSafeRwLockWriteGuard<'_, P, T> {
        let restore_interrupts = P::interrupts_enabled();

        loop {
            if restore_interrupts {
                P::disable_interrupts();
            }

            if let Some(guard) = self.inner.try_write() {
                return IrqSafeRwLockWriteGuard {
                    guard: ManuallyDrop::new(guard),
                    restore_interrupts,
                    _platform: PhantomData,
                };
            }

            core::hint::spin_loop();
        }
    }

    #[inline(always)]
    pub fn try_write(&self) -> Option<IrqSafeRwLockWriteGuard<'_, P, T>> {
        let restore_interrupts = P::interrupts_enabled();

        if restore_interrupts {
            P::disable_interrupts();
        }

        match self.inner.try_write() {
            Some(guard) => Some(IrqSafeRwLockWriteGuard {
                guard: ManuallyDrop::new(guard),
                restore_interrupts,
                _platform: PhantomData,
            }),
            None => {
                if restore_interrupts {
                    P::enable_interrupts();
                }

                None
            }
        }
    }
}

impl<'a, P: Platform, T> Deref for IrqSafeRwLockReadGuard<'a, P, T> {
    type Target = T;

    #[inline(always)]
    fn deref(&self) -> &T {
        &self.guard
    }
}

impl<'a, P: Platform, T> Drop for IrqSafeRwLockReadGuard<'a, P, T> {
    #[inline(always)]
    fn drop(&mut self) {
        unsafe {
            ManuallyDrop::drop(&mut self.guard);
        }

        if self.restore_interrupts {
            P::enable_interrupts();
        }
    }
}

impl<'a, P: Platform, T> Deref for IrqSafeRwLockWriteGuard<'a, P, T> {
    type Target = T;

    #[inline(always)]
    fn deref(&self) -> &T {
        &self.guard
    }
}

impl<'a, P: Platform, T> DerefMut for IrqSafeRwLockWriteGuard<'a, P, T> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut T {
        &mut self.guard
    }
}

impl<'a, P: Platform, T> Drop for IrqSafeRwLockWriteGuard<'a, P, T> {
    #[inline(always)]
    fn drop(&mut self) {
        unsafe {
            ManuallyDrop::drop(&mut self.guard);
        }

        if self.restore_interrupts {
            P::enable_interrupts();
        }
    }
}
