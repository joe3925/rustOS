use core::mem::ManuallyDrop;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

pub type IrqInterruptsEnabled = extern "C" fn() -> bool;
pub type IrqInterruptsSet = extern "C" fn();

static IRQ_INTERRUPTS_ENABLED: AtomicUsize = AtomicUsize::new(0);
static IRQ_INTERRUPTS_DISABLE: AtomicUsize = AtomicUsize::new(0);
static IRQ_INTERRUPTS_ENABLE: AtomicUsize = AtomicUsize::new(0);
static IRQ_INTERRUPTS_ENABLE_AND_HLT: AtomicUsize = AtomicUsize::new(0);

pub fn set_irq_interrupt_control(
    enabled: IrqInterruptsEnabled,
    disable: IrqInterruptsSet,
    enable: IrqInterruptsSet,
    enable_and_hlt: IrqInterruptsSet,
) {
    IRQ_INTERRUPTS_ENABLED.store(enabled as usize, Ordering::Release);
    IRQ_INTERRUPTS_DISABLE.store(disable as usize, Ordering::Release);
    IRQ_INTERRUPTS_ENABLE.store(enable as usize, Ordering::Release);
    IRQ_INTERRUPTS_ENABLE_AND_HLT.store(enable_and_hlt as usize, Ordering::Release);
}

#[inline(always)]
fn interrupts_enabled() -> bool {
    let enabled = IRQ_INTERRUPTS_ENABLED.load(Ordering::Acquire);

    if enabled == 0 {
        return false;
    }

    let enabled: IrqInterruptsEnabled = unsafe { core::mem::transmute(enabled) };
    enabled()
}

#[inline(always)]
fn interrupts_disable() {
    let disable = IRQ_INTERRUPTS_DISABLE.load(Ordering::Acquire);

    if disable == 0 {
        return;
    }

    let disable: IrqInterruptsSet = unsafe { core::mem::transmute(disable) };
    disable();
}

#[inline(always)]
fn interrupts_enable() {
    let enable = IRQ_INTERRUPTS_ENABLE.load(Ordering::Acquire);

    if enable == 0 {
        return;
    }

    let enable: IrqInterruptsSet = unsafe { core::mem::transmute(enable) };
    enable();
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
        let restore_interrupts = interrupts_enabled();

        loop {
            if restore_interrupts {
                interrupts_disable();
            }

            if let Some(guard) = self.inner.try_lock() {
                return IrqSafeMutexGuard {
                    guard: ManuallyDrop::new(guard),
                    restore_interrupts,
                };
            }

            core::hint::spin_loop();
        }
    }

    #[inline(always)]
    pub fn try_lock(&self) -> Option<IrqSafeMutexGuard<'_, T>> {
        let restore_interrupts = interrupts_enabled();

        if restore_interrupts {
            interrupts_disable();
        }

        match self.inner.try_lock() {
            Some(guard) => Some(IrqSafeMutexGuard {
                guard: ManuallyDrop::new(guard),
                restore_interrupts,
            }),
            None => {
                if restore_interrupts {
                    interrupts_enable();
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
        unsafe {
            ManuallyDrop::drop(&mut self.guard);
        }

        if self.restore_interrupts {
            interrupts_enable();
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
        let restore_interrupts = interrupts_enabled();

        loop {
            if restore_interrupts {
                interrupts_disable();
            }

            if let Some(guard) = self.inner.try_read() {
                return IrqSafeRwLockReadGuard {
                    guard: ManuallyDrop::new(guard),
                    restore_interrupts,
                };
            }

            core::hint::spin_loop();
        }
    }

    #[inline(always)]
    pub fn try_read(&self) -> Option<IrqSafeRwLockReadGuard<'_, T>> {
        let restore_interrupts = interrupts_enabled();

        if restore_interrupts {
            interrupts_disable();
        }

        match self.inner.try_read() {
            Some(guard) => Some(IrqSafeRwLockReadGuard {
                guard: ManuallyDrop::new(guard),
                restore_interrupts,
            }),
            None => {
                if restore_interrupts {
                    interrupts_enable();
                }

                None
            }
        }
    }

    #[inline(always)]
    pub fn write(&self) -> IrqSafeRwLockWriteGuard<'_, T> {
        let restore_interrupts = interrupts_enabled();

        loop {
            if restore_interrupts {
                interrupts_disable();
            }

            if let Some(guard) = self.inner.try_write() {
                return IrqSafeRwLockWriteGuard {
                    guard: ManuallyDrop::new(guard),
                    restore_interrupts,
                };
            }

            core::hint::spin_loop();
        }
    }

    #[inline(always)]
    pub fn try_write(&self) -> Option<IrqSafeRwLockWriteGuard<'_, T>> {
        let restore_interrupts = interrupts_enabled();

        if restore_interrupts {
            interrupts_disable();
        }

        match self.inner.try_write() {
            Some(guard) => Some(IrqSafeRwLockWriteGuard {
                guard: ManuallyDrop::new(guard),
                restore_interrupts,
            }),
            None => {
                if restore_interrupts {
                    interrupts_enable();
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
        unsafe {
            ManuallyDrop::drop(&mut self.guard);
        }

        if self.restore_interrupts {
            interrupts_enable();
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
        unsafe {
            ManuallyDrop::drop(&mut self.guard);
        }

        if self.restore_interrupts {
            interrupts_enable();
        }
    }
}
