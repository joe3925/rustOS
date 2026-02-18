use core::{
    mem::ManuallyDrop,
    ops::{Deref, DerefMut},
};

use spin::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
use x86_64::instructions::interrupts;

/// Opaque handle type - the actual struct is defined in kernel
/// This is a zero-sized marker type used for type safety at FFI boundaries.
#[repr(C)]
pub struct IrqHandleOpaque {
    _opaque: [u8; 0],
}

/// Raw pointer to an IRQ handle
pub type IrqHandlePtr = *mut IrqHandleOpaque;

/// ISR function signature
/// Returns true if the interrupt was claimed/handled by this handler.
///
/// # Arguments
/// * `vector` - The interrupt vector number
/// * `cpu` - The CPU ID that received the interrupt
/// * `frame` - Pointer to the interrupt stack frame
/// * `handle` - The IRQ handle for signaling waiters
/// * `ctx` - User-provided context value
pub type IrqIsrFn = extern "win64" fn(
    vector: u8,
    cpu: u32,
    frame: *mut x86_64::structures::idt::InterruptStackFrame,
    handle: IrqHandlePtr,
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
