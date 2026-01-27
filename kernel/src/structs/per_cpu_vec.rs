use alloc::vec::Vec;
use core::cell::UnsafeCell;

use crate::drivers::interrupt_index::current_cpu_id;

/// Per-CPU storage backed by a Vec.
///
/// Safe because `.get()` uses `current_cpu_id()` so each CPU only accesses its own slot.
/// No locks needed for per-CPU access after initialization.
pub struct PerCpuVec<T> {
    data: UnsafeCell<Vec<T>>,
}

unsafe impl<T: Send> Send for PerCpuVec<T> {}
unsafe impl<T: Send> Sync for PerCpuVec<T> {}

impl<T> PerCpuVec<T> {
    pub const fn new() -> Self {
        Self {
            data: UnsafeCell::new(Vec::new()),
        }
    }

    /// Initialize storage for n CPUs. Must be called before any get() calls.
    pub fn init(&self, n: usize, f: impl Fn() -> T) {
        let v = unsafe { &mut *self.data.get() };
        v.clear();
        for _ in 0..n {
            v.push(f());
        }
    }

    /// Get reference to current CPU's slot (uses current_cpu_id())
    #[inline]
    pub fn get(&self) -> &T {
        let id = current_cpu_id();
        unsafe { &(&*self.data.get())[id] }
    }

    /// Get mutable reference to current CPU's slot
    #[inline]
    pub fn get_mut(&self) -> &mut T {
        let id = current_cpu_id();
        unsafe { &mut (&mut *self.data.get())[id] }
    }

    /// Get by explicit ID (for cases like GDT init where LAPIC ID is used)
    #[inline]
    pub fn get_by_id(&self, id: usize) -> &T {
        unsafe { &(&*self.data.get())[id] }
    }

    /// Get mutable reference by explicit ID
    #[inline]
    pub fn get_mut_by_id(&self, id: usize) -> &mut T {
        unsafe { &mut (&mut *self.data.get())[id] }
    }

    /// Unsafe iterator - caller ensures no concurrent modification
    pub unsafe fn iter(&self) -> impl Iterator<Item = &T> {
        (*self.data.get()).iter()
    }

    /// Set value at explicit ID, growing the vec if necessary.
    /// Useful for cases where IDs may not be sequential or pre-initialized.
    pub fn set_by_id(&self, id: usize, value: T, default: impl Fn() -> T) {
        let v = unsafe { &mut *self.data.get() };
        if id >= v.len() {
            v.resize_with(id + 1, default);
        }
        v[id] = value;
    }
}
