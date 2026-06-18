use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicIsize, Ordering};

const UNUSED: isize = 0;
const WRITING: isize = -1;

pub(crate) struct SendCell<T> {
    borrows: AtomicIsize,
    value: UnsafeCell<T>,
}

pub(crate) struct SendRef<'a, T> {
    cell: &'a SendCell<T>,
}

pub(crate) struct SendRefMut<'a, T> {
    cell: &'a SendCell<T>,
}

unsafe impl<T: Send> Send for SendCell<T> {}
unsafe impl<T: Send> Sync for SendCell<T> {}
unsafe impl<T: Send> Send for SendRef<'_, T> {}
unsafe impl<T: Send> Send for SendRefMut<'_, T> {}

impl<T> SendCell<T> {
    pub(crate) const fn new(value: T) -> Self {
        Self {
            borrows: AtomicIsize::new(UNUSED),
            value: UnsafeCell::new(value),
        }
    }

    pub(crate) fn borrow(&self) -> SendRef<'_, T> {
        self.borrows
            .compare_exchange(UNUSED, 1, Ordering::Acquire, Ordering::Relaxed)
            .expect("SendCell already borrowed");

        SendRef { cell: self }
    }

    pub(crate) fn borrow_mut(&self) -> SendRefMut<'_, T> {
        self.borrows
            .compare_exchange(UNUSED, WRITING, Ordering::Acquire, Ordering::Relaxed)
            .expect("SendCell already borrowed");

        SendRefMut { cell: self }
    }
}

impl<T: Copy> SendCell<T> {
    pub(crate) fn get(&self) -> T {
        *self.borrow()
    }

    pub(crate) fn set(&self, value: T) {
        *self.borrow_mut() = value;
    }
}

impl<T> Deref for SendRef<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.cell.value.get() }
    }
}

impl<T> Drop for SendRef<'_, T> {
    fn drop(&mut self) {
        let prev = self.cell.borrows.swap(UNUSED, Ordering::Release);
        debug_assert_eq!(prev, 1);
    }
}

impl<T> Deref for SendRefMut<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.cell.value.get() }
    }
}

impl<T> DerefMut for SendRefMut<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.cell.value.get() }
    }
}

impl<T> Drop for SendRefMut<'_, T> {
    fn drop(&mut self) {
        let prev = self.cell.borrows.swap(UNUSED, Ordering::Release);
        debug_assert_eq!(prev, WRITING);
    }
}
