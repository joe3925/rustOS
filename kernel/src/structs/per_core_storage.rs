use alloc::vec::Vec;
use spin::{RwLock, RwLockReadGuard, RwLockWriteGuard};

pub struct PCS<T> {
    data: RwLock<PCSInner<T>>,
}

struct PCSInner<T> {
    items: Vec<T>,
    // logical_id -> Some(index into items) or None if not present
    logical_id_map: Vec<Option<usize>>,
}

pub struct PCSGuard<'a, T> {
    _lock: RwLockReadGuard<'a, PCSInner<T>>,
    value: *const T,
}
impl<'a, T> core::ops::Deref for PCSGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.value }
    }
}

pub struct PCSWriteGuard<'a, T> {
    _lock: RwLockWriteGuard<'a, PCSInner<T>>,
    value: *mut T,
}
impl<'a, T> core::ops::Deref for PCSWriteGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.value }
    }
}
impl<'a, T> core::ops::DerefMut for PCSWriteGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.value }
    }
}

pub struct PCSIter<'a, T> {
    _lock: RwLockReadGuard<'a, PCSInner<T>>,
    ptr: *const T,
    len: usize,
    idx: usize,
}
impl<'a, T> Iterator for PCSIter<'a, T> {
    type Item = &'a T;
    fn next(&mut self) -> Option<&'a T> {
        if self.idx >= self.len {
            return None;
        }
        let r = unsafe { &*self.ptr.add(self.idx) };
        self.idx += 1;
        Some(r)
    }
}

pub struct PCSIterMut<'a, T> {
    _lock: RwLockWriteGuard<'a, PCSInner<T>>,
    ptr: *mut T,
    len: usize,
    idx: usize,
}
impl<'a, T> Iterator for PCSIterMut<'a, T> {
    type Item = &'a mut T;
    fn next(&mut self) -> Option<&'a mut T> {
        if self.idx >= self.len {
            return None;
        }
        let r = unsafe { &mut *self.ptr.add(self.idx) };
        self.idx += 1;
        Some(r)
    }
}

impl<T> PCS<T> {
    pub fn new() -> Self {
        Self {
            data: RwLock::new(PCSInner {
                items: Vec::new(),
                logical_id_map: Vec::new(),
            }),
        }
    }

    pub fn get(&self, logical_id: usize) -> Option<PCSGuard<'_, T>> {
        let lock = self.data.read();
        if logical_id >= lock.logical_id_map.len() {
            return None;
        }
        let index = lock.logical_id_map[logical_id]?; // None => no entry
        let ptr = &lock.items[index] as *const T;
        Some(PCSGuard {
            _lock: lock,
            value: ptr,
        })
    }

    pub fn get_mut(&self, logical_id: usize) -> Option<PCSWriteGuard<'_, T>> {
        let mut lock = self.data.write();
        if logical_id >= lock.logical_id_map.len() {
            return None;
        }
        let index = lock.logical_id_map[logical_id]?;
        let ptr = &mut lock.items[index] as *mut T;
        Some(PCSWriteGuard {
            _lock: lock,
            value: ptr,
        })
    }

    pub fn set(&self, logical_id: usize, value: T) -> PCSWriteGuard<'_, T> {
        let mut lock = self.data.write();

        if logical_id >= lock.logical_id_map.len() {
            lock.logical_id_map.resize_with(logical_id + 1, || None);
        }

        let index = match lock.logical_id_map[logical_id] {
            Some(idx) => {
                lock.items[idx] = value;
                idx
            }
            None => {
                let idx = lock.items.len();
                lock.items.push(value);
                lock.logical_id_map[logical_id] = Some(idx);
                idx
            }
        };

        let ptr = &mut lock.items[index] as *mut T;
        PCSWriteGuard {
            _lock: lock,
            value: ptr,
        }
    }

    pub fn iter(&self) -> PCSIter<'_, T> {
        let lock = self.data.read();
        let ptr = lock.items.as_ptr();
        let len = lock.items.len();
        PCSIter {
            _lock: lock,
            ptr,
            len,
            idx: 0,
        }
    }

    pub fn iter_mut(&self) -> PCSIterMut<'_, T> {
        let mut lock = self.data.write();
        let ptr = lock.items.as_mut_ptr();
        let len = lock.items.len();
        PCSIterMut {
            _lock: lock,
            ptr,
            len,
            idx: 0,
        }
    }
}
