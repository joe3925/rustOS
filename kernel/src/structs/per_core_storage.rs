use alloc::vec::Vec;
use hashbrown::HashMap;
use spin::{Mutex, MutexGuard};

pub struct PCS<T> {
    data: Mutex<PCSInner<T>>,
}

struct PCSInner<T> {
    items: Vec<T>,
    logical_id_map: HashMap<usize, usize>,
}

pub struct PCSGuard<'a, T> {
    _lock: MutexGuard<'a, PCSInner<T>>,
    value: *mut T,
}

impl<'a, T> core::ops::Deref for PCSGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.value }
    }
}
impl<'a, T> core::ops::DerefMut for PCSGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.value }
    }
}

pub struct PCSIter<'a, T> {
    _lock: MutexGuard<'a, PCSInner<T>>,
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
    _lock: MutexGuard<'a, PCSInner<T>>,
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
            data: Mutex::new(PCSInner {
                items: Vec::new(),
                logical_id_map: HashMap::new(),
            }),
        }
    }

    pub fn get(&self, logical_id: usize) -> Option<PCSGuard<'_, T>> {
        let lock = self.data.lock();
        let index = lock.logical_id_map.get(&logical_id).copied()?;
        let ptr = &lock.items[index] as *const T as *mut T;
        Some(PCSGuard {
            _lock: lock,
            value: ptr,
        })
    }

    pub fn set(&self, logical_id: usize, value: T) -> PCSGuard<'_, T> {
        let mut lock = self.data.lock();
        let index = match lock.logical_id_map.get(&logical_id) {
            Some(&idx) => {
                lock.items[idx] = value;
                idx
            }
            None => {
                let idx = lock.items.len();
                lock.items.push(value);
                lock.logical_id_map.insert(logical_id, idx);
                idx
            }
        };
        let ptr = &mut lock.items[index] as *mut T;
        PCSGuard {
            _lock: lock,
            value: ptr,
        }
    }

    pub fn iter(&self) -> PCSIter<'_, T> {
        let lock = self.data.lock();
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
        let lock = self.data.lock();
        let ptr = lock.items.as_ptr() as *mut T;
        let len = lock.items.len();
        PCSIterMut {
            _lock: lock,
            ptr,
            len,
            idx: 0,
        }
    }
}
