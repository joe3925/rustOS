use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, AtomicUsize, Ordering};

#[repr(C)]
struct TreiberNode<T> {
    data: UnsafeCell<MaybeUninit<T>>,
    next: AtomicPtr<TreiberNode<T>>,
    retired_next: AtomicPtr<TreiberNode<T>>,
}

#[repr(C)]
pub struct TreiberStack<T> {
    head: AtomicPtr<TreiberNode<T>>,
    retired: AtomicPtr<TreiberNode<T>>,
    len: AtomicUsize,
}

struct DetachedTreiberValues<'a, T> {
    stack: &'a TreiberStack<T>,
    values: Vec<T>,
}

impl<T> Drop for DetachedTreiberValues<'_, T> {
    fn drop(&mut self) {
        let count = self.values.len();
        let mut head = ptr::null_mut();
        let mut tail: *mut TreiberNode<T> = ptr::null_mut();

        while let Some(data) = self.values.pop() {
            let node = Box::into_raw(Box::new(TreiberNode {
                data: UnsafeCell::new(MaybeUninit::new(data)),
                next: AtomicPtr::new(head),
                retired_next: AtomicPtr::new(ptr::null_mut()),
            }));
            if tail.is_null() {
                tail = node;
            }
            head = node;
        }

        if count != 0 {
            self.stack.len.fetch_add(count, Ordering::Release);
            unsafe { TreiberStack::push_raw(&self.stack.head, head, tail) };
        }
    }
}

unsafe impl<T: Send> Send for TreiberStack<T> {}
unsafe impl<T: Send> Sync for TreiberStack<T> {}

impl<T> TreiberStack<T> {
    pub const fn new() -> Self {
        Self {
            head: AtomicPtr::new(ptr::null_mut()),
            retired: AtomicPtr::new(ptr::null_mut()),
            len: AtomicUsize::new(0),
        }
    }

    pub fn len(&self) -> usize {
        self.len.load(Ordering::Acquire)
    }

    pub fn is_empty(&self) -> bool {
        self.head.load(Ordering::Acquire).is_null()
    }

    pub fn push(&self, data: T) {
        let node = Box::into_raw(Box::new(TreiberNode {
            data: UnsafeCell::new(MaybeUninit::new(data)),
            next: AtomicPtr::new(ptr::null_mut()),
            retired_next: AtomicPtr::new(ptr::null_mut()),
        }));

        self.len.fetch_add(1, Ordering::Release);
        unsafe { Self::push_raw(&self.head, node, node) };
    }

    pub fn pop(&self) -> Option<T> {
        let node = loop {
            let head = self.head.load(Ordering::Acquire);
            if head.is_null() {
                return None;
            }

            let next = unsafe { (*head).next.load(Ordering::Relaxed) };
            if self
                .head
                .compare_exchange_weak(head, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                break head;
            }
        };

        self.len.fetch_sub(1, Ordering::AcqRel);

        let data = unsafe {
            let data = (*(*node).data.get()).assume_init_read();
            self.retire_node(node);
            data
        };

        Some(data)
    }

    pub fn drain_fifo<F>(&self, mut f: F)
    where
        F: FnMut(T),
    {
        let mut detached = self.detach_values();
        while let Some(data) = detached.values.pop() {
            f(data);
        }
    }

    pub fn remove_one_by<F>(&self, mut pred: F) -> Option<T>
    where
        F: FnMut(&T) -> bool,
    {
        let mut detached = self.detach_values();
        let index = detached.values.iter().position(&mut pred)?;
        Some(detached.values.remove(index))
    }

    fn detach_values(&self) -> DetachedTreiberValues<'_, T> {
        let mut node = self.head.swap(ptr::null_mut(), Ordering::AcqRel);
        let mut detached = DetachedTreiberValues {
            stack: self,
            values: Vec::new(),
        };

        while !node.is_null() {
            unsafe {
                let next = (*node).next.load(Ordering::Relaxed);
                detached.values.push((*(*node).data.get()).assume_init_read());
                self.retire_node(node);
                node = next;
            }
        }

        self.len.fetch_sub(detached.values.len(), Ordering::AcqRel);
        detached
    }

    unsafe fn push_raw(
        stack: &AtomicPtr<TreiberNode<T>>,
        node: *mut TreiberNode<T>,
        tail: *mut TreiberNode<T>,
    ) {
        loop {
            let head = stack.load(Ordering::Acquire);

            unsafe {
                (*tail).next.store(head, Ordering::Relaxed);
            }

            if stack
                .compare_exchange_weak(head, node, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
        }
    }

    unsafe fn retire_node(&self, node: *mut TreiberNode<T>) {
        loop {
            let head = self.retired.load(Ordering::Acquire);
            unsafe {
                (*node).retired_next.store(head, Ordering::Relaxed);
            }
            if self
                .retired
                .compare_exchange_weak(head, node, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
        }
    }
}

impl<T> Drop for TreiberStack<T> {
    fn drop(&mut self) {
        while self.pop().is_some() {}

        let mut node = *self.retired.get_mut();
        while !node.is_null() {
            unsafe {
                let next = (*node).retired_next.load(Ordering::Relaxed);
                drop(Box::from_raw(node));
                node = next;
            }
        }
    }
}

impl<T> Default for TreiberStack<T> {
    fn default() -> Self {
        Self::new()
    }
}

const NULL_INDEX: u32 = u32::MAX;

#[repr(C)]
struct BoundedTreiberNode<T> {
    data: UnsafeCell<MaybeUninit<T>>,
    next: AtomicU32,
}

#[repr(C)]
pub struct BoundedTreiberStack<T> {
    head: AtomicU64,
    free: AtomicU64,
    nodes: Vec<BoundedTreiberNode<T>>,
    len: AtomicUsize,
}

unsafe impl<T: Send> Send for BoundedTreiberStack<T> {}
unsafe impl<T: Send> Sync for BoundedTreiberStack<T> {}

impl<T> BoundedTreiberStack<T> {
    pub fn new(capacity: usize) -> Self {
        Self::try_new(capacity).expect("failed to allocate BoundedTreiberStack")
    }

    pub fn try_new(capacity: usize) -> Result<Self, alloc::collections::TryReserveError> {
        if capacity >= NULL_INDEX as usize {
            panic!("BoundedTreiberStack capacity too large");
        }

        let mut nodes = Vec::new();
        nodes.try_reserve_exact(capacity)?;

        let mut i = 0usize;
        while i < capacity {
            let next = if i + 1 < capacity {
                (i + 1) as u32
            } else {
                NULL_INDEX
            };

            nodes.push(BoundedTreiberNode {
                data: UnsafeCell::new(MaybeUninit::uninit()),
                next: AtomicU32::new(next),
            });

            i += 1;
        }

        let free = if capacity == 0 { NULL_INDEX } else { 0 };

        Ok(Self {
            head: AtomicU64::new(Self::pack(NULL_INDEX, 0)),
            free: AtomicU64::new(Self::pack(free, 0)),
            nodes,
            len: AtomicUsize::new(0),
        })
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.nodes.len()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len.load(Ordering::Acquire)
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        let packed = self.head.load(Ordering::Acquire);
        let (idx, _) = Self::unpack(packed);

        idx == NULL_INDEX
    }

    #[inline]
    pub fn try_push(&self, data: T) -> Result<(), T> {
        let idx = match self.pop_index(&self.free) {
            Some(idx) => idx,
            None => return Err(data),
        };

        unsafe {
            (*self.nodes.get_unchecked(idx as usize).data.get()).write(data);
        }

        self.len.fetch_add(1, Ordering::Release);
        self.push_index(&self.head, idx);

        Ok(())
    }

    #[inline]
    pub fn push(&self, data: T) {
        if self.try_push(data).is_err() {
            panic!("BoundedTreiberStack full");
        }
    }

    #[inline]
    pub fn pop(&self) -> Option<T> {
        let idx = self.pop_index(&self.head)?;

        self.len.fetch_sub(1, Ordering::AcqRel);

        let data =
            unsafe { (*self.nodes.get_unchecked(idx as usize).data.get()).assume_init_read() };

        self.push_index(&self.free, idx);

        Some(data)
    }

    pub fn drain_fifo<F>(&self, mut f: F)
    where
        F: FnMut(T),
    {
        let mut list = self.take_all_indices();
        let mut reversed = NULL_INDEX;
        let mut count = 0usize;

        while list != NULL_INDEX {
            let idx = list;

            unsafe {
                let node = self.nodes.get_unchecked(idx as usize);
                list = node.next.load(Ordering::Relaxed);
                node.next.store(reversed, Ordering::Relaxed);
            }

            reversed = idx;
            count += 1;
        }

        if count != 0 {
            self.len.fetch_sub(count, Ordering::AcqRel);
        }

        while reversed != NULL_INDEX {
            let idx = reversed;

            let data = unsafe {
                let node = self.nodes.get_unchecked(idx as usize);
                reversed = node.next.load(Ordering::Relaxed);
                (*node.data.get()).assume_init_read()
            };

            self.push_index(&self.free, idx);
            f(data);
        }
    }

    pub fn remove_one_by<F>(&self, mut pred: F) -> Option<T>
    where
        F: FnMut(&T) -> bool,
    {
        let mut list = self.take_all_indices();
        let mut keep = NULL_INDEX;
        let mut removed = None;

        while list != NULL_INDEX {
            let idx = list;

            unsafe {
                let node = self.nodes.get_unchecked(idx as usize);
                let next = node.next.load(Ordering::Relaxed);

                if removed.is_none() && pred((*node.data.get()).assume_init_ref()) {
                    let data = (*node.data.get()).assume_init_read();
                    self.push_index(&self.free, idx);
                    removed = Some(data);
                } else {
                    node.next.store(keep, Ordering::Relaxed);
                    keep = idx;
                }

                list = next;
            }
        }

        while keep != NULL_INDEX {
            let idx = keep;

            unsafe {
                let node = self.nodes.get_unchecked(idx as usize);
                keep = node.next.load(Ordering::Relaxed);
            }

            self.push_index(&self.head, idx);
        }

        if removed.is_some() {
            self.len.fetch_sub(1, Ordering::AcqRel);
        }

        removed
    }

    #[inline]
    fn push_index(&self, stack: &AtomicU64, idx: u32) {
        loop {
            let old = stack.load(Ordering::Acquire);
            let (old_idx, old_tag) = Self::unpack(old);

            unsafe {
                self.nodes
                    .get_unchecked(idx as usize)
                    .next
                    .store(old_idx, Ordering::Relaxed);
            }

            let new = Self::pack(idx, old_tag.wrapping_add(1));

            if stack
                .compare_exchange_weak(old, new, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
        }
    }

    #[inline]
    fn pop_index(&self, stack: &AtomicU64) -> Option<u32> {
        loop {
            let old = stack.load(Ordering::Acquire);
            let (idx, old_tag) = Self::unpack(old);

            if idx == NULL_INDEX {
                return None;
            }

            let next = unsafe {
                self.nodes
                    .get_unchecked(idx as usize)
                    .next
                    .load(Ordering::Acquire)
            };

            let new = Self::pack(next, old_tag.wrapping_add(1));

            if stack
                .compare_exchange_weak(old, new, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(idx);
            }
        }
    }

    #[inline]
    fn take_all_indices(&self) -> u32 {
        loop {
            let old = self.head.load(Ordering::Acquire);
            let (_, old_tag) = Self::unpack(old);
            let new = Self::pack(NULL_INDEX, old_tag.wrapping_add(1));

            if self
                .head
                .compare_exchange_weak(old, new, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                let (idx, _) = Self::unpack(old);
                return idx;
            }
        }
    }

    #[inline]
    const fn pack(idx: u32, tag: u32) -> u64 {
        ((tag as u64) << 32) | idx as u64
    }

    #[inline]
    const fn unpack(value: u64) -> (u32, u32) {
        (value as u32, (value >> 32) as u32)
    }
}

impl<T> Drop for BoundedTreiberStack<T> {
    fn drop(&mut self) {
        while self.pop().is_some() {}
    }
}
