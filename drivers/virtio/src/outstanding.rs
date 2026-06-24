use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use crate::completion::CompletionToken;
use kernel_api::dma::dma::{IoBuffer, IoBufferAccess, PhysFramed};

pub(crate) const VIRTIO_QUEUE_BATCH_LIMIT: usize = 64;

const SLOT_FREE: u8 = 0;
const SLOT_RESERVED: u8 = 1;
const SLOT_INITIALIZED: u8 = 2;

pub(crate) struct PendingBlockOp<'data, D>
where
    D: IoBufferAccess,
{
    pub(crate) sector: u64,
    pub(crate) len: usize,
    pub(crate) mapped_buffer: IoBuffer<'data, 'data, PhysFramed, D>,
}

pub(crate) struct SubmittedCompletion<'completion> {
    pub(crate) completion: CompletionToken<'completion>,
    pub(crate) byte_len: usize,
}

struct PendingOpSlot<D>
where
    D: IoBufferAccess + 'static,
{
    state: AtomicU8,
    storage: UnsafeCell<MaybeUninit<PendingBlockOp<'static, D>>>,
}

pub(crate) struct PendingOpPool<D>
where
    D: IoBufferAccess + 'static,
{
    slots: Box<[PendingOpSlot<D>]>,
    cursor: AtomicUsize,
}

pub(crate) struct PendingOpLease<'pool, 'data, D>
where
    D: IoBufferAccess + 'static,
{
    pool: &'pool PendingOpPool<D>,
    index: usize,
    initialized: bool,
    active: bool,
    _data: PhantomData<PendingBlockOp<'data, D>>,
}

pub(crate) struct PendingOpBatch<'pool, 'data, D>
where
    D: IoBufferAccess + 'static,
{
    pool: &'pool PendingOpPool<D>,
    indices: [usize; VIRTIO_QUEUE_BATCH_LIMIT],
    len: usize,
    _data: PhantomData<PendingBlockOp<'data, D>>,
}

struct SubmittedCompletionSlot {
    state: AtomicU8,
    storage: UnsafeCell<MaybeUninit<SubmittedCompletion<'static>>>,
}

pub(crate) struct SubmittedCompletionPool {
    slots: Box<[SubmittedCompletionSlot]>,
    cursor: AtomicUsize,
}

pub(crate) struct SubmittedCompletionLease<'pool, 'completion> {
    pool: &'pool SubmittedCompletionPool,
    index: usize,
    initialized: bool,
    active: bool,
    _completion: PhantomData<SubmittedCompletion<'completion>>,
}

pub(crate) struct SubmittedCompletionBatch<'pool, 'completion> {
    pool: &'pool SubmittedCompletionPool,
    indices: [usize; VIRTIO_QUEUE_BATCH_LIMIT],
    len: usize,
    _completion: PhantomData<SubmittedCompletion<'completion>>,
}

unsafe impl<D> Send for PendingOpSlot<D> where D: IoBufferAccess + 'static {}
unsafe impl<D> Sync for PendingOpSlot<D> where D: IoBufferAccess + 'static {}
unsafe impl<D> Send for PendingOpPool<D> where D: IoBufferAccess + 'static {}
unsafe impl<D> Sync for PendingOpPool<D> where D: IoBufferAccess + 'static {}
unsafe impl Send for SubmittedCompletionSlot {}
unsafe impl Sync for SubmittedCompletionSlot {}
unsafe impl Send for SubmittedCompletionPool {}
unsafe impl Sync for SubmittedCompletionPool {}

impl<D> PendingOpPool<D>
where
    D: IoBufferAccess + 'static,
{
    pub(crate) fn new(capacity: usize) -> Option<Self> {
        let mut slots = Vec::new();
        slots.try_reserve_exact(capacity).ok()?;

        for _ in 0..capacity {
            slots.push(PendingOpSlot {
                state: AtomicU8::new(SLOT_FREE),
                storage: UnsafeCell::new(MaybeUninit::uninit()),
            });
        }

        Some(Self {
            slots: slots.into_boxed_slice(),
            cursor: AtomicUsize::new(0),
        })
    }

    #[inline]
    pub(crate) fn capacity(&self) -> usize {
        self.slots.len()
    }

    pub(crate) fn alloc<'pool, 'data>(&'pool self) -> Option<PendingOpLease<'pool, 'data, D>> {
        let capacity = self.slots.len();
        if capacity == 0 {
            return None;
        }

        let start = self.cursor.fetch_add(1, Ordering::Relaxed) % capacity;
        for offset in 0..capacity {
            let index = (start + offset) % capacity;
            let slot = &self.slots[index];

            if slot
                .state
                .compare_exchange(
                    SLOT_FREE,
                    SLOT_RESERVED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                return Some(PendingOpLease {
                    pool: self,
                    index,
                    initialized: false,
                    active: true,
                    _data: PhantomData,
                });
            }
        }

        None
    }

    #[inline]
    fn ptr<'data>(&self, index: usize) -> *mut PendingBlockOp<'data, D> {
        self.slots[index].storage.get() as *mut MaybeUninit<PendingBlockOp<'static, D>>
            as *mut PendingBlockOp<'data, D>
    }

    unsafe fn drop_initialized<'data>(&self, index: usize) {
        unsafe {
            core::ptr::drop_in_place(self.ptr::<'data>(index));
        }
        self.release(index);
    }

    #[inline]
    fn release(&self, index: usize) {
        self.slots[index].state.store(SLOT_FREE, Ordering::Release);
    }
}

impl<'pool, 'data, D> PendingOpLease<'pool, 'data, D>
where
    D: IoBufferAccess + 'static,
{
    pub(crate) fn write(&mut self, op: PendingBlockOp<'data, D>) {
        assert!(self.active);
        assert!(!self.initialized);

        unsafe {
            self.pool.ptr::<'data>(self.index).write(op);
        }
        self.initialized = true;
        self.pool.slots[self.index]
            .state
            .store(SLOT_INITIALIZED, Ordering::Release);
    }

    fn into_initialized_index(mut self) -> usize {
        assert!(self.active);
        assert!(self.initialized);

        self.active = false;
        self.index
    }
}

impl<'pool, 'data, D> Drop for PendingOpLease<'pool, 'data, D>
where
    D: IoBufferAccess + 'static,
{
    fn drop(&mut self) {
        if !self.active {
            return;
        }

        if self.initialized {
            unsafe {
                self.pool.drop_initialized::<'data>(self.index);
            }
        } else {
            self.pool.release(self.index);
        }
    }
}

impl<'pool, 'data, D> PendingOpBatch<'pool, 'data, D>
where
    D: IoBufferAccess + 'static,
{
    pub(crate) fn new(pool: &'pool PendingOpPool<D>) -> Self {
        Self {
            pool,
            indices: [usize::MAX; VIRTIO_QUEUE_BATCH_LIMIT],
            len: 0,
            _data: PhantomData,
        }
    }

    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub(crate) fn is_full(&self) -> bool {
        self.len == VIRTIO_QUEUE_BATCH_LIMIT
    }

    pub(crate) fn push(&mut self, lease: PendingOpLease<'pool, 'data, D>) {
        assert!(!self.is_full());
        self.indices[self.len] = lease.into_initialized_index();
        self.len += 1;
    }

    #[inline]
    pub(crate) fn get(&self, index: usize) -> &PendingBlockOp<'data, D> {
        assert!(index < self.len);
        unsafe { &*self.pool.ptr::<'data>(self.indices[index]) }
    }

    pub(crate) fn clear(&mut self) {
        while self.len != 0 {
            self.len -= 1;
            let index = self.indices[self.len];
            self.indices[self.len] = usize::MAX;
            unsafe {
                self.pool.drop_initialized::<'data>(index);
            }
        }
    }
}

impl<'pool, 'data, D> Drop for PendingOpBatch<'pool, 'data, D>
where
    D: IoBufferAccess + 'static,
{
    fn drop(&mut self) {
        self.clear();
    }
}

impl SubmittedCompletionPool {
    pub(crate) fn new(capacity: usize) -> Option<Self> {
        let mut slots = Vec::new();
        slots.try_reserve_exact(capacity).ok()?;

        for _ in 0..capacity {
            slots.push(SubmittedCompletionSlot {
                state: AtomicU8::new(SLOT_FREE),
                storage: UnsafeCell::new(MaybeUninit::uninit()),
            });
        }

        Some(Self {
            slots: slots.into_boxed_slice(),
            cursor: AtomicUsize::new(0),
        })
    }

    #[inline]
    pub(crate) fn capacity(&self) -> usize {
        self.slots.len()
    }

    pub(crate) fn alloc<'pool, 'completion>(
        &'pool self,
    ) -> Option<SubmittedCompletionLease<'pool, 'completion>> {
        let capacity = self.slots.len();
        if capacity == 0 {
            return None;
        }

        let start = self.cursor.fetch_add(1, Ordering::Relaxed) % capacity;
        for offset in 0..capacity {
            let index = (start + offset) % capacity;
            let slot = &self.slots[index];

            if slot
                .state
                .compare_exchange(
                    SLOT_FREE,
                    SLOT_RESERVED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                return Some(SubmittedCompletionLease {
                    pool: self,
                    index,
                    initialized: false,
                    active: true,
                    _completion: PhantomData,
                });
            }
        }

        None
    }

    #[inline]
    fn ptr<'completion>(&self, index: usize) -> *mut SubmittedCompletion<'completion> {
        self.slots[index].storage.get() as *mut MaybeUninit<SubmittedCompletion<'static>>
            as *mut SubmittedCompletion<'completion>
    }

    unsafe fn take_initialized<'completion>(
        &self,
        index: usize,
    ) -> SubmittedCompletion<'completion> {
        let value = unsafe { self.ptr::<'completion>(index).read() };
        self.release(index);
        value
    }

    unsafe fn drop_initialized<'completion>(&self, index: usize) {
        unsafe {
            core::ptr::drop_in_place(self.ptr::<'completion>(index));
        }
        self.release(index);
    }

    #[inline]
    fn release(&self, index: usize) {
        self.slots[index].state.store(SLOT_FREE, Ordering::Release);
    }
}

impl<'pool, 'completion> SubmittedCompletionLease<'pool, 'completion> {
    pub(crate) fn write(&mut self, submitted: SubmittedCompletion<'completion>) {
        assert!(self.active);
        assert!(!self.initialized);

        unsafe {
            self.pool.ptr::<'completion>(self.index).write(submitted);
        }
        self.initialized = true;
        self.pool.slots[self.index]
            .state
            .store(SLOT_INITIALIZED, Ordering::Release);
    }

    fn into_initialized_index(mut self) -> usize {
        assert!(self.active);
        assert!(self.initialized);

        self.active = false;
        self.index
    }
}

impl<'pool, 'completion> Drop for SubmittedCompletionLease<'pool, 'completion> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }

        if self.initialized {
            unsafe {
                self.pool.drop_initialized::<'completion>(self.index);
            }
        } else {
            self.pool.release(self.index);
        }
    }
}

impl<'pool, 'completion> SubmittedCompletionBatch<'pool, 'completion> {
    pub(crate) fn new(pool: &'pool SubmittedCompletionPool) -> Self {
        Self {
            pool,
            indices: [usize::MAX; VIRTIO_QUEUE_BATCH_LIMIT],
            len: 0,
            _completion: PhantomData,
        }
    }

    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub(crate) fn is_full(&self) -> bool {
        self.len == VIRTIO_QUEUE_BATCH_LIMIT
    }

    pub(crate) fn push(&mut self, lease: SubmittedCompletionLease<'pool, 'completion>) {
        assert!(!self.is_full());
        self.indices[self.len] = lease.into_initialized_index();
        self.len += 1;
    }

    pub(crate) fn pop(&mut self) -> Option<SubmittedCompletion<'completion>> {
        if self.len == 0 {
            return None;
        }

        self.len -= 1;
        let index = self.indices[self.len];
        self.indices[self.len] = usize::MAX;
        Some(unsafe { self.pool.take_initialized::<'completion>(index) })
    }

    pub(crate) fn clear(&mut self) {
        while self.len != 0 {
            self.len -= 1;
            let index = self.indices[self.len];
            self.indices[self.len] = usize::MAX;
            unsafe {
                self.pool.drop_initialized::<'completion>(index);
            }
        }
    }
}

impl<'pool, 'completion> Drop for SubmittedCompletionBatch<'pool, 'completion> {
    fn drop(&mut self) {
        self.clear();
    }
}
