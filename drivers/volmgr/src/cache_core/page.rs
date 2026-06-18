use crate::alloc::vec::Vec;
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::hint::cold_path;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use spin::{Mutex, RwLock};

pub(super) struct PageBuf<const BLOCK_SIZE: usize> {
    pub(super) bytes: [u8; BLOCK_SIZE],
}

impl<const BLOCK_SIZE: usize> PageBuf<BLOCK_SIZE> {
    fn zeroed() -> Box<Self> {
        Box::new(Self {
            bytes: [0u8; BLOCK_SIZE],
        })
    }
}

pub(crate) struct Page<const BLOCK_SIZE: usize> {
    pub(super) data: RwLock<Box<PageBuf<BLOCK_SIZE>>>,
    pub(super) dirty: AtomicBool,
    pub(super) writeback: AtomicBool,
    pub(super) generation: AtomicU64,
    pub(super) wb_generation: AtomicU64,
    pub(super) active_ops: AtomicUsize,
    /// File-level owner tag. 0 = unowned; owner-targeted flushes only match
    /// explicit non-zero owners.
    pub(super) owner: AtomicU64,
}

impl<const BLOCK_SIZE: usize> Page<BLOCK_SIZE> {
    pub(super) fn new_zeroed() -> Option<Self> {
        Some(Self {
            data: RwLock::new(PageBuf::zeroed()),
            dirty: AtomicBool::new(false),
            writeback: AtomicBool::new(false),
            generation: AtomicU64::new(0),
            wb_generation: AtomicU64::new(0),
            active_ops: AtomicUsize::new(0),
            owner: AtomicU64::new(0),
        })
    }

    pub(super) fn mark_dirty(&self) -> bool {
        self.owner.store(0, Ordering::Release);
        self.generation.fetch_add(1, Ordering::AcqRel);
        !self.dirty.swap(true, Ordering::AcqRel)
    }

    pub(super) fn mark_dirty_with_owner(&self, owner: u64) -> bool {
        self.owner.store(owner, Ordering::Release);
        self.generation.fetch_add(1, Ordering::AcqRel);
        !self.dirty.swap(true, Ordering::AcqRel)
    }

    pub(super) fn enter_use(&self) {
        self.active_ops.fetch_add(1, Ordering::AcqRel);
    }

    pub(super) fn leave_use(&self) {
        self.active_ops.fetch_sub(1, Ordering::AcqRel);
    }

    pub(super) fn reset_for_reuse(&self) {
        self.dirty.store(false, Ordering::Release);
        self.writeback.store(false, Ordering::Release);
        self.generation.store(0, Ordering::Release);
        self.wb_generation.store(0, Ordering::Release);
        self.active_ops.store(0, Ordering::Release);
        self.owner.store(0, Ordering::Release);
    }

    pub(super) fn is_evictable(&self) -> bool {
        !self.dirty.load(Ordering::Acquire)
            && !self.writeback.load(Ordering::Acquire)
            && self.active_ops.load(Ordering::Acquire) == 0
    }
}

pub(super) struct PageUseGuard<'a, const BLOCK_SIZE: usize> {
    page: &'a Page<BLOCK_SIZE>,
}

impl<'a, const BLOCK_SIZE: usize> PageUseGuard<'a, BLOCK_SIZE> {
    pub(super) fn new(page: &'a Page<BLOCK_SIZE>) -> Self {
        page.enter_use();
        Self { page }
    }
}

impl<'a, const BLOCK_SIZE: usize> Drop for PageUseGuard<'a, BLOCK_SIZE> {
    fn drop(&mut self) {
        self.page.leave_use();
    }
}

pub(super) struct PagePool<const BLOCK_SIZE: usize> {
    free: Mutex<Vec<Arc<Page<BLOCK_SIZE>>>>,
}

impl<const BLOCK_SIZE: usize> PagePool<BLOCK_SIZE> {
    pub(super) fn new(capacity: usize) -> Option<Self> {
        let mut free = Vec::with_capacity(capacity);
        let mut i = 0usize;
        while i < capacity {
            free.push(Arc::new(Page::new_zeroed()?));
            i += 1;
        }

        Some(Self {
            free: Mutex::new(free),
        })
    }

    pub(super) fn pop(&self) -> Option<Arc<Page<BLOCK_SIZE>>> {
        self.free.lock().pop()
    }

    pub(super) fn push(&self, mut page: Arc<Page<BLOCK_SIZE>>) {
        if let Some(inner) = Arc::get_mut(&mut page) {
            inner.reset_for_reuse();
            self.free.lock().push(page);
        } else {
            cold_path();
        }
    }
}
