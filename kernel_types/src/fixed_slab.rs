use core::cell::UnsafeCell;
use core::mem::{self, MaybeUninit};
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicUsize, Ordering};

pub const USIZE_BITS: usize = usize::BITS as usize;
pub const CACHELINE_ALIGN: usize = 64;

#[repr(C, align(64))]
pub struct CachelineAtomicUsize {
    v: AtomicUsize,
}

impl CachelineAtomicUsize {
    pub const fn new(v: usize) -> Self {
        Self {
            v: AtomicUsize::new(v),
        }
    }

    #[inline(always)]
    pub fn load(&self, order: Ordering) -> usize {
        self.v.load(order)
    }

    #[inline(always)]
    pub fn compare_exchange_weak(
        &self,
        current: usize,
        new: usize,
        success: Ordering,
        failure: Ordering,
    ) -> Result<usize, usize> {
        self.v.compare_exchange_weak(current, new, success, failure)
    }
}

#[repr(C, align(64))]
pub struct BitmapFreelist<const N: usize, const W: usize> {
    words: [AtomicUsize; W],
}

impl<const N: usize, const W: usize> BitmapFreelist<N, W> {
    pub const fn new() -> Self {
        Self {
            words: [const { AtomicUsize::new(0) }; W],
        }
    }

    #[inline(always)]
    pub fn push(&self, idx: usize) {
        debug_assert!(idx < N);

        let wi = idx / USIZE_BITS;
        let bi = idx % USIZE_BITS;
        debug_assert!(wi < W);

        let mask = 1usize << bi;
        let prev = self.words[wi].fetch_or(mask, Ordering::Release);

        debug_assert!((prev & mask) == 0, "double free");
    }

    #[inline(always)]
    pub fn pop(&self) -> Option<usize> {
        let mut wi = 0usize;

        while wi < W {
            let word = &self.words[wi];
            let mut cur = word.load(Ordering::Relaxed);

            while cur != 0 {
                let bit = cur.trailing_zeros() as usize;
                let mask = 1usize << bit;
                let new = cur & !mask;

                match word.compare_exchange_weak(cur, new, Ordering::Acquire, Ordering::Relaxed) {
                    Ok(_) => {
                        let idx = wi * USIZE_BITS + bit;

                        if idx < N {
                            return Some(idx);
                        }

                        cur = new;
                    }
                    Err(v) => cur = v,
                }
            }

            wi += 1;
        }

        None
    }
}

pub struct FixedSlotAlloc<const N: usize, const W: usize> {
    free: BitmapFreelist<N, W>,
    watermark: CachelineAtomicUsize,
}

impl<const N: usize, const W: usize> FixedSlotAlloc<N, W> {
    pub const fn new() -> Self {
        Self {
            free: BitmapFreelist::new(),
            watermark: CachelineAtomicUsize::new(0),
        }
    }

    #[inline(always)]
    pub fn alloc(&self) -> Option<usize> {
        if let Some(i) = self.free.pop() {
            return Some(i);
        }

        loop {
            let wm = self.watermark.load(Ordering::Relaxed);

            if wm >= N {
                return self.free.pop();
            }

            match self.watermark.compare_exchange_weak(
                wm,
                wm + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(wm),
                Err(_) => core::hint::spin_loop(),
            }
        }
    }

    #[inline(always)]
    pub fn free(&self, idx: usize) {
        self.free.push(idx);
    }
}

pub struct StaticObjectPool<T, const N: usize, const W: usize> {
    alloc: FixedSlotAlloc<N, W>,
    slots: UnsafeCell<[MaybeUninit<T>; N]>,
}

unsafe impl<T: Send, const N: usize, const W: usize> Sync for StaticObjectPool<T, N, W> {}

impl<T, const N: usize, const W: usize> StaticObjectPool<T, N, W> {
    pub const fn new() -> Self {
        Self {
            alloc: FixedSlotAlloc::new(),
            slots: UnsafeCell::new([const { MaybeUninit::uninit() }; N]),
        }
    }

    #[inline(always)]
    pub fn try_alloc(&self, value: T) -> Option<NonNull<T>> {
        if mem::size_of::<T>() == 0 {
            return None;
        }

        let idx = self.alloc.alloc()?;

        unsafe {
            let slot = (*self.slots.get()).as_mut_ptr().add(idx);
            let ptr = slot as *mut T;

            ptr::write(ptr, value);
            Some(NonNull::new_unchecked(ptr))
        }
    }

    #[inline(always)]
    pub unsafe fn dealloc(&self, ptr: *mut T) -> bool {
        let Some(idx) = self.index_of(ptr) else {
            return false;
        };

        unsafe {
            ptr::drop_in_place(ptr);
        }

        self.alloc.free(idx);
        true
    }

    #[inline(always)]
    pub fn contains(&self, ptr: *const T) -> bool {
        self.index_of(ptr).is_some()
    }

    #[inline(always)]
    pub fn index_of(&self, ptr: *const T) -> Option<usize> {
        if mem::size_of::<T>() == 0 {
            return None;
        }

        let base = self.slots.get() as *const [MaybeUninit<T>; N] as *const MaybeUninit<T> as usize;
        let end = base.checked_add(mem::size_of::<[MaybeUninit<T>; N]>())?;
        let p = ptr as usize;

        if p < base || p >= end {
            return None;
        }

        let off = p - base;
        let slot_size = mem::size_of::<MaybeUninit<T>>();

        if off % slot_size != 0 {
            return None;
        }

        let idx = off / slot_size;

        if idx < N { Some(idx) } else { None }
    }
}

#[repr(C, align(64))]
pub struct StaticBytePool64<const N: usize, const W: usize, const SLOT_BYTES: usize> {
    alloc: FixedSlotAlloc<N, W>,
    slots: UnsafeCell<[[u8; SLOT_BYTES]; N]>,
}

unsafe impl<const N: usize, const W: usize, const SLOT_BYTES: usize> Sync
    for StaticBytePool64<N, W, SLOT_BYTES>
{
}

impl<const N: usize, const W: usize, const SLOT_BYTES: usize> StaticBytePool64<N, W, SLOT_BYTES> {
    pub const fn new() -> Self {
        Self {
            alloc: FixedSlotAlloc::new(),
            slots: UnsafeCell::new([[0; SLOT_BYTES]; N]),
        }
    }

    #[inline(always)]
    pub fn try_alloc_raw(&self, size: usize, align: usize) -> Option<NonNull<u8>> {
        if size > SLOT_BYTES
            || align > CACHELINE_ALIGN
            || !SLOT_BYTES.is_multiple_of(CACHELINE_ALIGN)
        {
            return None;
        }

        let idx = self.alloc.alloc()?;

        unsafe {
            let base = (*self.slots.get()).as_mut_ptr() as *mut u8;
            Some(NonNull::new_unchecked(base.add(idx * SLOT_BYTES)))
        }
    }

    #[inline(always)]
    pub unsafe fn dealloc<T>(&self, ptr: *mut T) -> bool {
        let Some(idx) = self.index_of(ptr as *const u8) else {
            return false;
        };

        unsafe {
            ptr::drop_in_place(ptr);
        }

        self.alloc.free(idx);
        true
    }

    #[inline(always)]
    pub fn contains(&self, ptr: *const u8) -> bool {
        self.index_of(ptr).is_some()
    }

    #[inline(always)]
    pub fn index_of(&self, ptr: *const u8) -> Option<usize> {
        let base = self.slots.get() as *const [[u8; SLOT_BYTES]; N] as *const u8 as usize;
        let total = N.checked_mul(SLOT_BYTES)?;
        let end = base.checked_add(total)?;
        let p = ptr as usize;

        if p < base || p >= end {
            return None;
        }

        let off = p - base;

        if off % SLOT_BYTES != 0 {
            return None;
        }

        let idx = off / SLOT_BYTES;

        if idx < N { Some(idx) } else { None }
    }
}
