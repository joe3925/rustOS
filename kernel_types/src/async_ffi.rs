// Heap allocate path is based off of https://github.com/oxalica/async-ffi
#![cfg_attr(docsrs, feature(doc_cfg))]

extern crate alloc;

use alloc::boxed::Box;
use core::future::Future;
use core::marker::PhantomData;
use core::mem;
use core::mem::MaybeUninit;
use core::pin::Pin;
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

#[cfg(feature = "macros")]
#[cfg_attr(docsrs, doc(cfg(feature = "macros")))]
pub use macros::async_ffi;

pub const ABI_VERSION: u32 = 2;

const SLAB_ALIGN: usize = 64;

const fn sel(b: bool) -> usize {
    if b { 1 } else { 0 }
}

const FREELIST_IDX_BITS: usize = 16;
const FREELIST_NULL: usize = (1usize << FREELIST_IDX_BITS) - 1; // 0xFFFF
const FREELIST_ALLOC_SENTINEL: u16 = (FREELIST_NULL - 1) as u16; // 0xFFFE

const fn freelist_pack(tag: usize, idx: usize) -> usize {
    (tag << FREELIST_IDX_BITS) | (idx & FREELIST_NULL)
}
const fn freelist_idx(word: usize) -> usize {
    word & FREELIST_NULL
}
const fn freelist_tag(word: usize) -> usize {
    word >> FREELIST_IDX_BITS
}

#[inline(always)]
unsafe fn freelist_pop<const N: usize>(head: &AtomicUsize, next_base: *mut u16) -> Option<usize> {
    loop {
        let h = head.load(Ordering::Acquire);
        let idx = freelist_idx(h);
        if idx == FREELIST_NULL {
            return None;
        }
        if idx >= N {
            panic!("async-ffi slab freelist corrupt head idx={}", idx);
        }

        let next = *next_base.add(idx) as usize;
        let tag = freelist_tag(h);
        let newh = freelist_pack(tag.wrapping_add(1), next);

        if head
            .compare_exchange_weak(h, newh, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return Some(idx);
        }
    }
}

#[inline(always)]
unsafe fn freelist_push<const N: usize>(head: &AtomicUsize, next_base: *mut u16, idx: usize) {
    if idx >= N {
        panic!("async-ffi slab freelist push idx out of range idx={}", idx);
    }

    loop {
        let h = head.load(Ordering::Acquire);
        let head_idx = freelist_idx(h);
        if head_idx != FREELIST_NULL && head_idx >= N {
            panic!("async-ffi slab freelist corrupt head idx={}", head_idx);
        }

        *next_base.add(idx) = head_idx as u16;

        let tag = freelist_tag(h);
        let newh = freelist_pack(tag.wrapping_add(1), idx);

        if head
            .compare_exchange_weak(h, newh, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return;
        }
    }
}

const fn make_freelist_next<const N: usize>() -> [u16; N] {
    let mut out = [0u16; N];
    let mut i = 0usize;
    while i < N {
        out[i] = if i + 1 < N {
            (i + 1) as u16
        } else {
            FREELIST_NULL as u16
        };
        i += 1;
    }
    out
}

// ---------- slots selection ----------

const SLOTS_SEL: usize = sel(cfg!(feature = "async-ffi-slab-slots-16"))
    + sel(cfg!(feature = "async-ffi-slab-slots-32"))
    + sel(cfg!(feature = "async-ffi-slab-slots-64"))
    + sel(cfg!(feature = "async-ffi-slab-slots-128"))
    + sel(cfg!(feature = "async-ffi-slab-slots-256"))
    + sel(cfg!(feature = "async-ffi-slab-slots-512"))
    + sel(cfg!(feature = "async-ffi-slab-slots-1024"))
    + sel(cfg!(feature = "async-ffi-slab-slots-2048"))
    + sel(cfg!(feature = "async-ffi-slab-slots-4096"))
    + sel(cfg!(feature = "async-ffi-slab-slots-8192"));

const ASYNC_FFI_SLAB_SLOTS: usize = if cfg!(feature = "async-ffi-slab-slots-16") {
    16
} else if cfg!(feature = "async-ffi-slab-slots-32") {
    32
} else if cfg!(feature = "async-ffi-slab-slots-64") {
    64
} else if cfg!(feature = "async-ffi-slab-slots-128") {
    128
} else if cfg!(feature = "async-ffi-slab-slots-256") {
    256
} else if cfg!(feature = "async-ffi-slab-slots-512") {
    512
} else if cfg!(feature = "async-ffi-slab-slots-1024") {
    1024
} else if cfg!(feature = "async-ffi-slab-slots-2048") {
    2048
} else if cfg!(feature = "async-ffi-slab-slots-4096") {
    4096
} else if cfg!(feature = "async-ffi-slab-slots-8192") {
    8192
} else {
    1024
};

// ---------- slot-bytes selection ----------

const SLOT_BYTES_SEL: usize = sel(cfg!(feature = "async-ffi-slab-slot-bytes-256"))
    + sel(cfg!(feature = "async-ffi-slab-slot-bytes-512"))
    + sel(cfg!(feature = "async-ffi-slab-slot-bytes-1k"))
    + sel(cfg!(feature = "async-ffi-slab-slot-bytes-2k"))
    + sel(cfg!(feature = "async-ffi-slab-slot-bytes-4k"))
    + sel(cfg!(feature = "async-ffi-slab-slot-bytes-8k"))
    + sel(cfg!(feature = "async-ffi-slab-slot-bytes-16k"))
    + sel(cfg!(feature = "async-ffi-slab-slot-bytes-32k"))
    + sel(cfg!(feature = "async-ffi-slab-slot-bytes-64k"));

const ASYNC_FFI_SLAB_SLOT_BYTES: usize = if cfg!(feature = "async-ffi-slab-slot-bytes-256") {
    256
} else if cfg!(feature = "async-ffi-slab-slot-bytes-512") {
    512
} else if cfg!(feature = "async-ffi-slab-slot-bytes-1k") {
    1024
} else if cfg!(feature = "async-ffi-slab-slot-bytes-2k") {
    2 * 1024
} else if cfg!(feature = "async-ffi-slab-slot-bytes-4k") {
    4 * 1024
} else if cfg!(feature = "async-ffi-slab-slot-bytes-8k") {
    8 * 1024
} else if cfg!(feature = "async-ffi-slab-slot-bytes-16k") {
    16 * 1024
} else if cfg!(feature = "async-ffi-slab-slot-bytes-32k") {
    32 * 1024
} else if cfg!(feature = "async-ffi-slab-slot-bytes-64k") {
    64 * 1024
} else {
    1024
};

// ---------- derived + compile-time checks ----------

const _: () = {
    if SLOTS_SEL > 1 {
        panic!(
            "Enable at most one async-ffi-slab-slots-* feature. \
If you are overriding defaults, set default-features = false on the dependency."
        );
    }
    if SLOT_BYTES_SEL > 1 {
        panic!(
            "Enable at most one async-ffi-slab-slot-bytes-* feature. \
If you are overriding defaults, set default-features = false on the dependency."
        );
    }

    if ASYNC_FFI_SLAB_SLOTS == 0 {
        panic!("ASYNC_FFI_SLAB_SLOTS must be non-zero.");
    }
    if ASYNC_FFI_SLAB_SLOTS >= FREELIST_NULL {
        panic!("ASYNC_FFI_SLAB_SLOTS must be < 65535.");
    }
    if ASYNC_FFI_SLAB_SLOT_BYTES == 0 {
        panic!("ASYNC_FFI_SLAB_SLOT_BYTES must be non-zero.");
    }
    if (ASYNC_FFI_SLAB_SLOT_BYTES % SLAB_ALIGN) != 0 {
        panic!("async-ffi slab slot bytes must be a multiple of SLAB_ALIGN (64).");
    }
    if ASYNC_FFI_SLAB_SLOTS > (usize::MAX / ASYNC_FFI_SLAB_SLOT_BYTES) {
        panic!("async-ffi slab total bytes overflow.");
    }
};

const ASYNC_FFI_SLAB_TOTAL_BYTES: usize = ASYNC_FFI_SLAB_SLOTS * ASYNC_FFI_SLAB_SLOT_BYTES;
const ASYNC_FFI_FUTURE_SLOT_BYTES: usize = ASYNC_FFI_SLAB_SLOT_BYTES;

#[repr(C, align(64))]
struct AlignedFutureBuf {
    buf: [u8; ASYNC_FFI_SLAB_TOTAL_BYTES],
}

#[cfg(feature = "async-ffi-slab")]
static FUTURE_SLAB_HEAD: AtomicUsize = AtomicUsize::new(freelist_pack(0, 0));
#[cfg(feature = "async-ffi-slab")]
static mut FUTURE_SLAB_NEXT: [u16; ASYNC_FFI_SLAB_SLOTS] =
    make_freelist_next::<ASYNC_FFI_SLAB_SLOTS>();
#[cfg(feature = "async-ffi-slab")]
static mut FUTURE_SLAB_BUF: AlignedFutureBuf = AlignedFutureBuf {
    buf: [0; ASYNC_FFI_SLAB_TOTAL_BYTES],
};

#[cfg(feature = "async-ffi-slab")]
static WAKER_TO_FFI_HEAD: AtomicUsize = AtomicUsize::new(freelist_pack(0, 0));
#[cfg(feature = "async-ffi-slab")]
static mut WAKER_TO_FFI_NEXT: [u16; ASYNC_FFI_SLAB_SLOTS] =
    make_freelist_next::<ASYNC_FFI_SLAB_SLOTS>();
#[cfg(feature = "async-ffi-slab")]
static mut WAKER_TO_FFI_SLAB: [MaybeUninit<RustWakerBox>; ASYNC_FFI_SLAB_SLOTS] =
    [const { MaybeUninit::uninit() }; ASYNC_FFI_SLAB_SLOTS];

#[cfg(feature = "async-ffi-slab")]
static FFI_TO_WAKER_HEAD: AtomicUsize = AtomicUsize::new(freelist_pack(0, 0));
#[cfg(feature = "async-ffi-slab")]
static mut FFI_TO_WAKER_NEXT: [u16; ASYNC_FFI_SLAB_SLOTS] =
    make_freelist_next::<ASYNC_FFI_SLAB_SLOTS>();
#[cfg(feature = "async-ffi-slab")]
static mut FFI_TO_WAKER_SLAB: [MaybeUninit<FfiWakerBox>; ASYNC_FFI_SLAB_SLOTS] =
    [const { MaybeUninit::uninit() }; ASYNC_FFI_SLAB_SLOTS];

#[repr(C)]
pub struct FfiPoll<T> {
    tag: u8,
    pad: [u8; 7],
    value: MaybeUninit<T>,
}

impl<T> FfiPoll<T> {
    pub fn pending() -> Self {
        Self {
            tag: 0,
            pad: [0; 7],
            value: MaybeUninit::uninit(),
        }
    }

    pub fn ready(v: T) -> Self {
        Self {
            tag: 1,
            pad: [0; 7],
            value: MaybeUninit::new(v),
        }
    }

    pub fn is_pending(&self) -> bool {
        self.tag == 0
    }

    pub fn is_ready(&self) -> bool {
        self.tag == 1
    }

    pub unsafe fn into_poll(self) -> Poll<T> {
        if self.tag == 0 {
            Poll::Pending
        } else {
            Poll::Ready(unsafe { self.value.assume_init() })
        }
    }
}

impl<T> From<Poll<T>> for FfiPoll<T> {
    fn from(p: Poll<T>) -> Self {
        match p {
            Poll::Pending => Self::pending(),
            Poll::Ready(v) => Self::ready(v),
        }
    }
}

#[repr(C)]
pub struct FfiWakerVTable {
    pub clone: unsafe extern "win64" fn(*const ()) -> FfiWaker,
    pub wake: unsafe extern "win64" fn(*const ()),
    pub wake_by_ref: unsafe extern "win64" fn(*const ()),
    pub drop: unsafe extern "win64" fn(*const ()),
}

#[repr(C)]
pub struct FfiWaker {
    pub data: *const (),
    pub vtable: &'static FfiWakerVTable,
}

impl Clone for FfiWaker {
    fn clone(&self) -> Self {
        unsafe { (self.vtable.clone)(self.data) }
    }
}

impl Drop for FfiWaker {
    fn drop(&mut self) {
        unsafe { (self.vtable.drop)(self.data) }
    }
}

impl FfiWaker {
    pub fn wake(self) {
        let me = core::mem::ManuallyDrop::new(self);
        unsafe { (me.vtable.wake)(me.data) }
    }

    pub fn wake_by_ref(&self) {
        unsafe { (self.vtable.wake_by_ref)(self.data) }
    }
}

#[repr(C)]
pub struct FfiFuture<T> {
    pub abi_version: u32,
    pub data: *mut (),
    pub poll_fn: unsafe extern "win64" fn(*mut (), *const FfiWaker) -> FfiPoll<T>,
    pub drop_fn: unsafe extern "win64" fn(*mut ()),
}

unsafe impl<T: Send> Send for FfiFuture<T> {}

impl<T> FfiFuture<T> {
    pub fn is_null(&self) -> bool {
        self.data.is_null()
    }

    pub unsafe fn poll(&mut self, waker: *const FfiWaker) -> FfiPoll<T> {
        unsafe { (self.poll_fn)(self.data, waker) }
    }
}

impl<T> Drop for FfiFuture<T> {
    fn drop(&mut self) {
        if !self.data.is_null() {
            unsafe { (self.drop_fn)(self.data) }
            self.data = ptr::null_mut();
        }
    }
}

pub trait FutureExt: Future + Sized {
    fn into_ffi(self) -> FfiFuture<Self::Output>;
}

impl<F> FutureExt for F
where
    F: Future,
{
    fn into_ffi(self) -> FfiFuture<Self::Output> {
        ffi_future_from_future(self)
    }
}

pub trait WakerExt {
    fn into_ffi(self) -> FfiWaker;
}

impl WakerExt for Waker {
    fn into_ffi(self) -> FfiWaker {
        ffi_waker_from_waker(self)
    }
}

fn ffi_future_from_future<F>(fut: F) -> FfiFuture<F::Output>
where
    F: Future,
{
    let mut fut = Some(fut);
    let mut data_ptr: *mut FutureBox<F> = ptr::null_mut();

    #[cfg(feature = "async-ffi-slab")]
    unsafe {
        let size = mem::size_of::<FutureBox<F>>();
        let align = mem::align_of::<FutureBox<F>>();

        if size <= ASYNC_FFI_FUTURE_SLOT_BYTES && align <= SLAB_ALIGN {
            let next_base = core::ptr::addr_of_mut!(FUTURE_SLAB_NEXT) as *mut u16;
            if let Some(i) =
                unsafe { freelist_pop::<ASYNC_FFI_SLAB_SLOTS>(&FUTURE_SLAB_HEAD, next_base) }
            {
                *next_base.add(i) = FREELIST_ALLOC_SENTINEL;

                let buf_base = core::ptr::addr_of_mut!(FUTURE_SLAB_BUF.buf) as *mut u8;
                let slot = buf_base.add(i * ASYNC_FFI_FUTURE_SLOT_BYTES);
                data_ptr = slot as *mut FutureBox<F>;

                let f = fut.take().unwrap();
                ptr::write(data_ptr, FutureBox { future: f });
            }
        }
    }

    if data_ptr.is_null() {
        let f = fut.take().unwrap();
        let boxed = Box::new(FutureBox { future: f });
        data_ptr = Box::into_raw(boxed);
    }

    FfiFuture {
        abi_version: ABI_VERSION,
        data: data_ptr as *mut (),
        poll_fn: future_box_poll::<F>,
        drop_fn: future_box_drop::<F>,
    }
}

struct FutureBox<F>
where
    F: Future,
{
    future: F,
}

unsafe extern "win64" fn future_box_poll<F>(
    data: *mut (),
    waker: *const FfiWaker,
) -> FfiPoll<F::Output>
where
    F: Future,
{
    if waker.is_null() {
        return FfiPoll::pending();
    }

    let fb = data as *mut FutureBox<F>;
    let w = ffi_waker_to_waker(unsafe { &*waker });
    let mut cx = Context::from_waker(&w);
    let p = Future::poll(unsafe { Pin::new_unchecked(&mut (*fb).future) }, &mut cx);
    FfiPoll::from(p)
}

unsafe extern "win64" fn future_box_drop<F>(data: *mut ())
where
    F: Future,
{
    let fb = data as *mut FutureBox<F>;

    #[cfg(feature = "async-ffi-slab")]
    unsafe {
        let base = core::ptr::addr_of!(FUTURE_SLAB_BUF.buf) as *const u8 as usize;
        let end = base + ASYNC_FFI_SLAB_TOTAL_BYTES;
        let p = fb as usize;

        if p >= base && p < end {
            let off = p - base;
            if off % ASYNC_FFI_FUTURE_SLOT_BYTES != 0 {
                panic!("async-ffi: future ptr not on slot boundary");
            }
            let idx = off / ASYNC_FFI_FUTURE_SLOT_BYTES;

            let next_base = core::ptr::addr_of_mut!(FUTURE_SLAB_NEXT) as *mut u16;
            let mark = *next_base.add(idx);
            if mark != FREELIST_ALLOC_SENTINEL {
                panic!("async-ffi: future double-free/corrupt slab idx={}", idx);
            }

            ptr::drop_in_place(fb);
            unsafe { freelist_push::<ASYNC_FFI_SLAB_SLOTS>(&FUTURE_SLAB_HEAD, next_base, idx) };
            return;
        }
    }

    drop(unsafe { Box::from_raw(fb) });
}

struct RustWakerBox {
    refs: AtomicUsize,
    waker: Waker,
}

static RUST_WAKER_BOX_VTABLE: FfiWakerVTable = FfiWakerVTable {
    clone: rust_waker_box_clone,
    wake: rust_waker_box_wake,
    wake_by_ref: rust_waker_box_wake_by_ref,
    drop: rust_waker_box_drop,
};

fn ffi_waker_from_waker(w: Waker) -> FfiWaker {
    let mut w = Some(w);
    let mut ptr_box: *mut RustWakerBox = ptr::null_mut();

    #[cfg(feature = "async-ffi-slab")]
    unsafe {
        let next_base = core::ptr::addr_of_mut!(WAKER_TO_FFI_NEXT) as *mut u16;
        if let Some(i) =
            unsafe { freelist_pop::<ASYNC_FFI_SLAB_SLOTS>(&WAKER_TO_FFI_HEAD, next_base) }
        {
            *next_base.add(i) = FREELIST_ALLOC_SENTINEL;

            let slab_base =
                core::ptr::addr_of_mut!(WAKER_TO_FFI_SLAB) as *mut MaybeUninit<RustWakerBox>;
            ptr_box = slab_base.add(i) as *mut RustWakerBox;

            let ww = w.take().unwrap();
            ptr::write(
                ptr_box,
                RustWakerBox {
                    refs: AtomicUsize::new(1),
                    waker: ww,
                },
            );
        }
    }

    if ptr_box.is_null() {
        let ww = w.take().unwrap();
        let boxed = Box::new(RustWakerBox {
            refs: AtomicUsize::new(1),
            waker: ww,
        });
        ptr_box = Box::into_raw(boxed);
    }

    FfiWaker {
        data: ptr_box as *const (),
        vtable: &RUST_WAKER_BOX_VTABLE,
    }
}

unsafe extern "win64" fn rust_waker_box_clone(data: *const ()) -> FfiWaker {
    let b = data as *const RustWakerBox;
    unsafe { (*b).refs.fetch_add(1, Ordering::Relaxed) };
    FfiWaker {
        data,
        vtable: &RUST_WAKER_BOX_VTABLE,
    }
}

unsafe extern "win64" fn rust_waker_box_wake(data: *const ()) {
    let b = data as *const RustWakerBox;
    unsafe { (*b).waker.wake_by_ref() };
    rust_waker_box_drop(data);
}

unsafe extern "win64" fn rust_waker_box_wake_by_ref(data: *const ()) {
    let b = data as *const RustWakerBox;
    unsafe { (*b).waker.wake_by_ref() };
}

unsafe extern "win64" fn rust_waker_box_drop(data: *const ()) {
    let b = data as *mut RustWakerBox;
    if unsafe { (*b).refs.fetch_sub(1, Ordering::AcqRel) } != 1 {
        return;
    }

    #[cfg(feature = "async-ffi-slab")]
    unsafe {
        let base =
            core::ptr::addr_of!(WAKER_TO_FFI_SLAB) as *const MaybeUninit<RustWakerBox> as usize;
        let end = base + mem::size_of::<[MaybeUninit<RustWakerBox>; ASYNC_FFI_SLAB_SLOTS]>();
        let p = b as usize;

        if p >= base && p < end {
            let idx = (p - base) / mem::size_of::<MaybeUninit<RustWakerBox>>();

            let next_base = core::ptr::addr_of_mut!(WAKER_TO_FFI_NEXT) as *mut u16;
            let mark = *next_base.add(idx);
            if mark != FREELIST_ALLOC_SENTINEL {
                panic!("async-ffi: rust waker double-free/corrupt slab idx={}", idx);
            }

            ptr::drop_in_place(b);
            unsafe { freelist_push::<ASYNC_FFI_SLAB_SLOTS>(&WAKER_TO_FFI_HEAD, next_base, idx) };
            return;
        }
    }

    drop(unsafe { Box::from_raw(b) });
}

struct FfiWakerBox {
    refs: AtomicUsize,
    waker: FfiWaker,
}

static FFI_WAKER_BOX_RAW_VTABLE: RawWakerVTable = RawWakerVTable::new(
    ffi_waker_box_raw_clone,
    ffi_waker_box_raw_wake,
    ffi_waker_box_raw_wake_by_ref,
    ffi_waker_box_raw_drop,
);

fn ffi_waker_to_waker(w: &FfiWaker) -> Waker {
    let mut ptr_box: *mut FfiWakerBox = ptr::null_mut();

    #[cfg(feature = "async-ffi-slab")]
    unsafe {
        let next_base = core::ptr::addr_of_mut!(FFI_TO_WAKER_NEXT) as *mut u16;
        if let Some(i) =
            unsafe { freelist_pop::<ASYNC_FFI_SLAB_SLOTS>(&FFI_TO_WAKER_HEAD, next_base) }
        {
            *next_base.add(i) = FREELIST_ALLOC_SENTINEL;

            let slab_base =
                core::ptr::addr_of_mut!(FFI_TO_WAKER_SLAB) as *mut MaybeUninit<FfiWakerBox>;
            ptr_box = slab_base.add(i) as *mut FfiWakerBox;

            ptr::write(
                ptr_box,
                FfiWakerBox {
                    refs: AtomicUsize::new(1),
                    waker: w.clone(),
                },
            );
        }
    }

    if ptr_box.is_null() {
        let boxed = Box::new(FfiWakerBox {
            refs: AtomicUsize::new(1),
            waker: w.clone(),
        });
        ptr_box = Box::into_raw(boxed);
    }

    unsafe {
        Waker::from_raw(RawWaker::new(
            ptr_box as *const (),
            &FFI_WAKER_BOX_RAW_VTABLE,
        ))
    }
}

unsafe fn ffi_waker_box_raw_clone(data: *const ()) -> RawWaker {
    let b = data as *const FfiWakerBox;
    unsafe { (*b).refs.fetch_add(1, Ordering::Relaxed) };
    RawWaker::new(data, &FFI_WAKER_BOX_RAW_VTABLE)
}

unsafe fn ffi_waker_box_raw_wake(data: *const ()) {
    unsafe { ffi_waker_box_raw_wake_by_ref(data) };
    unsafe { ffi_waker_box_raw_drop(data) };
}

unsafe fn ffi_waker_box_raw_wake_by_ref(data: *const ()) {
    let b = data as *const FfiWakerBox;
    unsafe { (*b).waker.wake_by_ref() };
}

unsafe fn ffi_waker_box_raw_drop(data: *const ()) {
    let b = data as *mut FfiWakerBox;
    if unsafe { (*b).refs.fetch_sub(1, Ordering::AcqRel) } != 1 {
        return;
    }

    #[cfg(feature = "async-ffi-slab")]
    unsafe {
        let base =
            core::ptr::addr_of!(FFI_TO_WAKER_SLAB) as *const MaybeUninit<FfiWakerBox> as usize;
        let end = base + mem::size_of::<[MaybeUninit<FfiWakerBox>; ASYNC_FFI_SLAB_SLOTS]>();
        let p = b as usize;

        if p >= base && p < end {
            let idx = (p - base) / mem::size_of::<MaybeUninit<FfiWakerBox>>();

            let next_base = core::ptr::addr_of_mut!(FFI_TO_WAKER_NEXT) as *mut u16;
            let mark = *next_base.add(idx);
            if mark != FREELIST_ALLOC_SENTINEL {
                panic!("async-ffi: ffi->waker double-free/corrupt slab idx={}", idx);
            }

            ptr::drop_in_place(b);
            unsafe { freelist_push::<ASYNC_FFI_SLAB_SLOTS>(&FFI_TO_WAKER_HEAD, next_base, idx) };
            return;
        }
    }

    drop(unsafe { Box::from_raw(b) });
}

#[repr(C)]
pub struct BorrowingFfiFuture<'a, T> {
    pub abi_version: u32,
    pub data: *mut (),
    pub poll_fn: unsafe extern "win64" fn(*mut (), *const FfiWaker) -> FfiPoll<T>,
    _pd: PhantomData<&'a mut ()>,
}

impl<'a, T> BorrowingFfiFuture<'a, T> {
    pub unsafe fn poll(&mut self, waker: *const FfiWaker) -> FfiPoll<T> {
        unsafe { (self.poll_fn)(self.data, waker) }
    }
}

pub trait BorrowingFutureExt: Future {
    fn borrow_into_ffi<'a>(self: Pin<&'a mut Self>) -> BorrowingFfiFuture<'a, Self::Output>
    where
        Self: Sized;
}

impl<F> BorrowingFutureExt for F
where
    F: Future,
{
    fn borrow_into_ffi<'a>(self: Pin<&'a mut Self>) -> BorrowingFfiFuture<'a, Self::Output>
    where
        Self: Sized,
    {
        borrowing_ffi_future_from_pin(self)
    }
}

pub fn borrowing_ffi_future_from_pin<'a, F>(
    fut: Pin<&'a mut F>,
) -> BorrowingFfiFuture<'a, F::Output>
where
    F: Future,
{
    let p = unsafe { Pin::get_unchecked_mut(fut) as *mut F };
    BorrowingFfiFuture {
        abi_version: ABI_VERSION,
        data: p as *mut (),
        poll_fn: borrowing_future_poll::<F>,
        _pd: PhantomData,
    }
}

unsafe extern "win64" fn borrowing_future_poll<F>(
    data: *mut (),
    waker: *const FfiWaker,
) -> FfiPoll<F::Output>
where
    F: Future,
{
    if waker.is_null() {
        return FfiPoll::pending();
    }

    let f = data as *mut F;
    let w = ffi_waker_to_waker(unsafe { &*waker });
    let mut cx = Context::from_waker(&w);
    let p = Future::poll(unsafe { Pin::new_unchecked(&mut *f) }, &mut cx);
    FfiPoll::from(p)
}

impl<'a, T> Future for BorrowingFfiFuture<'a, T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<T> {
        let this = unsafe { self.get_unchecked_mut() };
        let ffi_waker = cx.waker().clone().into_ffi();
        let p = unsafe { (this.poll_fn)(this.data, &ffi_waker as *const FfiWaker) };
        unsafe { p.into_poll() }
    }
}

impl<T> Future for FfiFuture<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<T> {
        let this = unsafe { self.get_unchecked_mut() };
        if this.data.is_null() {
            return Poll::Pending;
        }

        let ffi_waker = cx.waker().clone().into_ffi();
        let p = unsafe { (this.poll_fn)(this.data, &ffi_waker as *const FfiWaker) };
        match unsafe { p.into_poll() } {
            Poll::Pending => Poll::Pending,
            Poll::Ready(v) => {
                unsafe { (this.drop_fn)(this.data) };
                this.data = ptr::null_mut();
                Poll::Ready(v)
            }
        }
    }
}
