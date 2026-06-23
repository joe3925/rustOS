// Heap allocate path is based off of https://github.com/oxalica/async-ffi
#![cfg_attr(docsrs, feature(doc_cfg))]

extern crate alloc;

use alloc::boxed::Box;
use core::future::Future;
use core::marker::PhantomData;
use core::mem::{self, MaybeUninit};
use core::pin::Pin;
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

#[cfg(feature = "async-ffi-slab")]
use crate::fixed_slab::{StaticBytePool64, StaticObjectPool, USIZE_BITS};

#[cfg(feature = "macros")]
#[cfg_attr(docsrs, doc(cfg(feature = "macros")))]
pub use macros::async_ffi;

pub const ABI_VERSION: u32 = 2;

const SLAB_ALIGN: usize = 64;
const SLAB_CHECKS: bool = cfg!(debug_assertions);

const fn sel(b: bool) -> usize {
    if b { 1 } else { 0 }
}

#[cfg(feature = "async-ffi-slab")]
const ASYNC_FFI_SLAB_WORDS: usize = ASYNC_FFI_SLAB_SLOTS.div_ceil(USIZE_BITS);

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

    if ASYNC_FFI_SLAB_SLOT_BYTES == 0 {
        panic!("ASYNC_FFI_SLAB_SLOT_BYTES must be non-zero.");
    }

    if !ASYNC_FFI_SLAB_SLOT_BYTES.is_multiple_of(SLAB_ALIGN) {
        panic!("async-ffi slab slot bytes must be a multiple of SLAB_ALIGN (64).");
    }

    if ASYNC_FFI_SLAB_SLOTS > (usize::MAX / ASYNC_FFI_SLAB_SLOT_BYTES) {
        panic!("async-ffi slab total bytes overflow.");
    }
};

const ASYNC_FFI_FUTURE_SLOT_BYTES: usize = ASYNC_FFI_SLAB_SLOT_BYTES;

#[cfg(feature = "async-ffi-slab")]
static FUTURE_POOL: StaticBytePool64<
    ASYNC_FFI_SLAB_SLOTS,
    ASYNC_FFI_SLAB_WORDS,
    ASYNC_FFI_FUTURE_SLOT_BYTES,
> = StaticBytePool64::new();

#[cfg(feature = "async-ffi-slab")]
static WAKER_TO_FFI_POOL: StaticObjectPool<
    RustWakerBox,
    ASYNC_FFI_SLAB_SLOTS,
    ASYNC_FFI_SLAB_WORDS,
> = StaticObjectPool::new();

#[cfg(feature = "async-ffi-slab")]
static FFI_TO_WAKER_POOL: StaticObjectPool<
    FfiWakerBox,
    ASYNC_FFI_SLAB_SLOTS,
    ASYNC_FFI_SLAB_WORDS,
> = StaticObjectPool::new();

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
        unsafe {
            if self.tag == 0 {
                Poll::Pending
            } else {
                Poll::Ready(self.value.assume_init())
            }
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
unsafe impl Sync for FfiWakerVTable {}
#[repr(C)]
pub struct FfiWakerVTable {
    pub clone: unsafe extern "C" fn(*const ()) -> FfiWaker,
    pub wake: unsafe extern "C" fn(*const ()),
    pub wake_by_ref: unsafe extern "C" fn(*const ()),
    pub drop: unsafe extern "C" fn(*const ()),
}
unsafe impl Send for FfiWaker {}
unsafe impl Sync for FfiWaker {}
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
    pub data: Option<*mut ()>,
    pub poll_fn: unsafe extern "C" fn(*mut (), *const FfiWaker) -> FfiPoll<T>,
    pub drop_fn: unsafe extern "C" fn(*mut ()),
}

unsafe impl<T: Send> Send for FfiFuture<T> {}

impl<T> FfiFuture<T> {
    pub fn is_null(&self) -> bool {
        self.data.is_none()
    }

    pub unsafe fn poll(&mut self, waker: *const FfiWaker) -> FfiPoll<T> {
        if let Some(ptr) = self.data {
            unsafe { (self.poll_fn)(ptr, waker) }
        } else {
            FfiPoll::pending()
        }
    }
}

impl<T> Drop for FfiFuture<T> {
    fn drop(&mut self) {
        if let Some(ptr) = self.data.take() {
            unsafe { (self.drop_fn)(ptr) }
        }
    }
}

pub trait FutureExt: Future + Sized + Send {
    fn into_ffi(self) -> FfiFuture<Self::Output>;
}

impl<F> FutureExt for F
where
    F: Future + Send,
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

        if let Some(slot) = FUTURE_POOL.try_alloc_raw(size, align) {
            data_ptr = slot.as_ptr().cast::<FutureBox<F>>();

            let f = fut.take().unwrap();
            ptr::write(data_ptr, FutureBox { future: f });
        }
    }

    if data_ptr.is_null() {
        let f = fut.take().unwrap();
        let boxed = Box::new(FutureBox { future: f });
        data_ptr = Box::into_raw(boxed);
    }

    FfiFuture {
        abi_version: ABI_VERSION,
        data: Some(data_ptr as *mut ()),
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

unsafe extern "C" fn future_box_poll<F>(data: *mut (), waker: *const FfiWaker) -> FfiPoll<F::Output>
where
    F: Future,
{
    unsafe {
        if waker.is_null() {
            return FfiPoll::pending();
        }

        let fb = data as *mut FutureBox<F>;
        let w = ffi_waker_to_waker(&*waker);
        let mut cx = Context::from_waker(&w);
        let p = Future::poll(Pin::new_unchecked(&mut (*fb).future), &mut cx);

        FfiPoll::from(p)
    }
}

unsafe extern "C" fn future_box_drop<F>(data: *mut ())
where
    F: Future,
{
    unsafe {
        let fb = data as *mut FutureBox<F>;

        #[cfg(feature = "async-ffi-slab")]
        {
            if SLAB_CHECKS && FUTURE_POOL.contains(fb as *const u8) {
                debug_assert!(FUTURE_POOL.index_of(fb as *const u8).is_some_and(|_| {
                    (fb as usize).is_multiple_of(mem::align_of::<FutureBox<F>>())
                }));
            }

            if FUTURE_POOL.dealloc(fb) {
                return;
            }
        }

        drop(Box::from_raw(fb));
    }
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
    #[cfg(feature = "async-ffi-slab")]
    {
        if let Some(p) = WAKER_TO_FFI_POOL.try_alloc(RustWakerBox {
            refs: AtomicUsize::new(1),
            // TODO: it is possible to get rid of this clone
            waker: w.clone(),
        }) {
            return FfiWaker {
                data: p.as_ptr() as *const (),
                vtable: &RUST_WAKER_BOX_VTABLE,
            };
        }
    }

    let boxed = Box::new(RustWakerBox {
        refs: AtomicUsize::new(1),
        waker: w,
    });

    FfiWaker {
        data: Box::into_raw(boxed) as *const (),
        vtable: &RUST_WAKER_BOX_VTABLE,
    }
}

unsafe extern "C" fn rust_waker_box_clone(data: *const ()) -> FfiWaker {
    unsafe {
        let b = data as *const RustWakerBox;

        (*b).refs.fetch_add(1, Ordering::Relaxed);

        FfiWaker {
            data,
            vtable: &RUST_WAKER_BOX_VTABLE,
        }
    }
}

unsafe extern "C" fn rust_waker_box_wake(data: *const ()) {
    unsafe {
        let b = data as *const RustWakerBox;

        (*b).waker.wake_by_ref();
        rust_waker_box_drop(data);
    }
}

unsafe extern "C" fn rust_waker_box_wake_by_ref(data: *const ()) {
    unsafe {
        let b = data as *const RustWakerBox;

        (*b).waker.wake_by_ref();
    }
}

unsafe extern "C" fn rust_waker_box_drop(data: *const ()) {
    unsafe {
        let b = data as *mut RustWakerBox;

        if (*b).refs.fetch_sub(1, Ordering::AcqRel) != 1 {
            return;
        }

        #[cfg(feature = "async-ffi-slab")]
        {
            if WAKER_TO_FFI_POOL.dealloc(b) {
                return;
            }
        }

        drop(Box::from_raw(b));
    }
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
    {
        if let Some(p) = FFI_TO_WAKER_POOL.try_alloc(FfiWakerBox {
            refs: AtomicUsize::new(1),
            waker: w.clone(),
        }) {
            ptr_box = p.as_ptr();
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
    unsafe {
        let b = data as *const FfiWakerBox;

        (*b).refs.fetch_add(1, Ordering::Relaxed);
        RawWaker::new(data, &FFI_WAKER_BOX_RAW_VTABLE)
    }
}

unsafe fn ffi_waker_box_raw_wake(data: *const ()) {
    unsafe {
        ffi_waker_box_raw_wake_by_ref(data);
        ffi_waker_box_raw_drop(data);
    }
}

unsafe fn ffi_waker_box_raw_wake_by_ref(data: *const ()) {
    unsafe {
        let b = data as *const FfiWakerBox;

        (*b).waker.wake_by_ref();
    }
}

unsafe fn ffi_waker_box_raw_drop(data: *const ()) {
    unsafe {
        let b = data as *mut FfiWakerBox;

        if (*b).refs.fetch_sub(1, Ordering::AcqRel) != 1 {
            return;
        }

        #[cfg(feature = "async-ffi-slab")]
        {
            if FFI_TO_WAKER_POOL.dealloc(b) {
                return;
            }
        }

        drop(Box::from_raw(b));
    }
}

#[repr(C)]
pub struct BorrowingFfiFuture<'a, T> {
    pub abi_version: u32,
    pub data: *mut (),
    pub poll_fn: unsafe extern "C" fn(*mut (), *const FfiWaker) -> FfiPoll<T>,
    pub drop_fn: Option<unsafe extern "C" fn(*mut ())>,
    _pd: PhantomData<&'a mut ()>,
}

impl<'a, T> BorrowingFfiFuture<'a, T> {
    pub unsafe fn poll(&mut self, waker: *const FfiWaker) -> FfiPoll<T> {
        unsafe { (self.poll_fn)(self.data, waker) }
    }

    pub fn from_owned_ffi<'b>(mut fut: FfiFuture<T>) -> BorrowingFfiFuture<'b, T> {
        let data_ptr = fut.data.take().unwrap_or(ptr::null_mut());

        BorrowingFfiFuture {
            abi_version: fut.abi_version,
            data: data_ptr,
            poll_fn: fut.poll_fn,
            drop_fn: Some(fut.drop_fn),
            _pd: PhantomData,
        }
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
        drop_fn: None,
        _pd: PhantomData,
    }
}

unsafe extern "C" fn borrowing_future_poll<F>(
    data: *mut (),
    waker: *const FfiWaker,
) -> FfiPoll<F::Output>
where
    F: Future,
{
    unsafe {
        if waker.is_null() {
            return FfiPoll::pending();
        }

        let f = data as *mut F;
        let w = ffi_waker_to_waker(&*waker);
        let mut cx = Context::from_waker(&w);
        let p = Future::poll(Pin::new_unchecked(&mut *f), &mut cx);

        FfiPoll::from(p)
    }
}

impl<'a, T> Future for BorrowingFfiFuture<'a, T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<T> {
        let this = unsafe { self.get_unchecked_mut() };
        let ffi_waker = cx.waker().clone().into_ffi();
        let p = unsafe { (this.poll_fn)(this.data, &ffi_waker as *const FfiWaker) };

        match unsafe { p.into_poll() } {
            Poll::Pending => Poll::Pending,
            Poll::Ready(v) => {
                if let Some(df) = this.drop_fn {
                    if !this.data.is_null() {
                        unsafe { df(this.data) };
                        this.data = ptr::null_mut();
                    }
                }

                Poll::Ready(v)
            }
        }
    }
}

impl<'a, T> Drop for BorrowingFfiFuture<'a, T> {
    fn drop(&mut self) {
        if let Some(df) = self.drop_fn {
            if !self.data.is_null() {
                unsafe { df(self.data) };
                self.data = ptr::null_mut();
            }
        }
    }
}

impl<T> Future for FfiFuture<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<T> {
        let this = unsafe { self.get_unchecked_mut() };
        let Some(ptr) = this.data else {
            return Poll::Pending;
        };

        let ffi_waker = cx.waker().clone().into_ffi();
        let p = unsafe { (this.poll_fn)(ptr, &ffi_waker as *const FfiWaker) };

        match unsafe { p.into_poll() } {
            Poll::Pending => Poll::Pending,
            Poll::Ready(v) => {
                unsafe { (this.drop_fn)(ptr) };
                this.data = None;
                Poll::Ready(v)
            }
        }
    }
}
