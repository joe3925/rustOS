// this is a no_std version of async_ffi

//! # FFI-compatible [`Future`][`core::future::Future`]s
//!
//! Rust currently doesn't provide stable ABI nor stable layout of related structs like
//! `dyn Future` or `Waker`.
//! With this crate, we can wrap async blocks or async functions to make a `Future` FFI-safe.
//!
//! [`FfiFuture`] provides the same functionality as `Box<dyn Future<Output = T> + Send>` but
//! it's FFI-compatible, aka. `repr(C)`. Any `Future<Output = T> + Send + 'static` can be converted
//! into [`FfiFuture`] by calling [`into_ffi`][`FutureExt::into_ffi`] on it, after `use`ing the
//! trait [`FutureExt`].
//!
//! [`FfiFuture`] implements `Future<Output = T> + Send`. You can `await` a [`FfiFuture`] just like
//! a normal `Future` to wait and get the output.
//!
//! For non-[`Send`] or non-`'static` futures, see the section
//! [Variants of `FfiFuture`](#variants-of-ffifuture) below.
//!
//!
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

extern crate alloc;

use alloc::boxed::Box;
use core::{
    convert::{TryFrom, TryInto},
    fmt,
    future::Future,
    marker::PhantomData,
    mem::{self, ManuallyDrop},
    pin::Pin,
    task::{Context, Poll, RawWaker, RawWakerVTable, Waker},
};

#[cfg(feature = "macros")]
#[cfg_attr(docsrs, doc(cfg(feature = "macros")))]
pub use macros::async_ffi;

/// The ABI version of [`FfiFuture`] and all variants.
/// Every non-compatible ABI change will increase this number, as well as the crate major version.
pub const ABI_VERSION: u32 = 2;

/// The FFI compatible [`core::task::Poll`]
///
/// [`core::task::Poll`]: core::task::Poll
#[repr(C, u8)]
#[cfg_attr(feature = "abi_stable", derive(abi_stable::StableAbi))]
pub enum FfiPoll<T> {
    /// Represents that a value is immediately ready.
    Ready(T),
    /// Represents that a value is not ready yet.
    Pending,
    /// Represents that the future panicked.
    /// Note: In no_std/kernel environments, this variant is effectively unreachable
    /// because panics usually abort the system immediately.
    Panicked,
}

/// Abort on drop with a message.
struct DropBomb(&'static str);

impl DropBomb {
    fn with<T, F: FnOnce() -> T>(message: &'static str, f: F) -> T {
        let bomb = DropBomb(message);
        let ret = f();
        mem::forget(bomb);
        ret
    }
}

impl Drop for DropBomb {
    fn drop(&mut self) {
        // In no_std, we cannot write to stderr. We just panic with the message.
        // If panic = abort, this terminates the context.
        panic!(
            "async-ffi: abort due to panic across FFI boundary: {}",
            self.0
        );
    }
}

/// The FFI compatible [`core::task::Context`]
///
/// [`core::task::Context`]: core::task::Context
#[repr(C)]
#[cfg_attr(feature = "abi_stable", derive(abi_stable::StableAbi))]
pub struct FfiContext<'a> {
    /// This waker is passed as borrow semantic.
    /// The external fn must not `drop` or `wake` it.
    waker: *const FfiWakerBase,
    /// Lets the compiler know that this references the `FfiWaker` and should not outlive it
    _marker: PhantomData<&'a FfiWakerBase>,
}

impl<'a> FfiContext<'a> {
    /// SAFETY: Vtable functions of `waker` are unsafe, the caller must ensure they have a
    /// sane behavior as a Waker. `with_context` relies on this to be safe.
    unsafe fn new(waker: &'a FfiWaker) -> Self {
        Self {
            waker: (waker as *const FfiWaker).cast::<FfiWakerBase>(),
            _marker: PhantomData,
        }
    }

    /// Runs a closure with the [`FfiContext`] as a normal [`core::task::Context`].
    ///
    /// [`core::task::Context`]: core::task::Context
    pub fn with_context<T, F: FnOnce(&mut Context) -> T>(&mut self, closure: F) -> T {
        // C vtable functions are considered from FFI and they are not expected to unwind, so we don't
        // need to wrap them with `DropBomb`.
        static RUST_WAKER_VTABLE: RawWakerVTable = {
            unsafe fn clone(data: *const ()) -> RawWaker {
                let waker = data.cast::<FfiWakerBase>();
                let cloned = ((*(*waker).vtable).clone)(waker);
                RawWaker::new(cloned.cast(), &RUST_WAKER_VTABLE)
            }
            unsafe fn wake(data: *const ()) {
                let waker = data.cast::<FfiWakerBase>();
                ((*(*waker).vtable).wake)(waker);
            }
            unsafe fn wake_by_ref(data: *const ()) {
                let waker = data.cast::<FfiWakerBase>();
                ((*(*waker).vtable).wake_by_ref)(waker);
            }
            unsafe fn drop(data: *const ()) {
                let waker = data.cast::<FfiWakerBase>();
                ((*(*waker).vtable).drop)(waker);
            }
            RawWakerVTable::new(clone, wake, wake_by_ref, drop)
        };

        // SAFETY: `waker`'s vtable functions must have sane behaviors, this is the contract of
        // `FfiContext::new`.
        let waker = unsafe {
            // The waker reference is borrowed from external context. We must not call drop on it.
            ManuallyDrop::new(Waker::from_raw(RawWaker::new(
                self.waker.cast(),
                &RUST_WAKER_VTABLE,
            )))
        };
        let mut ctx = Context::from_waker(&waker);

        closure(&mut ctx)
    }
}

/// Helper trait to provide convenience methods for converting a [`core::task::Context`] to [`FfiContext`]
///
/// [`core::task::Context`]: core::task::Context
pub trait ContextExt {
    /// Runs a closure with the [`core::task::Context`] as a [`FfiContext`].
    ///
    /// [`core::task::Context`]: core::task::Context
    fn with_ffi_context<T, F: FnOnce(&mut FfiContext) -> T>(&mut self, closure: F) -> T;
}

impl ContextExt for Context<'_> {
    fn with_ffi_context<T, F: FnOnce(&mut FfiContext) -> T>(&mut self, closure: F) -> T {
        static C_WAKER_VTABLE_OWNED: FfiWakerVTable = {
            unsafe extern "C" fn clone(data: *const FfiWakerBase) -> *const FfiWakerBase {
                DropBomb::with("Waker::clone", || {
                    let data = data as *mut FfiWaker;
                    let waker: Waker = (*(*data).waker.owned).clone();
                    Box::into_raw(Box::new(FfiWaker {
                        base: FfiWakerBase {
                            vtable: &C_WAKER_VTABLE_OWNED,
                        },
                        waker: WakerUnion {
                            owned: ManuallyDrop::new(waker),
                        },
                    }))
                    .cast()
                })
            }
            // In this case, we must own `data`. This can only happen when the `data` pointer is returned from `clone`.
            // Thus the it is `Box<FfiWaker>`.
            unsafe extern "C" fn wake(data: *const FfiWakerBase) {
                DropBomb::with("Waker::wake", || {
                    let b = Box::from_raw(data as *mut FfiWaker);
                    ManuallyDrop::into_inner(b.waker.owned).wake();
                });
            }
            unsafe extern "C" fn wake_by_ref(data: *const FfiWakerBase) {
                DropBomb::with("Waker::wake_by_ref", || {
                    let data = data as *mut FfiWaker;
                    (*data).waker.owned.wake_by_ref();
                });
            }
            // Same as `wake`.
            unsafe extern "C" fn drop(data: *const FfiWakerBase) {
                DropBomb::with("Waker::drop", || {
                    let mut b = Box::from_raw(data as *mut FfiWaker);
                    ManuallyDrop::drop(&mut b.waker.owned);
                    mem::drop(b);
                });
            }
            FfiWakerVTable {
                clone,
                wake,
                wake_by_ref,
                drop,
            }
        };

        static C_WAKER_VTABLE_REF: FfiWakerVTable = {
            unsafe extern "C" fn clone(data: *const FfiWakerBase) -> *const FfiWakerBase {
                DropBomb::with("Waker::clone", || {
                    let data = data as *mut FfiWaker;
                    let waker: Waker = (*(*data).waker.reference).clone();
                    Box::into_raw(Box::new(FfiWaker {
                        base: FfiWakerBase {
                            vtable: &C_WAKER_VTABLE_OWNED,
                        },
                        waker: WakerUnion {
                            owned: ManuallyDrop::new(waker),
                        },
                    }))
                    .cast()
                })
            }
            unsafe extern "C" fn wake_by_ref(data: *const FfiWakerBase) {
                DropBomb::with("Waker::wake_by_ref", || {
                    let data = data as *mut FfiWaker;
                    (*(*data).waker.reference).wake_by_ref();
                });
            }
            unsafe extern "C" fn unreachable(_: *const FfiWakerBase) {
                panic!("async-ffi: unreachable waker call");
            }
            FfiWakerVTable {
                clone,
                wake: unreachable,
                wake_by_ref,
                drop: unreachable,
            }
        };

        let waker = FfiWaker {
            base: FfiWakerBase {
                vtable: &C_WAKER_VTABLE_REF,
            },
            waker: WakerUnion {
                reference: self.waker(),
            },
        };

        // SAFETY: The behavior of `waker` is sane since we forward them to another valid Waker.
        // That waker must be safe to use due to the contract of `RawWaker::new`.
        let mut ctx = unsafe { FfiContext::new(&waker) };

        closure(&mut ctx)
    }
}

// Inspired by Gary Guo (github.com/nbdd0121)
//
// The base is what can be accessed through FFI, and the regular struct contains
// internal data (the original waker).
#[repr(C)]
#[cfg_attr(feature = "abi_stable", derive(abi_stable::StableAbi))]
struct FfiWakerBase {
    vtable: *const FfiWakerVTable,
}
#[repr(C)]
struct FfiWaker {
    base: FfiWakerBase,
    waker: WakerUnion,
}

#[repr(C)]
union WakerUnion {
    reference: *const Waker,
    owned: ManuallyDrop<Waker>,
    unknown: (),
}

#[derive(Clone, Copy)]
#[repr(C)]
#[cfg_attr(feature = "abi_stable", derive(abi_stable::StableAbi))]
struct FfiWakerVTable {
    clone: unsafe extern "C" fn(*const FfiWakerBase) -> *const FfiWakerBase,
    wake: unsafe extern "C" fn(*const FfiWakerBase),
    wake_by_ref: unsafe extern "C" fn(*const FfiWakerBase),
    drop: unsafe extern "C" fn(*const FfiWakerBase),
}

/// The FFI compatible future type with [`Send`] bound.
///
/// See [module level documentation](`crate`) for more details.
#[repr(transparent)]
#[cfg_attr(feature = "abi_stable", derive(abi_stable::StableAbi))]
pub struct BorrowingFfiFuture<'a, T>(LocalBorrowingFfiFuture<'a, T>);

/// The FFI compatible future type with [`Send`] bound and `'static` lifetime,
/// which is needed for most use cases.
///
/// See [module level documentation](`crate`) for more details.
pub type FfiFuture<T> = BorrowingFfiFuture<'static, T>;

/// Helper trait to provide conversion from `Future` to [`FfiFuture`] or [`LocalFfiFuture`].
///
/// See [module level documentation](`crate`) for more details.
pub trait FutureExt: Future + Sized {
    /// Convert a Rust `Future` implementing [`Send`] into a FFI-compatible [`FfiFuture`].
    fn into_ffi<'a>(self) -> BorrowingFfiFuture<'a, Self::Output>
    where
        Self: Send + 'a,
    {
        BorrowingFfiFuture::new(self)
    }

    /// Convert a Rust `Future` into a FFI-compatible [`LocalFfiFuture`].
    fn into_local_ffi<'a>(self) -> LocalBorrowingFfiFuture<'a, Self::Output>
    where
        Self: 'a,
    {
        LocalBorrowingFfiFuture::new(self)
    }
}

impl<F> FutureExt for F where F: Future + Sized {}

/// Represents that the poll function panicked.
#[derive(Debug)]
pub struct PollPanicked {
    _private: (),
}

impl fmt::Display for PollPanicked {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FFI poll function panicked")
    }
}

// core::error::Error is stable since 1.81.
// If you are on an older compiler, comment this impl out.
impl core::error::Error for PollPanicked {}

impl<T> FfiPoll<T> {
    /// Converts a [`core::task::Poll`] to the [`FfiPoll`].
    ///
    /// [`core::task::Poll`]: core::task::Poll
    pub fn from_poll(poll: Poll<T>) -> Self {
        match poll {
            Poll::Ready(r) => Self::Ready(r),
            Poll::Pending => Self::Pending,
        }
    }

    /// Try to convert a [`FfiPoll`] back to the [`core::task::Poll`].
    ///
    /// # Errors
    /// Returns `Err(PollPanicked)` if the result indicates the poll function panicked.
    ///
    /// [`core::task::Poll`]: core::task::Poll
    pub fn try_into_poll(self) -> Result<Poll<T>, PollPanicked> {
        match self {
            Self::Ready(r) => Ok(Poll::Ready(r)),
            Self::Pending => Ok(Poll::Pending),
            Self::Panicked => Err(PollPanicked { _private: () }),
        }
    }
}

impl<T> From<Poll<T>> for FfiPoll<T> {
    fn from(poll: Poll<T>) -> Self {
        Self::from_poll(poll)
    }
}

impl<T> TryFrom<FfiPoll<T>> for Poll<T> {
    type Error = PollPanicked;

    fn try_from(ffi_poll: FfiPoll<T>) -> Result<Self, PollPanicked> {
        ffi_poll.try_into_poll()
    }
}

impl<'a, T> BorrowingFfiFuture<'a, T> {
    /// Convert an [`core::future::Future`] implementing [`Send`] into a FFI-compatible [`FfiFuture`].
    ///
    /// Usually [`FutureExt::into_ffi`] is preferred and is identical to this method.
    pub fn new<F: Future<Output = T> + Send + 'a>(fut: F) -> Self {
        Self(LocalBorrowingFfiFuture::new(fut))
    }
}

// SAFETY: This is safe since we allow only `Send` Future in `FfiFuture::new`.
unsafe impl<T> Send for BorrowingFfiFuture<'_, T> {}

impl<T> Future for BorrowingFfiFuture<'_, T> {
    type Output = T;

    fn poll(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(ctx)
    }
}

/// The FFI compatible future type without [`Send`] bound.
///
/// Non-[`Send`] `Future`s can only be converted into [`LocalFfiFuture`]. It is not able to be
/// `spawn`ed in a multi-threaded runtime, but is useful for thread-local futures, single-threaded
/// runtimes, or single-threaded targets like `wasm32-unknown-unknown`.
///
/// See [module level documentation](`crate`) for more details.
#[repr(C)]
#[cfg_attr(feature = "abi_stable", derive(abi_stable::StableAbi))]
pub struct LocalBorrowingFfiFuture<'a, T> {
    fut_ptr: *mut (),
    poll_fn: unsafe extern "C" fn(fut_ptr: *mut (), context_ptr: *mut FfiContext) -> FfiPoll<T>,
    drop_fn: unsafe extern "C" fn(*mut ()),
    _marker: PhantomData<&'a ()>,
}
impl<'a, T> fmt::Debug for LocalBorrowingFfiFuture<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalBorrowingFfiFuture")
            .field("fut_ptr", &self.fut_ptr)
            .field("poll_fn", &(self.poll_fn as *const ()))
            .field("drop_fn", &(self.drop_fn as *const ()))
            .finish()
    }
}

impl<'a, T> fmt::Debug for BorrowingFfiFuture<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("BorrowingFfiFuture").field(&self.0).finish()
    }
}
/// The FFI compatible future type without `Send` bound but with `'static` lifetime.
///
/// See [module level documentation](`crate`) for more details.
pub type LocalFfiFuture<T> = LocalBorrowingFfiFuture<'static, T>;

impl<'a, T> LocalBorrowingFfiFuture<'a, T> {
    /// Convert an [`core::future::Future`] into a FFI-compatible [`LocalFfiFuture`].
    ///
    /// Usually [`FutureExt::into_local_ffi`] is preferred and is identical to this method.
    pub fn new<F: Future<Output = T> + 'a>(fut: F) -> Self {
        unsafe extern "C" fn poll_fn<F: Future>(
            fut_ptr: *mut (),
            context_ptr: *mut FfiContext,
        ) -> FfiPoll<F::Output> {
            // NO_STD MODIFICATION:
            // catch_unwind is not supported in no_std. If F::poll panics,
            // the kernel will abort. We cannot catch it.
            let fut_pin = Pin::new_unchecked(&mut *fut_ptr.cast::<F>());
            let poll_res = (*context_ptr).with_context(|ctx| F::poll(fut_pin, ctx));
            poll_res.into()
        }

        unsafe extern "C" fn drop_fn<T>(ptr: *mut ()) {
            DropBomb::with("Future::drop", || {
                drop(Box::from_raw(ptr.cast::<T>()));
            });
        }

        let ptr = Box::into_raw(Box::new(fut));
        Self {
            fut_ptr: ptr.cast(),
            poll_fn: poll_fn::<F>,
            drop_fn: drop_fn::<F>,
            _marker: PhantomData,
        }
    }
}

impl<T> Drop for LocalBorrowingFfiFuture<'_, T> {
    fn drop(&mut self) {
        // SAFETY: This is safe since `drop_fn` is construct from `LocalBorrowingFfiFuture::new`
        // and is a dropper
        // `LocalBorrowingFfiFuture::new` and they are just a Box pointer and its corresponding
        // dropper.
        unsafe { (self.drop_fn)(self.fut_ptr) };
    }
}

impl<T> Future for LocalBorrowingFfiFuture<'_, T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: This is safe since `poll_fn` is constructed from `LocalBorrowingFfiFuture::new`
        // and it just forwards to the original safe `Future::poll`.
        let result = ctx.with_ffi_context(|ctx| unsafe { (self.poll_fn)(self.fut_ptr, ctx) });

        // NO_STD MODIFICATION:
        // Since we removed catch_unwind, we will never realistically see Panicked here
        // generated from *our* side. If the other side generates it, we panic.
        result
            .try_into()
            .expect("FFI future panicked (and was caught by the other side)")
    }
}
