use alloc::boxed::Box;
use core::future::Future;
use core::mem::{align_of, MaybeUninit};
use core::pin::Pin;
use core::task::{Context, Poll};

use super::{INLINE_FUTURE_ALIGN, INLINE_FUTURE_SIZE};

pub(super) struct CachePadded<T>(T);

impl<T> CachePadded<T> {
    pub(super) const fn new(v: T) -> Self {
        Self(v)
    }
}

impl<T> core::ops::Deref for CachePadded<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> core::ops::DerefMut for CachePadded<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

#[repr(C, align(8))]
pub(super) struct InlineFutureBuffer {
    data: MaybeUninit<[u8; INLINE_FUTURE_SIZE]>,
}

impl InlineFutureBuffer {
    pub(super) const fn new() -> Self {
        Self {
            data: MaybeUninit::uninit(),
        }
    }

    #[inline]
    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.data.as_mut_ptr() as *mut u8
    }
}

pub(super) enum FutureStorage {
    Boxed(Pin<Box<dyn Future<Output = ()> + Send + 'static>>),
    Inline {
        storage: InlineFutureBuffer,
        poll_fn: unsafe fn(*mut u8, &mut Context<'_>) -> Poll<()>,
        drop_fn: unsafe fn(*mut u8),
    },
}

unsafe fn poll_inline<F>(ptr: *mut u8, cx: &mut Context<'_>) -> Poll<()>
where
    F: Future<Output = ()>,
{
    let future = &mut *(ptr as *mut F);
    Pin::new_unchecked(future).poll(cx)
}

pub(super) unsafe fn drop_inline<F>(ptr: *mut u8) {
    core::ptr::drop_in_place(ptr as *mut F);
}

impl FutureStorage {
    pub(super) fn new<F>(future: F) -> Self
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let size = core::mem::size_of::<F>();
        let align = align_of::<F>();
        if size <= INLINE_FUTURE_SIZE && align <= INLINE_FUTURE_ALIGN {
            Self::new_inline(future)
        } else {
            Self::Boxed(Box::pin(future))
        }
    }

    fn new_inline<F>(future: F) -> Self
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let mut storage = InlineFutureBuffer::new();

        debug_assert!(align_of::<F>() <= INLINE_FUTURE_ALIGN);

        unsafe {
            let ptr = storage.as_mut_ptr() as *mut F;
            core::ptr::write(ptr, future);
        }

        Self::Inline {
            storage,
            poll_fn: poll_inline::<F>,
            drop_fn: drop_inline::<F>,
        }
    }

    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        match self {
            FutureStorage::Boxed(fut) => fut.as_mut().poll(cx),
            FutureStorage::Inline {
                storage, poll_fn, ..
            } => unsafe { poll_fn(storage.as_mut_ptr(), cx) },
        }
    }
}

impl Drop for FutureStorage {
    fn drop(&mut self) {
        if let FutureStorage::Inline {
            storage, drop_fn, ..
        } = self
        {
            unsafe { drop_fn(storage.as_mut_ptr()) }
        }
    }
}
