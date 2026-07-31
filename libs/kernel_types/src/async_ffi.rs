use core::future::Future;
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::pin::Pin;
use core::task::{Context, Poll};

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct AbiFutureAllocation {
    pub ptr: *mut (),
    pub owner_domain: u64,
    pub token: u64,
    pub capacity: u32,
    pub align: u32,
}

impl AbiFutureAllocation {
    pub const fn null() -> Self {
        Self {
            ptr: core::ptr::null_mut(),
            owner_domain: 0,
            token: 0,
            capacity: 0,
            align: 0,
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbiPoll {
    Pending = 0,
    Ready = 1,
}

pub type AbiFuturePollFn<T> =
    unsafe extern "C" fn(future: *mut (), context: *mut (), output: *mut MaybeUninit<T>) -> AbiPoll;
pub type AbiFutureDropFn = unsafe extern "C" fn(*mut ());
pub type AbiFutureFreeFn = unsafe extern "C" fn(AbiFutureAllocation);

unsafe extern "C" {
    fn kernel_abi_future_allocate(size: usize, align: usize) -> AbiFutureAllocation;
    fn kernel_abi_future_free(allocation: AbiFutureAllocation);
}

#[repr(C)]
pub struct AbiFuture<T> {
    allocation: AbiFutureAllocation,
    poll_fn: AbiFuturePollFn<T>,
    drop_fn: AbiFutureDropFn,
    free_fn: AbiFutureFreeFn,
    live: bool,
    _output: PhantomData<fn() -> T>,
}

unsafe impl<T: Send> Send for AbiFuture<T> {}

impl<T> AbiFuture<T> {
    pub fn is_live(&self) -> bool {
        self.live
    }

    unsafe fn destroy_live(&mut self) {
        if !self.live {
            return;
        }
        self.live = false;
        unsafe {
            (self.drop_fn)(self.allocation.ptr);
            (self.free_fn)(self.allocation);
        }
        self.allocation = AbiFutureAllocation::null();
    }
}

impl<T> Future for AbiFuture<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<T> {
        let this = unsafe { self.get_unchecked_mut() };
        assert!(this.live, "AbiFuture polled after completion");
        let mut output = MaybeUninit::uninit();
        let state = unsafe {
            (this.poll_fn)(
                this.allocation.ptr,
                (cx as *mut Context<'_>).cast(),
                &mut output,
            )
        };
        match state {
            AbiPoll::Pending => Poll::Pending,
            AbiPoll::Ready => {
                unsafe { this.destroy_live() };
                Poll::Ready(unsafe { output.assume_init() })
            }
        }
    }
}

impl<T> Drop for AbiFuture<T> {
    fn drop(&mut self) {
        unsafe { self.destroy_live() };
    }
}

pub trait FutureExt: Future + Sized + Send {
    fn into_abi(self) -> AbiFuture<Self::Output>;
}

impl<F> FutureExt for F
where
    F: Future + Send,
{
    fn into_abi(self) -> AbiFuture<Self::Output> {
        let allocation = unsafe {
            kernel_abi_future_allocate(core::mem::size_of::<F>(), core::mem::align_of::<F>())
        };
        assert!(
            !allocation.ptr.is_null(),
            "AbiFuture created outside an executor poll context or arena allocation failed"
        );
        unsafe {
            allocation.ptr.cast::<F>().write(self);
        }
        AbiFuture {
            allocation,
            poll_fn: poll_future::<F>,
            drop_fn: drop_future::<F>,
            free_fn: kernel_abi_future_free,
            live: true,
            _output: PhantomData,
        }
    }
}

unsafe extern "C" fn poll_future<F>(
    future: *mut (),
    context: *mut (),
    output: *mut MaybeUninit<F::Output>,
) -> AbiPoll
where
    F: Future,
{
    let future = unsafe { &mut *future.cast::<F>() };
    let context = unsafe { &mut *context.cast::<Context<'_>>() };
    match unsafe { Pin::new_unchecked(future) }.poll(context) {
        Poll::Pending => AbiPoll::Pending,
        Poll::Ready(value) => {
            unsafe { (*output).write(value) };
            AbiPoll::Ready
        }
    }
}

unsafe extern "C" fn drop_future<F>(future: *mut ()) {
    unsafe { core::ptr::drop_in_place(future.cast::<F>()) };
}
