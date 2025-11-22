use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};

use alloc::sync::Arc;
use spin::RwLock;
pub trait AsyncWaitable {
    /// Returns true if the operation is complete
    fn is_ready(&self) -> bool;

    /// Stores the waker so the object can notify the executor later
    fn set_waker(&mut self, waker: Option<Waker>);
}
pub struct AsyncFuture<T: ?Sized> {
    pub target: Arc<RwLock<T>>,
}

impl<T: AsyncWaitable + ?Sized> Future for AsyncFuture<T> {
    type Output = Arc<RwLock<T>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut guard = self.target.write();

        if guard.is_ready() {
            guard.set_waker(None);
            return Poll::Ready(self.target.clone());
        }

        guard.set_waker(Some(cx.waker().clone()));

        Poll::Pending
    }
}
