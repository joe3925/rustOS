use alloc::sync::{Arc, Weak};
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::Ordering;
use core::task::{Context, Poll, Waker};
use kernel_types::async_ffi::FfiFuture;
use kernel_types::device::{DevNode, DeviceObject};
use kernel_types::io::{DeviceOps, IoHandler, IoTarget};
use kernel_types::pnp::DriverStep;
use kernel_types::request::{
    DeviceControl, Dummy, Flush, FlushDirty, FlushOwner, Fs, FsOperation, Pnp, Read, RequestHandle,
    RequestKind, Write,
};
use kernel_types::status::DriverStatus;

#[cfg(feature = "kernel_link")]
unsafe extern "Rust" {
    // Linker seam for kernel print
    fn routing_print_impl(s: &str);
    fn routing_resolve_path_to_device_impl(path: &str) -> Option<IoTarget>;
    fn routing_get_stack_top_from_weak_impl(
        dev_node_weak: &Weak<DevNode>,
    ) -> Option<Arc<DeviceObject>>;
}

#[cfg(feature = "kernel_link")]
#[inline]
fn resolve_path_to_device(path: &str) -> Option<IoTarget> {
    unsafe { routing_resolve_path_to_device_impl(path) }
}

#[cfg(feature = "kernel_link")]
#[inline]
pub fn print(s: &str) {
    unsafe { routing_print_impl(s) }
}

#[cfg(feature = "kernel_link")]
#[inline]
fn get_stack_top_from_weak(dev_node_weak: &Weak<DevNode>) -> Option<Arc<DeviceObject>> {
    unsafe { routing_get_stack_top_from_weak_impl(dev_node_weak) }
}

#[cfg(not(feature = "kernel_link"))]
#[inline]
fn resolve_path_to_device(path: &str) -> Option<IoTarget> {
    unsafe { kernel_sys::routing_resolve_path_to_device(path) }
}

#[cfg(not(feature = "kernel_link"))]
#[inline]
pub fn print(s: &str) {
    unsafe { kernel_sys::print(s) }
}

#[cfg(not(feature = "kernel_link"))]
#[inline]
fn get_stack_top_from_weak(dev_node_weak: &Weak<DevNode>) -> Option<Arc<DeviceObject>> {
    unsafe { kernel_sys::routing_get_stack_top_from_weak(dev_node_weak) }
}

#[macro_export]
macro_rules! println {
    () => {
        $crate::print("\n");
    };
    ($($arg:tt)*) => {
        $crate::print(&alloc::format!("{}\n", core::format_args!($($arg)*)));
    };
}

pub trait RoutedRequest: RequestKind + Sized {
    fn invoke_at<'a, 'req>(
        dev: &'a Arc<DeviceObject>,
        handle: &'a mut RequestHandle<'req, Self>,
    ) -> impl Future<Output = Option<DriverStep>> + Send + 'a;
}

pub trait IoRequest: RoutedRequest {
    type Handler: Copy;

    fn handler(ops: &DeviceOps) -> Option<&IoHandler<Self::Handler>>;

    fn call<'req, 'b>(
        handler: Self::Handler,
        dev: &Arc<DeviceObject>,
        handle: &'b mut RequestHandle<'req, Self>,
    ) -> FfiFuture<DriverStep>;
}

impl<'io> IoRequest for Read<'io> {
    type Handler = kernel_types::EvtIoRead;

    #[inline]
    fn handler(ops: &DeviceOps) -> Option<&IoHandler<Self::Handler>> {
        ops.read.as_handler()
    }

    #[inline]
    fn call<'req, 'b>(
        handler: Self::Handler,
        dev: &Arc<DeviceObject>,
        handle: &'b mut RequestHandle<'req, Self>,
    ) -> FfiFuture<DriverStep> {
        handler(dev, handle)
    }
}

impl<'io> IoRequest for Write<'io> {
    type Handler = kernel_types::EvtIoWrite;

    #[inline]
    fn handler(ops: &DeviceOps) -> Option<&IoHandler<Self::Handler>> {
        ops.write.as_handler()
    }

    #[inline]
    fn call<'req, 'b>(
        handler: Self::Handler,
        dev: &Arc<DeviceObject>,
        handle: &'b mut RequestHandle<'req, Self>,
    ) -> FfiFuture<DriverStep> {
        handler(dev, handle)
    }
}
impl IoRequest for Flush {
    type Handler = kernel_types::EvtIoFlush;

    #[inline]
    fn handler(ops: &DeviceOps) -> Option<&IoHandler<Self::Handler>> {
        ops.flush.as_handler()
    }

    #[inline]
    fn call<'req, 'b>(
        handler: Self::Handler,
        dev: &Arc<DeviceObject>,
        handle: &'b mut RequestHandle<'req, Self>,
    ) -> FfiFuture<DriverStep> {
        handler(dev, handle)
    }
}

impl IoRequest for FlushDirty {
    type Handler = kernel_types::EvtIoFlushDirty;

    #[inline]
    fn handler(ops: &DeviceOps) -> Option<&IoHandler<Self::Handler>> {
        ops.flush_dirty.as_handler()
    }

    #[inline]
    fn call<'req, 'b>(
        handler: Self::Handler,
        dev: &Arc<DeviceObject>,
        handle: &'b mut RequestHandle<'req, Self>,
    ) -> FfiFuture<DriverStep> {
        handler(dev, handle)
    }
}

impl IoRequest for FlushOwner {
    type Handler = kernel_types::EvtIoFlushOwner;

    #[inline]
    fn handler(ops: &DeviceOps) -> Option<&IoHandler<Self::Handler>> {
        ops.flush_owner.as_handler()
    }

    #[inline]
    fn call<'req, 'b>(
        handler: Self::Handler,
        dev: &Arc<DeviceObject>,
        handle: &'b mut RequestHandle<'req, Self>,
    ) -> FfiFuture<DriverStep> {
        handler(dev, handle)
    }
}

impl<'data> IoRequest for DeviceControl<'data> {
    type Handler = kernel_types::EvtIoDeviceControl;

    #[inline]
    fn handler(ops: &DeviceOps) -> Option<&IoHandler<Self::Handler>> {
        ops.device_control.as_handler()
    }

    #[inline]
    fn call<'req, 'b>(
        handler: Self::Handler,
        dev: &Arc<DeviceObject>,
        handle: &'b mut RequestHandle<'req, Self>,
    ) -> FfiFuture<DriverStep> {
        handler(dev, handle)
    }
}

impl<'data, O> IoRequest for Fs<'data, O>
where
    O: FsOperation + Send,
    O::Handler: Sync,
    for<'any> O::Params<'any>: Send,
    O::Result: Send,
{
    type Handler = O::Handler;

    #[inline]
    fn handler(ops: &DeviceOps) -> Option<&IoHandler<Self::Handler>> {
        let fs = ops.fs.as_ops()?;
        O::handler(fs)
    }

    #[inline]
    fn call<'req, 'b>(
        handler: Self::Handler,
        dev: &Arc<DeviceObject>,
        handle: &'b mut RequestHandle<'req, Self>,
    ) -> FfiFuture<DriverStep> {
        O::call(handler, dev, handle)
    }
}

async fn invoke_io_handler<K: IoRequest>(
    dev: &Arc<DeviceObject>,
    handle: &mut RequestHandle<'_, K>,
) -> Option<DriverStep> {
    let h = K::handler(&dev.ops)?;

    if h.depth == 0 {
        return Some(K::call(h.handler, dev, handle).await);
    }

    let guard = acquire_slot(h).await;
    let result = K::call(h.handler, dev, handle).await;
    drop(guard);
    Some(result)
}

macro_rules! impl_routed_io {
    ($ty:ty) => {
        impl RoutedRequest for $ty {
            #[inline]
            fn invoke_at<'a, 'req>(
                dev: &'a Arc<DeviceObject>,
                handle: &'a mut RequestHandle<'req, Self>,
            ) -> impl Future<Output = Option<DriverStep>> + Send + 'a {
                async move { invoke_io_handler::<Self>(dev, handle).await }
            }
        }
    };
}

impl<'io> RoutedRequest for Read<'io> {
    #[inline]
    fn invoke_at<'a, 'req>(
        dev: &'a Arc<DeviceObject>,
        handle: &'a mut RequestHandle<'req, Self>,
    ) -> impl Future<Output = Option<DriverStep>> + Send + 'a {
        async move { invoke_io_handler::<Self>(dev, handle).await }
    }
}

impl<'io> RoutedRequest for Write<'io> {
    #[inline]
    fn invoke_at<'a, 'req>(
        dev: &'a Arc<DeviceObject>,
        handle: &'a mut RequestHandle<'req, Self>,
    ) -> impl Future<Output = Option<DriverStep>> + Send + 'a {
        async move { invoke_io_handler::<Self>(dev, handle).await }
    }
}

impl_routed_io!(Flush);
impl_routed_io!(FlushDirty);
impl_routed_io!(FlushOwner);

impl<'data> RoutedRequest for DeviceControl<'data> {
    #[inline]
    fn invoke_at<'a, 'req>(
        dev: &'a Arc<DeviceObject>,
        handle: &'a mut RequestHandle<'req, Self>,
    ) -> impl Future<Output = Option<DriverStep>> + Send + 'a {
        async move { invoke_io_handler::<Self>(dev, handle).await }
    }
}

impl<'data, O> RoutedRequest for Fs<'data, O>
where
    O: FsOperation + Send,
    O::Handler: Sync,
    for<'any> O::Params<'any>: Send,
    O::Result: Send,
{
    #[inline]
    fn invoke_at<'a, 'req>(
        dev: &'a Arc<DeviceObject>,
        handle: &'a mut RequestHandle<'req, Self>,
    ) -> impl Future<Output = Option<DriverStep>> + Send + 'a {
        async move { invoke_io_handler::<Self>(dev, handle).await }
    }
}

impl<'data> RoutedRequest for Pnp<'data> {
    fn invoke_at<'a, 'req>(
        dev: &'a Arc<DeviceObject>,
        handle: &'a mut RequestHandle<'req, Self>,
    ) -> impl Future<Output = Option<DriverStep>> + Send + 'a {
        async move { pnp_minor_dispatch(dev, handle).await }
    }
}

impl RoutedRequest for Dummy {
    #[inline]
    fn invoke_at<'a, 'req>(
        _dev: &'a Arc<DeviceObject>,
        _handle: &'a mut RequestHandle<'req, Self>,
    ) -> impl Future<Output = Option<DriverStep>> + Send + 'a {
        async move { None }
    }
}

fn prepare_request<K: RequestKind>(handle: &mut RequestHandle<'_, K>) {
    {
        let guard = handle.get_mut();
        guard.status = DriverStatus::ContinueStep;
        guard.completed = false;
    }
}

/// Complete a request.
#[inline]
pub fn complete_request<K: RequestKind>(handle: &mut RequestHandle<'_, K>) -> DriverStatus {
    let guard = handle.get_mut();
    guard.complete()
}

#[cold]
fn complete_with_status<K: RequestKind>(
    handle: &mut RequestHandle<'_, K>,
    status: DriverStatus,
) -> DriverStatus {
    handle.get_mut().status = status;
    complete_request(handle)
}

async fn call_one_device<K: RoutedRequest>(
    dev: &Arc<DeviceObject>,
    handle: &mut RequestHandle<'_, K>,
) -> DriverStatus {
    match K::invoke_at(dev, handle).await {
        Some(DriverStep::Complete { status }) => complete_with_status(handle, status),
        Some(DriverStep::Continue) | None => {
            complete_with_status(handle, DriverStatus::NotImplemented)
        }
    }
}

async fn call_io_down_stack<K: IoRequest>(
    mut dev: Arc<DeviceObject>,
    handle: &mut RequestHandle<'_, K>,
) -> DriverStatus {
    loop {
        match K::invoke_at(&dev, handle).await {
            Some(DriverStep::Complete { status }) => {
                return complete_with_status(handle, status);
            }
            Some(DriverStep::Continue) => {
                return complete_with_status(handle, DriverStatus::NotImplemented);
            }
            None => match dev.lower_device.get().cloned() {
                Some(n) => {
                    dev = n;
                }
                None => {
                    return complete_with_status(handle, DriverStatus::NotImplemented);
                }
            },
        }
    }
}

async fn call_pnp_down_stack<'data>(
    mut dev: Arc<DeviceObject>,
    handle: &mut RequestHandle<'_, Pnp<'data>>,
) -> DriverStatus {
    loop {
        match Pnp::invoke_at(&dev, handle).await {
            Some(DriverStep::Complete { status }) => {
                return complete_with_status(handle, status);
            }
            Some(DriverStep::Continue) | None => match dev.lower_device.get().cloned() {
                Some(n) => {
                    dev = n;
                }
                None => {
                    let status = handle
                        .get()
                        .body
                        .request
                        .minor_function
                        .default_status_for_unhandled();
                    return complete_with_status(handle, status);
                }
            },
        }
    }
}

pub mod io {
    use super::*;

    /// Dispatches an I/O request to exactly `target`.
    ///
    /// The request does not traverse to lower or upper devices. If `target` has no handler for
    /// the request kind, or the handler returns `Continue`, the request completes with
    /// `NotImplemented`.
    pub async fn send_to_device<K: IoRequest>(
        target: IoTarget,
        handle: &mut RequestHandle<'_, K>,
    ) -> DriverStatus {
        prepare_request(handle);
        call_one_device(&target, handle).await
    }

    /// Dispatches an I/O request downward through the current device stack starting at `target`.
    ///
    /// Each device is tried until a handler completes the request. Missing handlers move to the
    /// next lower device in the same stack. The traversal never crosses into a parent or child
    /// devnode. If the stack exists but no device handles the request, the request completes with
    /// `NotImplemented`.
    pub async fn send_down_stack<K: IoRequest>(
        target: IoTarget,
        handle: &mut RequestHandle<'_, K>,
    ) -> DriverStatus {
        prepare_request(handle);
        call_io_down_stack(target, handle).await
    }

    /// Dispatches an I/O request downward starting at `from.lower_device`.
    ///
    /// The traversal remains within the current device stack. If `from` has no lower device, the
    /// request completes with `NoSuchDevice`. If lower devices exist but none handle the request,
    /// it completes with `NotImplemented`.
    pub async fn send_next_lower<K: IoRequest>(
        from: Arc<DeviceObject>,
        handle: &mut RequestHandle<'_, K>,
    ) -> DriverStatus {
        let Some(target) = from.lower_device.get().cloned() else {
            return complete_with_status(handle, DriverStatus::NoSuchDevice);
        };

        send_down_stack(target, handle).await
    }

    /// Dispatches an I/O request downward from the top device in `dev_node_weak`'s stack.
    ///
    /// The traversal remains within that single stack. If the devnode cannot be resolved to a
    /// stack top or PDO, the request completes with `NoSuchDevice`. If a stack is found but no
    /// device handles the request, it completes with `NotImplemented`.
    pub async fn send_to_stack_top<K: IoRequest>(
        dev_node_weak: Weak<DevNode>,
        handle: &mut RequestHandle<'_, K>,
    ) -> DriverStatus {
        match get_stack_top_from_weak(&dev_node_weak) {
            Some(target) => send_down_stack(target, handle).await,
            None => complete_with_status(handle, DriverStatus::NoSuchDevice),
        }
    }

    /// Resolves `link_path` to a device object without dispatching a request.
    ///
    /// Callers must choose an explicit traversal helper after resolving the target, such as
    /// `send_to_device` or `send_down_stack`.
    pub fn resolve_target(link_path: &str) -> Option<IoTarget> {
        resolve_path_to_device(link_path)
    }
}

pub mod pnp {
    use super::*;

    /// Dispatches a PnP request to exactly `target`.
    ///
    /// The request does not traverse to lower or upper devices. If `target` has no handler for the
    /// PnP minor, the request completes with that minor's default unhandled status.
    pub async fn send_to_device<'data>(
        target: IoTarget,
        handle: &mut RequestHandle<'_, Pnp<'data>>,
    ) -> DriverStatus {
        prepare_request(handle);
        match Pnp::invoke_at(&target, handle).await {
            Some(DriverStep::Complete { status }) => complete_with_status(handle, status),
            Some(DriverStep::Continue) | None => {
                let status = handle
                    .get()
                    .body
                    .request
                    .minor_function
                    .default_status_for_unhandled();
                complete_with_status(handle, status)
            }
        }
    }

    /// Dispatches a PnP request downward through the current device stack starting at `target`.
    ///
    /// Missing handlers and `Continue` move to the next lower device in the same stack. The
    /// traversal never crosses into parent or child devnodes. If the stack ends unhandled, the
    /// request completes with the PnP minor's default unhandled status.
    pub async fn send_down_stack<'data>(
        target: IoTarget,
        handle: &mut RequestHandle<'_, Pnp<'data>>,
    ) -> DriverStatus {
        prepare_request(handle);
        call_pnp_down_stack(target, handle).await
    }

    /// Dispatches a PnP request downward starting at `from.lower_device`.
    ///
    /// The traversal remains within the current device stack. If `from` has no lower device, the
    /// request completes with `NoSuchDevice`. If the lower stack ends unhandled, the request
    /// completes with the PnP minor's default unhandled status.
    pub async fn send_next_lower<'data>(
        from: Arc<DeviceObject>,
        handle: &mut RequestHandle<'_, Pnp<'data>>,
    ) -> DriverStatus {
        let Some(target) = from.lower_device.get().cloned() else {
            return complete_with_status(handle, DriverStatus::NoSuchDevice);
        };

        send_down_stack(target, handle).await
    }

    /// Dispatches a PnP request downward from the top device in `dev_node_weak`'s stack.
    ///
    /// The traversal remains within that single stack. If the devnode cannot be resolved to a
    /// stack top or PDO, the request completes with `NoSuchDevice`. If a stack is found but ends
    /// unhandled, it completes with the PnP minor's default unhandled status.
    pub async fn send_to_stack_top<'data>(
        dev_node_weak: Weak<DevNode>,
        handle: &mut RequestHandle<'_, Pnp<'data>>,
    ) -> DriverStatus {
        match get_stack_top_from_weak(&dev_node_weak) {
            Some(target) => send_down_stack(target, handle).await,
            None => complete_with_status(handle, DriverStatus::NoSuchDevice),
        }
    }

    /// Resolves `link_path` to a device object without dispatching a request.
    ///
    /// Callers must choose an explicit traversal helper after resolving the target, such as
    /// `send_to_device` or `send_down_stack`.
    pub fn resolve_target(link_path: &str) -> Option<IoTarget> {
        resolve_path_to_device(link_path)
    }
}

async fn pnp_minor_dispatch<'data>(
    device: &Arc<DeviceObject>,
    handle: &mut RequestHandle<'_, Pnp<'data>>,
) -> Option<DriverStep> {
    let minor = handle.get().body.request.minor_function;

    if let Some(cb) = device.pnp_vtable.as_ref().and_then(|vt| vt.get(minor)) {
        let mut step = cb(device, handle).await;
        if matches!(
            step,
            DriverStep::Complete {
                status: DriverStatus::NotImplemented
            }
        ) {
            step = DriverStep::Complete {
                status: minor.default_status_for_unhandled(),
            };
        }
        return Some(step);
    }

    None
}

// =============================================================================
// Synchronization helpers
// =============================================================================

#[inline]
fn wake_one(list: &kernel_types::io::TreiberStack<Waker>) {
    if let Some(w) = list.pop() {
        w.wake();
    }
}

#[inline]
fn remove_waiter(list: &kernel_types::io::TreiberStack<Waker>, waker: &Waker) {
    let _ = list.remove_one_by(|w| w.will_wake(waker));
}

#[inline]
fn try_acquire_slot<T>(handler: &IoHandler<T>) -> bool {
    loop {
        let cur = handler.running_request.load(Ordering::Acquire);
        if cur >= handler.depth as u64 {
            return false;
        }

        if handler
            .running_request
            .compare_exchange(cur, cur + 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            return true;
        }
    }
}

struct SlotAcquireFuture<'a, T> {
    handler: &'a IoHandler<T>,
}

impl<T> Future for SlotAcquireFuture<'_, T> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let h = self.handler;

        if try_acquire_slot(h) {
            return Poll::Ready(());
        }

        remove_waiter(&h.waiters, cx.waker());
        h.waiters.push(cx.waker().clone());

        if try_acquire_slot(h) {
            remove_waiter(&h.waiters, cx.waker());
            return Poll::Ready(());
        }

        Poll::Pending
    }
}

struct SlotGuard<'a, T> {
    handler: &'a IoHandler<T>,
}

impl<T> Drop for SlotGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        self.handler.running_request.fetch_sub(1, Ordering::Release);
        wake_one(&self.handler.waiters);
    }
}

#[inline]
async fn acquire_slot<T>(handler: &IoHandler<T>) -> SlotGuard<'_, T> {
    SlotAcquireFuture { handler }.await;
    SlotGuard { handler }
}
