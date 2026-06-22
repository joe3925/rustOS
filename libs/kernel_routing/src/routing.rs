use alloc::string::String;
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
    RequestKind, TraversalPolicy, Write,
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
    #[inline]
    fn validate_policy(_policy: TraversalPolicy) -> Result<(), DriverStatus> {
        Ok(())
    }

    fn invoke_at<'a, 'req>(
        dev: &'a Arc<DeviceObject>,
        handle: &'a mut RequestHandle<'req, Self>,
    ) -> impl Future<Output = Option<DriverStep>> + Send + 'a;

    #[inline]
    fn next_device(
        dev: &Arc<DeviceObject>,
        policy: TraversalPolicy,
    ) -> Result<Arc<DeviceObject>, DriverStatus> {
        match policy {
            TraversalPolicy::ForwardLower => dev
                .lower_device
                .get()
                .cloned()
                .ok_or(DriverStatus::NotImplemented),
            TraversalPolicy::ForwardUpper => dev
                .upper_device
                .get()
                .and_then(|w| w.upgrade())
                .ok_or(DriverStatus::NotImplemented),
            TraversalPolicy::FailIfUnhandled => Err(DriverStatus::NotImplemented),
        }
    }
}

trait IoSlotRequest: RequestKind + Sized {
    type Handler: Copy;

    fn handler(ops: &DeviceOps) -> Option<&IoHandler<Self::Handler>>;

    fn call<'req, 'b>(
        handler: Self::Handler,
        dev: &Arc<DeviceObject>,
        handle: &'b mut RequestHandle<'req, Self>,
    ) -> FfiFuture<DriverStep>;
}

impl<'io> IoSlotRequest for Read<'io> {
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
        let len = handle.read().body.len;
        handler(dev, handle, len)
    }
}

impl<'io> IoSlotRequest for Write<'io> {
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
        let len = handle.read().body.len;
        handler(dev, handle, len)
    }
}
impl IoSlotRequest for Flush {
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

impl IoSlotRequest for FlushDirty {
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

impl IoSlotRequest for FlushOwner {
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

impl<'data> IoSlotRequest for DeviceControl<'data> {
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

impl<'data, O> IoSlotRequest for Fs<'data, O>
where
    O: FsOperation,
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

async fn invoke_io_handler<K: IoSlotRequest>(
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
    #[inline]
    fn validate_policy(policy: TraversalPolicy) -> Result<(), DriverStatus> {
        if policy == TraversalPolicy::ForwardLower {
            Ok(())
        } else {
            Err(DriverStatus::InvalidParameter)
        }
    }

    fn invoke_at<'a, 'req>(
        dev: &'a Arc<DeviceObject>,
        handle: &'a mut RequestHandle<'req, Self>,
    ) -> impl Future<Output = Option<DriverStep>> + Send + 'a {
        async move { pnp_minor_dispatch(dev, handle).await }
    }

    #[inline]
    fn next_device(
        dev: &Arc<DeviceObject>,
        _policy: TraversalPolicy,
    ) -> Result<Arc<DeviceObject>, DriverStatus> {
        dev.lower_device.get().cloned().ok_or(DriverStatus::Success)
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

    #[inline]
    fn next_device(
        _dev: &Arc<DeviceObject>,
        _policy: TraversalPolicy,
    ) -> Result<Arc<DeviceObject>, DriverStatus> {
        Err(DriverStatus::Success)
    }
}

/// Send a request to a target device.
/// This is the main entry point for request routing.
pub async fn send_request<K: RoutedRequest>(
    target: IoTarget,
    handle: &mut RequestHandle<'_, K>,
) -> DriverStatus {
    {
        let guard = handle.write();
        guard.status = DriverStatus::ContinueStep;
        guard.completed = false;
    }

    let policy = handle.read().traversal_policy;
    call_device_handler(target, handle, policy).await
}

/// Forward a request to the next lower device in the stack.
pub async fn send_request_to_next_lower<K: RoutedRequest>(
    from: Arc<DeviceObject>,
    handle: &mut RequestHandle<'_, K>,
) -> DriverStatus {
    let Some(target_dev) = from.lower_device.get() else {
        return DriverStatus::NoSuchDevice;
    };

    send_request(target_dev.clone(), handle).await
}

/// Forward a request to the next upper device in the stack.
pub async fn send_request_to_next_upper<K: RoutedRequest>(
    from: Arc<DeviceObject>,
    handle: &mut RequestHandle<'_, K>,
) -> DriverStatus {
    let Some(target_dev_weak) = from.upper_device.get() else {
        return DriverStatus::NoSuchDevice;
    };

    let Some(up) = target_dev_weak.upgrade() else {
        return DriverStatus::NoSuchDevice;
    };

    send_request(up, handle).await
}

/// Send a request via a symlink path.
pub async fn send_request_via_symlink<K: RoutedRequest>(
    link_path: String,
    handle: &mut RequestHandle<'_, K>,
) -> DriverStatus {
    match resolve_path_to_device(&link_path) {
        Some(tgt) => send_request(tgt, handle).await,
        None => DriverStatus::NoSuchDevice,
    }
}

/// Send an IOCTL request via a symlink path.
pub async fn ioctl_via_symlink<'data>(
    link_path: String,
    control_code: u32,
    handle: &mut RequestHandle<'_, DeviceControl<'data>>,
) -> DriverStatus {
    handle.write().body.code = control_code;
    send_request_via_symlink(link_path, handle).await
}

/// Send a request to the top of a device stack.
pub async fn send_request_to_stack_top<K: RoutedRequest>(
    dev_node_weak: Weak<DevNode>,
    handle: &mut RequestHandle<'_, K>,
) -> DriverStatus {
    match get_stack_top_from_weak(&dev_node_weak) {
        Some(tgt) => send_request(tgt, handle).await,
        None => DriverStatus::NoSuchDevice,
    }
}

/// Complete a request.
#[inline]
pub fn complete_request<K: RequestKind>(handle: &mut RequestHandle<'_, K>) -> DriverStatus {
    let guard = handle.write();
    guard.complete()
}

#[cold]
fn complete_with_status<K: RequestKind>(
    handle: &mut RequestHandle<'_, K>,
    status: DriverStatus,
) -> DriverStatus {
    handle.write().status = status;
    complete_request(handle)
}

async fn call_device_handler<K: RoutedRequest>(
    mut dev: Arc<DeviceObject>,
    handle: &mut RequestHandle<'_, K>,
    policy: TraversalPolicy,
) -> DriverStatus {
    if let Err(status) = K::validate_policy(policy) {
        return complete_with_status(handle, status);
    }

    loop {
        match K::invoke_at(&dev, handle).await {
            Some(DriverStep::Complete { status }) => {
                return complete_with_status(handle, status);
            }
            Some(DriverStep::Continue) | None => match K::next_device(&dev, policy) {
                Ok(n) => {
                    dev = n;
                }
                Err(status) => {
                    return complete_with_status(handle, status);
                }
            },
        }
    }
}

async fn pnp_minor_dispatch<'data>(
    device: &Arc<DeviceObject>,
    handle: &mut RequestHandle<'_, Pnp<'data>>,
) -> Option<DriverStep> {
    let minor = handle.read().body.request.minor_function;

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
