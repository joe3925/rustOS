use alloc::sync::{Arc, Weak};
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::Ordering;
use core::task::{Context, Poll, Waker};
use kernel_types::async_ffi::FfiFuture;
use kernel_types::device::{DevNode, DeviceObject};
use kernel_types::io::{DeviceOps, IoHandler, IoTarget};
use kernel_types::pnp::{
    DriverStep, PnpHandler, PnpOp, PnpOps, QueryDeviceRelations, QueryId, QueryResources,
    InitComplete, RegisterDmaBacking, RemoveDevice, StartDevice, StopDevice, SurpriseRemoval,
};
use kernel_types::request::{
    DeviceControl, Flush, FlushDirty, FlushOwner, Fs, FsOperation, Read, Write,
};
use kernel_types::status::DriverStatus;

#[cfg(feature = "kernel_link")]
unsafe extern "Rust" {
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
    () => { $crate::print("\n") };
    ($($arg:tt)*) => {
        $crate::print(&alloc::format!("{}\n", core::format_args!($($arg)*)))
    };
}

pub trait RoutedOperation: Sized {
    fn invoke_at<'a>(
        dev: &'a Arc<DeviceObject>,
        req: &'a mut Self,
    ) -> impl Future<Output = Option<DriverStep>> + Send + 'a;

    fn default_unhandled_status(&self) -> DriverStatus {
        DriverStatus::NotImplemented
    }
}

pub trait IoRequest: RoutedOperation {
    type Handler: Copy;

    fn handler(ops: &DeviceOps) -> Option<&IoHandler<Self::Handler>>;

    fn call<'a>(
        handler: Self::Handler,
        dev: &'a Arc<DeviceObject>,
        req: &'a mut Self,
    ) -> FfiFuture<DriverStep>;
}

pub trait PnpRequest: RoutedOperation {
    const OP: PnpOp;
    type Handler: Copy;

    fn handler(ops: &PnpOps) -> Option<&PnpHandler<Self::Handler>>;

    fn call<'a>(
        handler: Self::Handler,
        dev: &'a Arc<DeviceObject>,
        op: PnpOp,
        req: &'a mut Self,
    ) -> FfiFuture<DriverStep>;

    fn default_status_for_unhandled() -> DriverStatus {
        Self::OP.default_status_for_unhandled()
    }
}

async fn invoke_io_handler<K: IoRequest>(dev: &Arc<DeviceObject>, req: &mut K) -> Option<DriverStep>
where
    K::Handler: Sync,
{
    let handler = K::handler(&dev.ops)?;
    if handler.depth == 0 {
        return Some(K::call(handler.handler, dev, req).await);
    }

    let guard = acquire_slot(handler).await;
    let result = K::call(handler.handler, dev, req).await;
    drop(guard);
    Some(result)
}

async fn invoke_pnp_handler<K: PnpRequest>(
    dev: &Arc<DeviceObject>,
    req: &mut K,
) -> Option<DriverStep>
where
    K::Handler: Sync,
{
    let ops = dev.pnp_ops.as_ref()?;
    let handler = K::handler(ops)?;
    Some(K::call(handler.handler, dev, K::OP, req).await)
}

macro_rules! impl_io_request {
    (for<$lt:lifetime> $ty:ty, $handler_ty:ty, $slot:ident) => {
        impl<$lt> IoRequest for $ty {
            type Handler = $handler_ty;

            #[inline]
            fn handler(ops: &DeviceOps) -> Option<&IoHandler<Self::Handler>> {
                ops.$slot.as_handler()
            }

            #[inline]
            fn call<'a>(
                handler: Self::Handler,
                dev: &'a Arc<DeviceObject>,
                req: &'a mut Self,
            ) -> FfiFuture<DriverStep> {
                handler(dev, req)
            }
        }

        impl<$lt> RoutedOperation for $ty {
            #[inline]
            fn invoke_at<'a>(
                dev: &'a Arc<DeviceObject>,
                req: &'a mut Self,
            ) -> impl Future<Output = Option<DriverStep>> + Send + 'a {
                async move { invoke_io_handler::<Self>(dev, req).await }
            }
        }
    };
    ($ty:ty, $handler_ty:ty, $slot:ident) => {
        impl IoRequest for $ty {
            type Handler = $handler_ty;

            #[inline]
            fn handler(ops: &DeviceOps) -> Option<&IoHandler<Self::Handler>> {
                ops.$slot.as_handler()
            }

            #[inline]
            fn call<'a>(
                handler: Self::Handler,
                dev: &'a Arc<DeviceObject>,
                req: &'a mut Self,
            ) -> FfiFuture<DriverStep> {
                handler(dev, req)
            }
        }

        impl RoutedOperation for $ty {
            #[inline]
            fn invoke_at<'a>(
                dev: &'a Arc<DeviceObject>,
                req: &'a mut Self,
            ) -> impl Future<Output = Option<DriverStep>> + Send + 'a {
                async move { invoke_io_handler::<Self>(dev, req).await }
            }
        }
    };
}

impl_io_request!(for<'io> Read<'io>, kernel_types::EvtIoRead, read);
impl_io_request!(for<'io> Write<'io>, kernel_types::EvtIoWrite, write);
impl_io_request!(Flush, kernel_types::EvtIoFlush, flush);
impl_io_request!(FlushDirty, kernel_types::EvtIoFlushDirty, flush_dirty);
impl_io_request!(FlushOwner, kernel_types::EvtIoFlushOwner, flush_owner);
impl_io_request!(
    for<'data> DeviceControl<'data>,
    kernel_types::EvtIoDeviceControl,
    device_control
);

impl<'data, O> IoRequest for Fs<'data, O>
where
    O: FsOperation + Send,
    O::Handler: Sync,
    for<'any> O::Params<'any>: Send,
    O::Result: Send,
{
    type Handler = O::Handler;

    fn handler(ops: &DeviceOps) -> Option<&IoHandler<Self::Handler>> {
        O::handler(ops.fs.as_ops()?)
    }

    fn call<'a>(
        handler: Self::Handler,
        dev: &'a Arc<DeviceObject>,
        req: &'a mut Self,
    ) -> FfiFuture<DriverStep> {
        O::call(handler, dev, req)
    }
}

impl<'data, O> RoutedOperation for Fs<'data, O>
where
    O: FsOperation + Send,
    O::Handler: Sync,
    for<'any> O::Params<'any>: Send,
    O::Result: Send,
{
    fn invoke_at<'a>(
        dev: &'a Arc<DeviceObject>,
        req: &'a mut Self,
    ) -> impl Future<Output = Option<DriverStep>> + Send + 'a {
        async move { invoke_io_handler::<Self>(dev, req).await }
    }
}

macro_rules! impl_pnp_request {
    (for<$lt:lifetime> $ty:ty, $op:expr, $handler_ty:ty, $slot:ident) => {
        impl<$lt> PnpRequest for $ty {
            const OP: PnpOp = $op;
            type Handler = $handler_ty;

            fn handler(ops: &PnpOps) -> Option<&PnpHandler<Self::Handler>> {
                ops.$slot.as_handler()
            }

            fn call<'a>(
                handler: Self::Handler,
                dev: &'a Arc<DeviceObject>,
                op: PnpOp,
                req: &'a mut Self,
            ) -> FfiFuture<DriverStep> {
                handler(dev, op, req)
            }
        }

        impl<$lt> RoutedOperation for $ty {
            fn invoke_at<'a>(
                dev: &'a Arc<DeviceObject>,
                req: &'a mut Self,
            ) -> impl Future<Output = Option<DriverStep>> + Send + 'a {
                async move { invoke_pnp_handler::<Self>(dev, req).await }
            }

            fn default_unhandled_status(&self) -> DriverStatus {
                <$ty as PnpRequest>::default_status_for_unhandled()
            }
        }
    };
    ($ty:ty, $op:expr, $handler_ty:ty, $slot:ident) => {
        impl PnpRequest for $ty {
            const OP: PnpOp = $op;
            type Handler = $handler_ty;

            fn handler(ops: &PnpOps) -> Option<&PnpHandler<Self::Handler>> {
                ops.$slot.as_handler()
            }

            fn call<'a>(
                handler: Self::Handler,
                dev: &'a Arc<DeviceObject>,
                op: PnpOp,
                req: &'a mut Self,
            ) -> FfiFuture<DriverStep> {
                handler(dev, op, req)
            }
        }

        impl RoutedOperation for $ty {
            fn invoke_at<'a>(
                dev: &'a Arc<DeviceObject>,
                req: &'a mut Self,
            ) -> impl Future<Output = Option<DriverStep>> + Send + 'a {
                async move { invoke_pnp_handler::<Self>(dev, req).await }
            }

            fn default_unhandled_status(&self) -> DriverStatus {
                <$ty as PnpRequest>::default_status_for_unhandled()
            }
        }
    };
}

impl_pnp_request!(
    InitComplete,
    PnpOp::InitComplete,
    kernel_types::EvtPnpInitComplete,
    init_complete
);
impl_pnp_request!(
    StartDevice,
    PnpOp::StartDevice,
    kernel_types::EvtPnpStartDevice,
    start_device
);
impl_pnp_request!(
    QueryDeviceRelations,
    PnpOp::QueryDeviceRelations,
    kernel_types::EvtPnpQueryDeviceRelations,
    query_device_relations
);
impl_pnp_request!(
    QueryId,
    PnpOp::QueryId,
    kernel_types::EvtPnpQueryId,
    query_id
);
impl_pnp_request!(
    for<'data> RegisterDmaBacking<'data>,
    PnpOp::RegisterDmaBacking,
    kernel_types::EvtPnpRegisterDmaBacking,
    register_dma_backing
);
impl_pnp_request!(
    QueryResources,
    PnpOp::QueryResources,
    kernel_types::EvtPnpQueryResources,
    query_resources
);
impl_pnp_request!(
    SurpriseRemoval,
    PnpOp::SurpriseRemoval,
    kernel_types::EvtPnpSurpriseRemoval,
    surprise_removal
);
impl_pnp_request!(
    RemoveDevice,
    PnpOp::RemoveDevice,
    kernel_types::EvtPnpRemoveDevice,
    remove_device
);
impl_pnp_request!(
    StopDevice,
    PnpOp::StopDevice,
    kernel_types::EvtPnpStopDevice,
    stop_device
);

async fn call_one_device<K: RoutedOperation>(dev: &Arc<DeviceObject>, req: &mut K) -> DriverStatus {
    match K::invoke_at(dev, req).await {
        Some(DriverStep::Complete { status }) => status,
        Some(DriverStep::Continue) | None => K::default_unhandled_status(req),
    }
}

async fn call_down_stack<K: RoutedOperation>(
    mut dev: Arc<DeviceObject>,
    req: &mut K,
) -> DriverStatus {
    loop {
        match K::invoke_at(&dev, req).await {
            Some(DriverStep::Complete { status }) => return status,
            Some(DriverStep::Continue) | None => match dev.lower_device.get().cloned() {
                Some(lower) => dev = lower,
                None => return K::default_unhandled_status(req),
            },
        }
    }
}

macro_rules! routing_api {
    ($module:ident, $bound:ident) => {
        pub mod $module {
            use super::*;

            pub async fn send_to_device<K: $bound>(target: IoTarget, req: &mut K) -> DriverStatus {
                call_one_device(&target, req).await
            }

            pub async fn send_down_stack<K: $bound>(target: IoTarget, req: &mut K) -> DriverStatus {
                call_down_stack(target, req).await
            }

            pub async fn send_next_lower<K: $bound>(
                from: Arc<DeviceObject>,
                req: &mut K,
            ) -> DriverStatus {
                let Some(target) = from.lower_device.get().cloned() else {
                    return DriverStatus::NoSuchDevice;
                };
                call_down_stack(target, req).await
            }

            pub async fn send_to_stack_top<K: $bound>(
                dev_node_weak: Weak<DevNode>,
                req: &mut K,
            ) -> DriverStatus {
                match get_stack_top_from_weak(&dev_node_weak) {
                    Some(target) => call_down_stack(target, req).await,
                    None => DriverStatus::NoSuchDevice,
                }
            }

            pub fn resolve_target(link_path: &str) -> Option<IoTarget> {
                resolve_path_to_device(link_path)
            }
        }
    };
}

routing_api!(io, IoRequest);
routing_api!(pnp, PnpRequest);

#[inline]
fn wake_one(list: &kernel_types::io::TreiberStack<Waker>) {
    if let Some(waker) = list.pop() {
        waker.wake();
    }
}

#[inline]
fn remove_waiter(list: &kernel_types::io::TreiberStack<Waker>, waker: &Waker) {
    let _ = list.remove_one_by(|candidate| candidate.will_wake(waker));
}

#[inline]
fn try_acquire_slot<T>(handler: &IoHandler<T>) -> bool {
    loop {
        let current = handler.running_request.load(Ordering::Acquire);
        if current >= handler.depth as u64 {
            return false;
        }
        if handler
            .running_request
            .compare_exchange(current, current + 1, Ordering::Acquire, Ordering::Relaxed)
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
        let handler = self.handler;
        if try_acquire_slot(handler) {
            return Poll::Ready(());
        }
        remove_waiter(&handler.waiters, cx.waker());
        handler.waiters.push(cx.waker().clone());
        if try_acquire_slot(handler) {
            remove_waiter(&handler.waiters, cx.waker());
            return Poll::Ready(());
        }
        Poll::Pending
    }
}

struct SlotGuard<'a, T> {
    handler: &'a IoHandler<T>,
}

impl<T> Drop for SlotGuard<'_, T> {
    fn drop(&mut self) {
        self.handler.running_request.fetch_sub(1, Ordering::Release);
        wake_one(&self.handler.waiters);
    }
}

async fn acquire_slot<T>(handler: &IoHandler<T>) -> SlotGuard<'_, T> {
    SlotAcquireFuture { handler }.await;
    SlotGuard { handler }
}
