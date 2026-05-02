use alloc::string::String;
use alloc::sync::{Arc, Weak};
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::Ordering;
use core::task::{Context, Poll, Waker};
use crossbeam_queue::SegQueue;
use kernel_types::device::{DevNode, DeviceObject};
use kernel_types::io::{IoHandler, IoTarget};
use kernel_types::pnp::DriverStep;
use kernel_types::request::{Request, RequestHandle, RequestType, TraversalPolicy};
use kernel_types::status::DriverStatus;

pub type CompletionRoutine =
    extern "win64" fn(request: &mut Request, context: usize) -> DriverStatus;

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
fn resolve_path_to_device(path: &str) -> Option<IoTarget> {
    unsafe { routing_resolve_path_to_device_impl(path) }
}

#[cfg(feature = "kernel_link")]
pub fn print(s: &str) {
    unsafe { routing_print_impl(s) }
}

#[cfg(feature = "kernel_link")]
fn get_stack_top_from_weak(dev_node_weak: &Weak<DevNode>) -> Option<Arc<DeviceObject>> {
    unsafe { routing_get_stack_top_from_weak_impl(dev_node_weak) }
}

#[cfg(not(feature = "kernel_link"))]
fn resolve_path_to_device(path: &str) -> Option<IoTarget> {
    unsafe { kernel_sys::routing_resolve_path_to_device(path) }
}

#[cfg(not(feature = "kernel_link"))]
pub fn print(s: &str) {
    unsafe { kernel_sys::print(s) }
}

#[cfg(not(feature = "kernel_link"))]
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

/// Send a request to a target device.
/// This is the main entry point for request routing.
pub async fn send_request(target: IoTarget, handle: &mut RequestHandle<'_, '_>) -> DriverStatus {
    {
        let guard = handle.write();
        guard.status = DriverStatus::ContinueStep;
        guard.completed = false;
    }

    let (kind, policy) = {
        let guard = handle.read();
        (guard.kind, guard.traversal_policy)
    };

    call_device_handler(target.clone(), handle, kind, policy).await
}

/// Forward a request to the next lower device in the stack.
pub async fn send_request_to_next_lower(
    from: Arc<DeviceObject>,
    handle: &mut RequestHandle<'_, '_>,
) -> DriverStatus {
    let Some(target_dev) = from.lower_device.get() else {
        return DriverStatus::NoSuchDevice;
    };

    send_request(target_dev.clone(), handle).await
}

/// Forward a request to the next upper device in the stack.
pub async fn send_request_to_next_upper(
    from: Arc<DeviceObject>,
    handle: &mut RequestHandle<'_, '_>,
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
pub async fn send_request_via_symlink(
    link_path: String,
    handle: &mut RequestHandle<'_, '_>,
) -> DriverStatus {
    match resolve_path_to_device(&link_path) {
        Some(tgt) => send_request(tgt, handle).await,
        None => DriverStatus::NoSuchDevice,
    }
}

/// Send an IOCTL request via a symlink path.
/// Note: The control_code parameter is currently unused (matches kernel behavior).
pub async fn ioctl_via_symlink(
    link_path: String,
    _control_code: u32,
    handle: &mut RequestHandle<'_, '_>,
) -> DriverStatus {
    send_request_via_symlink(link_path, handle).await
}

/// Send a request to the top of a device stack.
pub async fn send_request_to_stack_top(
    dev_node_weak: Weak<DevNode>,
    handle: &mut RequestHandle<'_, '_>,
) -> DriverStatus {
    match get_stack_top_from_weak(&dev_node_weak) {
        Some(tgt) => send_request(tgt, handle).await,
        None => DriverStatus::NoSuchDevice,
    }
}

/// Complete a request.
pub fn complete_request(handle: &mut RequestHandle<'_, '_>) -> DriverStatus {
    let mut guard = handle.write();

    if guard.completed {
        return guard.status.clone();
    }

    if let Some(fp) = guard.completion_routine.take() {
        let f: CompletionRoutine = unsafe { core::mem::transmute(fp) };
        let context = guard.completion_context;
        guard.status = f(&mut guard, context);
    }

    if guard.status == DriverStatus::ContinueStep {
        guard.status = DriverStatus::Success;
    }
    guard.completion_context = 0;
    guard.completed = true;
    guard.status.clone()
}

async fn call_device_handler(
    mut dev: Arc<DeviceObject>,
    handle: &mut RequestHandle<'_, '_>,
    kind: RequestType,
    policy: TraversalPolicy,
) -> DriverStatus {
    if matches!(kind, RequestType::Dummy) {
        handle.write().status = DriverStatus::Success;
        return complete_request(handle);
    }

    if matches!(kind, RequestType::Pnp) {
        if policy != TraversalPolicy::ForwardLower {
            handle.write().status = DriverStatus::InvalidParameter;
            return complete_request(handle);
        }

        loop {
            let step = {
                let h: &mut RequestHandle<'_, '_> = handle;
                pnp_minor_dispatch(&dev, h).await
            };
            match step {
                DriverStep::Complete { status } => {
                    handle.write().status = status;
                    return complete_request(handle);
                }
                DriverStep::Continue => match dev.lower_device.get() {
                    Some(n) => {
                        dev = n.clone();
                        continue;
                    }
                    None => {
                        handle.write().status = DriverStatus::Success;
                        return complete_request(handle);
                    }
                },
            }
        }
    }

    loop {
        match invoke_io_handler(&dev, handle, &kind).await {
            Some(DriverStep::Complete { status }) => {
                handle.write().status = status;
                return complete_request(handle);
            }
            Some(DriverStep::Continue) | None => {
                let next = match policy {
                    TraversalPolicy::ForwardLower => dev
                        .lower_device
                        .get()
                        .cloned()
                        .ok_or(DriverStatus::NoSuchDevice),
                    TraversalPolicy::ForwardUpper => dev
                        .upper_device
                        .get()
                        .and_then(|w| w.upgrade())
                        .ok_or(DriverStatus::NoSuchDevice),
                    TraversalPolicy::FailIfUnhandled => Err(DriverStatus::NotImplemented),
                };

                match next {
                    Ok(n) => {
                        dev = n;
                        continue;
                    }
                    Err(_) => {
                        handle.write().status = DriverStatus::NotImplemented;
                        return complete_request(handle);
                    }
                }
            }
        }
    }
}

async fn invoke_io_handler(
    dev: &Arc<DeviceObject>,
    handle: &mut RequestHandle<'_, '_>,
    kind: &RequestType,
) -> Option<DriverStep> {
    // let addr: usize = 0xFFFF_8500_0000_0000;

    // let entropy = unsafe { ptr::read_volatile(&addr) };

    // if (entropy & 1) != 0 {
    //     for _ in 0..512 {
    //         compiler_fence(Ordering::SeqCst);
    //     }

    //     core::future::poll_fn(|cx| {
    //         cx.waker().wake_by_ref();
    //         Poll::<()>::Pending
    //     })
    //     .await;
    // }

    let Some(h) = dev.dev_init.io_vtable.get_for(kind) else {
        return None;
    };

    if h.depth == 0 {
        return Some(h.handler.invoke(dev, handle).await);
    }

    let guard = acquire_slot(h).await;
    let result = h.handler.invoke(dev, handle).await;
    drop(guard);
    Some(result)
}

async fn pnp_minor_dispatch(
    device: &Arc<DeviceObject>,
    handle: &mut RequestHandle<'_, '_>,
) -> DriverStep {
    let minor_opt = {
        let r = handle.read();
        r.pnp.as_ref().map(|p| p.minor_function)
    };

    let Some(minor) = minor_opt else {
        return DriverStep::complete(DriverStatus::InvalidParameter);
    };

    if let Some(cb) = device
        .dev_init
        .pnp_vtable
        .as_ref()
        .and_then(|vt| vt.get(minor))
    {
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
        return step;
    }

    DriverStep::Continue
}

// =============================================================================
// Synchronization helpers
// =============================================================================

fn wake_one(list: &SegQueue<Waker>) {
    if let Some(w) = list.pop() {
        w.wake();
    }
}

struct SlotAcquireFuture<'a> {
    handler: &'a IoHandler,
}

impl Future for SlotAcquireFuture<'_> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let h = self.handler;

        loop {
            let cur = h.running_request.load(Ordering::Acquire);
            if cur < h.depth as u64 {
                if h.running_request
                    .compare_exchange(cur, cur + 1, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    return Poll::Ready(());
                }
                continue;
            }

            // Unable to acquire: enqueue current waker and yield.
            h.waiters.push(cx.waker().clone());
            return Poll::Pending;
        }
    }
}

struct SlotGuard<'a> {
    handler: &'a IoHandler,
}

impl Drop for SlotGuard<'_> {
    fn drop(&mut self) {
        self.handler.running_request.fetch_sub(1, Ordering::Release);
        wake_one(&self.handler.waiters);
    }
}

async fn acquire_slot(handler: &IoHandler) -> SlotGuard<'_> {
    SlotAcquireFuture { handler }.await;
    SlotGuard { handler }
}
