use alloc::string::String;
use alloc::sync::{Arc, Weak};
use core::sync::atomic::Ordering;
use kernel_types::device::{DevNode, DeviceObject};
use kernel_types::io::{IoTarget, Synchronization};
use kernel_types::pnp::DriverStep;
use kernel_types::request::{
    Request, RequestCompletionHandle, RequestHandle, RequestType, TraversalPolicy,
};
use kernel_types::status::DriverStatus;

pub type CompletionRoutine =
    extern "win64" fn(request: &mut Request, context: usize) -> DriverStatus;

// =============================================================================
// Linker seams - these are resolved at link time when kernel_link is enabled
// =============================================================================

#[cfg(feature = "kernel_link")]
unsafe extern "Rust" {
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
fn get_stack_top_from_weak(dev_node_weak: &Weak<DevNode>) -> Option<Arc<DeviceObject>> {
    unsafe { routing_get_stack_top_from_weak_impl(dev_node_weak) }
}

// =============================================================================
// FFI calls - used when compiled into drivers (not kernel)
// =============================================================================

#[cfg(not(feature = "kernel_link"))]
fn resolve_path_to_device(path: &str) -> Option<IoTarget> {
    unsafe { kernel_sys::routing_resolve_path_to_device(path) }
}

#[cfg(not(feature = "kernel_link"))]
fn get_stack_top_from_weak(dev_node_weak: &Weak<DevNode>) -> Option<Arc<DeviceObject>> {
    unsafe { kernel_sys::routing_get_stack_top_from_weak(dev_node_weak) }
}

/// Send a request to a target device.
/// This is the main entry point for request routing.
pub async fn send_request(target: IoTarget, handle: &mut RequestHandle<'_>) -> DriverStatus {
    {
        let mut guard = handle.write();
        guard.status = DriverStatus::ContinueStep;
        guard.completed = false;
        guard.waker = None;
    }

    let (kind, policy) = {
        let guard = handle.read();
        (guard.kind, guard.traversal_policy)
    };

    let dev = target.clone();
    let result = call_device_handler(dev, handle, kind, policy).await;

    match result {
        DriverStep::Pending => {
            // Handler returned Pending with promoted handle
            let shared = match &handle {
                RequestHandle::Shared(s) => s.clone(),
                _ => panic!("Pending returned without promoted handle"),
            };
            RequestCompletionHandle::new(shared).await
        }
        DriverStep::Complete { status } => status,
        DriverStep::Continue => handle.read().status,
    }
}

/// Forward a request to the next lower device in the stack.
pub async fn send_request_to_next_lower(
    from: Arc<DeviceObject>,
    handle: &mut RequestHandle<'_>,
) -> DriverStatus {
    let Some(target_dev) = from.lower_device.get() else {
        return DriverStatus::NoSuchDevice;
    };

    send_request(target_dev.clone(), handle).await
}

/// Forward a request to the next upper device in the stack.
pub async fn send_request_to_next_upper(
    from: Arc<DeviceObject>,
    handle: &mut RequestHandle<'_>,
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
    handle: &mut RequestHandle<'_>,
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
    handle: &mut RequestHandle<'_>,
) -> DriverStatus {
    send_request_via_symlink(link_path, handle).await
}

/// Send a request to the top of a device stack.
pub async fn send_request_to_stack_top(
    dev_node_weak: Weak<DevNode>,
    handle: &mut RequestHandle<'_>,
) -> DriverStatus {
    match get_stack_top_from_weak(&dev_node_weak) {
        Some(tgt) => send_request(tgt, handle).await,
        None => DriverStatus::NoSuchDevice,
    }
}

/// Complete a request. Does NOT promote - returns handle with same lifetime.
pub fn complete_request(handle: &mut RequestHandle<'_>) -> DriverStatus {
    let (status, waker) = {
        let mut guard = handle.write();

        if guard.completed {
            return guard.status;
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
        guard.completion_routine = None;
        guard.completed = true;
        (guard.status, guard.waker.take())
    };

    if let Some(w) = waker {
        w.wake();
    }

    status
}

async fn call_device_handler(
    mut dev: Arc<DeviceObject>,
    handle: &mut RequestHandle<'_>,
    kind: RequestType,
    policy: TraversalPolicy,
) -> DriverStep {
    loop {
        if matches!(kind, RequestType::Dummy) {
            handle.write().status = DriverStatus::Success;
            return DriverStep::complete(complete_request(handle));
        }

        if matches!(kind, RequestType::Pnp) {
            let step = {
                let h: &mut RequestHandle<'_> = handle;
                pnp_minor_dispatch(&dev, h).await
            };
            match step {
                DriverStep::Pending => {
                    // PnP handlers should never return pending
                }
                DriverStep::Complete { status } => {
                    handle.write().status = status;
                    return DriverStep::complete(complete_request(handle));
                }
                DriverStep::Continue => {
                    if policy != TraversalPolicy::ForwardLower {
                        handle.write().status = DriverStatus::InvalidParameter;
                        return DriverStep::complete(complete_request(handle));
                    }

                    match dev.lower_device.get() {
                        Some(n) => {
                            dev = n.clone();
                            continue;
                        }
                        None => {
                            handle.write().status = DriverStatus::Success;
                            return DriverStep::complete(complete_request(handle));
                        }
                    }
                }
            }
        }

        match invoke_io_handler(&dev, handle, &kind).await {
            DriverStep::Pending => {
                handle.write().status = DriverStatus::PendingStep;
                return DriverStep::Pending;
            }
            DriverStep::Complete { status } => {
                handle.write().status = status;
                return DriverStep::complete(complete_request(handle));
            }
            DriverStep::Continue => {
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
                        return DriverStep::complete(complete_request(handle));
                    }
                }
            }
        }
    }
}

async fn invoke_io_handler(
    dev: &Arc<DeviceObject>,
    handle: &mut RequestHandle<'_>,
    kind: &RequestType,
) -> DriverStep {
    let Some(h) = dev.dev_init.io_vtable.get_for(kind) else {
        return DriverStep::Complete {
            status: DriverStatus::NotImplemented,
        };
    };

    let result = h.handler.invoke(dev, handle).await;

    match h.synchronization {
        Synchronization::Sync | Synchronization::Async => {
            h.running_request.fetch_sub(1, Ordering::Release);
        }
        _ => {}
    }

    result
}

async fn pnp_minor_dispatch(
    device: &Arc<DeviceObject>,
    handle: &mut RequestHandle<'_>,
) -> DriverStep {
    let (minor_opt, policy) = {
        let r = handle.read();
        (r.pnp.as_ref().map(|p| p.minor_function), r.traversal_policy)
    };

    let Some(minor) = minor_opt else {
        return DriverStep::complete(DriverStatus::InvalidParameter);
    };

    if policy != TraversalPolicy::ForwardLower {
        return DriverStep::complete(DriverStatus::InvalidParameter);
    }

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
        } else if matches!(step, DriverStep::Pending) {
            panic!("PNP request handlers can not return pending")
        }
        return step;
    }

    DriverStep::Continue
}
