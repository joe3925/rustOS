use crate::drivers::pnp::manager::{PnpManager, PNP_MANAGER};
use crate::println;
use crate::scheduling::runtime::runtime::{spawn, spawn_detached};
use crate::static_handlers::create_kernel_task;
use crate::structs::thread_pool::ThreadPool;
use crate::util::random_number;
use acpi::spcr::SpcrInterfaceType;
use alloc::{boxed::Box, collections::vec_deque::VecDeque, sync::Arc};
use core::sync::atomic::{AtomicBool, Ordering};
use kernel_types::device::DeviceObject;
use kernel_types::io::{IoTarget, Synchronization};
use kernel_types::pnp::{DriverStep, PnpRequest};
use kernel_types::request::{
    Request, RequestCompletionHandle, RequestData, RequestHandle, RequestHandleResult, RequestType,
    SharedRequest, TraversalPolicy,
};
use kernel_types::status::DriverStatus;
use spin::Mutex;
use spin::RwLock;

#[derive(Clone, Copy)]
pub struct Dpc {
    pub func: DpcFn,
    pub arg: usize,
}

pub type DpcFn = extern "win64" fn(usize);
pub type CompletionRoutine =
    extern "win64" fn(request: &mut Request, context: usize) -> DriverStatus;

lazy_static::lazy_static! {
    static ref GLOBAL_DPCQ: Mutex<VecDeque<Dpc>> = Mutex::new(VecDeque::new());
}

impl PnpManager {
    pub fn queue_dpc(&self, func: extern "win64" fn(usize), arg: usize) {
        GLOBAL_DPCQ.lock().push_back(Dpc { func, arg });
        spawn_detached(PNP_MANAGER.run_one_dpc());
    }

    async fn run_one_dpc(&self) {
        let dpc_opt = { GLOBAL_DPCQ.lock().pop_front() };
        let Some(dpc) = dpc_opt else {
            return;
        };
        (dpc.func)(dpc.arg);
    }

    /// Send a request. Caller retains access to stack request after return
    /// (unless it was promoted by a handler returning Pending).
    pub async fn send_request<'a>(
        &self,
        target: IoTarget,
        handle: &mut RequestHandle<'a>,
    ) -> (DriverStatus) {
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
        let result = self.call_device_handler(dev, handle, kind, policy).await;

        match result {
            DriverStep::Pending => {
                // Handler returned Pending with promoted handle
                let shared = match &handle {
                    RequestHandle::Shared(s) => s.clone(),
                    _ => panic!("Pending returned without promoted handle"),
                };
                let status = RequestCompletionHandle::new(shared).await;
                status
            }
            DriverStep::Complete { status } => status,
            DriverStep::Continue => {
                let status = handle.read().status;
                status
            }
        }
    }
    pub async fn send_request_to_next_lower<'a>(
        &self,
        from: Arc<DeviceObject>,
        handle: &mut RequestHandle<'a>,
    ) -> DriverStatus {
        let Some(target_dev) = from.lower_device.get() else {
            return DriverStatus::NoSuchDevice;
        };

        self.send_request(target_dev.clone(), handle).await
    }

    pub async fn send_request_to_next_upper<'a>(
        &self,
        from: Arc<DeviceObject>,
        handle: &mut RequestHandle<'a>,
    ) -> DriverStatus {
        let Some(target_dev) = from.upper_device.get() else {
            return DriverStatus::NoSuchDevice;
        };

        let Some(up) = target_dev.upgrade() else {
            return DriverStatus::NoSuchDevice;
        };

        self.send_request(up, handle).await
    }
    /// Complete a request. Does NOT promote - returns handle with same lifetime.
    pub fn complete_request<'a>(&self, handle: &mut RequestHandle<'a>) -> DriverStatus {
        let (status, waker) = {
            let mut guard = handle.write();

            if guard.completed {
                return guard.status;
            }

            if let Some(fp) = guard.completion_routine.take() {
                let f: CompletionRoutine = unsafe { core::mem::transmute(fp) };
                let context = guard.completion_context;
                guard.status = f(&mut *guard, context);
            }

            if guard.status == DriverStatus::ContinueStep {
                guard.status = DriverStatus::Success;
            }

            guard.completed = true;
            (guard.status, guard.waker.take())
        };

        if let Some(w) = waker {
            w.wake();
        }

        status
    }

    async fn call_device_handler<'a>(
        &self,
        mut dev: Arc<DeviceObject>,
        mut handle: &mut RequestHandle<'a>,
        kind: RequestType,
        policy: TraversalPolicy,
    ) -> DriverStep {
        loop {
            if matches!(kind, RequestType::Dummy) {
                handle.write().status = DriverStatus::Success;
                return DriverStep::complete(self.complete_request(handle));
            }

            if matches!(kind, RequestType::Pnp) {
                let step = Self::pnp_minor_dispatch(&dev, handle).await;
                match step {
                    DriverStep::Pending => {
                        // This case can't happen
                    }
                    DriverStep::Complete { status } => {
                        handle.write().status = status;
                        return DriverStep::complete(self.complete_request(handle));
                    }
                    DriverStep::Continue => {
                        if policy != TraversalPolicy::ForwardLower {
                            handle.write().status = DriverStatus::InvalidParameter;
                            return DriverStep::complete(self.complete_request(handle));
                        }

                        let next = match dev.lower_device.get() {
                            Some(n) => n.clone(),
                            None => {
                                handle.write().status = DriverStatus::Success;
                                return DriverStep::complete(self.complete_request(handle));
                            }
                        };
                        dev = next;
                        continue;
                    }
                }
            }

            let step = if let Some(h) = dev.dev_init.io_vtable.get_for(&kind) {
                let result = h.handler.invoke(dev.clone(), handle).await;

                match h.synchronization {
                    Synchronization::Sync | Synchronization::Async => {
                        h.running_request.fetch_sub(1, Ordering::Release);
                    }
                    _ => {}
                }

                result
            } else {
                DriverStep::Continue
            };

            match step {
                DriverStep::Pending => {
                    handle.write().status = DriverStatus::PendingStep;
                    return DriverStep::Pending;
                }
                DriverStep::Complete { status } => {
                    handle.write().status = status;
                    return DriverStep::complete(self.complete_request(handle));
                }
                DriverStep::Continue => {
                    let next = match policy {
                        TraversalPolicy::ForwardLower => match dev.lower_device.get() {
                            Some(n) => Ok(n.clone()),
                            None => Err(DriverStatus::NoSuchDevice),
                        },
                        TraversalPolicy::ForwardUpper => match dev.upper_device.get() {
                            Some(n) => n.upgrade().ok_or(DriverStatus::NoSuchDevice),
                            None => Err(DriverStatus::NoSuchDevice),
                        },
                        TraversalPolicy::FailIfUnhandled => Err(DriverStatus::NotImplemented),
                    };

                    match next {
                        Ok(n) => {
                            dev = n;
                            continue;
                        }
                        Err(_) => {
                            handle.write().status = DriverStatus::NotImplemented;
                            return DriverStep::complete(self.complete_request(handle));
                        }
                    }
                }
            }
        }
    }

    async fn pnp_minor_dispatch<'a>(
        device: &Arc<DeviceObject>,
        handle: &'a mut RequestHandle<'a>,
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
            let mut step = cb(device.clone(), handle).await;
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
}

extern "C" fn job_run_dpc(arg: usize) {
    let p = unsafe { &*(arg as *const (extern "win64" fn(usize), usize)) };
    (p.0)(p.1);
    let _ = unsafe { Box::from_raw(arg as *mut (extern "win64" fn(usize), usize)) };
}

pub trait RequestExt {
    fn new(kind: RequestType, data: RequestData) -> Self;
    fn new_pnp(pnp: PnpRequest, data: RequestData) -> Self;
    #[inline]
    fn new_t<T: 'static>(kind: RequestType, data: T) -> Self
    where
        Self: Sized,
    {
        Self::new(kind, RequestData::from_t(data))
    }
    #[inline]
    fn new_pnp_t<T: 'static>(pnp: PnpRequest, data: T) -> Self
    where
        Self: Sized,
    {
        Self::new_pnp(pnp, RequestData::from_t(data))
    }
    #[inline]
    fn new_bytes(kind: RequestType, data: Box<[u8]>) -> Self
    where
        Self: Sized,
    {
        Self::new(kind, RequestData::from_boxed_bytes(data))
    }
    #[inline]
    fn new_pnp_bytes(pnp: PnpRequest, data: Box<[u8]>) -> Self
    where
        Self: Sized,
    {
        Self::new_pnp(pnp, RequestData::from_boxed_bytes(data))
    }
}

impl RequestExt for Request {
    fn new(kind: RequestType, data: RequestData) -> Self {
        if matches!(kind, RequestType::Pnp) {
            panic!("Request::new called with RequestType::Pnp. Use Request::new_pnp instead.");
        }

        Self {
            kind,
            data,
            completed: false,
            status: DriverStatus::ContinueStep,
            traversal_policy: TraversalPolicy::FailIfUnhandled,
            pnp: None,
            completion_routine: None,
            completion_context: 0,

            waker: None,
        }
    }

    #[inline]
    fn new_pnp(pnp_request: PnpRequest, data: RequestData) -> Self {
        Self {
            kind: RequestType::Pnp,
            data,
            completed: false,
            status: DriverStatus::ContinueStep,
            traversal_policy: TraversalPolicy::ForwardLower,
            pnp: Some(pnp_request),
            completion_routine: None,
            completion_context: 0,

            waker: None,
        }
    }
}
