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
use kernel_types::io::Synchronization;
use kernel_types::pnp::{DriverStep, PnpRequest};
use kernel_types::request::{Request, RequestCompletion, RequestType, TraversalPolicy};
use kernel_types::status::DriverStatus;
use spin::Mutex;
use spin::RwLock;

#[derive(Clone, Copy)]
pub struct Dpc {
    pub func: DpcFn,
    pub arg: usize,
}

#[derive(Clone)]
pub struct IoTarget {
    pub target_device: Arc<DeviceObject>,
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

    pub async fn send_request(&self, target: IoTarget, req: Arc<RwLock<Request>>) -> DriverStatus {
        {
            let mut guard = req.write();
            guard.status = DriverStatus::ContinueStep;
            guard.completed = false;
            guard.waker = None;
        }

        let dev = target.target_device.clone();
        let status = self.call_device_handler(dev, req.clone()).await;

        if status == DriverStatus::PendingStep {
            return RequestCompletion { req }.await;
        }

        status
    }
    pub async fn send_request_to_next_lower(
        &self,
        from: Arc<DeviceObject>,
        req: Arc<RwLock<Request>>,
    ) -> DriverStatus {
        let Some(target_dev) = from.lower_device.get() else {
            return DriverStatus::NoSuchDevice;
        };

        self.send_request(
            IoTarget {
                target_device: target_dev.clone(),
            },
            req,
        )
        .await
    }

    pub async fn send_request_to_next_upper(
        &self,
        from: Arc<DeviceObject>,
        req: Arc<RwLock<Request>>,
    ) -> DriverStatus {
        let Some(target_dev) = from.upper_device.get() else {
            return DriverStatus::NoSuchDevice;
        };

        let Some(up) = target_dev.upgrade() else {
            return DriverStatus::NoSuchDevice;
        };

        self.send_request(IoTarget { target_device: up }, req).await
    }
    pub fn complete_request(&self, req_arc: &Arc<RwLock<Request>>) -> DriverStatus {
        let (status, waker) = {
            let mut req = req_arc.write();

            if req.completed {
                return req.status;
            }

            if let Some(fp) = req.completion_routine.take() {
                let f: CompletionRoutine = unsafe { core::mem::transmute(fp) };
                let context = req.completion_context;
                req.status = f(&mut *req, context);
            }

            if req.status == DriverStatus::ContinueStep {
                req.status = DriverStatus::Success;
            }

            req.completed = true;
            (req.status, req.waker.take())
        };

        if let Some(w) = waker {
            w.wake();
        }

        status
    }

    // pub fn spawn_device_handler(dev: Arc<DeviceObject>, req_arc: Arc<RwLock<Request>>) {
    //     spawn(async || PNP_MANAGER.call_device_handler(dev, req_arc)());
    // }

    async fn call_device_handler(
        &self,
        mut dev: Arc<DeviceObject>,
        req_arc: Arc<RwLock<Request>>,
    ) -> DriverStatus {
        loop {
            let (kind, policy) = {
                let r = req_arc.read();
                (r.kind, r.traversal_policy)
            };

            if matches!(kind, RequestType::Dummy) {
                req_arc.write().status = DriverStatus::Success;
                return self.complete_request(&req_arc);
            }

            if matches!(kind, RequestType::Pnp) {
                let step = Self::pnp_minor_dispatch(&dev, req_arc.clone()).await;

                match step {
                    DriverStep::Pending => {
                        req_arc.write().status = DriverStatus::PendingStep;
                        return DriverStatus::PendingStep;
                    }
                    DriverStep::Complete { status } => {
                        req_arc.write().status = status;
                        return self.complete_request(&req_arc);
                    }
                    DriverStep::Continue => {
                        if policy != TraversalPolicy::ForwardLower {
                            req_arc.write().status = DriverStatus::InvalidParameter;
                            return self.complete_request(&req_arc);
                        }

                        let next = match dev.lower_device.get() {
                            Some(n) => n.clone(),
                            None => {
                                req_arc.write().status = DriverStatus::Success;
                                return self.complete_request(&req_arc);
                            }
                        };
                        dev = next;
                        continue;
                    }
                }
            }

            let step = if let Some(h) = dev.dev_init.io_vtable.get_for(&kind) {
                let step = h.handler.invoke(dev.clone(), req_arc.clone()).await;

                match h.synchronization {
                    Synchronization::Sync | Synchronization::Async => {
                        h.running_request.fetch_sub(1, Ordering::Release);
                    }
                    _ => {}
                }

                step
            } else {
                DriverStep::Continue
            };

            match step {
                DriverStep::Pending => {
                    req_arc.write().status = DriverStatus::PendingStep;
                    return DriverStatus::PendingStep;
                }
                DriverStep::Complete { status } => {
                    req_arc.write().status = status;
                    return self.complete_request(&req_arc);
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
                            req_arc.write().status = DriverStatus::NotImplemented;
                            return self.complete_request(&req_arc);
                        }
                    }
                }
            }
        }
    }

    async fn pnp_minor_dispatch(
        device: &Arc<DeviceObject>,
        request: Arc<RwLock<Request>>,
    ) -> DriverStep {
        let (minor_opt, policy) = {
            let r = request.read();
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
            let mut step = cb(device.clone(), request.clone()).await;
            if step == DriverStep::complete(DriverStatus::NotImplemented) {
                step = DriverStep::complete(minor.default_status_for_unhandled())
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
    fn new(kind: RequestType, data: Box<[u8]>) -> Self;
    fn new_pnp(pnp: PnpRequest, data: Box<[u8]>) -> Self;
}

impl RequestExt for Request {
    fn new(kind: RequestType, data: Box<[u8]>) -> Self {
        if matches!(kind, RequestType::Pnp) {
            panic!("Request::new called with RequestType::Pnp. Use Request::new_pnp instead.");
        }

        Self {
            id: random_number(),
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
    fn new_pnp(pnp_request: PnpRequest, data: Box<[u8]>) -> Self {
        Self {
            id: random_number(),
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
