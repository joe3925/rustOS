use crate::drivers::pnp::manager::{PnpManager, PNP_MANAGER};
use crate::println;
use crate::scheduling::runtime::runtime::spawn;
use crate::static_handlers::create_kernel_task;
use crate::structs::thread_pool::ThreadPool;
use crate::util::random_number;
use acpi::spcr::SpcrInterfaceType;
use alloc::{boxed::Box, collections::vec_deque::VecDeque, sync::Arc};
use core::sync::atomic::{AtomicBool, Ordering};
use kernel_types::device::DeviceObject;
use kernel_types::io::Synchronization;
use kernel_types::pnp::PnpRequest;
use kernel_types::request::{Request, RequestFuture, RequestType, TraversalPolicy};
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

        spawn(PNP_MANAGER.run_one_dpc());
    }

    async fn run_one_dpc(&self) {
        let dpc_opt = { GLOBAL_DPCQ.lock().pop_front() };
        let Some(dpc) = dpc_opt else {
            return;
        };

        (dpc.func)(dpc.arg);
    }

    pub fn send_request(
        &self,
        target: &IoTarget,
        req: Arc<RwLock<Request>>,
    ) -> Result<RequestFuture, DriverStatus> {
        {
            let mut guard = req.write();
            guard.status = DriverStatus::Continue;
            guard.completed = false;
        }

        let dev = target.target_device.clone();
        let req_clone = req.clone();

        Self::spawn_device_handler(dev, req_clone);

        Ok(RequestFuture { req })
    }

    pub fn send_request_to_next_lower(
        &self,
        from: &Arc<DeviceObject>,
        req: Arc<RwLock<Request>>,
    ) -> Result<RequestFuture, DriverStatus> {
        if let Some(target_dev) = from.lower_device.get() {
            self.send_request(
                &IoTarget {
                    target_device: target_dev.clone(),
                },
                req,
            )
        } else {
            Err(DriverStatus::NoSuchDevice)
        }
    }

    pub fn send_request_to_next_upper(
        &self,
        from: &Arc<DeviceObject>,
        req: Arc<RwLock<Request>>,
    ) -> Result<RequestFuture, DriverStatus> {
        if let Some(target_dev) = from.upper_device.get() {
            self.send_request(
                &IoTarget {
                    target_device: target_dev.upgrade().unwrap(),
                },
                req,
            )
        } else {
            Err(DriverStatus::NoSuchDevice)
        }
    }

    pub fn complete_request(&self, req_arc: &Arc<RwLock<Request>>) {
        let (waker_func, waker_ctx) = {
            let mut req = req_arc.write();

            if req.completed {
                return;
            }

            if let Some(fp) = req.completion_routine.take() {
                let f: CompletionRoutine = unsafe { core::mem::transmute(fp) };
                let context = req.completion_context;
                req.status = f(&mut *req, context);
            }

            if req.status == DriverStatus::Continue {
                req.status = DriverStatus::Success;
            }

            req.completed = true;

            (req.waker_func.take(), req.waker_context.take())
        };

        if let (Some(func), Some(ctx)) = (waker_func, waker_ctx) {
            func(ctx);
        }
    }

    pub fn spawn_device_handler(dev: Arc<DeviceObject>, req_arc: Arc<RwLock<Request>>) {
        spawn(PNP_MANAGER.call_device_handler(dev.clone(), req_arc.clone()));
    }
    async fn call_device_handler(&self, dev: Arc<DeviceObject>, req_arc: Arc<RwLock<Request>>) {
        let (kind, policy) = {
            let r = req_arc.read();
            (r.kind, r.traversal_policy)
        };

        if matches!(kind, RequestType::Dummy) {
            return;
        }

        if matches!(kind, RequestType::Pnp) {
            Self::pnp_minor_dispatch(&dev, req_arc.clone()).await;
            return;
        }

        if let Some(h) = dev.dev_init.io_vtable.get_for(&kind) {
            // match h.synchronization {
            //     Synchronization::Sync | Synchronization::Async => {
            //         let depth = if matches!(h.synchronization, Synchronization::Sync) {
            //             1u64
            //         } else {
            //             h.depth as u64
            //         };
            //         let cur = h.running_request.fetch_add(1, Ordering::AcqRel);
            //         if depth > 0 && cur >= depth {
            //             h.running_request.fetch_sub(1, Ordering::Release);
            //             {
            //                 Self::spawn_device_handler(dev, req_arc);
            //             }
            //             return;
            //         }
            //     }
            //     _ => {}
            // }

            let status = h.handler.invoke(dev.clone(), req_arc.clone()).await;

            let req_for_task = req_arc.clone();
            let dev_for_task = dev.clone();

            match h.synchronization {
                Synchronization::Sync | Synchronization::Async => {
                    h.running_request.fetch_sub(1, Ordering::Release);
                }
                _ => {}
            }

            match status {
                DriverStatus::Pending => {
                    // Pending was returned we no longer own the request
                }
                DriverStatus::Continue | DriverStatus::NotImplemented => {
                    let next_res = match policy {
                        TraversalPolicy::ForwardLower => PNP_MANAGER
                            .send_request_to_next_lower(&dev_for_task, req_for_task.clone()),
                        TraversalPolicy::ForwardUpper => PNP_MANAGER
                            .send_request_to_next_upper(&dev_for_task, req_for_task.clone()),
                        TraversalPolicy::FailIfUnhandled => Err(DriverStatus::NotImplemented),
                    };

                    if next_res.is_err() {
                        {
                            req_for_task.write().status = DriverStatus::NotImplemented;
                        }
                        PNP_MANAGER.complete_request(&req_for_task);
                    }
                }
                other => {
                    {
                        req_for_task.write().status = other;
                    }
                    PNP_MANAGER.complete_request(&req_for_task);
                }
            }
        } else {
            match policy {
                TraversalPolicy::ForwardLower => {
                    if PNP_MANAGER
                        .send_request_to_next_lower(&dev, req_arc.clone())
                        .is_err()
                    {
                        {
                            req_arc.write().status = DriverStatus::NotImplemented;
                        }
                        PNP_MANAGER.complete_request(&req_arc);
                    }
                }
                TraversalPolicy::ForwardUpper => {
                    if PNP_MANAGER
                        .send_request_to_next_upper(&dev, req_arc.clone())
                        .is_err()
                    {
                        {
                            req_arc.write().status = DriverStatus::NotImplemented;
                        }
                        PNP_MANAGER.complete_request(&req_arc);
                    }
                }
                TraversalPolicy::FailIfUnhandled => {
                    {
                        req_arc.write().status = DriverStatus::NotImplemented;
                    }
                    PNP_MANAGER.complete_request(&req_arc);
                }
            }
        }
    }

    async fn pnp_minor_dispatch(device: &Arc<DeviceObject>, request: Arc<RwLock<Request>>) {
        let me = &*PNP_MANAGER;
        let (minor_opt, policy) = {
            let r = request.read();
            (r.pnp.as_ref().map(|p| p.minor_function), r.traversal_policy)
        };

        let Some(minor) = minor_opt else {
            {
                request.write().status = DriverStatus::InvalidParameter;
            }
            me.complete_request(&request);
            return;
        };

        if policy != TraversalPolicy::ForwardLower {
            {
                request.write().status = DriverStatus::InvalidParameter;
            }
            me.complete_request(&request);
            return;
        }

        if let Some(cb) = device
            .dev_init
            .pnp_vtable
            .as_ref()
            .and_then(|vt| vt.get(minor))
        {
            let status = cb(device.clone(), request.clone()).await;
            if status == DriverStatus::Pending {
                request.write().status = DriverStatus::Pending;
                return;
            }
            if status != DriverStatus::Continue && status != DriverStatus::NotImplemented {
                request.write().status = status;
                me.complete_request(&request);
                return;
            }
        }

        if me
            .send_request_to_next_lower(device, request.clone())
            .is_err()
        {
            {
                request.write().status = minor.default_status_for_unhandled();
            }
            me.complete_request(&request);
        }
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
            status: DriverStatus::Continue,
            traversal_policy: TraversalPolicy::FailIfUnhandled,
            pnp: None,
            completion_routine: None,
            completion_context: 0,
            waker_context: None,
            waker_func: None,
        }
    }

    #[inline]
    fn new_pnp(pnp_request: PnpRequest, data: Box<[u8]>) -> Self {
        Self {
            id: random_number(),
            kind: RequestType::Pnp,
            data,
            completed: false,
            status: DriverStatus::Continue,
            traversal_policy: TraversalPolicy::ForwardLower,
            pnp: Some(pnp_request),
            completion_routine: None,
            completion_context: 0,
            waker_context: None,
            waker_func: None,
        }
    }
}

pub trait RequestResultExt {
    async fn resolve(self) -> DriverStatus;
}

impl RequestResultExt for Result<RequestFuture, DriverStatus> {
    #[inline(always)]
    async fn resolve(self) -> DriverStatus {
        match self {
            Ok(future) => future.await,
            Err(status) => status,
        }
    }
}
