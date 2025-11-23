use crate::drivers::pnp::manager::{PnpManager, PNP_MANAGER};
use crate::static_handlers::create_kernel_task;
use crate::structs::thread_pool::ThreadPool;
use crate::util::random_number;
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

static DISPATCHER_STARTED: AtomicBool = AtomicBool::new(false);
const START_THREADS: usize = 12;

lazy_static::lazy_static! {
    pub static ref THREADS: Arc<ThreadPool> = ThreadPool::new(START_THREADS);
    static ref DISPATCH_REQ_Q: Mutex<VecDeque<(Arc<DeviceObject>, Arc<RwLock<Request>>)>> = Mutex::new(VecDeque::new());
    static ref GLOBAL_DPCQ: Mutex<VecDeque<Dpc>> = Mutex::new(VecDeque::new());
}

impl PnpManager {
    pub fn queue_dpc(&self, func: extern "win64" fn(usize), arg: usize) {
        GLOBAL_DPCQ.lock().push_back(Dpc { func, arg });
    }

    pub fn init_io_dispatcher(&self) {
        if !DISPATCHER_STARTED.swap(true, Ordering::AcqRel) {
            create_kernel_task(
                io_dispatcher_trampoline as usize,
                alloc::format!("io-dispatch{:x}", crate::util::random_number()),
            );
        }
    }

    pub fn run_once(&self) -> bool {
        self.run_one_dpc() | self.run_one_device_request()
    }

    pub fn dispatch_forever(&self) -> ! {
        loop {
            if !self.run_once() {
                core::hint::spin_loop();
            }
        }
    }

    fn run_one_dpc(&self) -> bool {
        let dpc_opt = { GLOBAL_DPCQ.lock().pop_front() };
        let Some(dpc) = dpc_opt else {
            return false;
        };

        let pair = Box::new((dpc.func, dpc.arg));
        let ptr = Box::into_raw(pair) as usize;

        if !THREADS.submit_if_runnable(job_run_dpc, ptr) {
            let _ = unsafe { Box::from_raw(ptr as *mut (extern "win64" fn(usize), usize)) };
            GLOBAL_DPCQ.lock().push_front(dpc);
            return false;
        }
        true
    }

    pub fn execute_one() -> bool {
        THREADS.try_execute_one()
    }

    fn run_one_device_request(&self) -> bool {
        let item = { DISPATCH_REQ_Q.lock().pop_front() };
        let Some((dev, req)) = item else {
            return false;
        };

        let arg = Box::new(DispatchJobArg { dev, req });
        let ptr = Box::into_raw(arg) as usize;

        THREADS.submit(job_dispatch_request, ptr);
        true
    }

    pub fn send_request(
        &self,
        target: &IoTarget,
        req: Arc<RwLock<Request>>,
    ) -> Result<RequestFuture, DriverStatus> {
        {
            let mut guard = req.write();
            // Initialize as Continue (Waiting in queue/Traversing).
            // Pending is reserved for when a driver takes ownership (untracked).
            guard.status = DriverStatus::Continue;
            guard.completed = false;
        }
        DISPATCH_REQ_Q
            .lock()
            .push_back((target.target_device.clone(), req.clone()));
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
        let (comp_routine_addr, comp_ctx, waker_func, waker_ctx) = {
            let mut g = req_arc.write();
            g.completed = true;

            let cr = g.completion_routine.take().map(|fp| fp as usize);
            let cc = g.completion_context;

            let wf = g.waker_func.take();
            let wc = g.waker_context;

            g.waker_context = None;

            (cr, cc, wf, wc)
        };

        if let Some(addr) = comp_routine_addr {
            let f: CompletionRoutine = unsafe { core::mem::transmute(addr) };

            let ref_req = &mut req_arc.write();
            ref_req.status = f(ref_req, comp_ctx);
        }

        {
            let mut req = req_arc.write();
            // Only default to Success if the status is Continue (meaning it was just waiting/traversing).
            // If it is Pending, the driver explicitly set it to Untracked, so the driver *must* have set a result status.
            if req.status == DriverStatus::Continue {
                req.status = DriverStatus::Success;
            }
        }

        if let Some(func) = waker_func {
            func(waker_ctx.unwrap());
        }
    }

    /// The entry point for async request dispatch.
    /// Finds the handler, spawns a task on the executor, and handles the result asynchronously.
    fn call_device_handler(&self, dev: &Arc<DeviceObject>, req_arc: Arc<RwLock<Request>>) {
        let (kind, policy) = {
            let r = req_arc.read();
            (r.kind, r.traversal_policy)
        };

        if matches!(kind, RequestType::Dummy) {
            return;
        }

        // PnP dispatch is currently still synchronous in logic, but could be wrapped.
        if matches!(kind, RequestType::Pnp) {
            Self::pnp_minor_dispatch(dev, req_arc.clone());
            return;
        }

        if let Some(h) = dev.dev_init.io_vtable.get_for(&kind) {
            // Check queue depth limits
            match h.synchronization {
                Synchronization::Sync | Synchronization::Async => {
                    let depth = if matches!(h.synchronization, Synchronization::Sync) {
                        1u64
                    } else {
                        h.depth as u64
                    };
                    let cur = h.running_request.fetch_add(1, Ordering::AcqRel);
                    if depth > 0 && cur >= depth {
                        h.running_request.fetch_sub(1, Ordering::Release);
                        {
                            req_arc.write().status = DriverStatus::DeviceNotReady;
                        }
                        self.complete_request(&req_arc);
                        return;
                    }
                }
                _ => {}
            }

            let future = h.handler.invoke(dev.clone(), req_arc.clone());
            let req_for_task = req_arc.clone();
            let dev_for_task = dev.clone();

            nostd_runtime::spawn(async move {
                let status = future.await;

                match h.synchronization {
                    Synchronization::Sync | Synchronization::Async => {
                        h.running_request.fetch_sub(1, Ordering::Release);
                    }
                    _ => {}
                }

                match status {
                    DriverStatus::Pending => {
                        // Driver took ownership (Untracked). Mark as Pending.
                        req_for_task.write().status = DriverStatus::Pending;
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
            });
        } else {
            match policy {
                TraversalPolicy::ForwardLower => {
                    if PNP_MANAGER
                        .send_request_to_next_lower(dev, req_arc.clone())
                        .is_err()
                    {
                        {
                            req_arc.write().status = DriverStatus::NotImplemented;
                        }
                        self.complete_request(&req_arc);
                    }
                }
                TraversalPolicy::ForwardUpper => {
                    if PNP_MANAGER
                        .send_request_to_next_upper(dev, req_arc.clone())
                        .is_err()
                    {
                        {
                            req_arc.write().status = DriverStatus::NotImplemented;
                        }
                        self.complete_request(&req_arc);
                    }
                }
                TraversalPolicy::FailIfUnhandled => {
                    {
                        req_arc.write().status = DriverStatus::NotImplemented;
                    }
                    self.complete_request(&req_arc);
                }
            }
        }
    }

    fn pnp_minor_dispatch(device: &Arc<DeviceObject>, request: Arc<RwLock<Request>>) {
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
            let status = cb(device.clone(), request.clone());
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

extern "C" fn io_dispatcher_trampoline() {
    PNP_MANAGER.dispatch_forever();
}

struct DispatchJobArg {
    dev: Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
}

extern "win64" fn job_run_dpc(arg: usize) {
    let p = unsafe { &*(arg as *const (extern "win64" fn(usize), usize)) };
    (p.0)(p.1);
    let _ = unsafe { Box::from_raw(arg as *mut (extern "win64" fn(usize), usize)) };
}

extern "win64" fn job_dispatch_request(arg: usize) {
    let b: Box<DispatchJobArg> = unsafe { Box::from_raw(arg as *mut DispatchJobArg) };
    PNP_MANAGER.call_device_handler(&b.dev, b.req);
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
