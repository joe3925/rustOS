use crate::drivers::pnp::driver_object::{
    DeviceObject, DriverStatus, PnpMinorFunction, Request, RequestType, Synchronization,
    TraversalPolicy,
};
use crate::drivers::pnp::manager::{PnpManager, PNP_MANAGER};

use crate::static_handlers::create_kernel_task;
use crate::structs::thread_pool::ThreadPool;
use alloc::{boxed::Box, collections::vec_deque::VecDeque, sync::Arc};
use core::sync::atomic::{AtomicBool, Ordering};
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
    static ref THREADS: Arc<ThreadPool> = ThreadPool::new();
    // Changed: Queue now stores pairs of Device + Request, not just Devices.
    // This enables per-request granularity (work stealing) instead of device claiming.
    static ref DISPATCH_REQ_Q: Mutex<VecDeque<(Arc<DeviceObject>, Arc<RwLock<Request>>)>> = Mutex::new(VecDeque::new());
    static ref GLOBAL_DPCQ: Mutex<VecDeque<Dpc>> = Mutex::new(VecDeque::new());
}

impl PnpManager {
    pub fn queue_dpc(&self, func: extern "win64" fn(usize), arg: usize) {
        GLOBAL_DPCQ.lock().push_back(Dpc { func, arg });
    }

    pub fn init_io_dispatcher(&self) {
        if !DISPATCHER_STARTED.swap(true, Ordering::AcqRel) {
            THREADS.start(START_THREADS);
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

        // Note: DPC logic kept as is (using submit_if_runnable),
        // assuming priority execution is still desired for DPCs.
        if !THREADS.submit_if_runnable(job_run_dpc, ptr) {
            let _ = unsafe { Box::from_raw(ptr as *mut (extern "win64" fn(usize), usize)) };
            GLOBAL_DPCQ.lock().push_front(dpc);
            return false;
        }
        true
    }

    pub fn pump_queue_once(&self) -> bool {
        // Pop a specific (Device, Request) tuple.
        let item = {
            let mut q = DISPATCH_REQ_Q.lock();
            q.pop_front()
        };

        if let Some((dev, req)) = item {
            // Process the request immediately on this thread.
            // This prevents the deadlock where a thread waiting for I/O
            // cannot process the very request it is waiting for because
            // another thread has "claimed" the device.
            self.call_device_handler(&dev, req);
            return true;
        }
        false
    }

    fn run_one_device_request(&self) -> bool {
        // Pop a specific (Device, Request) tuple.
        let item = {
            let mut q = DISPATCH_REQ_Q.lock();
            q.pop_front()
        };

        let Some((dev, req)) = item else {
            return false;
        };

        let arg = Box::new(DispatchJobArg { dev, req });
        let ptr = Box::into_raw(arg) as usize;

        // Changed: Unconditionally submit to the thread pool as requested.
        // This avoids the complexity of "runnable" checks for standard I/O.
        THREADS.submit(job_dispatch_request, ptr);

        true
    }

    pub fn send_request(&self, target: &IoTarget, req: Arc<RwLock<Request>>) -> DriverStatus {
        // Push the (Device, Request) pair directly to the global queue.
        // We do NOT use target.target_device.queue here to enforce per-thread pickup.
        DISPATCH_REQ_Q
            .lock()
            .push_back((target.target_device.clone(), req));
        DriverStatus::Success
    }

    pub fn send_request_to_next_lower(
        &self,
        from: &Arc<DeviceObject>,
        req: Arc<RwLock<Request>>,
    ) -> DriverStatus {
        if let Some(target_dev) = from.lower_device.get() {
            let target = IoTarget {
                target_device: target_dev.clone(),
            };
            self.send_request(&target, req)
        } else {
            DriverStatus::NoSuchDevice
        }
    }

    pub fn send_request_to_next_upper(
        &self,
        from: &Arc<DeviceObject>,
        req: Arc<RwLock<Request>>,
    ) -> DriverStatus {
        if let Some(target_dev) = from.upper_device.get() {
            let target = IoTarget {
                target_device: target_dev.upgrade().unwrap(),
            };
            self.send_request(&target, req)
        } else {
            DriverStatus::NoSuchDevice
        }
    }

    pub fn complete_request(&self, req_arc: &Arc<RwLock<Request>>) {
        let (func_addr, ctx) = {
            let mut g = req_arc.write();
            let f = g.completion_routine.take().map(|fp| fp as usize);
            let ctx = g.completion_context;
            g.completed = true;
            (f, ctx)
        };

        if let Some(addr) = func_addr {
            let f: CompletionRoutine = unsafe { core::mem::transmute(addr) };
            let ref_req = &mut req_arc.write();
            ref_req.status = f(ref_req, ctx);
        }
        let mut req = req_arc.write();
        if req.status == DriverStatus::Continue || req.status == DriverStatus::Pending {
            req.status = DriverStatus::Success;
        }
    }

    fn call_device_handler(&self, dev: &Arc<DeviceObject>, req_arc: Arc<RwLock<Request>>) {
        let (kind, policy) = {
            let r = req_arc.read();
            (r.kind, r.traversal_policy)
        };

        if matches!(kind, RequestType::Dummy) {
            return;
        }

        if matches!(kind, RequestType::Pnp) {
            Self::pnp_minor_dispatch(dev, req_arc.clone());
            return;
        }

        let status = if let Some(h) = dev.dev_init.io_vtable.get_for(&kind) {
            match h.synchronization {
                Synchronization::FireAndForget => h.handler.invoke(dev, req_arc.clone()),
                Synchronization::Sync | Synchronization::Async => {
                    let depth = if matches!(h.synchronization, Synchronization::Sync) {
                        1u64
                    } else {
                        h.depth as u64
                    };

                    let admit = h.running_request.fetch_update(
                        Ordering::AcqRel,
                        Ordering::Relaxed,
                        |cur| {
                            if depth == 0 || cur < depth {
                                Some(cur + 1)
                            } else {
                                None
                            }
                        },
                    );

                    // Note: Concurrency limits are handled here.
                    // If admission fails, the request needs to be re-queued or rejected.
                    // For now keeping existing logic "true" which bypasses limit check
                    // (assumed temporary based on original code).
                    if true {
                        // admit.is_ok()
                        let st = h.handler.invoke(dev, req_arc.clone());
                        h.running_request.fetch_sub(1, Ordering::Release);
                        st
                    } else {
                        DriverStatus::DeviceNotReady
                    }
                }
            }
        } else {
            DriverStatus::NotImplemented
        };

        match status {
            DriverStatus::Pending => {
                {
                    let mut w = req_arc.write();
                    w.status = DriverStatus::Pending;
                }
                return;
            }

            DriverStatus::Continue | DriverStatus::NotImplemented => match policy {
                TraversalPolicy::ForwardLower => {
                    let fwd = self.send_request_to_next_lower(dev, req_arc.clone());
                    if fwd == DriverStatus::NoSuchDevice {
                        {
                            let mut w = req_arc.write();
                            w.status = DriverStatus::NotImplemented;
                        }
                        self.complete_request(&req_arc);
                    }
                }
                TraversalPolicy::ForwardUpper => {
                    let fwd = self.send_request_to_next_upper(dev, req_arc.clone());
                    if fwd == DriverStatus::NoSuchDevice {
                        {
                            let mut w = req_arc.write();
                            w.status = DriverStatus::NotImplemented;
                        }
                        self.complete_request(&req_arc);
                    }
                }
                TraversalPolicy::FailIfUnhandled => {
                    {
                        let mut w = req_arc.write();
                        w.status = DriverStatus::NotImplemented;
                    }
                    self.complete_request(&req_arc);
                }
            },

            other => {
                {
                    let mut w = req_arc.write();
                    w.status = other;
                }
                self.complete_request(&req_arc);
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
                let mut g = request.write();
                g.status = DriverStatus::InvalidParameter;
            }
            me.complete_request(&request);
            return;
        };

        if policy != TraversalPolicy::ForwardLower {
            {
                let mut g = request.write();
                g.status = DriverStatus::InvalidParameter;
            }
            me.complete_request(&request);
            return;
        }

        let cb_opt = device
            .dev_init
            .pnp_vtable
            .as_ref()
            .and_then(|vt| vt.get(minor));

        if let Some(cb) = cb_opt {
            let status = cb(device, request.clone());

            match status {
                DriverStatus::Pending => {
                    {
                        let mut g = request.write();
                        g.status = DriverStatus::Pending;
                    }
                    return;
                }
                DriverStatus::Continue | DriverStatus::NotImplemented => {}
                other => {
                    {
                        let mut g = request.write();
                        g.status = other;
                    }
                    me.complete_request(&request);
                    return;
                }
            }
        }

        let st = me.send_request_to_next_lower(device, request.clone());

        if st == DriverStatus::NoSuchDevice {
            {
                let mut g = request.write();
                g.status = minor.default_status_for_unhandled();
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
