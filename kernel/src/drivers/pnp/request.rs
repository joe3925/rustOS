use crate::drivers::pnp::driver_object::{
    DeviceObject, DriverObject, DriverStatus, PnpMinorFunction, Request, RequestType,
    Synchronization,
};
use crate::drivers::pnp::manager::{PnpManager, PNP_MANAGER};
use crate::drivers::pnp::request;
use crate::static_handlers::create_kernel_task;
use crate::structs::thread_pool::ThreadPool;
use alloc::{boxed::Box, collections::vec_deque::VecDeque, string::String, sync::Arc};
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
pub type CompletionRoutine = extern "win64" fn(request: &mut Request, context: usize);

static DISPATCHER_STARTED: AtomicBool = AtomicBool::new(false);
const START_THREADS: usize = 12;

lazy_static::lazy_static! {
    static ref THREADS: Arc<ThreadPool> = ThreadPool::new();
    static ref DISPATCH_DEVQ: Mutex<VecDeque<Arc<DeviceObject>>> = Mutex::new(VecDeque::new());
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

        if !THREADS.submit_if_runnable(job_run_dpc, ptr) {
            let _ = unsafe { Box::from_raw(ptr as *mut (extern "win64" fn(usize), usize)) };
            GLOBAL_DPCQ.lock().push_front(dpc);
            return false;
        }
        true
    }

    pub fn pump_queue_once(&self) -> bool {
        let dev_opt = { DISPATCH_DEVQ.lock().pop_front() };
        let Some(dev) = dev_opt else {
            return false;
        };

        dev.in_queue.store(false, Ordering::Release);
        let _ = dev
            .dispatch_tickets
            .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |cur| {
                Some(cur.saturating_sub(1))
            });

        self.drain_device(&dev);
        true
    }

    fn run_one_device_request(&self) -> bool {
        let dev_opt = { DISPATCH_DEVQ.lock().pop_front() };
        let Some(dev) = dev_opt else {
            return false;
        };

        dev.in_queue.store(false, Ordering::Release);
        let _ = dev
            .dispatch_tickets
            .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |cur| {
                Some(cur.saturating_sub(1))
            });

        let arg = Box::new(DrainJobArg { dev: dev.clone() });
        let ptr = Box::into_raw(arg) as usize;

        if !THREADS.submit_if_runnable(job_drain_device, ptr) {
            let _ = unsafe { Box::from_raw(ptr as *mut DrainJobArg) };
            dev.dispatch_tickets.fetch_add(1, Ordering::AcqRel);
            if !dev.in_queue.swap(true, Ordering::AcqRel) {
                DISPATCH_DEVQ.lock().push_front(dev);
            }
            return false;
        }
        true
    }

    fn drain_device(&self, dev: &Arc<DeviceObject>) {
        loop {
            let req_opt = { dev.queue.lock().pop_front() };

            if let Some(req) = req_opt {
                self.call_device_handler(dev, req);
                continue;
            }

            let needs_requeue = {
                let more = dev.dispatch_tickets.load(Ordering::Acquire);
                let has_items = { !dev.queue.lock().is_empty() };
                more > 0 || has_items
            };

            if needs_requeue && !dev.in_queue.swap(true, Ordering::AcqRel) {
                DISPATCH_DEVQ.lock().push_back(dev.clone());
            }
            return;
        }
    }
    pub fn send_request(&self, target: &IoTarget, req: Arc<RwLock<Request>>) -> DriverStatus {
        target.target_device.queue.lock().push_back(req);
        self.schedule_device_dispatch(&target.target_device);
        DriverStatus::Pending
    }

    pub fn send_request_to_next_lower(
        &self,
        from: &Arc<DeviceObject>,
        req: Arc<RwLock<Request>>,
    ) -> DriverStatus {
        if let Some(target_dev) = from.lower_device.clone() {
            let target = IoTarget {
                target_device: target_dev,
            };
            self.send_request(&target, req)
        } else {
            DriverStatus::NoSuchDevice
        }
    }

    pub fn complete_request(&self, req: &mut Request) {
        if let Some(completion) = req.completion_routine.take() {
            completion(req, req.completion_context);
        }
        req.completed = true;
    }

    fn schedule_device_dispatch(&self, dev: &Arc<DeviceObject>) {
        let _ = dev.dispatch_tickets.fetch_add(1, Ordering::AcqRel);
        if !dev.in_queue.swap(true, Ordering::AcqRel) {
            DISPATCH_DEVQ.lock().push_back(dev.clone());
        }
    }

    fn call_device_handler(&self, dev: &Arc<DeviceObject>, req_arc: Arc<RwLock<Request>>) {
        let kind = { req_arc.read().kind };
        if matches!(kind, RequestType::Dummy) {
            return;
        }
        if matches!(kind, RequestType::Pnp) {
            Self::pnp_minor_dispatch(dev, req_arc.clone());
            return;
        }

        if let Some(h) = dev.dev_init.io_vtable.get_for(&kind) {
            match h.synchronization {
                Synchronization::FireAndForget => {
                    h.handler.invoke(dev, req_arc.clone());
                }
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
                    let _ = admit;
                    h.handler.invoke(dev, req_arc.clone());
                    h.running_request
                        .fetch_sub(1, core::sync::atomic::Ordering::Release);
                }
            }
        } else {
            req_arc.write().status = DriverStatus::Pending;
        }

        let st = { req_arc.read().status };
        if st == DriverStatus::Pending {
            let fwd = self.send_request_to_next_lower(dev, req_arc.clone());
            if fwd == DriverStatus::NoSuchDevice {
                with_req_mut(&req_arc, |r| {
                    if let Some(pnp) = r.pnp.as_ref() {
                        r.status = match pnp.minor_function {
                            PnpMinorFunction::StartDevice
                            | PnpMinorFunction::QueryDeviceRelations => DriverStatus::Success,
                            _ => DriverStatus::NotImplemented,
                        };
                    } else {
                        r.status = DriverStatus::NotImplemented;
                    }
                    if !r.completed {
                        self.complete_request(r);
                    }
                });
            }
            return;
        }
        with_req_mut(&req_arc, |r| {
            if !r.completed {
                self.complete_request(r);
            }
        });
    }

    fn pnp_minor_dispatch(device: &Arc<DeviceObject>, request: Arc<RwLock<Request>>) {
        let me = &*PNP_MANAGER;

        let minor_opt = { request.read().pnp.as_ref().map(|p| p.minor_function) };
        let Some(minor) = minor_opt else {
            let st = me.send_request_to_next_lower(device, request.clone());
            if st == DriverStatus::NoSuchDevice {
                let mut g = request.write();
                g.status = DriverStatus::NotImplemented;
                me.complete_request(&mut *g);
            } else {
                request.write().status = DriverStatus::Pending;
            }
            return;
        };

        let cb_opt = device
            .dev_init
            .pnp_vtable
            .as_ref()
            .and_then(|vt| vt.get(minor));

        if let Some(cb) = cb_opt {
            match cb(device, request.clone()) {
                DriverStatus::Success => {
                    let mut g = request.write();
                    g.status = DriverStatus::Success;
                    me.complete_request(&mut *g);
                }
                DriverStatus::Pending => {
                    request.write().status = DriverStatus::Pending;
                    let st = me.send_request_to_next_lower(device, request.clone());
                    if st == DriverStatus::NoSuchDevice {
                        let mut g = request.write();
                        g.status = match minor {
                            PnpMinorFunction::StartDevice
                            | PnpMinorFunction::QueryDeviceRelations => DriverStatus::Success,
                            _ => DriverStatus::NotImplemented,
                        };
                        me.complete_request(&mut *g);
                    }
                }
                other => {
                    let mut g = request.write();
                    g.status = other;
                    me.complete_request(&mut *g);
                }
            }
            return;
        }

        match minor {
            PnpMinorFunction::StartDevice | PnpMinorFunction::QueryDeviceRelations => {
                let st = me.send_request_to_next_lower(device, request.clone());
                if st == DriverStatus::NoSuchDevice {
                    let mut g = request.write();
                    g.status = DriverStatus::Success;
                    me.complete_request(&mut *g);
                } else {
                    request.write().status = DriverStatus::Pending;
                }
            }
            _ => {
                let st = me.send_request_to_next_lower(device, request.clone());
                if st == DriverStatus::NoSuchDevice {
                    let mut g = request.write();
                    g.status = DriverStatus::NoSuchDevice;
                    me.complete_request(&mut *g);
                } else {
                    request.write().status = DriverStatus::Pending;
                }
            }
        }
    }
}

#[inline]
fn with_req_mut<F: FnOnce(&mut Request)>(r: &Arc<RwLock<Request>>, f: F) {
    let mut g = r.write();
    f(&mut *g);
}

extern "C" fn io_dispatcher_trampoline() {
    PNP_MANAGER.dispatch_forever();
}

struct DrainJobArg {
    dev: Arc<DeviceObject>,
}

extern "win64" fn job_run_dpc(arg: usize) {
    let p = unsafe { &*(arg as *const (extern "win64" fn(usize), usize)) };
    (p.0)(p.1);
    let _ = unsafe { Box::from_raw(arg as *mut (extern "win64" fn(usize), usize)) };
}

extern "win64" fn job_drain_device(arg: usize) {
    let b: Box<DrainJobArg> = unsafe { Box::from_raw(arg as *mut DrainJobArg) };
    PNP_MANAGER.drain_device(&b.dev);
}
