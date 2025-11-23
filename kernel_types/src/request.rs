use crate::CompletionRoutine;
use crate::fs::FsOp;
use crate::pnp::PnpRequest;
use crate::status::DriverStatus;
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::{
    pin::Pin,
    task::{Context, Poll, Waker},
};
use spin::RwLock;

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(C)]
pub enum RequestType {
    Read { offset: u64, len: usize },
    Write { offset: u64, len: usize },
    DeviceControl(u32),
    Fs(FsOp),
    Pnp,
    Dummy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum TraversalPolicy {
    ForwardLower,
    FailIfUnhandled,
    ForwardUpper,
}

#[derive(Debug)]
#[repr(C)]
pub struct Request {
    pub id: u64,
    pub kind: RequestType,
    pub data: Box<[u8]>,
    pub completed: bool,
    pub status: DriverStatus,
    pub traversal_policy: TraversalPolicy,
    pub pnp: Option<PnpRequest>,
    pub completion_routine: Option<CompletionRoutine>,
    pub completion_context: usize,
    pub waker_func: Option<extern "win64" fn(context: usize)>,
    pub waker_context: Option<usize>,
}

impl Request {
    #[inline]
    pub fn set_traversal_policy(mut self, policy: TraversalPolicy) -> Self {
        self.traversal_policy = policy;
        self
    }

    #[inline]
    pub fn empty() -> Self {
        Self {
            id: 0,
            kind: RequestType::Dummy,
            data: Box::new([]),
            completed: true,
            status: DriverStatus::Success,
            traversal_policy: TraversalPolicy::FailIfUnhandled,
            pnp: None,
            completion_routine: None,
            completion_context: 0,
            waker_func: None,
            waker_context: None,
        }
    }

    pub fn set_completion(&mut self, routine: CompletionRoutine, context: usize) {
        self.completion_routine = Some(routine);
        self.completion_context = context;
    }
}

#[repr(transparent)]
pub struct RequestFuture {
    pub req: Arc<RwLock<Request>>,
}

impl Future for RequestFuture {
    type Output = DriverStatus;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut req = self.req.write();

        if req.completed {
            return Poll::Ready(req.status);
        }

        let waker = cx.waker().clone();

        let waker_ptr = Box::into_raw(Box::new(waker)) as usize;

        if let Some(context) = req.waker_context {
            unsafe {
                let _ = Box::from_raw(context as *mut Waker);
            }
        }

        req.waker_func = Some(waker_trampoline);
        req.waker_context = Some(waker_ptr);

        Poll::Pending
    }
}

extern "win64" fn waker_trampoline(context: usize) {
    if context == 0 {
        return;
    }

    unsafe {
        let waker = Box::from_raw(context as *mut Waker);

        waker.wake();
    }
}
