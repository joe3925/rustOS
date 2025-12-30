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

    pub waker: Option<Waker>,
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

            waker: None,
        }
    }

    pub fn add_completion(&mut self, func: CompletionRoutine, ctx: usize) {
        match self.completion_routine {
            None => {
                self.completion_routine = Some(func);
                self.completion_context = ctx;
            }
            Some(prev) => {
                let prev_ctx = self.completion_context;
                let chain_ctx = store_prev_and_new(prev, prev_ctx, func, ctx);
                self.completion_routine = Some(chained_completion);
                self.completion_context = chain_ctx;
            }
        }
    }
    #[inline]
    fn complete_for_drop(&mut self) {
        let (status, waker) = {
            if self.completed {
                return;
            }

            if let Some(fp) = self.completion_routine.take() {
                let f: CompletionRoutine = unsafe { core::mem::transmute(fp) };
                let context = self.completion_context;
                self.status = f(&mut *self, context);
            }

            if self.status == DriverStatus::ContinueStep {
                self.status = DriverStatus::Success;
            }

            self.completed = true;
            (self.status, self.waker.take())
        };

        if let Some(w) = waker {
            w.wake();
        }
    }
}
impl Drop for Request {
    fn drop(&mut self) {
        self.complete_for_drop();
    }
}
struct CompletionNode {
    func: CompletionRoutine,
    ctx: usize,
    next: Option<*mut CompletionNode>,
}

fn store_prev_and_new(
    prev: CompletionRoutine,
    prev_ctx: usize,
    next: CompletionRoutine,
    next_ctx: usize,
) -> usize {
    let head = Box::new(CompletionNode {
        func: next,
        ctx: next_ctx,
        next: Some(Box::into_raw(Box::new(CompletionNode {
            func: prev,
            ctx: prev_ctx,
            next: None,
        }))),
    });
    Box::into_raw(head) as usize
}

extern "win64" fn chained_completion(req: &mut Request, ctx: usize) -> DriverStatus {
    let head = unsafe { Box::from_raw(ctx as *mut CompletionNode) };

    let mut status = DriverStatus::Success;

    let mut node_opt: Option<Box<CompletionNode>> = Some(head);
    while let Some(mut node) = node_opt {
        let st = (node.func)(req, node.ctx);
        status = st;
        let next_raw = node.next.take();
        node_opt = next_raw.map(|p| unsafe { Box::from_raw(p) });
    }

    status
}
pub struct RequestCompletion {
    pub req: Arc<RwLock<Request>>,
}

impl Future for RequestCompletion {
    type Output = DriverStatus;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut guard = self.req.write();

        if guard.completed {
            return Poll::Ready(guard.status);
        }

        guard.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}
