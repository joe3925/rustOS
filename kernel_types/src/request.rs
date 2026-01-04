use crate::CompletionRoutine;
use crate::fs::FsOp;
use crate::pnp::PnpRequest;
use crate::status::DriverStatus;
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::{
    mem::size_of,
    pin::Pin,
    task::{Context, Poll, Waker},
};
use spin::RwLock;

fn box_to_bytes<T>(b: Box<T>) -> Box<[u8]> {
    let len = size_of::<T>();
    let ptr = Box::into_raw(b) as *mut u8;
    unsafe { Box::from_raw(core::slice::from_raw_parts_mut(ptr, len)) }
}

unsafe fn bytes_to_box<T>(b: Box<[u8]>) -> Box<T> {
    debug_assert_eq!(b.len(), size_of::<T>());
    let ptr = Box::into_raw(b) as *mut u8 as *mut T;
    Box::from_raw(ptr)
}

#[derive(Debug)]
#[repr(C)]
pub struct RequestData {
    bytes: Box<[u8]>,
    tag: Option<u64>,
    dropper: fn(Box<[u8]>),
    size: usize,
}
// TODO: better hashing is probably possible to reduce the case where 2 types have the same name.
#[inline]
pub const fn type_tag<T: 'static>() -> u64 {
    const fn fnv1a(bytes: &[u8]) -> u64 {
        let mut hash: u64 = 0x817776954A86F58E;
        let mut i = 0;
        while i < bytes.len() {
            hash ^= bytes[i] as u64;
            hash = hash.wrapping_mul(0x100000001b3);
            i += 1;
        }
        hash
    }

    fnv1a(core::any::type_name::<T>().as_bytes())
}

impl RequestData {
    pub fn empty() -> Self {
        Self {
            bytes: Box::new([]),
            tag: None,
            dropper: |b| drop(b),
            size: 0,
        }
    }

    pub fn from_boxed_bytes(bytes: Box<[u8]>) -> Self {
        let size = bytes.len();
        Self {
            bytes,
            tag: None,
            dropper: |b| drop(b),
            size,
        }
    }

    pub fn from_t<T: 'static>(value: T) -> Self {
        let size = size_of::<T>();
        let bytes = box_to_bytes(Box::new(value));
        Self {
            bytes,
            tag: Some(type_tag::<T>()),
            size,
            dropper: |b| {
                let _ = unsafe { bytes_to_box::<T>(b) };
            },
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    fn matches<T: 'static>(&self) -> bool {
        self.tag == Some(type_tag::<T>()) && self.size == size_of::<T>()
    }

    pub fn view<T: 'static>(&self) -> Option<&T> {
        if !self.matches::<T>() {
            return None;
        }
        Some(unsafe { &*(self.bytes.as_ptr() as *const T) })
    }

    pub fn view_mut<T: 'static>(&mut self) -> Option<&mut T> {
        if !self.matches::<T>() {
            return None;
        }
        Some(unsafe { &mut *(self.bytes.as_mut_ptr() as *mut T) })
    }

    pub fn try_take<T: 'static>(&mut self) -> Option<T> {
        if !self.matches::<T>() {
            return None;
        }
        let raw = core::mem::replace(&mut self.bytes, Box::new([]));
        self.tag = None;
        self.size = 0;
        self.dropper = |b| drop(b);
        Some(*unsafe { bytes_to_box::<T>(raw) })
    }

    pub fn take_bytes(&mut self) -> Box<[u8]> {
        let raw = core::mem::replace(&mut self.bytes, Box::new([]));
        self.tag = None;
        self.size = 0;
        self.dropper = |b| drop(b);
        raw
    }
}

impl Drop for RequestData {
    fn drop(&mut self) {
        let raw = core::mem::replace(&mut self.bytes, Box::new([]));
        (self.dropper)(raw);
    }
}

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
    pub data: RequestData,
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
    pub fn set_data(&mut self, data: RequestData) {
        self.data = data;
    }

    #[inline]
    pub fn set_data_t<T: 'static>(&mut self, data: T) {
        self.data = RequestData::from_t(data);
    }

    #[inline]
    pub fn set_data_bytes(&mut self, data: Box<[u8]>) {
        self.data = RequestData::from_boxed_bytes(data);
    }

    #[inline]
    pub fn data_len(&self) -> usize {
        self.data.len()
    }

    #[inline]
    pub fn data_slice(&self) -> &[u8] {
        self.data.as_slice()
    }

    #[inline]
    pub fn data_slice_mut(&mut self) -> &mut [u8] {
        self.data.as_mut_slice()
    }

    #[inline]
    pub fn view_data<T: 'static>(&self) -> Option<&T> {
        self.data.view::<T>()
    }

    #[inline]
    pub fn view_data_mut<T: 'static>(&mut self) -> Option<&mut T> {
        self.data.view_mut::<T>()
    }

    #[inline]
    pub fn take_data<T: 'static>(&mut self) -> Option<T> {
        self.data.try_take::<T>()
    }

    #[inline]
    pub fn take_data_bytes(&mut self) -> Box<[u8]> {
        self.data.take_bytes()
    }

    #[inline]
    pub fn empty() -> Self {
        Self {
            id: 0,
            kind: RequestType::Dummy,
            data: RequestData::empty(),
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
