use crate::CompletionRoutine;
use crate::fs::FsOp;
use crate::pnp::DriverStep;
use crate::pnp::PnpRequest;
use crate::status::DriverStatus;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::{
    alloc::Layout,
    mem::{MaybeUninit, align_of, size_of},
    ops::{Deref, DerefMut},
    pin::Pin,
    ptr::null_mut,
    task::{Context, Poll, Waker},
};
use spin::RwLock;

/// Maximum size for inline storage (bytes)
const INLINE_THRESHOLD: usize = 64;

/// Alignment for inline buffer
const INLINE_ALIGN: usize = 8;

/// Storage mode indicator
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum StorageMode {
    /// Data is stored inline in the `inline` buffer
    Inline = 0,
    /// Data is heap-allocated as typed data (raw ptr + Layout for deallocation)
    HeapTyped = 1,
    /// Data is heap-allocated as raw bytes (from Box<[u8]>, reconstruct on drop)
    HeapBytes = 2,
    /// Data is borrowed from an external buffer (raw pointer, no deallocation)
    BorrowedBytes = 3,
}

/// Aligned inline buffer for small data
#[repr(C, align(8))]
struct InlineBuffer {
    data: MaybeUninit<[u8; INLINE_THRESHOLD]>,
}

impl InlineBuffer {
    #[inline]
    const fn new() -> Self {
        Self {
            data: MaybeUninit::uninit(),
        }
    }

    #[inline]
    fn as_ptr(&self) -> *const u8 {
        self.data.as_ptr() as *const u8
    }

    #[inline]
    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.data.as_mut_ptr() as *mut u8
    }
}

impl core::fmt::Debug for InlineBuffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InlineBuffer").finish_non_exhaustive()
    }
}

/// Dropper function signature - only does drop_in_place, never deallocates
type DropperFn = fn(*mut u8);

// TODO: Consider adding a safe zero-copy borrowed mode using raw pointer + PhantomData
// lifetime tracking to avoid memory copies on I/O operations. Current approach removes
// borrowed mode entirely and copies data, which is safe but has overhead.

#[repr(C)]
pub struct RequestData {
    /// Inline buffer for small data (always present, may be unused)
    inline: InlineBuffer,
    /// Raw heap pointer (valid when mode is HeapTyped or HeapBytes)
    heap_ptr: *mut u8,
    /// Layout of the heap allocation (only used for HeapTyped mode)
    heap_layout: Layout,
    /// Type tag for runtime type checking
    tag: Option<u64>,
    /// Custom drop function that runs T's destructor (drop_in_place only, no dealloc)
    dropper: DropperFn,
    /// Size of contained data in bytes
    size: usize,
    /// Storage mode indicator
    mode: StorageMode,
}

impl core::fmt::Debug for RequestData {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RequestData")
            .field("tag", &self.tag)
            .field("size", &self.size)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

// SAFETY: RequestData owns its heap allocation exclusively. The raw pointer is only
// used internally and never escapes. The data pointed to is either:
// - HeapTyped: allocated via alloc::alloc, exclusively owned
// - HeapBytes: from Box::into_raw, exclusively owned
// Both cases ensure exclusive ownership, making Send/Sync safe.
unsafe impl Send for RequestData {}
unsafe impl Sync for RequestData {}
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

/// No-op dropper for raw bytes or empty data
fn noop_dropper(_: *mut u8) {}

impl RequestData {
    pub fn empty() -> Self {
        Self {
            inline: InlineBuffer::new(),
            heap_ptr: null_mut(),
            heap_layout: Layout::new::<()>(),
            tag: None,
            dropper: noop_dropper,
            size: 0,
            mode: StorageMode::Inline,
        }
    }

    pub fn from_boxed_bytes(bytes: Box<[u8]>) -> Self {
        let size = bytes.len();

        if size <= INLINE_THRESHOLD {
            // Copy to inline buffer
            let mut result = Self {
                inline: InlineBuffer::new(),
                heap_ptr: null_mut(),
                heap_layout: Layout::new::<()>(),
                tag: None,
                dropper: noop_dropper,
                size,
                mode: StorageMode::Inline,
            };

            unsafe {
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), result.inline.as_mut_ptr(), size);
            }
            // Original box is dropped here

            result
        } else {
            // Keep as heap allocation - store raw pointer from Box
            let ptr = Box::into_raw(bytes) as *mut u8;

            Self {
                inline: InlineBuffer::new(),
                heap_ptr: ptr,
                heap_layout: Layout::new::<()>(), // Not used for HeapBytes
                tag: None,
                dropper: noop_dropper,
                size,
                mode: StorageMode::HeapBytes,
            }
        }
    }

    /// Borrow a typed value without taking ownership.
    ///
    /// # Safety
    /// The caller must guarantee that `ptr` points to a valid instance of `T` that
    /// remains alive and correctly aligned for the full lifetime of this
    /// `RequestData` and any `RequestHandle` that contains it.
    pub unsafe fn from_borrowed_t<T: Send + 'static>(ptr: &'static mut T) -> Self {
        Self {
            inline: InlineBuffer::new(),
            heap_ptr: (ptr as *mut T) as *mut u8,
            // Stored for metadata only; we never deallocate borrowed data.
            heap_layout: Layout::new::<T>(),
            tag: Some(type_tag::<T>()),
            dropper: noop_dropper,
            size: size_of::<T>(),
            mode: StorageMode::BorrowedBytes,
        }
    }

    pub fn from_t<T: 'static>(value: T) -> Self {
        let size = size_of::<T>();
        let align = align_of::<T>();

        /// Typed dropper that only runs T's destructor (no deallocation)
        fn typed_dropper<T>(ptr: *mut u8) {
            unsafe { core::ptr::drop_in_place(ptr as *mut T) };
        }

        if size <= INLINE_THRESHOLD && align <= INLINE_ALIGN {
            // INLINE PATH: Copy value into inline buffer
            let mut result = Self {
                inline: InlineBuffer::new(),
                heap_ptr: null_mut(),
                heap_layout: Layout::new::<()>(),
                tag: Some(type_tag::<T>()),
                dropper: typed_dropper::<T>,
                size,
                mode: StorageMode::Inline,
            };

            unsafe {
                let dst = result.inline.as_mut_ptr() as *mut T;
                core::ptr::write(dst, value);
            }

            result
        } else {
            // HEAP PATH: Allocate with correct Layout
            let layout = Layout::new::<T>();
            let ptr = unsafe { alloc::alloc::alloc(layout) };

            if ptr.is_null() {
                alloc::alloc::handle_alloc_error(layout);
            }

            unsafe {
                core::ptr::write(ptr as *mut T, value);
            }

            Self {
                inline: InlineBuffer::new(),
                heap_ptr: ptr,
                heap_layout: layout,
                tag: Some(type_tag::<T>()),
                dropper: typed_dropper::<T>,
                size,
                mode: StorageMode::HeapTyped,
            }
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.size
    }

    #[inline]
    pub fn set_len(&mut self, new_size: usize) {
        self.size = new_size;
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        match self.mode {
            StorageMode::Inline => unsafe {
                core::slice::from_raw_parts(self.inline.as_ptr(), self.size)
            },
            StorageMode::HeapTyped | StorageMode::HeapBytes | StorageMode::BorrowedBytes => {
                if self.heap_ptr.is_null() {
                    &[]
                } else {
                    unsafe { core::slice::from_raw_parts(self.heap_ptr, self.size) }
                }
            }
        }
    }

    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        match self.mode {
            StorageMode::Inline => unsafe {
                core::slice::from_raw_parts_mut(self.inline.as_mut_ptr(), self.size)
            },
            StorageMode::HeapTyped | StorageMode::HeapBytes | StorageMode::BorrowedBytes => {
                if self.heap_ptr.is_null() {
                    &mut []
                } else {
                    unsafe { core::slice::from_raw_parts_mut(self.heap_ptr, self.size) }
                }
            }
        }
    }

    fn matches<T: 'static>(&self) -> bool {
        self.tag == Some(type_tag::<T>()) && self.size == size_of::<T>()
    }

    pub fn view<T: 'static>(&self) -> Option<&T> {
        if !self.matches::<T>() {
            return None;
        }

        let ptr = match self.mode {
            StorageMode::Inline => self.inline.as_ptr(),
            StorageMode::HeapTyped => self.heap_ptr,
            StorageMode::HeapBytes | StorageMode::BorrowedBytes => return None,
        };

        if ptr.is_null() {
            return None;
        }

        Some(unsafe { &*(ptr as *const T) })
    }

    pub fn view_mut<T: 'static>(&mut self) -> Option<&mut T> {
        if !self.matches::<T>() {
            return None;
        }

        let ptr = match self.mode {
            StorageMode::Inline => self.inline.as_mut_ptr(),
            StorageMode::HeapTyped => self.heap_ptr,
            StorageMode::HeapBytes | StorageMode::BorrowedBytes => return None,
        };

        if ptr.is_null() {
            return None;
        }

        Some(unsafe { &mut *(ptr as *mut T) })
    }

    pub fn try_take<T: 'static>(&mut self) -> Option<T> {
        if !self.matches::<T>() {
            return None;
        }

        let value = match self.mode {
            StorageMode::Inline => {
                // Read from inline storage
                unsafe {
                    let ptr = self.inline.as_ptr() as *const T;
                    core::ptr::read(ptr)
                }
            }
            StorageMode::HeapTyped => {
                // Read from heap, then deallocate the memory
                if self.heap_ptr.is_null() {
                    return None;
                }

                let value = unsafe { core::ptr::read(self.heap_ptr as *const T) };

                // Deallocate the memory (we've taken ownership of the value)
                unsafe {
                    alloc::alloc::dealloc(self.heap_ptr, self.heap_layout);
                }

                value
            }
            StorageMode::HeapBytes | StorageMode::BorrowedBytes => {
                // Cannot take typed value from raw bytes
                return None;
            }
        };

        // Reset to empty state (don't run dropper - we took ownership)
        self.heap_ptr = null_mut();
        self.tag = None;
        self.size = 0;
        self.mode = StorageMode::Inline;
        self.dropper = noop_dropper;

        Some(value)
    }

    pub fn take_bytes(&mut self) -> Box<[u8]> {
        let result = match self.mode {
            StorageMode::Inline => {
                // Must allocate a new box and copy inline data into it
                let mut vec = Vec::with_capacity(self.size);
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        self.inline.as_ptr(),
                        vec.as_mut_ptr(),
                        self.size,
                    );
                    vec.set_len(self.size);
                }

                // Run dropper for typed inline data
                if self.tag.is_some() {
                    (self.dropper)(self.inline.as_mut_ptr());
                }

                vec.into_boxed_slice()
            }
            StorageMode::HeapTyped => {
                // Allocate new Box<[u8]>, copy data, deallocate original
                if self.heap_ptr.is_null() {
                    return Box::new([]);
                }

                let mut vec = Vec::with_capacity(self.size);
                unsafe {
                    core::ptr::copy_nonoverlapping(self.heap_ptr, vec.as_mut_ptr(), self.size);
                    vec.set_len(self.size);

                    // Run typed dropper
                    (self.dropper)(self.heap_ptr);

                    // Deallocate with original layout
                    alloc::alloc::dealloc(self.heap_ptr, self.heap_layout);
                }

                vec.into_boxed_slice()
            }
            StorageMode::HeapBytes => {
                // Reconstruct the Box<[u8]> directly
                if self.heap_ptr.is_null() {
                    Box::new([])
                } else {
                    unsafe {
                        let slice = core::slice::from_raw_parts_mut(self.heap_ptr, self.size);
                        Box::from_raw(slice)
                    }
                }
            }
            StorageMode::BorrowedBytes => {
                // Must copy — we don't own the memory
                if self.heap_ptr.is_null() || self.size == 0 {
                    Box::new([])
                } else {
                    let mut vec = Vec::with_capacity(self.size);
                    unsafe {
                        core::ptr::copy_nonoverlapping(self.heap_ptr, vec.as_mut_ptr(), self.size);
                        vec.set_len(self.size);
                    }
                    vec.into_boxed_slice()
                }
            }
        };

        // Reset to empty state
        self.heap_ptr = null_mut();
        self.tag = None;
        self.size = 0;
        self.mode = StorageMode::Inline;
        self.dropper = noop_dropper;

        result
    }
}

impl Drop for RequestData {
    fn drop(&mut self) {
        match self.mode {
            StorageMode::Inline => {
                // Run dropper for typed data
                if self.tag.is_some() && self.size > 0 {
                    (self.dropper)(self.inline.as_mut_ptr());
                }
                // Inline buffer is part of struct, no deallocation needed
            }
            StorageMode::HeapTyped => {
                if !self.heap_ptr.is_null() {
                    // Run typed dropper (drop_in_place)
                    (self.dropper)(self.heap_ptr);

                    // Deallocate with stored Layout
                    unsafe {
                        alloc::alloc::dealloc(self.heap_ptr, self.heap_layout);
                    }
                }
            }
            StorageMode::HeapBytes => {
                if !self.heap_ptr.is_null() {
                    // Reconstruct and drop the Box<[u8]>
                    unsafe {
                        let slice = core::slice::from_raw_parts_mut(self.heap_ptr, self.size);
                        let _ = Box::from_raw(slice);
                        // Box drops here, deallocating with correct layout
                    }
                }
            }
            StorageMode::BorrowedBytes => {
                // Borrowed — caller owns the memory, nothing to free.
            }
        }
    }
}

impl RequestData {
    /// Print metadata without the actual data payload
    pub fn print_meta(&self) -> alloc::string::String {
        alloc::format!(
            "RequestData {{ tag: {:?}, size: {}, mode: {:?} }}",
            self.tag,
            self.size,
            self.mode
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(C)]
pub enum RequestType {
    Read {
        offset: u64,
        len: usize,
    },
    Write {
        offset: u64,
        len: usize,
        flush_write_through: bool,
    },
    Flush,
    FlushDirty,
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
#[non_exhaustive]
pub struct Request {
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
    /// Ensure all payloads are owned (no borrowed pointers). Copies borrowed buffers.
    pub fn safe(&mut self) {
        fn ensure_owned(data: &mut RequestData) {
            if matches!(data.mode, StorageMode::BorrowedBytes) {
                // take_bytes() will copy for borrowed storage, yielding owned Box<[u8]>.
                let owned = data.take_bytes();
                *data = RequestData::from_boxed_bytes(owned);
            }
        }

        ensure_owned(&mut self.data);

        if let Some(pnp) = self.pnp.as_mut() {
            ensure_owned(&mut pnp.data_out);
        }
    }

    /// Create a non-PnP request. Panics if called with `RequestType::Pnp`.
    pub(crate) fn new(kind: RequestType, data: RequestData) -> Self {
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

    /// Create a PnP request.
    #[inline]
    pub(crate) fn new_pnp(pnp_request: PnpRequest, data: RequestData) -> Self {
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

    /// Create a request with typed payload.
    #[inline]
    pub(crate) fn new_t<T: 'static>(kind: RequestType, data: T) -> Self {
        Self::new(kind, RequestData::from_t(data))
    }

    /// Create a PnP request with typed payload.
    #[inline]
    pub(crate) fn new_pnp_t<T: 'static>(pnp: PnpRequest, data: T) -> Self {
        Self::new_pnp(pnp, RequestData::from_t(data))
    }

    /// Create a request from boxed bytes.
    #[inline]
    pub(crate) fn new_bytes(kind: RequestType, data: Box<[u8]>) -> Self {
        Self::new(kind, RequestData::from_boxed_bytes(data))
    }

    /// Create a PnP request from boxed bytes.
    #[inline]
    pub(crate) fn new_pnp_bytes(pnp: PnpRequest, data: Box<[u8]>) -> Self {
        Self::new_pnp(pnp, RequestData::from_boxed_bytes(data))
    }

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

    /// Print all fields except the actual data payloads
    pub fn print_meta(&self) -> alloc::string::String {
        let pnp_str = match &self.pnp {
            Some(p) => p.print_meta(),
            None => alloc::string::String::from("None"),
        };
        alloc::format!(
            "Request {{ kind: {:?}, data: {}, completed: {}, status: {:?}, traversal_policy: {:?}, pnp: {}, completion_routine: {:?}, completion_context: {:#x}, waker: {} }}",
            self.kind,
            self.data.print_meta(),
            self.completed,
            self.status,
            self.traversal_policy,
            pnp_str,
            self.completion_routine.map(|_| "Some(fn)"),
            self.completion_context,
            if self.waker.is_some() { "Some" } else { "None" }
        )
    }

    #[inline]
    pub(crate) fn empty() -> Self {
        Self {
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
        let (_status, waker) = {
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
#[repr(C)]
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
#[repr(C)]
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

// ============================================================================
// RequestHandle - Stack or Shared ownership abstraction
// ============================================================================

/// Wrapper for shared request ownership. Guarantees 'static lifetime.
#[repr(transparent)]
#[derive(Debug)]
pub struct SharedRequest(pub Arc<RwLock<Request>>);

impl SharedRequest {
    #[inline]
    pub fn new(req: Request) -> Self {
        Self(Arc::new(RwLock::new(req)))
    }

    #[inline]
    pub fn arc(&self) -> &Arc<RwLock<Request>> {
        &self.0
    }

    #[inline]
    pub fn read(&self) -> spin::RwLockReadGuard<'_, Request> {
        self.0.read()
    }

    #[inline]
    pub fn write(&self) -> spin::RwLockWriteGuard<'_, Request> {
        self.0.write()
    }
}

impl Clone for SharedRequest {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/// Handle to a request - stack-allocated, owned, or heap-allocated (shared).
#[repr(C)]
#[derive(Debug)]
pub enum RequestHandle<'a> {
    /// Mutable borrow of a stack-allocated request.
    Stack(&'a mut Request),
    /// Owned request - the RequestHandle owns the Request directly.
    Owned(Request),
    /// Shared ownership - already heap-allocated.
    Shared(SharedRequest),
}

/// Read guard for RequestHandle - either a direct reference or an RwLock guard.
#[repr(C)]
pub enum HandleReadGuard<'a> {
    Stack(&'a Request),
    Shared(spin::RwLockReadGuard<'a, Request>),
}

impl<'a> Deref for HandleReadGuard<'a> {
    type Target = Request;

    #[inline]
    fn deref(&self) -> &Request {
        match self {
            HandleReadGuard::Stack(r) => r,
            HandleReadGuard::Shared(g) => g,
        }
    }
}

/// Write guard for RequestHandle - either a direct reference or an RwLock guard.
#[repr(C)]
pub enum HandleWriteGuard<'a> {
    Stack(&'a mut Request),
    Shared(spin::RwLockWriteGuard<'a, Request>),
}

impl<'a> Deref for HandleWriteGuard<'a> {
    type Target = Request;

    #[inline]
    fn deref(&self) -> &Request {
        match self {
            HandleWriteGuard::Stack(r) => r,
            HandleWriteGuard::Shared(g) => g,
        }
    }
}

impl<'a> DerefMut for HandleWriteGuard<'a> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Request {
        match self {
            HandleWriteGuard::Stack(r) => r,
            HandleWriteGuard::Shared(g) => &mut *g,
        }
    }
}

impl<'a> RequestHandle<'a> {
    /// Create a non-PnP request owned by the RequestHandle. Panics if called with `RequestType::Pnp`.
    #[inline]
    pub fn new(kind: RequestType, data: RequestData) -> Self {
        RequestHandle::Owned(Request::new(kind, data))
    }

    /// Create a PnP request owned by the RequestHandle.
    #[inline]
    pub fn new_pnp(pnp_request: PnpRequest, data: RequestData) -> Self {
        RequestHandle::Owned(Request::new_pnp(pnp_request, data))
    }

    /// Create a request with typed payload owned by the RequestHandle.
    #[inline]
    pub fn new_t<T: 'static>(kind: RequestType, data: T) -> Self {
        RequestHandle::Owned(Request::new_t(kind, data))
    }

    /// Create a PnP request with typed payload owned by the RequestHandle.
    #[inline]
    pub fn new_pnp_t<T: 'static>(pnp: PnpRequest, data: T) -> Self {
        RequestHandle::Owned(Request::new_pnp_t(pnp, data))
    }

    /// Create a request from boxed bytes owned by the RequestHandle.
    #[inline]
    pub fn new_bytes(kind: RequestType, data: Box<[u8]>) -> Self {
        RequestHandle::Owned(Request::new_bytes(kind, data))
    }

    /// Create a PnP request from boxed bytes owned by the RequestHandle.
    #[inline]
    pub fn new_pnp_bytes(pnp: PnpRequest, data: Box<[u8]>) -> Self {
        RequestHandle::Owned(Request::new_pnp_bytes(pnp, data))
    }
    #[inline]
    pub fn is_stack(&self) -> bool {
        matches!(self, Self::Stack(_))
    }

    #[inline]
    pub fn is_owned(&self) -> bool {
        matches!(self, Self::Owned(_))
    }

    #[inline]
    pub fn is_shared(&self) -> bool {
        matches!(self, Self::Shared(_))
    }
    #[inline]
    pub fn status(&self) -> DriverStatus {
        self.read().status
    }

    /// Acquire read access. Returns a guard that derefs to &Request.
    #[inline]
    pub fn read(&self) -> HandleReadGuard<'_> {
        match self {
            RequestHandle::Stack(r) => HandleReadGuard::Stack(r),
            RequestHandle::Owned(r) => HandleReadGuard::Stack(r),
            RequestHandle::Shared(s) => HandleReadGuard::Shared(s.read()),
        }
    }

    /// Acquire write access. Returns a guard that derefs to &mut Request.
    #[inline]
    pub fn write(&mut self) -> HandleWriteGuard<'_> {
        match self {
            RequestHandle::Stack(r) => HandleWriteGuard::Stack(r),
            RequestHandle::Owned(r) => HandleWriteGuard::Stack(r),
            RequestHandle::Shared(s) => HandleWriteGuard::Shared(s.write()),
        }
    }
    // TODO: this currently does not work as intended the request on the request handle on the stack should not point to nothing
    /// Promote stack/owned request to shared (heap) ownership.
    /// Stack: copies content into a new SharedRequest, leaves empty sentinel in original.
    /// Owned: moves the owned request into a new SharedRequest.
    /// Shared: no-op, already on heap.
    pub fn promote(&mut self) {
        match self {
            RequestHandle::Stack(req_ref) => {
                req_ref.safe(); // The request may now live longer then the caller expects, so ensure all payloads are owned and safe to move to heap.
                let request = core::mem::replace(*req_ref, Request::empty());
                *self = RequestHandle::Shared(SharedRequest::new(request));
            }
            RequestHandle::Owned(req_ref) => {
                // Take ownership of the request and wrap in SharedRequest
                req_ref.safe();
                let old = core::mem::replace(self, RequestHandle::Owned(Request::empty()));
                if let RequestHandle::Owned(request) = old {
                    *self = RequestHandle::Shared(SharedRequest::new(request));
                }
            }
            RequestHandle::Shared(_) => {}
        }
    }

    /// Convert to SharedRequest. Promotes if needed.
    #[inline]
    pub fn into_shared(mut self) -> SharedRequest {
        self.promote();
        match self {
            RequestHandle::Shared(s) => s,
            _ => unreachable!(),
        }
    }

    /// Get SharedRequest if already shared.
    #[inline]
    pub fn as_shared(&self) -> Option<&SharedRequest> {
        match self {
            RequestHandle::Shared(s) => Some(s),
            _ => None,
        }
    }

    #[inline]
    pub fn set_traversal_policy(&mut self, policy: TraversalPolicy) {
        match self {
            RequestHandle::Stack(r) => {
                r.traversal_policy = policy;
            }
            RequestHandle::Shared(s) => {
                s.write().traversal_policy = policy;
            }
            RequestHandle::Owned(request) => {
                request.traversal_policy = policy;
            }
        }
    }
}

impl RequestHandle<'static> {
    #[inline]
    pub fn pending(self) -> RequestHandleResult<'static> {
        RequestHandleResult {
            step: DriverStep::Pending,
            handle: self,
        }
    }
}
impl<'a> RequestHandleResult<'a> {
    pub fn status(&self) -> DriverStatus {
        match self.step {
            DriverStep::Complete { status } => status,
            DriverStep::Continue => todo!(),
            DriverStep::Pending => DriverStatus::PendingStep,
        }
    }
}
/// Handler return type. Carries step + handle back to dispatcher.
#[repr(C)]
pub struct RequestHandleResult<'a> {
    pub step: DriverStep,
    pub handle: RequestHandle<'a>,
}

/// Future for awaiting completion of a shared request.
#[repr(C)]
pub struct RequestCompletionHandle(SharedRequest);

impl RequestCompletionHandle {
    pub fn new(shared: SharedRequest) -> Self {
        Self(shared)
    }
}

impl Future for RequestCompletionHandle {
    type Output = DriverStatus;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut guard = self.0.write();
        if guard.completed {
            Poll::Ready(guard.status)
        } else {
            guard.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}
