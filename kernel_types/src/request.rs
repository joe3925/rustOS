use crate::CompletionRoutine;
use crate::fs::FsOp;
use crate::pnp::DriverStep;
use crate::pnp::PnpRequest;
use crate::status::DriverStatus;
use alloc::string::String;
use core::{
    alloc::Layout,
    marker::PhantomData,
    mem::{MaybeUninit, align_of, size_of},
    ptr::null_mut,
};

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
    /// Must NOT be dropped or deallocated — the driver retains ownership via BorrowedHandle.
    /// Non-owning shared borrow of driver-owned data. `heap_ptr` is a raw *const T cast to
    /// `*mut u8` for erased storage. Must NOT be dropped or deallocated.
    BorrowedToDevice = 2,
    /// Non-owning mutable borrow of driver-owned data. `heap_ptr` is a raw *mut T cast to
    /// `*mut u8`. Must NOT be dropped or deallocated.
    BorrowedFromDevice = 3,
}

impl StorageMode {
    #[inline]
    fn is_borrowed(self) -> bool {
        matches!(self, Self::BorrowedToDevice | Self::BorrowedFromDevice)
    }
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

/// Marker for request data flowing toward a lower device.
#[derive(Debug, Clone, Copy)]
pub struct ToDevice;

/// Marker for request data flowing back from a lower device, or owned by the request and thus
/// still mutable/replaceable.
#[derive(Debug, Clone, Copy)]
pub struct FromDevice;

/// Shared directional request-data view.
#[derive(Debug)]
pub struct RequestDataRef<'a, Direction> {
    data: &'a RequestData,
    _direction: PhantomData<Direction>,
}

impl<'a, Direction> RequestDataRef<'a, Direction> {
    #[inline]
    pub fn view<T>(&self) -> Option<&'a T> {
        self.data.view::<T>()
    }
}

/// Mutable directional request-data view.
#[derive(Debug)]
pub struct RequestDataRefMut<'a, Direction> {
    data: &'a mut RequestData,
    _direction: PhantomData<Direction>,
}

impl<'a, Direction> RequestDataRefMut<'a, Direction> {
    #[inline]
    pub fn view<T>(&self) -> Option<&T> {
        self.data.view::<T>()
    }

    #[inline]
    pub fn to_device(self) -> RequestDataRef<'a, ToDevice> {
        RequestDataRef {
            data: &*self.data,
            _direction: PhantomData,
        }
    }
}

impl<'a> RequestDataRefMut<'a, FromDevice> {
    #[inline]
    pub fn view_mut<T>(&mut self) -> Option<&mut T> {
        unsafe { self.data.view_mut::<T>() }
    }
}

/// Runtime view over the currently installed request payload.
#[derive(Debug)]
pub enum RequestDataView<'a> {
    ToDevice(RequestDataRef<'a, ToDevice>),
    FromDevice(RequestDataRefMut<'a, FromDevice>),
}

impl<'a> RequestDataView<'a> {
    /// Obtain a shared `ToDevice` view regardless of the backing mode so callers that only need
    /// read access do not need to match on direction first.
    #[inline]
    pub fn to_device(self) -> RequestDataRef<'a, ToDevice> {
        match self {
            Self::ToDevice(view) => view,
            Self::FromDevice(view) => view.to_device(),
        }
    }
}
impl PnpRequest {
    #[inline]
    pub fn data_out_ref(&self) -> RequestDataRef<'_, ToDevice> {
        RequestDataRef {
            data: &self.data_out,
            _direction: PhantomData,
        }
    }
}

pub const fn strip_lifetimes_and_borrows(input: &[u8], out: &mut [u8; 512]) -> usize {
    let mut i = 0;
    let mut o = 0;
    let mut depth: usize = 0;

    // Skip leading '&'
    if i < input.len() && input[i] == b'&' {
        i += 1;
    }

    while i < input.len() && o < 512 {
        let b = input[i];
        if b == b'<' {
            depth += 1;
            out[o] = b;
            o += 1;
            i += 1;
        } else if b == b'>' {
            if depth > 0 {
                depth -= 1;
            }
            out[o] = b;
            o += 1;
            i += 1;
        } else if b == b'\'' {
            if depth > 0 {
                while o > 0 && out[o - 1] == b' ' {
                    o -= 1;
                }
                if o > 0 && out[o - 1] == b',' {
                    o -= 1;
                }
                i += 1;
                while i < input.len() && input[i] != b',' && input[i] != b'>' {
                    i += 1;
                }
                if i < input.len() && input[i] == b',' {
                    i += 1;
                    while i < input.len() && input[i] == b' ' {
                        i += 1;
                    }
                }
            } else {
                i += 1;
                while i < input.len() && input[i] != b' ' && input[i] != b',' && input[i] != b'>' {
                    i += 1;
                }
                if i < input.len() && input[i] == b' ' {
                    i += 1;
                }
            }
        } else {
            out[o] = b;
            o += 1;
            i += 1;
        }
    }
    o
}
pub fn type_name_stripped<T>() -> String {
    let mut buf = [0u8; 512];
    let len = strip_lifetimes_and_borrows(core::any::type_name::<T>().as_bytes(), &mut buf);
    String::from_utf8_lossy(&buf[..len]).into_owned()
}
// SAFETY: RequestData owns its heap allocation exclusively (HeapTyped) or holds a non-owning
// pointer to driver-owned data in one of the borrowed modes. Borrowed payloads are installed
// through BorrowedHandle, which enforces both the lifetime and T: Send + Sync bounds.
unsafe impl Send for RequestData {}
unsafe impl Sync for RequestData {}
/// Compute a type tag for `T`, stripping lifetime parameters from generic argument lists
/// so that e.g. `FsAppendParams<'_>` and `FsAppendParams<'data>` produce the same hash,
/// while non-lifetime generics (e.g. `Vec<u8>` vs `Vec<u16>`) remain distinct.
#[inline]
pub const fn type_tag<T>() -> u64 {
    /// Copy `input` into `out`, removing lifetime tokens (`'ident`) that appear inside
    /// angle-bracket generic argument lists, along with their adjacent `, ` separators.
    /// Returns the number of bytes written.

    const fn fnv1a(bytes: &[u8], len: usize) -> u64 {
        let mut hash: u64 = 0x817776954A86F58E;
        let mut i = 0;
        while i < len {
            hash ^= bytes[i] as u64;
            hash = hash.wrapping_mul(0x100000001b3);
            i += 1;
        }
        hash
    }

    let mut buf = [0u8; 512];
    let len = strip_lifetimes_and_borrows(core::any::type_name::<T>().as_bytes(), &mut buf);
    fnv1a(&buf, len)
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

    /// Install a non-owning borrow of driver-owned data. Only called by BorrowedHandle.
    /// The driver retains ownership; this RequestData must not drop or deallocate the pointer.
    fn from_borrowed_raw(ptr: *mut u8, tag: u64, size: usize, mode: StorageMode) -> Self {
        Self {
            inline: InlineBuffer::new(),
            heap_ptr: ptr,
            heap_layout: Layout::new::<()>(),
            tag: Some(tag),
            dropper: noop_dropper,
            size,
            mode,
        }
    }

    pub fn from_t<T: 'static + Send + Sync>(value: T) -> Self {
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

    fn matches<T>(&self) -> bool {
        self.tag == Some(type_tag::<T>()) && self.size == size_of::<T>()
    }
    pub fn get_type_tag(&self) -> Option<u64> {
        self.tag
    }
    pub(crate) fn view<T>(&self) -> Option<&T> {
        if !self.matches::<T>() {
            return None;
        }

        let ptr = match self.mode {
            StorageMode::Inline => self.inline.as_ptr(),
            StorageMode::HeapTyped
            | StorageMode::BorrowedToDevice
            | StorageMode::BorrowedFromDevice => self.heap_ptr as *const u8,
        };

        if ptr.is_null() {
            return None;
        }

        Some(unsafe { &*(ptr as *const T) })
    }

    pub(crate) unsafe fn view_mut<T>(&mut self) -> Option<&mut T> {
        if !self.matches::<T>() {
            return None;
        }

        let ptr = match self.mode {
            StorageMode::Inline => self.inline.as_mut_ptr(),
            StorageMode::HeapTyped | StorageMode::BorrowedFromDevice => self.heap_ptr,
            StorageMode::BorrowedToDevice => return None,
        };

        if ptr.is_null() {
            return None;
        }

        Some(unsafe { &mut *(ptr as *mut T) })
    }

    pub fn try_take<T>(&mut self) -> Option<T> {
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
            StorageMode::BorrowedToDevice | StorageMode::BorrowedFromDevice => {
                // Cannot move out of a borrow — driver retains ownership
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
            StorageMode::BorrowedToDevice | StorageMode::BorrowedFromDevice => {
                // Not owned — driver retains ownership via BorrowedHandle. Do nothing.
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
        /// File-level owner tag. 0 = unowned (included in all targeted flushes).
        owner: u64,
    },
    Flush {
        /// This flag indicates whether a flush job should be spawned, or if we should wait till all data is flushed.
        /// This flag can have unforeseen consequences if set to true, if something is activley writing data it is likely you won't return until they stop.
        should_block: bool,
    },
    FlushDirty {
        /// This flag indicates whether a flush job should be spawned, or if we should wait till all data is flushed.
        /// This flag can have unforeseen consequences if set to true, if something is activley writing data it is likely you won't return until they stop.
        should_block: bool,
    },
    /// Flush only dirty cache pages belonging to the given owner (and unowned pages).
    FlushOwner {
        owner: u64,
        should_block: bool,
    },
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
    pub(crate) data: RequestData,
    pub completed: bool,
    pub status: DriverStatus,
    pub traversal_policy: TraversalPolicy,
    pub pnp: Option<PnpRequest>,
    pub completion_routine: Option<CompletionRoutine>,
    pub completion_context: usize,
}

impl Request {
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
        }
    }

    /// Create a request with typed payload.
    #[inline]
    pub(crate) fn new_t<T: 'static + Send + Sync>(kind: RequestType, data: T) -> Self {
        Self::new(kind, RequestData::from_t(data))
    }

    /// Create a PnP request with typed payload.
    #[inline]
    pub(crate) fn new_pnp_t<T: 'static + Send + Sync>(pnp: PnpRequest, data: T) -> Self {
        Self::new_pnp(pnp, RequestData::from_t(data))
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
    pub fn set_data_t<T: 'static + Send + Sync>(&mut self, data: T) {
        self.data = RequestData::from_t(data);
    }

    #[inline]
    pub fn data(&mut self) -> RequestDataView<'_> {
        match self.data.mode {
            StorageMode::BorrowedToDevice => RequestDataView::ToDevice(RequestDataRef {
                data: &self.data,
                _direction: PhantomData,
            }),
            StorageMode::BorrowedFromDevice | StorageMode::Inline | StorageMode::HeapTyped => {
                RequestDataView::FromDevice(RequestDataRefMut {
                    data: &mut self.data,
                    _direction: PhantomData,
                })
            }
        }
    }

    /// Print all fields except the actual data payloads
    pub fn print_meta(&self) -> alloc::string::String {
        let pnp_str = match &self.pnp {
            Some(p) => p.print_meta(),
            None => alloc::string::String::from("None"),
        };
        alloc::format!(
            "Request {{ kind: {:?}, data: {}, completed: {}, status: {:?}, traversal_policy: {:?}, pnp: {}, completion_routine: {:?}, completion_context: {:#x} }}",
            self.kind,
            self.data.print_meta(),
            self.completed,
            self.status,
            self.traversal_policy,
            pnp_str,
            self.completion_routine.map(|_| "Some(fn)"),
            self.completion_context,
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
        let should_drop_chain_ctx = {
            if self.completed {
                return;
            }

            let mut drop_chain = false;

            if let Some(fp) = self.completion_routine.take() {
                drop_chain =
                    fp as usize == chained_completion as usize && self.completion_context != 0;
                let f: CompletionRoutine = unsafe { core::mem::transmute(fp) };
                let context = self.completion_context;
                self.status = f(&mut *self, context);
            }

            if self.status == DriverStatus::ContinueStep {
                self.status = DriverStatus::Success;
            }

            self.completed = true;
            drop_chain.then_some(self.completion_context)
        };

        if let Some(ctx) = should_drop_chain_ctx {
            unsafe {
                drop(alloc::sync::Arc::from_raw(
                    ctx as *const alloc::vec::Vec<CompletionEntry>,
                ));
            }
            self.completion_context = 0;
        }
    }
}
impl Drop for Request {
    fn drop(&mut self) {
        self.complete_for_drop();
    }
}
type CompletionEntry = (CompletionRoutine, usize);

fn store_prev_and_new(
    prev: CompletionRoutine,
    prev_ctx: usize,
    next: CompletionRoutine,
    next_ctx: usize,
) -> usize {
    let mut entries: alloc::vec::Vec<CompletionEntry> = alloc::vec::Vec::with_capacity(2);
    entries.push((next, next_ctx)); // newest first
    entries.push((prev, prev_ctx));
    let arc: alloc::sync::Arc<alloc::vec::Vec<CompletionEntry>> = alloc::sync::Arc::new(entries);
    alloc::sync::Arc::into_raw(arc) as usize
}

extern "win64" fn chained_completion(req: &mut Request, ctx: usize) -> DriverStatus {
    if ctx == 0 {
        return DriverStatus::Success;
    }

    // Temporarily borrow the chain without consuming the original Arc so
    // repeated invocations stay safe.
    let arc = unsafe { alloc::sync::Arc::from_raw(ctx as *const alloc::vec::Vec<CompletionEntry>) };
    let keep_alive = arc.clone();
    let _ = alloc::sync::Arc::into_raw(arc);

    let mut status = DriverStatus::Success;
    for (func, c) in keep_alive.iter() {
        status = func(req, *c);
    }

    status
}
// ============================================================================
// RequestHandle - Stack or Owned abstraction
// ============================================================================

/// Handle to a request - stack-borrowed or owned.
#[repr(C)]
#[derive(Debug)]
pub enum RequestHandle<'a> {
    /// Mutable borrow of a stack-allocated request.
    Stack(&'a mut Request),
    /// Owned request - the RequestHandle owns the Request directly.
    Owned(Request),
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
    pub fn new_t<T: 'static + Send + Sync>(kind: RequestType, data: T) -> Self {
        RequestHandle::Owned(Request::new_t(kind, data))
    }

    /// Create a PnP request with typed payload owned by the RequestHandle.
    #[inline]
    pub fn new_pnp_t<T: 'static + Send + Sync>(pnp: PnpRequest, data: T) -> Self {
        RequestHandle::Owned(Request::new_pnp_t(pnp, data))
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
    pub fn status(&self) -> DriverStatus {
        self.read().status
    }

    /// Acquire read access.
    #[inline]
    pub fn read(&self) -> &Request {
        match self {
            RequestHandle::Stack(r) => r,
            RequestHandle::Owned(r) => r,
        }
    }

    /// Acquire write access.
    #[inline]
    pub fn write(&mut self) -> &mut Request {
        match self {
            RequestHandle::Stack(r) => r,
            RequestHandle::Owned(r) => r,
        }
    }

    #[inline]
    pub fn data(&mut self) -> RequestDataView<'_> {
        self.write().data()
    }

    #[inline]
    pub fn set_traversal_policy(&mut self, policy: TraversalPolicy) {
        self.write().traversal_policy = policy;
    }

    /// Returns a raw pointer to the inner Request. Only for use by BorrowedHandle within
    /// this module — not accessible outside request.rs.
    pub(super) fn write_raw(&mut self) -> *mut Request {
        match self {
            RequestHandle::Stack(r) => *r as *mut Request,
            RequestHandle::Owned(r) => r as *mut Request,
        }
    }
}

impl<'a> RequestHandleResult<'a> {
    pub fn status(&self) -> DriverStatus {
        match self.step {
            DriverStep::Complete { status } => status,
            DriverStep::Continue => todo!(),
        }
    }
}

/// Handler return type. Carries step + handle back to dispatcher.
#[repr(C)]
pub struct RequestHandleResult<'a> {
    pub step: DriverStep,
    pub handle: RequestHandle<'a>,
}
// ============================================================================
// BorrowedHandle — zero-copy driver-owned data borrow for forwarded requests
// ============================================================================

/// Installs a lifetime-bounded borrow of driver-owned data into a request for the duration
/// of a forwarded call. The borrow checker enforces:
///
/// - `data` is exclusively borrowed while `BorrowedHandle` is alive (via `PhantomData<&'data mut T>`)
/// - `handle` is exclusively borrowed while `BorrowedHandle` is alive (via `&'req mut RequestHandle`)
/// - `'data: 'req` — data outlives the request's use of it (explicitly bounded on the struct)
///
/// On drop, clears the request's data field back to `RequestData::empty()` only if the lower
/// driver has not replaced it with a response. This prevents silently clobbering response data.
///
/// # Known limitation
/// Like all RAII guards in Rust, `mem::forget(borrow)` prevents Drop from running, leaving the
/// request with a dangling pointer. This is an accepted trade-off structurally, but in a kernel
/// environment, leaking this type will lead to a use-after-free and bug check.
///
/// `'data` — lifetime of the driver-owned data being lent
/// `'req`  — lifetime of our exclusive borrow of the RequestHandle
/// `'h`    — inner lifetime of the RequestHandle (e.g. lifetime of a Stack borrow)
enum BorrowedStorage<'data, T> {
    ToDevice(&'data T),
    FromDevice(&'data mut T),
}

pub struct BorrowedHandle<'data: 'req, 'req, 'h, T: Send + Sync> {
    handle: &'req mut RequestHandle<'h>,
    borrow: BorrowedStorage<'data, T>,
}

impl<'data: 'req, 'req, 'h, T: Send + Sync> BorrowedHandle<'data, 'req, 'h, T> {
    fn install(
        handle: &'req mut RequestHandle<'h>,
        ptr: *mut u8,
        mode: StorageMode,
        borrow: BorrowedStorage<'data, T>,
    ) -> Self {
        unsafe { &mut *handle.write_raw() }.data =
            RequestData::from_borrowed_raw(ptr, type_tag::<T>(), size_of::<T>(), mode);
        Self { handle, borrow }
    }

    pub fn to_device(handle: &'req mut RequestHandle<'h>, data: &'data T) -> Self {
        Self::install(
            handle,
            data as *const T as *mut u8,
            StorageMode::BorrowedToDevice,
            BorrowedStorage::ToDevice(data),
        )
    }

    pub fn from_device(handle: &'req mut RequestHandle<'h>, data: &'data mut T) -> Self {
        Self::install(
            handle,
            data as *mut T as *mut u8,
            StorageMode::BorrowedFromDevice,
            BorrowedStorage::FromDevice(data),
        )
    }

    /// Returns the inner handle for passing to lower drivers.
    pub fn handle(&mut self) -> &mut RequestHandle<'h> {
        self.handle
    }
}

impl<'data: 'req, 'req, 'h, T: Send + Sync> Drop for BorrowedHandle<'data, 'req, 'h, T> {
    fn drop(&mut self) {
        match &mut self.borrow {
            BorrowedStorage::ToDevice(data) => {
                let _ = *data as *const T;
            }
            BorrowedStorage::FromDevice(data) => {
                let _ = *data as *mut T;
            }
        }
        // SAFETY: handle is still valid — 'req is live while Self exists.
        let req = unsafe { &mut *self.handle.write_raw() };
        // Only clear if the request still holds one of the borrowed modes. If the lower driver set
        // a response,
        // leave it intact so the upper driver can read it after the await.
        if req.data.mode.is_borrowed() {
            req.data = RequestData::empty();
        }
    }
}

/// Thin wrapper around a raw `*mut u8` + length so a borrowed byte slice can be
/// stored in [`RequestData`] without carrying lifetime parameters.
///
/// Lower drivers resolve this with `view::<BufSlice>()` / `view_mut::<BufSlice>()`
/// and then call `.as_slice()` / `.as_mut_slice()` to access the underlying bytes.
///
/// # Safety
/// The caller must guarantee the pointer remains valid for the duration of the
/// request (enforced externally by [`BorrowedHandle`] lifetimes).
pub struct BufSlice {
    ptr: *const u8,
    len: usize,
}

// SAFETY: BufSlice is only constructed from references whose lifetimes are
// enforced by BorrowedHandle. The pointer is valid and exclusive for the
// duration of the borrow.
unsafe impl Send for BufSlice {}
unsafe impl Sync for BufSlice {}

impl BufSlice {
    /// Wrap a mutable byte slice into a `BufSlice`.
    #[inline]
    pub fn new(slice: &mut [u8]) -> Self {
        Self {
            ptr: slice.as_ptr(),
            len: slice.len(),
        }
    }

    /// Wrap an immutable byte slice into a `BufSlice`.
    #[inline]
    pub fn new_const(slice: &[u8]) -> Self {
        Self {
            ptr: slice.as_ptr(),
            len: slice.len(),
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// View the buffer as an immutable byte slice.
    ///
    /// # Safety
    /// Caller must ensure the pointer is still valid (guaranteed when accessed
    /// through a live `BorrowedHandle`).
    #[inline]
    pub unsafe fn as_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.ptr, self.len) }
    }

    /// View the buffer as a mutable byte slice.
    ///
    /// # Safety
    /// Caller must ensure the pointer is still valid and no other references
    /// exist (guaranteed when accessed through a live `BorrowedHandle`).
    #[inline]
    pub unsafe fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.ptr as *mut u8, self.len) }
    }
}
