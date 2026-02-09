use crate::CompletionRoutine;
use crate::fs::FsOp;
use crate::pnp::PnpRequest;
use crate::status::DriverStatus;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::{
    mem::{size_of, align_of, MaybeUninit},
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
    /// Data is heap-allocated in `heap`
    Heap = 1,
    /// Data is borrowed from an external source (uses heap field but not owned)
    Borrowed = 2,
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

/// Dropper function signature - takes pointer, size, and storage mode
type DropperFn = fn(*mut u8, usize, StorageMode);

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
    /// Inline buffer for small data (always present, may be unused)
    inline: InlineBuffer,
    /// Heap storage for large data (None when using inline)
    heap: Option<Box<[u8]>>,
    /// Type tag for runtime type checking
    tag: Option<u64>,
    /// Custom drop function that handles both inline and heap cases
    dropper: DropperFn,
    /// Size of contained data
    size: usize,
    /// Storage mode indicator
    mode: StorageMode,
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

/// No-op dropper for raw bytes or empty data
fn noop_dropper(_: *mut u8, _: usize, _: StorageMode) {}

impl RequestData {
    pub fn empty() -> Self {
        Self {
            inline: InlineBuffer::new(),
            heap: None,
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
                heap: None,
                tag: None,
                dropper: noop_dropper,
                size,
                mode: StorageMode::Inline,
            };

            unsafe {
                core::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    result.inline.as_mut_ptr(),
                    size,
                );
            }
            // Original box is dropped here

            result
        } else {
            // Keep as heap allocation
            Self {
                inline: InlineBuffer::new(),
                heap: Some(bytes),
                tag: None,
                dropper: noop_dropper,
                size,
                mode: StorageMode::Heap,
            }
        }
    }

    /// Create a RequestData that borrows from a mutable slice.
    ///
    /// # Safety
    /// The caller must ensure:
    /// - The slice outlives the RequestData
    /// - The RequestData is not dropped normally (use `take_bytes_borrowed` to reclaim)
    /// - No other code tries to deallocate the underlying buffer
    #[inline]
    pub unsafe fn from_borrowed_mut(slice: &mut [u8]) -> Self {
        let len = slice.len();
        let ptr = slice.as_mut_ptr();
        // Create a fake Box that points to the borrowed slice
        let fake_box = unsafe { Box::from_raw(core::slice::from_raw_parts_mut(ptr, len)) };
        Self {
            inline: InlineBuffer::new(),
            heap: Some(fake_box),
            tag: None,
            dropper: noop_dropper,
            size: len,
            mode: StorageMode::Borrowed,
        }
    }

    /// Create a RequestData that borrows from a const slice.
    ///
    /// # Safety
    /// The caller must ensure:
    /// - The slice outlives the RequestData
    /// - The RequestData is not dropped normally (use `take_bytes_borrowed` to reclaim)
    /// - No other code tries to deallocate the underlying buffer
    /// - The data is not mutated through this RequestData
    #[inline]
    pub unsafe fn from_borrowed_const(slice: &[u8]) -> Self {
        let len = slice.len();
        let ptr = slice.as_ptr() as *mut u8;
        // Create a fake Box that points to the borrowed slice
        let fake_box = unsafe { Box::from_raw(core::slice::from_raw_parts_mut(ptr, len)) };
        Self {
            inline: InlineBuffer::new(),
            heap: Some(fake_box),
            tag: None,
            dropper: noop_dropper,
            size: len,
            mode: StorageMode::Borrowed,
        }
    }

    /// Reclaim borrowed bytes without running the dropper.
    /// Use this to "return" the borrowed slice before the RequestData is dropped.
    #[inline]
    pub fn take_bytes_borrowed(&mut self) -> (*mut u8, usize) {
        debug_assert_eq!(self.mode, StorageMode::Borrowed, "take_bytes_borrowed called on non-borrowed data");

        let ptr = match &mut self.heap {
            Some(b) => b.as_mut_ptr(),
            None => null_mut(),
        };
        let len = self.size;

        // Forget the fake box to prevent deallocation
        if let Some(old) = self.heap.take() {
            core::mem::forget(old);
        }

        // Reset to empty state
        self.size = 0;
        self.mode = StorageMode::Inline;
        self.dropper = noop_dropper;

        (ptr, len)
    }

    pub fn from_t<T: 'static>(value: T) -> Self {
        let size = size_of::<T>();
        let align = align_of::<T>();

        /// Typed dropper that properly handles Drop for T
        fn typed_dropper<T>(ptr: *mut u8, _size: usize, mode: StorageMode) {
            match mode {
                StorageMode::Inline => {
                    // Drop in place - memory is owned by inline buffer
                    unsafe { core::ptr::drop_in_place(ptr as *mut T) };
                }
                StorageMode::Heap => {
                    // Reconstruct and drop the Box<T>
                    unsafe {
                        let boxed = Box::from_raw(ptr as *mut T);
                        drop(boxed);
                    }
                }
                StorageMode::Borrowed => {
                    // No-op: borrowed data is not owned
                }
            }
        }

        if size <= INLINE_THRESHOLD && align <= INLINE_ALIGN {
            // INLINE PATH: Copy value into inline buffer
            let mut result = Self {
                inline: InlineBuffer::new(),
                heap: None,
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
            // HEAP PATH: Box the value and convert to byte slice
            let boxed = Box::new(value);
            let bytes = box_to_bytes(boxed);

            Self {
                inline: InlineBuffer::new(),
                heap: Some(bytes),
                tag: Some(type_tag::<T>()),
                dropper: typed_dropper::<T>,
                size,
                mode: StorageMode::Heap,
            }
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.size
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        match self.mode {
            StorageMode::Inline => {
                unsafe { core::slice::from_raw_parts(self.inline.as_ptr(), self.size) }
            }
            StorageMode::Heap | StorageMode::Borrowed => {
                match &self.heap {
                    Some(b) => &b[..self.size],
                    None => &[],
                }
            }
        }
    }

    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        match self.mode {
            StorageMode::Inline => {
                unsafe { core::slice::from_raw_parts_mut(self.inline.as_mut_ptr(), self.size) }
            }
            StorageMode::Heap | StorageMode::Borrowed => {
                match &mut self.heap {
                    Some(b) => &mut b[..self.size],
                    None => &mut [],
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
            StorageMode::Heap | StorageMode::Borrowed => {
                match &self.heap {
                    Some(b) => b.as_ptr(),
                    None => return None,
                }
            }
        };

        Some(unsafe { &*(ptr as *const T) })
    }

    pub fn view_mut<T: 'static>(&mut self) -> Option<&mut T> {
        if !self.matches::<T>() {
            return None;
        }

        let ptr = match self.mode {
            StorageMode::Inline => self.inline.as_mut_ptr(),
            StorageMode::Heap | StorageMode::Borrowed => {
                match &mut self.heap {
                    Some(b) => b.as_mut_ptr(),
                    None => return None,
                }
            }
        };

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
            StorageMode::Heap => {
                // Take the heap box and convert back to T
                let bytes = self.heap.take()?;
                let boxed_t = unsafe { bytes_to_box::<T>(bytes) };
                *boxed_t
            }
            StorageMode::Borrowed => {
                // Cannot take ownership of borrowed data
                return None;
            }
        };

        // Reset to empty state (don't run dropper - we took ownership)
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
                vec.into_boxed_slice()
            }
            StorageMode::Heap => {
                // Take the existing box directly
                self.heap.take().unwrap_or_else(|| Box::new([]))
            }
            StorageMode::Borrowed => {
                // Copy borrowed data to owned box
                let slice = match &self.heap {
                    Some(b) => &b[..self.size],
                    None => &[],
                };
                let mut vec = Vec::with_capacity(slice.len());
                vec.extend_from_slice(slice);

                // Forget the fake box
                if let Some(old) = self.heap.take() {
                    core::mem::forget(old);
                }

                vec.into_boxed_slice()
            }
        };

        // Reset to empty state
        self.tag = None;
        self.size = 0;
        self.mode = StorageMode::Inline;
        self.dropper = noop_dropper;

        result
    }
}

impl Drop for RequestData {
    fn drop(&mut self) {
        // Get the data pointer based on storage mode
        let ptr = match self.mode {
            StorageMode::Inline => self.inline.as_mut_ptr(),
            StorageMode::Heap | StorageMode::Borrowed => {
                match &mut self.heap {
                    Some(b) => b.as_mut_ptr(),
                    None => return,
                }
            }
        };

        // Call the typed dropper to run T's destructor
        (self.dropper)(ptr, self.size, self.mode);

        // Handle memory deallocation based on mode
        match self.mode {
            StorageMode::Heap => {
                // Let the Option<Box> drop naturally (already handled by struct drop)
            }
            StorageMode::Borrowed => {
                // Forget the fake box to prevent deallocation of borrowed memory
                if let Some(fake) = self.heap.take() {
                    core::mem::forget(fake);
                }
            }
            StorageMode::Inline => {
                // Nothing to deallocate - inline buffer is part of the struct
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(C)]
pub enum RequestType {
    Read { offset: u64, len: usize },
    Write {
        offset: u64,
        len: usize,
        flush_write_through: bool,
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
