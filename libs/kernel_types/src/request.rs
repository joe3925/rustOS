use crate::CompletionRoutine;
use crate::async_ffi::FfiFuture;
use crate::device::DeviceObject;
use crate::dma::{FromDevice, IoBuffer, ToDevice};
use crate::fs::{
    FsAppendParams, FsAppendResult, FsCloseParams, FsCloseResult, FsCreateParams, FsCreateResult,
    FsFlushParams, FsFlushResult, FsGetInfoParams, FsGetInfoResult, FsListDirParams,
    FsListDirResult, FsOpenParams, FsOpenResult, FsReadParams, FsReadResult, FsRenameParams,
    FsRenameResult, FsSeekParams, FsSeekResult, FsSetLenParams, FsSetLenResult, FsWriteParams,
    FsWriteResult, FsZeroRangeParams, FsZeroRangeResult,
};
use crate::io::{FsOps, IoHandler};
use crate::pnp::DriverStep;
use crate::pnp::PnpRequest;
use crate::status::DriverStatus;
use crate::{
    EvtFsAppend, EvtFsClose, EvtFsCreate, EvtFsFlush, EvtFsGetInfo, EvtFsOpen, EvtFsRead,
    EvtFsReadDir, EvtFsRename, EvtFsSeek, EvtFsSetLen, EvtFsWrite, EvtFsZeroRange,
};
use core::ptr::null;
use core::sync::atomic::{AtomicPtr, Ordering};

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::{
    alloc::Layout,
    marker::PhantomData,
    mem::{MaybeUninit, align_of, size_of},
    ptr::null_mut,
};

/// Maximum size for inline storage (bytes)
const INLINE_THRESHOLD: usize = 512;

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
    /// Non-owning shared borrow of driver-owned data. `data_ptr` points at the erased payload
    /// data while `metadata` carries any DST metadata needed to rebuild it.
    BorrowedReadOnly = 2,
    /// Non-owning mutable borrow of driver-owned data. `data_ptr` points at the erased payload
    /// data while `metadata` carries any DST metadata needed to rebuild it.
    BorrowedWritable = 3,
}

impl StorageMode {
    #[inline]
    fn is_borrowed(self) -> bool {
        matches!(self, Self::BorrowedReadOnly | Self::BorrowedWritable)
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
type DropperFn = extern "C" fn(*mut u8);
type RequestPayloadViewFn =
    unsafe extern "C" fn(u64, RequestPayloadRawParts) -> Option<RequestPayloadRawParts>;
type RequestPayloadCanIntoFn = unsafe extern "C" fn(u64, RequestPayloadRawParts) -> bool;
type RequestPayloadIntoFn<'data> =
    unsafe extern "C" fn(u64, RequestPayloadRawParts, *mut RequestData<'data>) -> bool;
#[diagnostic::on_unimplemented(
    message = "`{Self}` cannot be used as RequestPayload without an outer layout guarantee",
    label = "missing outer layout guarantee for `{Self}`",
    note = "add #[repr(C)] or #[repr(transparent)] to the type, or write `unsafe impl FfiSafe for {Self}` if you are asserting it manually"
)]

/// Unsafe escape hatch for `RequestPayload` on types whose outer layout is not
/// expressed with a non-Rust `repr(...)`.
///
/// `#[repr(C)]`, `#[repr(transparent)]`, and supported enum primitive reprs are
/// accepted by `RequestPayload` derive without this trait.
///
/// Implementing `FfiSafe` asserts that the type's outer layout is still safe to
/// round-trip through the request payload FFI boundary even though the layout is
/// not being enforced structurally by `repr(...)`.
///
/// This trait only covers the outer layout contract of `Self`. It does not
/// guarantee anything about the internal layout or semantics of field types;
/// those remain the API author's responsibility.
///
/// # Safety
///
/// Implement this trait only if the exact type may be cast to and from its raw
/// payload representation across the request FFI boundary without causing
/// layout-related undefined behavior.
pub unsafe trait FfiSafe {}

/// Erased raw payload parts stored inside [`RequestData`].
#[doc(hidden)]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RequestPayloadRawParts {
    pub data: *mut u8,
    pub metadata: usize,
    pub bytes: usize,
}

pub unsafe trait RequestPayload<'data>: Send + 'data {
    /// Stable runtime tag for matching this payload type. Either impl or use type_tag::<T>()
    const RUNTIME_TAG: u64;

    #[inline]
    extern "C" fn runtime_tag() -> u64 {
        Self::RUNTIME_TAG
    }

    /// Static byte size for nominal sized payloads.
    #[inline]
    extern "C" fn static_size() -> Option<usize> {
        None
    }

    /// Erase a shared borrow into raw transport parts.
    extern "C" fn shared_raw_parts(payload: &Self) -> RequestPayloadRawParts;

    /// Erase a mutable borrow into raw transport parts.
    extern "C" fn mut_raw_parts(payload: &mut Self) -> RequestPayloadRawParts;

    /// Rebuild a shared view from erased raw transport parts.
    unsafe extern "C" fn shared_from_raw_parts<'a>(parts: RequestPayloadRawParts) -> &'a Self;

    /// Rebuild a mutable view from erased raw transport parts.
    unsafe extern "C" fn mut_from_raw_parts<'a>(parts: RequestPayloadRawParts) -> &'a mut Self;

    /// Try to project this concrete payload into a shared target payload view.
    ///
    /// The default implementation exposes no coercions. Derives may override
    /// this through `#[request_view(Source => Target)]` helper attributes.
    #[inline]
    unsafe extern "C" fn shared_view_raw_parts(
        _target_tag: u64,
        _parts: RequestPayloadRawParts,
    ) -> Option<RequestPayloadRawParts> {
        None
    }

    /// Try to project this concrete payload into a mutable target payload view.
    ///
    /// The default implementation exposes no coercions. Derives may override
    /// this through `#[request_view_mut(Source => Target)]` helper attributes.
    #[inline]
    unsafe extern "C" fn mut_view_raw_parts(
        _target_tag: u64,
        _parts: RequestPayloadRawParts,
    ) -> Option<RequestPayloadRawParts> {
        None
    }

    /// Try to consume this concrete owned payload into a target payload.
    ///
    /// The default implementation exposes no conversions. Derives may override
    /// this through `#[request_into(Source => Target)]` helper attributes.
    ///
    /// # Safety
    ///
    /// `out` must be valid for writes. Implementations must only write to `out`
    /// and consume `parts` when returning `true`.
    #[inline]
    unsafe extern "C" fn into_request_data(
        _target_tag: u64,
        _parts: RequestPayloadRawParts,
        _out: *mut RequestData<'data>,
    ) -> bool {
        false
    }

    /// Try to determine whether this concrete owned payload can be consumed into
    /// a target payload without consuming it.
    ///
    /// The default implementation exposes no conversions. Derives may override
    /// this through `#[request_into(Source => Target)]` helper attributes.
    #[inline]
    unsafe extern "C" fn can_into_request_data(
        _target_tag: u64,
        _parts: RequestPayloadRawParts,
    ) -> bool {
        false
    }
}

#[diagnostic::on_unimplemented(
    message = "`{Self}` cannot be used as a shared request view of `{Target}`",
    label = "missing shared request view conversion from `{Self}` to `{Target}`",
    note = "`#[request_view(Source => Target)]` requires Source: RequestPayload, Target: RequestPayload, and Source: AsRef<Target>"
)]
pub trait RequestPayloadView<'data, Target: RequestPayload<'data> + ?Sized>:
    RequestPayload<'data> + AsRef<Target>
{
}

impl<'data, Source, Target> RequestPayloadView<'data, Target> for Source
where
    Source: RequestPayload<'data> + AsRef<Target> + ?Sized,
    Target: RequestPayload<'data> + ?Sized,
{
}

#[diagnostic::on_unimplemented(
    message = "`{Self}` cannot be used as a mutable request view of `{Target}`",
    label = "missing mutable request view conversion from `{Self}` to `{Target}`",
    note = "`#[request_view_mut(Source => Target)]` requires Source: RequestPayload, Target: RequestPayload, and Source: AsMut<Target>"
)]
pub trait RequestPayloadViewMut<'data, Target: RequestPayload<'data> + ?Sized>:
    RequestPayload<'data> + AsMut<Target>
{
}

impl<'data, Source, Target> RequestPayloadViewMut<'data, Target> for Source
where
    Source: RequestPayload<'data> + AsMut<Target> + ?Sized,
    Target: RequestPayload<'data> + ?Sized,
{
}

#[diagnostic::on_unimplemented(
    message = "`{Self}` cannot be consumed as request data into `{Target}`",
    label = "missing owned request-data conversion from `{Self}` to `{Target}`",
    note = "`#[request_into(Source => Target)]` requires Source: RequestPayload + Into<Target> and Target: RequestPayload"
)]
pub trait RequestPayloadInto<'data, Target: RequestPayload<'data>>:
    RequestPayload<'data> + Into<Target>
{
}

impl<'data, Source, Target> RequestPayloadInto<'data, Target> for Source
where
    Source: RequestPayload<'data> + Into<Target>,
    Target: RequestPayload<'data>,
{
}

unsafe extern "C" fn no_payload_view(
    _target_tag: u64,
    _parts: RequestPayloadRawParts,
) -> Option<RequestPayloadRawParts> {
    None
}

unsafe extern "C" fn no_payload_into<'data>(
    _target_tag: u64,
    _parts: RequestPayloadRawParts,
    _out: *mut RequestData<'data>,
) -> bool {
    false
}

unsafe extern "C" fn no_payload_can_into(_target_tag: u64, _parts: RequestPayloadRawParts) -> bool {
    false
}

macro_rules! impl_nominal_request_payload {
    ($ty:path) => {
        unsafe impl<'data> RequestPayload<'data> for $ty {
            const RUNTIME_TAG: u64 = type_tag::<Self>();

            #[inline]
            extern "C" fn static_size() -> Option<usize> {
                Some(size_of::<Self>())
            }

            #[inline]
            extern "C" fn shared_raw_parts(payload: &Self) -> RequestPayloadRawParts {
                RequestPayloadRawParts {
                    data: payload as *const Self as *mut u8,
                    metadata: 0,
                    bytes: size_of::<Self>(),
                }
            }

            #[inline]
            extern "C" fn mut_raw_parts(payload: &mut Self) -> RequestPayloadRawParts {
                RequestPayloadRawParts {
                    data: payload as *mut Self as *mut u8,
                    metadata: 0,
                    bytes: size_of::<Self>(),
                }
            }

            #[inline]
            unsafe extern "C" fn shared_from_raw_parts<'a>(
                parts: RequestPayloadRawParts,
            ) -> &'a Self {
                unsafe { &*(parts.data as *const Self) }
            }

            #[inline]
            unsafe extern "C" fn mut_from_raw_parts<'a>(
                parts: RequestPayloadRawParts,
            ) -> &'a mut Self {
                unsafe { &mut *(parts.data as *mut Self) }
            }
        }
    };
}

unsafe impl<'data> RequestPayload<'data> for [u8] {
    const RUNTIME_TAG: u64 = type_tag::<[u8]>();

    #[inline]
    extern "C" fn shared_raw_parts(payload: &Self) -> RequestPayloadRawParts {
        RequestPayloadRawParts {
            data: payload.as_ptr() as *mut u8,
            metadata: payload.len(),
            bytes: payload.len(),
        }
    }

    #[inline]
    extern "C" fn mut_raw_parts(payload: &mut Self) -> RequestPayloadRawParts {
        RequestPayloadRawParts {
            data: payload.as_mut_ptr(),
            metadata: payload.len(),
            bytes: payload.len(),
        }
    }

    #[inline]
    unsafe extern "C" fn shared_from_raw_parts<'a>(parts: RequestPayloadRawParts) -> &'a Self {
        unsafe { core::slice::from_raw_parts(parts.data as *const u8, parts.metadata) }
    }

    #[inline]
    unsafe extern "C" fn mut_from_raw_parts<'a>(parts: RequestPayloadRawParts) -> &'a mut Self {
        unsafe { core::slice::from_raw_parts_mut(parts.data, parts.metadata) }
    }
}

unsafe impl<'data> RequestPayload<'data> for str {
    const RUNTIME_TAG: u64 = type_tag::<str>();

    #[inline]
    extern "C" fn shared_raw_parts(payload: &Self) -> RequestPayloadRawParts {
        let bytes = payload.as_bytes();
        RequestPayloadRawParts {
            data: bytes.as_ptr() as *mut u8,
            metadata: bytes.len(),
            bytes: bytes.len(),
        }
    }

    #[inline]
    extern "C" fn mut_raw_parts(payload: &mut Self) -> RequestPayloadRawParts {
        RequestPayloadRawParts {
            data: payload.as_ptr() as *mut u8,
            metadata: payload.len(),
            bytes: payload.len(),
        }
    }

    #[inline]
    unsafe extern "C" fn shared_from_raw_parts<'a>(parts: RequestPayloadRawParts) -> &'a Self {
        let bytes = unsafe { core::slice::from_raw_parts(parts.data as *const u8, parts.metadata) };
        unsafe { core::str::from_utf8_unchecked(bytes) }
    }

    #[inline]
    unsafe extern "C" fn mut_from_raw_parts<'a>(parts: RequestPayloadRawParts) -> &'a mut Self {
        let bytes = unsafe { core::slice::from_raw_parts_mut(parts.data, parts.metadata) };
        unsafe { core::str::from_utf8_unchecked_mut(bytes) }
    }
}

impl_nominal_request_payload!(Vec<u8>);

#[repr(C)]
pub struct RequestData<'data> {
    /// Inline buffer for small data (always present, may be unused)
    inline: InlineBuffer,
    /// Erased data pointer used for heap-backed or borrowed payloads
    data_ptr: *mut u8,
    /// Erased pointer metadata used for DST payloads such as `[u8]` and `str`
    metadata: usize,
    /// Layout of the heap allocation (only used for HeapTyped mode)
    heap_layout: Layout,
    /// Type tag for runtime type checking
    tag: Option<u64>,
    /// Source-type hook for shared request view coercions.
    shared_viewer: RequestPayloadViewFn,
    /// Source-type hook for mutable request view coercions.
    mut_viewer: RequestPayloadViewFn,
    /// Source-type hook for checking owned request-data conversions.
    can_into_converter: RequestPayloadCanIntoFn,
    /// Source-type hook for owned request-data conversions.
    into_converter: RequestPayloadIntoFn<'data>,
    /// Custom drop function that runs T's destructor (drop_in_place only, no dealloc)
    dropper: DropperFn,
    /// Size of contained data in bytes
    size: usize,
    /// Storage mode indicator
    mode: StorageMode,
    _marker: PhantomData<&'data ()>,
}

impl<'data> core::fmt::Debug for RequestData<'data> {
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
pub struct ReadOnly;

/// Marker for request data flowing back from a lower device, or owned by the request and thus
/// still mutable/replaceable.
#[derive(Debug, Clone, Copy)]
pub struct Writable;

/// Shared directional request-data view.
#[derive(Debug)]
pub struct RequestDataRef<'a, 'data, Direction> {
    data: &'a RequestData<'data>,
    _direction: PhantomData<Direction>,
}

impl<'a, 'data, Direction> RequestDataRef<'a, 'data, Direction> {
    #[inline]
    pub fn view<T: RequestPayload<'data> + ?Sized>(&self) -> Option<&'a T> {
        self.data.view::<T>()
    }

    #[inline]
    pub fn can_take_exact<T: RequestPayload<'data>>(&self) -> bool {
        self.data.can_take_exact::<T>()
    }

    #[inline]
    pub fn can_require<T: RequestPayload<'data>>(&self) -> bool {
        self.data.can_require::<T>()
    }
}

/// Mutable directional request-data view.
#[derive(Debug)]
pub struct RequestDataRefMut<'a, 'data, Direction> {
    data: &'a mut RequestData<'data>,
    _direction: PhantomData<Direction>,
}

impl<'a, 'data, Direction> RequestDataRefMut<'a, 'data, Direction> {
    #[inline]
    pub fn view<T: RequestPayload<'data> + ?Sized>(&self) -> Option<&T> {
        self.data.view::<T>()
    }

    #[inline]
    pub fn read_only(self) -> RequestDataRef<'a, 'data, ReadOnly> {
        RequestDataRef {
            data: &*self.data,
            _direction: PhantomData,
        }
    }
}

impl<'a, 'data> RequestDataRefMut<'a, 'data, Writable> {
    #[inline]
    pub fn view_mut<T: RequestPayload<'data> + ?Sized>(&mut self) -> Option<&mut T> {
        unsafe { self.data.view_mut::<T>() }
    }
    #[inline]
    pub fn can_take_exact<T: RequestPayload<'data>>(&self) -> bool {
        self.data.can_take_exact::<T>()
    }

    #[inline]
    pub fn take_exact<T: RequestPayload<'data>>(&mut self) -> Result<T, RequestDataError> {
        self.data.take_exact::<T>()
    }

    #[inline]
    pub fn can_require<T: RequestPayload<'data>>(&self) -> bool {
        self.data.can_require::<T>()
    }

    #[inline]
    pub fn require<T: RequestPayload<'data>>(&mut self) -> Result<T, RequestDataError> {
        self.data.require::<T>()
    }
}

/// Runtime view over the currently installed request payload.
#[derive(Debug)]
pub enum RequestDataView<'a, 'data> {
    ReadOnly(RequestDataRef<'a, 'data, ReadOnly>),
    Writable(RequestDataRefMut<'a, 'data, Writable>),
}

impl<'a, 'data> RequestDataView<'a, 'data> {
    /// Obtain a shared `ReadOnly` view regardless of the backing mode so callers that only need
    /// read access do not need to match on direction first.
    #[inline]
    pub fn read_only(self) -> RequestDataRef<'a, 'data, ReadOnly> {
        match self {
            Self::ReadOnly(view) => view,
            Self::Writable(view) => view.read_only(),
        }
    }
    #[inline]
    pub fn try_writable(self) -> Option<RequestDataRefMut<'a, 'data, Writable>> {
        match self {
            Self::ReadOnly(_) => None,
            Self::Writable(view) => Some(view),
        }
    }
}
impl<'data> PnpRequest<'data> {
    #[inline]
    pub fn data_out_ref<'a>(&'a self) -> RequestDataRef<'a, 'data, ReadOnly> {
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

    // Skip a leading borrow marker so nominal tags stay stable across `&T` / `&mut T`.
    if i < input.len() && input[i] == b'&' {
        i += 1;
        if i + 3 < input.len()
            && input[i] == b'm'
            && input[i + 1] == b'u'
            && input[i + 2] == b't'
            && input[i + 3] == b' '
        {
            i += 4;
        }
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
// through BorrowedHandle, which enforces both the lifetime and T: RequestPayload bounds.
unsafe impl Send for RequestData<'_> {}

/// Compute a type tag for `T`, stripping lifetime parameters from generic argument lists
/// so that e.g. `FsAppendParams<'_>` and `FsAppendParams<'data>` produce the same hash,
/// while non-lifetime generics (e.g. `Vec<u8>` vs `Vec<u16>`) remain distinct.
#[inline]
pub const fn type_tag<T: ?Sized>() -> u64 {
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestDataError {
    Missing,
    WrongType,
    BorrowedCannotBeConsumed,
    ConversionUnavailable,
    ConversionFailed,
}
/// No-op dropper for raw bytes or empty data
extern "C" fn noop_dropper(_: *mut u8) {}

impl<'data> RequestData<'data> {
    pub fn empty() -> Self {
        Self {
            inline: InlineBuffer::new(),
            data_ptr: null_mut(),
            metadata: 0,
            heap_layout: Layout::new::<()>(),
            tag: None,
            shared_viewer: no_payload_view,
            mut_viewer: no_payload_view,
            can_into_converter: no_payload_can_into,
            into_converter: no_payload_into,
            dropper: noop_dropper,
            size: 0,
            mode: StorageMode::Inline,
            _marker: PhantomData,
        }
    }

    /// Install a non-owning borrow of driver-owned data. Only called by BorrowedHandle.
    /// The driver retains ownership; this RequestData must not drop or deallocate the pointer.
    fn from_borrowed_raw<T: RequestPayload<'data> + ?Sized>(
        parts: RequestPayloadRawParts,
        mode: StorageMode,
    ) -> Self {
        Self {
            inline: InlineBuffer::new(),
            data_ptr: parts.data,
            metadata: parts.metadata,
            heap_layout: Layout::new::<()>(),
            tag: Some(T::RUNTIME_TAG),
            shared_viewer: T::shared_view_raw_parts,
            mut_viewer: T::mut_view_raw_parts,
            can_into_converter: T::can_into_request_data,
            into_converter: T::into_request_data,
            dropper: noop_dropper,
            size: parts.bytes,
            mode,
            _marker: PhantomData,
        }
    }

    pub fn from_t<T: RequestPayload<'data>>(value: T) -> Self {
        let size = size_of::<T>();
        let align = align_of::<T>();

        /// Typed dropper that only runs T's destructor (no deallocation)
        extern "C" fn typed_dropper<T>(ptr: *mut u8) {
            unsafe { core::ptr::drop_in_place(ptr as *mut T) };
        }

        if size <= INLINE_THRESHOLD && align <= INLINE_ALIGN {
            // INLINE PATH: Copy value into inline buffer
            let mut result = Self {
                inline: InlineBuffer::new(),
                data_ptr: null_mut(),
                metadata: 0,
                heap_layout: Layout::new::<()>(),
                tag: Some(T::RUNTIME_TAG),
                shared_viewer: T::shared_view_raw_parts,
                mut_viewer: T::mut_view_raw_parts,
                can_into_converter: T::can_into_request_data,
                into_converter: T::into_request_data,
                dropper: typed_dropper::<T>,
                size,
                mode: StorageMode::Inline,
                _marker: PhantomData,
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
                data_ptr: ptr,
                metadata: 0,
                heap_layout: layout,
                tag: Some(T::RUNTIME_TAG),
                shared_viewer: T::shared_view_raw_parts,
                mut_viewer: T::mut_view_raw_parts,
                can_into_converter: T::can_into_request_data,
                into_converter: T::into_request_data,
                dropper: typed_dropper::<T>,
                size,
                mode: StorageMode::HeapTyped,
                _marker: PhantomData,
            }
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.size
    }

    #[inline]
    fn raw_parts(&self) -> RequestPayloadRawParts {
        RequestPayloadRawParts {
            data: match self.mode {
                StorageMode::Inline => self.inline.as_ptr() as *mut u8,
                StorageMode::HeapTyped
                | StorageMode::BorrowedReadOnly
                | StorageMode::BorrowedWritable => self.data_ptr,
            },
            metadata: self.metadata,
            bytes: self.size,
        }
    }

    fn matches<T: RequestPayload<'data> + ?Sized>(&self) -> bool {
        if self.tag != Some(T::RUNTIME_TAG) {
            return false;
        }

        Self::matches_static_size::<T>(self.size)
    }

    fn matches_static_size<T: RequestPayload<'data> + ?Sized>(bytes: usize) -> bool {
        match T::static_size() {
            Some(expected) => bytes == expected,
            None => true,
        }
    }

    pub fn get_type_tag(&self) -> Option<u64> {
        self.tag
    }

    pub(crate) fn view<T: RequestPayload<'data> + ?Sized>(&self) -> Option<&T> {
        let parts = self.raw_parts();
        if parts.data.is_null() {
            return None;
        }

        if self.matches::<T>() {
            return Some(unsafe { T::shared_from_raw_parts(parts) });
        }

        let target_parts = unsafe { (self.shared_viewer)(T::RUNTIME_TAG, parts) }?;
        if target_parts.data.is_null() || !Self::matches_static_size::<T>(target_parts.bytes) {
            return None;
        }

        Some(unsafe { T::shared_from_raw_parts(target_parts) })
    }

    pub(crate) unsafe fn view_mut<T: RequestPayload<'data> + ?Sized>(&mut self) -> Option<&mut T> {
        let parts = RequestPayloadRawParts {
            data: match self.mode {
                StorageMode::Inline => self.inline.as_mut_ptr(),
                StorageMode::HeapTyped | StorageMode::BorrowedWritable => self.data_ptr,
                StorageMode::BorrowedReadOnly => return None,
            },
            metadata: self.metadata,
            bytes: self.size,
        };

        if parts.data.is_null() {
            return None;
        }

        if self.matches::<T>() {
            return Some(unsafe { T::mut_from_raw_parts(parts) });
        }

        let target_parts = unsafe { (self.mut_viewer)(T::RUNTIME_TAG, parts) }?;
        if target_parts.data.is_null() || !Self::matches_static_size::<T>(target_parts.bytes) {
            return None;
        }

        Some(unsafe { T::mut_from_raw_parts(target_parts) })
    }

    fn reset_after_payload_move(&mut self) {
        self.data_ptr = null_mut();
        self.metadata = 0;
        self.tag = None;
        self.size = 0;
        self.mode = StorageMode::Inline;
        self.shared_viewer = no_payload_view;
        self.mut_viewer = no_payload_view;
        self.can_into_converter = no_payload_can_into;
        self.into_converter = no_payload_into;
        self.dropper = noop_dropper;
    }

    fn release_owned_storage_without_drop(&mut self) {
        if let StorageMode::HeapTyped = self.mode {
            if !self.data_ptr.is_null() {
                unsafe {
                    alloc::alloc::dealloc(self.data_ptr, self.heap_layout);
                }
            }
        }

        self.reset_after_payload_move();
    }

    fn take_exact_owned<T: RequestPayload<'data>>(&mut self) -> Option<T> {
        let value = match self.mode {
            StorageMode::Inline => unsafe {
                let ptr = self.inline.as_ptr() as *const T;
                core::ptr::read(ptr)
            },

            StorageMode::HeapTyped => {
                if self.data_ptr.is_null() {
                    return None;
                }

                let value = unsafe { core::ptr::read(self.data_ptr as *const T) };

                unsafe {
                    alloc::alloc::dealloc(self.data_ptr, self.heap_layout);
                }

                value
            }

            StorageMode::BorrowedReadOnly | StorageMode::BorrowedWritable => {
                return None;
            }
        };

        self.reset_after_payload_move();

        Some(value)
    }
    fn convert_then_take<T: RequestPayload<'data>>(&mut self) -> Result<T, RequestDataError> {
        let parts = self.raw_parts();

        if unsafe { !(self.can_into_converter)(T::RUNTIME_TAG, parts) } {
            return Err(RequestDataError::ConversionUnavailable);
        }

        let mut converted = MaybeUninit::<RequestData<'data>>::uninit();

        let did_convert =
            unsafe { (self.into_converter)(T::RUNTIME_TAG, parts, converted.as_mut_ptr()) };

        if !did_convert {
            return Err(RequestDataError::ConversionFailed);
        }

        self.release_owned_storage_without_drop();

        let mut converted = unsafe { converted.assume_init() };

        converted.take_exact::<T>()
    }
    pub fn can_take_exact<T: RequestPayload<'data>>(&self) -> bool {
        !self.mode.is_borrowed() && self.matches::<T>()
    }

    pub fn take_exact<T: RequestPayload<'data>>(&mut self) -> Result<T, RequestDataError> {
        if self.tag.is_none() {
            return Err(RequestDataError::Missing);
        }

        if self.mode.is_borrowed() {
            return Err(RequestDataError::BorrowedCannotBeConsumed);
        }

        if !self.matches::<T>() {
            return Err(RequestDataError::WrongType);
        }

        self.take_exact_owned::<T>()
            .ok_or(RequestDataError::Missing)
    }

    pub fn can_require<T: RequestPayload<'data>>(&self) -> bool {
        if self.mode.is_borrowed() {
            return false;
        }

        if self.matches::<T>() {
            return true;
        }

        let parts = self.raw_parts();

        if parts.data.is_null() {
            return false;
        }

        unsafe { (self.can_into_converter)(T::RUNTIME_TAG, parts) }
    }

    pub fn require<T: RequestPayload<'data>>(&mut self) -> Result<T, RequestDataError> {
        if self.tag.is_none() {
            return Err(RequestDataError::Missing);
        }

        if self.mode.is_borrowed() {
            return Err(RequestDataError::BorrowedCannotBeConsumed);
        }

        if self.matches::<T>() {
            return self
                .take_exact_owned::<T>()
                .ok_or(RequestDataError::Missing);
        }

        if self.raw_parts().data.is_null() {
            return Err(RequestDataError::Missing);
        }

        self.convert_then_take::<T>()
    }
}

impl<'data> Drop for RequestData<'data> {
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
                if !self.data_ptr.is_null() {
                    // Run typed dropper (drop_in_place)
                    (self.dropper)(self.data_ptr);

                    // Deallocate with stored Layout
                    unsafe {
                        alloc::alloc::dealloc(self.data_ptr, self.heap_layout);
                    }
                }
            }
            StorageMode::BorrowedReadOnly | StorageMode::BorrowedWritable => {
                // Not owned — driver retains ownership via BorrowedHandle. Do nothing.
            }
        }
    }
}

impl<'data> RequestData<'data> {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RequestMajor {
    Read,
    Write,
    Flush,
    FlushDirty,
    FlushOwner,
    DeviceControl,
    Fs,
    Pnp,
    Dummy,
}

pub trait RequestKind {
    const MAJOR: RequestMajor;
}

#[repr(C)]
#[derive(Debug)]
pub struct Read<'io> {
    pub offset: u64,
    pub len: usize,
    pub no_buffer: bool,
    pub buffer: Option<IoBuffer<'io, 'io, FromDevice>>,
    next: AtomicPtr<Self>,
}
impl<'io> Read<'io> {
    pub fn new(
        offset: u64,
        len: usize,
        no_buffer: bool,
        buffer: Option<IoBuffer<'io, 'io, FromDevice>>,
    ) -> Self {
        Self {
            offset,
            len,
            no_buffer,
            buffer,
            next: AtomicPtr::new(null_mut()),
        }
    }
    // TODO: can be made safe by adding a chain lifetime param
    pub unsafe fn append_next(&self, next: *mut Self) {
        let mut curr = self as *const Self as *mut Self;

        loop {
            let curr_ref = unsafe { &*curr };
            let old = curr_ref.next.compare_exchange(
                core::ptr::null_mut(),
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            );

            match old {
                Ok(_) => break,
                Err(existing) => curr = existing,
            }
        }
    }

    #[inline]
    pub fn iter(&self) -> ReadIter<'_, 'io> {
        ReadIter { next: Some(self) }
    }

    #[inline]
    pub fn iter_mut(&mut self) -> ReadIterMut<'_, 'io> {
        ReadIterMut {
            next: AtomicPtr::new(self as *mut Self),
            _marker: PhantomData,
        }
    }
}

pub struct ReadIter<'a, 'io> {
    next: Option<&'a Read<'io>>,
}

impl<'a, 'io> Iterator for ReadIter<'a, 'io> {
    type Item = &'a Read<'io>;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.next?;
        let next = current.next.load(Ordering::Acquire);

        self.next = if next.is_null() {
            None
        } else {
            Some(unsafe { &*next })
        };

        Some(current)
    }
}

pub struct ReadIterMut<'a, 'io> {
    next: AtomicPtr<Read<'io>>,
    _marker: PhantomData<&'a mut Read<'io>>,
}

impl<'a, 'io> Iterator for ReadIterMut<'a, 'io> {
    type Item = &'a mut Read<'io>;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.next.load(Ordering::Relaxed);

        if current.is_null() {
            return None;
        }

        let current_ref = unsafe { &mut *current };
        let next = current_ref.next.load(Ordering::Acquire);

        self.next.store(next, Ordering::Relaxed);

        Some(current_ref)
    }
}

impl RequestKind for Read<'_> {
    const MAJOR: RequestMajor = RequestMajor::Read;
}

#[repr(C)]
#[derive(Debug)]
pub struct Write<'io> {
    pub offset: u64,
    pub len: usize,
    pub no_buffer: bool,
    pub owner: u64,
    pub buffer: Option<IoBuffer<'io, 'io, ToDevice>>,
    next: AtomicPtr<Self>,
}

impl<'io> Write<'io> {
    pub fn new(
        offset: u64,
        len: usize,
        no_buffer: bool,
        owner: u64,
        buffer: Option<IoBuffer<'io, 'io, ToDevice>>,
    ) -> Self {
        Self {
            offset,
            len,
            no_buffer,
            owner,
            buffer,
            next: AtomicPtr::new(null_mut()),
        }
    }
    pub unsafe fn append_next(&self, next: *mut Self) {
        let mut curr = self as *const Self as *mut Self;

        loop {
            let curr_ref = unsafe { &*curr };
            let old = curr_ref.next.compare_exchange(
                core::ptr::null_mut(),
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            );

            match old {
                Ok(_) => break,
                Err(existing) => curr = existing,
            }
        }
    }

    #[inline]
    pub fn iter(&self) -> WriteIter<'_, 'io> {
        WriteIter { next: Some(self) }
    }

    #[inline]
    pub fn iter_mut(&mut self) -> WriteIterMut<'_, 'io> {
        WriteIterMut {
            next: AtomicPtr::new(self as *mut Self),
            _marker: PhantomData,
        }
    }
}

pub struct WriteIter<'a, 'io> {
    next: Option<&'a Write<'io>>,
}

impl<'a, 'io> Iterator for WriteIter<'a, 'io> {
    type Item = &'a Write<'io>;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.next?;
        let next = current.next.load(Ordering::Acquire);

        self.next = if next.is_null() {
            None
        } else {
            Some(unsafe { &*next })
        };

        Some(current)
    }
}

pub struct WriteIterMut<'a, 'io> {
    next: AtomicPtr<Write<'io>>,
    _marker: PhantomData<&'a mut Write<'io>>,
}

impl<'a, 'io> Iterator for WriteIterMut<'a, 'io> {
    type Item = &'a mut Write<'io>;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.next.load(Ordering::Relaxed);

        if current.is_null() {
            return None;
        }

        let current_ref = unsafe { &mut *current };
        let next = current_ref.next.load(Ordering::Acquire);

        self.next.store(next, Ordering::Relaxed);

        Some(current_ref)
    }
}

impl RequestKind for Write<'_> {
    const MAJOR: RequestMajor = RequestMajor::Write;
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flush {
    /// This flag indicates whether a flush job should be spawned, or if we should wait till all data is flushed.
    /// This flag can have unforeseen consequences if set to true, if something is actively writing data it is likely you won't return until they stop.
    pub should_block: bool,
}

impl RequestKind for Flush {
    const MAJOR: RequestMajor = RequestMajor::Flush;
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlushDirty {
    /// This flag indicates whether a flush job should be spawned, or if we should wait till all data is flushed.
    /// This flag can have unforeseen consequences if set to true, if something is actively writing data it is likely you won't return until they stop.
    pub should_block: bool,
}

impl RequestKind for FlushDirty {
    const MAJOR: RequestMajor = RequestMajor::FlushDirty;
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlushOwner {
    /// Flush only dirty cache pages belonging to the given owner (and unowned pages).
    pub owner: u64,
    pub should_block: bool,
}

impl RequestKind for FlushOwner {
    const MAJOR: RequestMajor = RequestMajor::FlushOwner;
}

#[repr(C)]
#[derive(Debug)]
pub struct DeviceControl<'data> {
    pub code: u32,
    pub data: RequestData<'data>,
}

impl<'data> DeviceControl<'data> {
    #[inline]
    pub fn new(code: u32, data: RequestData<'data>) -> Self {
        Self { code, data }
    }

    #[inline]
    pub fn new_t<T: RequestPayload<'data>>(code: u32, typed_payload: T) -> Self {
        Self {
            code,
            data: RequestData::from_t(typed_payload),
        }
    }

    #[inline]
    pub fn data(&mut self) -> RequestDataView<'_, 'data> {
        request_data_view(&mut self.data)
    }

    #[inline]
    pub fn set_data(&mut self, data: RequestData<'data>) {
        self.data = data;
    }

    #[inline]
    pub fn set_data_t<T: RequestPayload<'data>>(&mut self, data: T) {
        self.data = RequestData::from_t(data);
    }
}

impl RequestKind for DeviceControl<'_> {
    const MAJOR: RequestMajor = RequestMajor::DeviceControl;
}

pub struct FsOpen;
pub struct FsClose;
pub struct FsRead;
pub struct FsWrite;
pub struct FsFlush;
pub struct FsSeek;
pub struct FsCreate;
pub struct FsRename;
pub struct FsReadDir;
pub struct FsGetInfo;
pub struct FsSetLen;
pub struct FsAppend;
pub struct FsZeroRange;

pub trait FsOperation: Sized {
    type Params<'data>;
    type Result;
    type Handler: Copy;

    fn handler(ops: &FsOps) -> Option<&IoHandler<Self::Handler>>;

    fn call<'req, 'data, 'b>(
        handler: Self::Handler,
        dev: &Arc<DeviceObject>,
        handle: &'b mut RequestHandle<'req, Fs<'data, Self>>,
    ) -> FfiFuture<DriverStep>;
}

#[repr(C)]
pub struct FsPayload<'data, O: FsOperation> {
    pub params: O::Params<'data>,
    pub result: Option<O::Result>,
    pub _marker: PhantomData<&'data mut O>,
}

#[repr(C)]
pub struct Fs<'data, O: FsOperation> {
    pub payload: FsPayload<'data, O>,
}

impl<'data, O> RequestKind for Fs<'data, O>
where
    O: FsOperation,
{
    const MAJOR: RequestMajor = RequestMajor::Fs;
}

macro_rules! impl_fs_operation {
    ($op:ty, $params:ty, $result:ty, $handler:ty, $slot:ident) => {
        impl FsOperation for $op {
            type Params<'data> = $params;
            type Result = $result;
            type Handler = $handler;

            #[inline]
            fn handler(ops: &FsOps) -> Option<&IoHandler<Self::Handler>> {
                ops.$slot.as_handler()
            }

            #[inline]
            fn call<'req, 'data, 'b>(
                handler: Self::Handler,
                dev: &Arc<DeviceObject>,
                handle: &'b mut RequestHandle<'req, Fs<'data, Self>>,
            ) -> FfiFuture<DriverStep> {
                handler(dev, handle)
            }
        }
    };
}

impl_fs_operation!(FsOpen, FsOpenParams, FsOpenResult, EvtFsOpen, open);
impl_fs_operation!(FsClose, FsCloseParams, FsCloseResult, EvtFsClose, close);
impl_fs_operation!(FsRead, FsReadParams<'data>, FsReadResult, EvtFsRead, read);
impl_fs_operation!(
    FsWrite,
    FsWriteParams<'data>,
    FsWriteResult,
    EvtFsWrite,
    write
);
impl_fs_operation!(FsFlush, FsFlushParams, FsFlushResult, EvtFsFlush, flush);
impl_fs_operation!(FsSeek, FsSeekParams, FsSeekResult, EvtFsSeek, seek);
impl_fs_operation!(
    FsCreate,
    FsCreateParams,
    FsCreateResult,
    EvtFsCreate,
    create
);
impl_fs_operation!(
    FsRename,
    FsRenameParams,
    FsRenameResult,
    EvtFsRename,
    rename
);
impl_fs_operation!(
    FsReadDir,
    FsListDirParams,
    FsListDirResult,
    EvtFsReadDir,
    read_dir
);
impl_fs_operation!(
    FsGetInfo,
    FsGetInfoParams,
    FsGetInfoResult,
    EvtFsGetInfo,
    get_info
);
impl_fs_operation!(
    FsSetLen,
    FsSetLenParams,
    FsSetLenResult,
    EvtFsSetLen,
    set_len
);
impl_fs_operation!(
    FsAppend,
    FsAppendParams<'data>,
    FsAppendResult,
    EvtFsAppend,
    append
);
impl_fs_operation!(
    FsZeroRange,
    FsZeroRangeParams,
    FsZeroRangeResult,
    EvtFsZeroRange,
    zero_range
);

#[repr(C)]
#[derive(Debug)]
pub struct Pnp<'data> {
    pub request: PnpRequest<'data>,
}

impl RequestKind for Pnp<'_> {
    const MAJOR: RequestMajor = RequestMajor::Pnp;
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dummy;

impl RequestKind for Dummy {
    const MAJOR: RequestMajor = RequestMajor::Dummy;
}

#[inline]
fn request_data_view<'a, 'data>(data: &'a mut RequestData<'data>) -> RequestDataView<'a, 'data> {
    match data.mode {
        StorageMode::BorrowedReadOnly => RequestDataView::ReadOnly(RequestDataRef {
            data,
            _direction: PhantomData,
        }),
        StorageMode::BorrowedWritable | StorageMode::Inline | StorageMode::HeapTyped => {
            RequestDataView::Writable(RequestDataRefMut {
                data,
                _direction: PhantomData,
            })
        }
    }
}

pub trait RequestDataCarrier<'data>: RequestKind {
    fn request_data_mut(&mut self) -> &mut RequestData<'data>;
}

impl<'data> RequestDataCarrier<'data> for DeviceControl<'data> {
    #[inline]
    fn request_data_mut(&mut self) -> &mut RequestData<'data> {
        &mut self.data
    }
}

#[derive(Debug)]
#[repr(C)]
#[non_exhaustive]
pub struct Request<K: RequestKind> {
    pub body: K,
    pub completed: bool,
    pub status: DriverStatus,
    pub completion_routine: Option<CompletionRoutine<K>>,
    pub completion_context: usize,
    completion_is_chain: bool,
    completion_chain: Option<Vec<CompletionEntry<K>>>,
}

impl<K: RequestKind> Request<K> {
    #[inline]
    pub fn new(body: K) -> Self {
        Self {
            body,
            completed: false,
            status: DriverStatus::ContinueStep,
            completion_routine: None,
            completion_context: 0,
            completion_is_chain: false,
            completion_chain: None,
        }
    }

    pub fn add_completion(&mut self, func: CompletionRoutine<K>, ctx: usize) {
        match self.completion_routine {
            None => {
                self.completion_routine = Some(func);
                self.completion_context = ctx;
                self.completion_is_chain = false;
            }
            Some(prev) => {
                let prev_ctx = self.completion_context;
                let mut chain = Vec::with_capacity(
                    self.completion_chain
                        .as_ref()
                        .map_or(2, |existing| existing.len() + 1),
                );
                chain.push((func, ctx)); // newest first

                if self.completion_is_chain {
                    if let Some(previous) = self.completion_chain.take() {
                        chain.extend(previous);
                    } else {
                        chain.push((prev, prev_ctx));
                    }
                } else {
                    chain.push((prev, prev_ctx));
                }

                self.completion_routine = Some(chained_completion::<K>);
                self.completion_context = 0;
                self.completion_is_chain = true;
                self.completion_chain = Some(chain);
            }
        }
    }

    pub fn complete(&mut self) -> DriverStatus {
        if self.completed {
            return self.status.clone();
        }

        if let Some(fp) = self.completion_routine.take() {
            let context = self.completion_context;
            self.status = fp(&mut *self, context);
        }

        if self.status == DriverStatus::ContinueStep {
            self.status = DriverStatus::Success;
        }

        self.completed = true;
        self.completion_context = 0;
        self.completion_is_chain = false;
        self.completion_chain = None;

        self.status.clone()
    }

    #[inline]
    fn complete_for_drop(&mut self) {
        let _ = self.complete();
    }
}

impl<K> Request<K>
where
    K: RequestKind + core::fmt::Debug,
{
    /// Print all fields except the actual data payloads.
    pub fn print_meta(&self) -> alloc::string::String {
        alloc::format!(
            "Request {{ major: {:?}, body: {:?}, completed: {}, status: {:?}, completion_routine: {:?}, completion_context: {:#x} }}",
            K::MAJOR,
            self.body,
            self.completed,
            self.status,
            self.completion_routine.map(|_| "Some(fn)"),
            self.completion_context,
        )
    }
}

impl<'data, K> Request<K>
where
    K: RequestDataCarrier<'data>,
{
    #[inline]
    pub fn set_data(&mut self, data: RequestData<'data>) {
        *self.body.request_data_mut() = data;
    }

    #[inline]
    pub fn set_data_t<T: RequestPayload<'data>>(&mut self, data: T) {
        self.set_data(RequestData::from_t(data));
    }

    #[inline]
    pub fn data(&mut self) -> RequestDataView<'_, 'data> {
        request_data_view(self.body.request_data_mut())
    }
}

impl Request<Dummy> {
    #[inline]
    pub fn empty() -> Self {
        Self {
            body: Dummy,
            completed: true,
            status: DriverStatus::Success,
            completion_routine: None,
            completion_context: 0,
            completion_is_chain: false,
            completion_chain: None,
        }
    }
}

impl<K: RequestKind> Drop for Request<K> {
    fn drop(&mut self) {
        self.complete_for_drop();
    }
}
type CompletionEntry<K: RequestKind> = (CompletionRoutine<K>, usize);

extern "C" fn chained_completion<K: RequestKind>(
    req: &mut Request<K>,
    _ctx: usize,
) -> DriverStatus {
    let Some(entries) = req.completion_chain.take() else {
        return DriverStatus::Success;
    };

    let mut status = DriverStatus::Success;
    for (func, c) in entries {
        status = func(req, c);
    }

    status
}
// ============================================================================
// RequestHandle - Stack or Owned abstraction
// ============================================================================

/// Handle to a request - stack-borrowed or owned.
#[repr(C)]
#[derive(Debug)]
pub enum RequestHandle<'req, K: RequestKind> {
    /// Mutable borrow of a stack-allocated request.
    Stack(&'req mut Request<K>),
    /// Owned request - the RequestHandle owns the Request directly.
    Owned(Request<K>),
}

impl<'req, K: RequestKind> RequestHandle<'req, K> {
    #[inline]
    pub fn stack(request: &'req mut Request<K>) -> Self {
        RequestHandle::Stack(request)
    }

    #[inline]
    pub fn owned(request: Request<K>) -> Self {
        RequestHandle::Owned(request)
    }

    #[inline]
    pub fn new(body: K) -> Self {
        RequestHandle::Owned(Request::new(body))
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
        self.get().status.clone()
    }

    /// Acquire read access.
    #[inline]
    pub fn get(&self) -> &Request<K> {
        match self {
            RequestHandle::Stack(r) => r,
            RequestHandle::Owned(r) => r,
        }
    }

    /// Acquire write access.
    #[inline]
    pub fn get_mut(&mut self) -> &mut Request<K> {
        match self {
            RequestHandle::Stack(r) => r,
            RequestHandle::Owned(r) => r,
        }
    }

    /// Returns a raw pointer to the inner Request. Only for use by BorrowedHandle within
    /// this module — not accessible outside request.rs.
    pub(super) fn write_raw(&mut self) -> *mut Request<K> {
        match self {
            RequestHandle::Stack(r) => *r as *mut Request<K>,
            RequestHandle::Owned(r) => r as *mut Request<K>,
        }
    }
}

impl<'req, 'data, K> RequestHandle<'req, K>
where
    K: RequestDataCarrier<'data>,
{
    #[inline]
    pub fn data(&mut self) -> RequestDataView<'_, 'data> {
        self.get_mut().data()
    }
}

impl<'req, K: RequestKind> RequestHandleResult<'req, K> {
    pub fn status(&self) -> DriverStatus {
        match &self.step {
            DriverStep::Complete { status } => status.clone(),
            DriverStep::Continue => todo!(),
        }
    }
}

/// Handler return type. Carries step + handle back to dispatcher.
#[repr(C)]
pub struct RequestHandleResult<'req, K: RequestKind> {
    pub step: DriverStep,
    pub handle: RequestHandle<'req, K>,
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
enum BorrowedStorage<'data, T: ?Sized> {
    ReadOnly(PhantomData<&'data T>),
    Writable(PhantomData<&'data mut T>),
}

pub struct BorrowedHandle<
    'data: 'req,
    'req,
    'h,
    K: RequestDataCarrier<'data>,
    T: RequestPayload<'data> + ?Sized,
> {
    handle: &'req mut RequestHandle<'h, K>,
    borrow: BorrowedStorage<'data, T>,
}

impl<'data: 'req, 'req, 'h, K, T> BorrowedHandle<'data, 'req, 'h, K, T>
where
    K: RequestDataCarrier<'data>,
    T: RequestPayload<'data> + ?Sized,
{
    fn install(
        handle: &'req mut RequestHandle<'h, K>,
        parts: RequestPayloadRawParts,
        mode: StorageMode,
        borrow: BorrowedStorage<'data, T>,
    ) -> Self {
        *unsafe { &mut *handle.write_raw() }.body.request_data_mut() =
            RequestData::from_borrowed_raw::<T>(parts, mode);
        Self { handle, borrow }
    }

    pub fn read_only(handle: &'req mut RequestHandle<'h, K>, data: &'data T) -> Self {
        Self::install(
            handle,
            T::shared_raw_parts(data),
            StorageMode::BorrowedReadOnly,
            BorrowedStorage::ReadOnly(PhantomData),
        )
    }

    pub fn writable(handle: &'req mut RequestHandle<'h, K>, data: &'data mut T) -> Self {
        let parts = T::mut_raw_parts(data);
        Self::install(
            handle,
            parts,
            StorageMode::BorrowedWritable,
            BorrowedStorage::Writable(PhantomData),
        )
    }

    /// Returns the inner handle for passing to lower drivers.
    pub fn handle(&mut self) -> &mut RequestHandle<'h, K> {
        self.handle
    }
}

impl<'data: 'req, 'req, 'h, K, T> Drop for BorrowedHandle<'data, 'req, 'h, K, T>
where
    K: RequestDataCarrier<'data>,
    T: RequestPayload<'data> + ?Sized,
{
    fn drop(&mut self) {
        let _ = &self.borrow;
        // SAFETY: handle is still valid — 'req is live while Self exists.
        let req = unsafe { &mut *self.handle.write_raw() };
        // Only clear if the request still holds one of the borrowed modes. If the lower driver set
        // a response,
        // leave it intact so the upper driver can read it after the await.
        let data = req.body.request_data_mut();
        if data.mode.is_borrowed() {
            *data = RequestData::empty();
        }
    }
}
