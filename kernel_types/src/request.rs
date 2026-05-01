use crate::CompletionRoutine;
use crate::fs::FsOp;
use crate::pnp::DriverStep;
use crate::pnp::PnpRequest;
use crate::status::DriverStatus;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::AtomicBool;
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
type DropperFn = extern "win64" fn(*mut u8);
type RequestPayloadViewFn =
    unsafe extern "win64" fn(u64, RequestPayloadRawParts) -> Option<RequestPayloadRawParts>;
type RequestPayloadCanIntoFn = unsafe extern "win64" fn(u64, RequestPayloadRawParts) -> bool;
type RequestPayloadIntoFn =
    unsafe extern "win64" fn(u64, RequestPayloadRawParts, *mut RequestData) -> bool;
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

pub unsafe trait RequestPayload: Send {
    /// Stable runtime tag for matching this payload type. Either impl or use type_tag::<T>()
    extern "win64" fn runtime_tag() -> u64;

    /// Static byte size for nominal sized payloads.
    #[inline]
    extern "win64" fn static_size() -> Option<usize> {
        None
    }

    /// Erase a shared borrow into raw transport parts.
    extern "win64" fn shared_raw_parts(payload: &Self) -> RequestPayloadRawParts;

    /// Erase a mutable borrow into raw transport parts.
    extern "win64" fn mut_raw_parts(payload: &mut Self) -> RequestPayloadRawParts;

    /// Rebuild a shared view from erased raw transport parts.
    unsafe extern "win64" fn shared_from_raw_parts<'a>(parts: RequestPayloadRawParts) -> &'a Self;

    /// Rebuild a mutable view from erased raw transport parts.
    unsafe extern "win64" fn mut_from_raw_parts<'a>(parts: RequestPayloadRawParts) -> &'a mut Self;

    /// Try to project this concrete payload into a shared target payload view.
    ///
    /// The default implementation exposes no coercions. Derives may override
    /// this through `#[request_view(Source => Target)]` helper attributes.
    #[inline]
    unsafe extern "win64" fn shared_view_raw_parts(
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
    unsafe extern "win64" fn mut_view_raw_parts(
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
    unsafe extern "win64" fn into_request_data(
        _target_tag: u64,
        _parts: RequestPayloadRawParts,
        _out: *mut RequestData,
    ) -> bool {
        false
    }

    /// Try to determine whether this concrete owned payload can be consumed into
    /// a target payload without consuming it.
    ///
    /// The default implementation exposes no conversions. Derives may override
    /// this through `#[request_into(Source => Target)]` helper attributes.
    #[inline]
    unsafe extern "win64" fn can_into_request_data(
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
pub trait RequestPayloadView<Target: RequestPayload + ?Sized>:
    RequestPayload + AsRef<Target>
{
}

impl<Source, Target> RequestPayloadView<Target> for Source
where
    Source: RequestPayload + AsRef<Target> + ?Sized,
    Target: RequestPayload + ?Sized,
{
}

#[diagnostic::on_unimplemented(
    message = "`{Self}` cannot be used as a mutable request view of `{Target}`",
    label = "missing mutable request view conversion from `{Self}` to `{Target}`",
    note = "`#[request_view_mut(Source => Target)]` requires Source: RequestPayload, Target: RequestPayload, and Source: AsMut<Target>"
)]
pub trait RequestPayloadViewMut<Target: RequestPayload + ?Sized>:
    RequestPayload + AsMut<Target>
{
}

impl<Source, Target> RequestPayloadViewMut<Target> for Source
where
    Source: RequestPayload + AsMut<Target> + ?Sized,
    Target: RequestPayload + ?Sized,
{
}

#[diagnostic::on_unimplemented(
    message = "`{Self}` cannot be consumed as request data into `{Target}`",
    label = "missing owned request-data conversion from `{Self}` to `{Target}`",
    note = "`#[request_into(Source => Target)]` requires Source: RequestPayload + Into<Target> and Target: 'static + RequestPayload"
)]
pub trait RequestPayloadInto<Target: 'static + RequestPayload>:
    RequestPayload + Into<Target>
{
}

impl<Source, Target> RequestPayloadInto<Target> for Source
where
    Source: RequestPayload + Into<Target>,
    Target: 'static + RequestPayload,
{
}

unsafe extern "win64" fn no_payload_view(
    _target_tag: u64,
    _parts: RequestPayloadRawParts,
) -> Option<RequestPayloadRawParts> {
    None
}

unsafe extern "win64" fn no_payload_into(
    _target_tag: u64,
    _parts: RequestPayloadRawParts,
    _out: *mut RequestData,
) -> bool {
    false
}

unsafe extern "win64" fn no_payload_can_into(
    _target_tag: u64,
    _parts: RequestPayloadRawParts,
) -> bool {
    false
}

macro_rules! impl_nominal_request_payload {
    ($ty:path) => {
        unsafe impl RequestPayload for $ty {
            #[inline]
            extern "win64" fn runtime_tag() -> u64 {
                type_tag::<Self>()
            }

            #[inline]
            extern "win64" fn static_size() -> Option<usize> {
                Some(size_of::<Self>())
            }

            #[inline]
            extern "win64" fn shared_raw_parts(payload: &Self) -> RequestPayloadRawParts {
                RequestPayloadRawParts {
                    data: payload as *const Self as *mut u8,
                    metadata: 0,
                    bytes: size_of::<Self>(),
                }
            }

            #[inline]
            extern "win64" fn mut_raw_parts(payload: &mut Self) -> RequestPayloadRawParts {
                RequestPayloadRawParts {
                    data: payload as *mut Self as *mut u8,
                    metadata: 0,
                    bytes: size_of::<Self>(),
                }
            }

            #[inline]
            unsafe extern "win64" fn shared_from_raw_parts<'a>(
                parts: RequestPayloadRawParts,
            ) -> &'a Self {
                unsafe { &*(parts.data as *const Self) }
            }

            #[inline]
            unsafe extern "win64" fn mut_from_raw_parts<'a>(
                parts: RequestPayloadRawParts,
            ) -> &'a mut Self {
                unsafe { &mut *(parts.data as *mut Self) }
            }
        }
    };
}

unsafe impl RequestPayload for [u8] {
    #[inline]
    extern "win64" fn runtime_tag() -> u64 {
        type_tag::<[u8]>()
    }

    #[inline]
    extern "win64" fn shared_raw_parts(payload: &Self) -> RequestPayloadRawParts {
        RequestPayloadRawParts {
            data: payload.as_ptr() as *mut u8,
            metadata: payload.len(),
            bytes: payload.len(),
        }
    }

    #[inline]
    extern "win64" fn mut_raw_parts(payload: &mut Self) -> RequestPayloadRawParts {
        RequestPayloadRawParts {
            data: payload.as_mut_ptr(),
            metadata: payload.len(),
            bytes: payload.len(),
        }
    }

    #[inline]
    unsafe extern "win64" fn shared_from_raw_parts<'a>(parts: RequestPayloadRawParts) -> &'a Self {
        unsafe { core::slice::from_raw_parts(parts.data as *const u8, parts.metadata) }
    }

    #[inline]
    unsafe extern "win64" fn mut_from_raw_parts<'a>(parts: RequestPayloadRawParts) -> &'a mut Self {
        unsafe { core::slice::from_raw_parts_mut(parts.data, parts.metadata) }
    }
}

unsafe impl RequestPayload for str {
    #[inline]
    extern "win64" fn runtime_tag() -> u64 {
        type_tag::<str>()
    }

    #[inline]
    extern "win64" fn shared_raw_parts(payload: &Self) -> RequestPayloadRawParts {
        let bytes = payload.as_bytes();
        RequestPayloadRawParts {
            data: bytes.as_ptr() as *mut u8,
            metadata: bytes.len(),
            bytes: bytes.len(),
        }
    }

    #[inline]
    extern "win64" fn mut_raw_parts(payload: &mut Self) -> RequestPayloadRawParts {
        RequestPayloadRawParts {
            data: payload.as_ptr() as *mut u8,
            metadata: payload.len(),
            bytes: payload.len(),
        }
    }

    #[inline]
    unsafe extern "win64" fn shared_from_raw_parts<'a>(parts: RequestPayloadRawParts) -> &'a Self {
        let bytes = unsafe { core::slice::from_raw_parts(parts.data as *const u8, parts.metadata) };
        unsafe { core::str::from_utf8_unchecked(bytes) }
    }

    #[inline]
    unsafe extern "win64" fn mut_from_raw_parts<'a>(parts: RequestPayloadRawParts) -> &'a mut Self {
        let bytes = unsafe { core::slice::from_raw_parts_mut(parts.data, parts.metadata) };
        unsafe { core::str::from_utf8_unchecked_mut(bytes) }
    }
}

impl_nominal_request_payload!(Vec<u8>);

#[repr(C)]
pub struct RequestData {
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
    into_converter: RequestPayloadIntoFn,
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
pub struct ReadOnly;

/// Marker for request data flowing back from a lower device, or owned by the request and thus
/// still mutable/replaceable.
#[derive(Debug, Clone, Copy)]
pub struct Writable;

/// Shared directional request-data view.
#[derive(Debug)]
pub struct RequestDataRef<'a, Direction> {
    data: &'a RequestData,
    _direction: PhantomData<Direction>,
}

impl<'a, Direction> RequestDataRef<'a, Direction> {
    #[inline]
    pub fn view<T: RequestPayload + ?Sized>(&self) -> Option<&'a T> {
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
    pub fn view<T: RequestPayload + ?Sized>(&self) -> Option<&T> {
        self.data.view::<T>()
    }

    #[inline]
    pub fn read_only(self) -> RequestDataRef<'a, ReadOnly> {
        RequestDataRef {
            data: &*self.data,
            _direction: PhantomData,
        }
    }
}

impl<'a> RequestDataRefMut<'a, Writable> {
    #[inline]
    pub fn view_mut<T: RequestPayload + ?Sized>(&mut self) -> Option<&mut T> {
        unsafe { self.data.view_mut::<T>() }
    }
    #[inline]
    pub fn can_take_exact<T: 'static + RequestPayload>(&self) -> bool {
        self.data.can_take_exact::<T>()
    }

    #[inline]
    pub fn take_exact<T: 'static + RequestPayload>(&mut self) -> Result<T, RequestDataError> {
        self.data.take_exact::<T>()
    }

    #[inline]
    pub fn can_require<T: 'static + RequestPayload>(&self) -> bool {
        self.data.can_require::<T>()
    }

    #[inline]
    pub fn require<T: 'static + RequestPayload>(&mut self) -> Result<T, RequestDataError> {
        self.data.require::<T>()
    }
}

/// Runtime view over the currently installed request payload.
#[derive(Debug)]
pub enum RequestDataView<'a> {
    ToDevice(RequestDataRef<'a, ReadOnly>),
    FromDevice(RequestDataRefMut<'a, Writable>),
}

impl<'a> RequestDataView<'a> {
    /// Obtain a shared `ToDevice` view regardless of the backing mode so callers that only need
    /// read access do not need to match on direction first.
    #[inline]
    pub fn read_only(self) -> RequestDataRef<'a, ReadOnly> {
        match self {
            Self::ToDevice(view) => view,
            Self::FromDevice(view) => view.read_only(),
        }
    }
}
impl PnpRequest {
    #[inline]
    pub fn data_out_ref(&self) -> RequestDataRef<'_, ReadOnly> {
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
unsafe impl Send for RequestData {}

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
extern "win64" fn noop_dropper(_: *mut u8) {}

impl RequestData {
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
        }
    }

    /// Install a non-owning borrow of driver-owned data. Only called by BorrowedHandle.
    /// The driver retains ownership; this RequestData must not drop or deallocate the pointer.
    fn from_borrowed_raw<T: RequestPayload + ?Sized>(
        parts: RequestPayloadRawParts,
        mode: StorageMode,
    ) -> Self {
        Self {
            inline: InlineBuffer::new(),
            data_ptr: parts.data,
            metadata: parts.metadata,
            heap_layout: Layout::new::<()>(),
            tag: Some(T::runtime_tag()),
            shared_viewer: T::shared_view_raw_parts,
            mut_viewer: T::mut_view_raw_parts,
            can_into_converter: T::can_into_request_data,
            into_converter: T::into_request_data,
            dropper: noop_dropper,
            size: parts.bytes,
            mode,
        }
    }

    pub fn from_t<T: 'static + RequestPayload>(value: T) -> Self {
        let size = size_of::<T>();
        let align = align_of::<T>();

        /// Typed dropper that only runs T's destructor (no deallocation)
        extern "win64" fn typed_dropper<T>(ptr: *mut u8) {
            unsafe { core::ptr::drop_in_place(ptr as *mut T) };
        }

        if size <= INLINE_THRESHOLD && align <= INLINE_ALIGN {
            // INLINE PATH: Copy value into inline buffer
            let mut result = Self {
                inline: InlineBuffer::new(),
                data_ptr: null_mut(),
                metadata: 0,
                heap_layout: Layout::new::<()>(),
                tag: Some(T::runtime_tag()),
                shared_viewer: T::shared_view_raw_parts,
                mut_viewer: T::mut_view_raw_parts,
                can_into_converter: T::can_into_request_data,
                into_converter: T::into_request_data,
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
                data_ptr: ptr,
                metadata: 0,
                heap_layout: layout,
                tag: Some(T::runtime_tag()),
                shared_viewer: T::shared_view_raw_parts,
                mut_viewer: T::mut_view_raw_parts,
                can_into_converter: T::can_into_request_data,
                into_converter: T::into_request_data,
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

    fn matches<T: RequestPayload + ?Sized>(&self) -> bool {
        if self.tag != Some(T::runtime_tag()) {
            return false;
        }

        Self::matches_static_size::<T>(self.size)
    }

    fn matches_static_size<T: RequestPayload + ?Sized>(bytes: usize) -> bool {
        match T::static_size() {
            Some(expected) => bytes == expected,
            None => true,
        }
    }

    pub fn get_type_tag(&self) -> Option<u64> {
        self.tag
    }

    pub(crate) fn view<T: RequestPayload + ?Sized>(&self) -> Option<&T> {
        let parts = self.raw_parts();
        if parts.data.is_null() {
            return None;
        }

        if self.matches::<T>() {
            return Some(unsafe { T::shared_from_raw_parts(parts) });
        }

        let target_parts = unsafe { (self.shared_viewer)(T::runtime_tag(), parts) }?;
        if target_parts.data.is_null() || !Self::matches_static_size::<T>(target_parts.bytes) {
            return None;
        }

        Some(unsafe { T::shared_from_raw_parts(target_parts) })
    }

    pub(crate) unsafe fn view_mut<T: RequestPayload + ?Sized>(&mut self) -> Option<&mut T> {
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

        let target_parts = unsafe { (self.mut_viewer)(T::runtime_tag(), parts) }?;
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

    fn take_exact_owned<T: 'static + RequestPayload>(&mut self) -> Option<T> {
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
    fn convert_then_take<T: 'static + RequestPayload>(&mut self) -> Result<T, RequestDataError> {
        let parts = self.raw_parts();

        if unsafe { !(self.can_into_converter)(T::runtime_tag(), parts) } {
            return Err(RequestDataError::ConversionUnavailable);
        }

        let mut converted = MaybeUninit::<RequestData>::uninit();

        let did_convert =
            unsafe { (self.into_converter)(T::runtime_tag(), parts, converted.as_mut_ptr()) };

        if !did_convert {
            return Err(RequestDataError::ConversionFailed);
        }

        self.release_owned_storage_without_drop();

        let mut converted = unsafe { converted.assume_init() };

        converted.take_exact::<T>()
    }
    pub fn can_take_exact<T: 'static + RequestPayload>(&self) -> bool {
        !self.mode.is_borrowed() && self.matches::<T>()
    }

    pub fn take_exact<T: 'static + RequestPayload>(&mut self) -> Result<T, RequestDataError> {
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

    pub fn can_require<T: 'static + RequestPayload>(&self) -> bool {
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

        unsafe { (self.can_into_converter)(T::runtime_tag(), parts) }
    }

    pub fn require<T: 'static + RequestPayload>(&mut self) -> Result<T, RequestDataError> {
        if self.tag.is_none() {
            return Err(RequestDataError::Missing);
        }

        if self.mode.is_borrowed() {
            return Err(RequestDataError::BorrowedCannotBeConsumed);
        }

        if self.matches::<T>() {
            return self.take_exact::<T>();
        }

        if self.raw_parts().data.is_null() {
            return Err(RequestDataError::Missing);
        }

        self.convert_then_take::<T>()
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
    pub(crate) fn new_t<T: 'static + RequestPayload>(kind: RequestType, data: T) -> Self {
        Self::new(kind, RequestData::from_t(data))
    }

    /// Create a PnP request with typed payload.
    #[inline]
    pub(crate) fn new_pnp_t<T: 'static + RequestPayload>(pnp: PnpRequest, data: T) -> Self {
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
    pub fn set_data_t<T: 'static + RequestPayload>(&mut self, data: T) {
        self.data = RequestData::from_t(data);
    }

    #[inline]
    pub fn data(&mut self) -> RequestDataView<'_> {
        match self.data.mode {
            StorageMode::BorrowedReadOnly => RequestDataView::ToDevice(RequestDataRef {
                data: &self.data,
                _direction: PhantomData,
            }),
            StorageMode::BorrowedWritable | StorageMode::Inline | StorageMode::HeapTyped => {
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
    pub fn new_t<T: 'static + RequestPayload>(kind: RequestType, data: T) -> Self {
        RequestHandle::Owned(Request::new_t(kind, data))
    }

    /// Create a PnP request with typed payload owned by the RequestHandle.
    #[inline]
    pub fn new_pnp_t<T: 'static + RequestPayload>(pnp: PnpRequest, data: T) -> Self {
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
        self.read().status.clone()
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
        match &self.step {
            DriverStep::Complete { status } => status.clone(),
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
enum BorrowedStorage<'data, T: ?Sized> {
    ReadOnly(&'data T),
    Writable(&'data mut T),
}

pub struct BorrowedHandle<'data: 'req, 'req, 'h, T: RequestPayload + ?Sized> {
    handle: &'req mut RequestHandle<'h>,
    borrow: BorrowedStorage<'data, T>,
}

impl<'data: 'req, 'req, 'h, T: RequestPayload + ?Sized> BorrowedHandle<'data, 'req, 'h, T> {
    fn install(
        handle: &'req mut RequestHandle<'h>,
        parts: RequestPayloadRawParts,
        mode: StorageMode,
        borrow: BorrowedStorage<'data, T>,
    ) -> Self {
        unsafe { &mut *handle.write_raw() }.data = RequestData::from_borrowed_raw::<T>(parts, mode);
        Self { handle, borrow }
    }

    pub fn read_only(handle: &'req mut RequestHandle<'h>, data: &'data T) -> Self {
        Self::install(
            handle,
            T::shared_raw_parts(data),
            StorageMode::BorrowedReadOnly,
            BorrowedStorage::ReadOnly(data),
        )
    }

    pub fn writable(handle: &'req mut RequestHandle<'h>, data: &'data mut T) -> Self {
        Self::install(
            handle,
            T::mut_raw_parts(data),
            StorageMode::BorrowedWritable,
            BorrowedStorage::Writable(data),
        )
    }

    /// Returns the inner handle for passing to lower drivers.
    pub fn handle(&mut self) -> &mut RequestHandle<'h> {
        self.handle
    }
}

impl<'data: 'req, 'req, 'h, T: RequestPayload + ?Sized> Drop
    for BorrowedHandle<'data, 'req, 'h, T>
{
    fn drop(&mut self) {
        let _ = &self.borrow;
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
