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
use crate::{
    EvtFsAppend, EvtFsClose, EvtFsCreate, EvtFsFlush, EvtFsGetInfo, EvtFsOpen, EvtFsRead,
    EvtFsReadDir, EvtFsRename, EvtFsSeek, EvtFsSetLen, EvtFsWrite, EvtFsZeroRange,
};
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

#[macro_export]
macro_rules! for_each_fs_operation {
    ($m:ident) => {
        $m! {
            open {
                op: FsOpen,
                params: FsOpenParams,
                result: FsOpenResult,
                handler: EvtFsOpen,
                method: open,
                depth: OPEN_DEPTH = 0
            },
            close {
                op: FsClose,
                params: FsCloseParams,
                result: FsCloseResult,
                handler: EvtFsClose,
                method: close,
                depth: CLOSE_DEPTH = 0
            },
            read {
                op: FsRead,
                params: FsReadParams<'data>,
                result: FsReadResult,
                handler: EvtFsRead,
                method: read,
                depth: READ_DEPTH = 0
            },
            write {
                op: FsWrite,
                params: FsWriteParams<'data>,
                result: FsWriteResult,
                handler: EvtFsWrite,
                method: write,
                depth: WRITE_DEPTH = 0
            },
            flush {
                op: FsFlush,
                params: FsFlushParams,
                result: FsFlushResult,
                handler: EvtFsFlush,
                method: flush,
                depth: FLUSH_DEPTH = 1
            },
            seek {
                op: FsSeek,
                params: FsSeekParams,
                result: FsSeekResult,
                handler: EvtFsSeek,
                method: seek,
                depth: SEEK_DEPTH = 0
            },
            create {
                op: FsCreate,
                params: FsCreateParams,
                result: FsCreateResult,
                handler: EvtFsCreate,
                method: create,
                depth: CREATE_DEPTH = 0
            },
            rename {
                op: FsRename,
                params: FsRenameParams,
                result: FsRenameResult,
                handler: EvtFsRename,
                method: rename,
                depth: RENAME_DEPTH = 0
            },
            read_dir {
                op: FsReadDir,
                params: FsListDirParams,
                result: FsListDirResult,
                handler: EvtFsReadDir,
                method: read_dir,
                depth: READ_DIR_DEPTH = 0
            },
            get_info {
                op: FsGetInfo,
                params: FsGetInfoParams,
                result: FsGetInfoResult,
                handler: EvtFsGetInfo,
                method: get_info,
                depth: GET_INFO_DEPTH = 0
            },
            set_len {
                op: FsSetLen,
                params: FsSetLenParams,
                result: FsSetLenResult,
                handler: EvtFsSetLen,
                method: set_len,
                depth: SET_LEN_DEPTH = 0
            },
            append {
                op: FsAppend,
                params: FsAppendParams<'data>,
                result: FsAppendResult,
                handler: EvtFsAppend,
                method: append,
                depth: APPEND_DEPTH = 0
            },
            zero_range {
                op: FsZeroRange,
                params: FsZeroRangeParams,
                result: FsZeroRangeResult,
                handler: EvtFsZeroRange,
                method: zero_range,
                depth: ZERO_RANGE_DEPTH = 0
            }
        }
    };
}

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
    unsafe extern "C" fn(u64, RequestPayloadRawParts, *mut IoctlData<'data>) -> bool;
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

/// Erased raw payload parts stored inside [`IoctlData`].
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
        _out: *mut IoctlData<'data>,
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
    _out: *mut IoctlData<'data>,
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
pub struct IoctlData<'data> {
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

impl<'data> core::fmt::Debug for IoctlData<'data> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IoctlData")
            .field("tag", &self.tag)
            .field("size", &self.size)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
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
// SAFETY: IoctlData exclusively owns its inline or heap allocation, and RequestPayload is Send.
unsafe impl Send for IoctlData<'_> {}

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
pub enum IoctlDataError {
    Missing,
    WrongType,
    ConversionUnavailable,
    ConversionFailed,
}
/// No-op dropper for raw bytes or empty data
extern "C" fn noop_dropper(_: *mut u8) {}

impl<'data> IoctlData<'data> {
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
                StorageMode::HeapTyped => self.data_ptr,
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

    pub fn view<T: RequestPayload<'data> + ?Sized>(&self) -> Option<&T> {
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

    pub fn view_mut<T: RequestPayload<'data> + ?Sized>(&mut self) -> Option<&mut T> {
        let parts = RequestPayloadRawParts {
            data: match self.mode {
                StorageMode::Inline => self.inline.as_mut_ptr(),
                StorageMode::HeapTyped => self.data_ptr,
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
        };

        self.reset_after_payload_move();

        Some(value)
    }
    fn convert_then_take<T: RequestPayload<'data>>(&mut self) -> Result<T, IoctlDataError> {
        let parts = self.raw_parts();

        if unsafe { !(self.can_into_converter)(T::RUNTIME_TAG, parts) } {
            return Err(IoctlDataError::ConversionUnavailable);
        }

        let mut converted = MaybeUninit::<IoctlData<'data>>::uninit();

        let did_convert =
            unsafe { (self.into_converter)(T::RUNTIME_TAG, parts, converted.as_mut_ptr()) };

        if !did_convert {
            return Err(IoctlDataError::ConversionFailed);
        }

        self.release_owned_storage_without_drop();

        let mut converted = unsafe { converted.assume_init() };

        converted.take_exact::<T>()
    }
    pub fn can_take_exact<T: RequestPayload<'data>>(&self) -> bool {
        self.matches::<T>()
    }

    pub fn take_exact<T: RequestPayload<'data>>(&mut self) -> Result<T, IoctlDataError> {
        if self.tag.is_none() {
            return Err(IoctlDataError::Missing);
        }

        if !self.matches::<T>() {
            return Err(IoctlDataError::WrongType);
        }

        self.take_exact_owned::<T>().ok_or(IoctlDataError::Missing)
    }

    pub fn can_require<T: RequestPayload<'data>>(&self) -> bool {
        if self.matches::<T>() {
            return true;
        }

        let parts = self.raw_parts();

        if parts.data.is_null() {
            return false;
        }

        unsafe { (self.can_into_converter)(T::RUNTIME_TAG, parts) }
    }

    pub fn require<T: RequestPayload<'data>>(&mut self) -> Result<T, IoctlDataError> {
        if self.tag.is_none() {
            return Err(IoctlDataError::Missing);
        }

        if self.matches::<T>() {
            return self.take_exact_owned::<T>().ok_or(IoctlDataError::Missing);
        }

        if self.raw_parts().data.is_null() {
            return Err(IoctlDataError::Missing);
        }

        self.convert_then_take::<T>()
    }
}

impl<'data> Drop for IoctlData<'data> {
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
        }
    }
}

impl<'data> IoctlData<'data> {
    /// Print metadata without the actual data payload
    pub fn print_meta(&self) -> alloc::string::String {
        alloc::format!(
            "IoctlData {{ tag: {:?}, size: {}, mode: {:?} }}",
            self.tag,
            self.size,
            self.mode
        )
    }
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

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flush {
    /// This flag indicates whether a flush job should be spawned, or if we should wait till all data is flushed.
    /// This flag can have unforeseen consequences if set to true, if something is actively writing data it is likely you won't return until they stop.
    pub should_block: bool,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlushDirty {
    /// This flag indicates whether a flush job should be spawned, or if we should wait till all data is flushed.
    /// This flag can have unforeseen consequences if set to true, if something is actively writing data it is likely you won't return until they stop.
    pub should_block: bool,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlushOwner {
    /// Flush only dirty cache pages belonging to the given owner (and unowned pages).
    pub owner: u64,
    pub should_block: bool,
}

#[repr(C)]
#[derive(Debug)]
pub struct DeviceControl<'data> {
    pub code: u32,
    pub data: IoctlData<'data>,
}

impl<'data> DeviceControl<'data> {
    #[inline]
    pub fn new(code: u32, data: IoctlData<'data>) -> Self {
        Self { code, data }
    }

    #[inline]
    pub fn new_t<T: RequestPayload<'data>>(code: u32, typed_payload: T) -> Self {
        Self {
            code,
            data: IoctlData::from_t(typed_payload),
        }
    }

    #[inline]
    pub fn set_data(&mut self, data: IoctlData<'data>) {
        self.data = data;
    }

    #[inline]
    pub fn set_data_t<T: RequestPayload<'data>>(&mut self, data: T) {
        self.data = IoctlData::from_t(data);
    }
}

macro_rules! define_fs_request_operations {
    (
        $(
            $field:ident {
                op: $op:ident,
                params: $params:ty,
                result: $result:ty,
                handler: $handler:ty,
                method: $method:ident,
                depth: $depth:ident = $default_depth:expr
            }
        ),+ $(,)?
    ) => {
        $(pub struct $op;)+

        pub trait FsOperation: Sized {
            type Params<'data>;
            type Result;
            type Handler: Copy;

            fn handler(ops: &FsOps) -> Option<&IoHandler<Self::Handler>>;

            fn call<'a, 'data>(
                handler: Self::Handler,
                dev: &'a Arc<DeviceObject>,
                req: &'a mut Fs<'data, Self>,
            ) -> FfiFuture<DriverStep>;
        }

        $(
            impl FsOperation for $op {
                type Params<'data> = $params;
                type Result = $result;
                type Handler = $handler;

                #[inline]
                fn handler(ops: &FsOps) -> Option<&IoHandler<Self::Handler>> {
                    ops.$field.as_handler()
                }

                #[inline]
                fn call<'a, 'data>(
                    handler: Self::Handler,
                    dev: &'a Arc<DeviceObject>,
                    req: &'a mut Fs<'data, Self>,
                ) -> FfiFuture<DriverStep> {
                    handler(dev, req)
                }
            }
        )+
    };
}

crate::for_each_fs_operation!(define_fs_request_operations);

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
