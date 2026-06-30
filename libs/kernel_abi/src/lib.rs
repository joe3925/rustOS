#![no_std]

use core::{fmt::Debug, ops, slice};

pub mod arch;

pub const RUSTOS_BOOT_INFO_MAGIC: u64 = 0x5255_5354_4F53_5045;
pub const RUSTOS_BOOT_INFO_VERSION: u32 = 8;

pub const MAX_BOOT_MEMORY_REGIONS: usize = 256;
pub const MAX_KERNEL_SECTIONS: usize = 96;
pub const MAX_KERNEL_IMPORT_SYMBOLS: usize = 512;
pub const MAX_KERNEL_EXPORT_SYMBOLS: usize = 1024;
pub const MAX_KERNEL_SYMBOL_STRING_BYTES: usize = 128 * 1024;
pub const MAX_BOOT_PACKAGES: usize = 256;

pub trait BootArchInfo: Copy + Debug {
    const EMPTY: Self;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct EmptyArchInfo {
    pub reserved: u64,
}

impl BootArchInfo for EmptyArchInfo {
    const EMPTY: Self = Self { reserved: 0 };
}

#[derive(Debug)]
#[repr(C)]
pub struct BootInfo<A: BootArchInfo = EmptyArchInfo> {
    pub magic: u64,
    pub version: u32,
    pub flags: u32,
    pub rsdp_addr: Optional<u64>,
    pub arch_info: A,
    pub memory_regions: MemoryRegions,
    pub framebuffer: Optional<FrameBuffer>,
    pub fdt_header: Optional<*const FdtHeader>,
    pub kernel_imports: KernelSymbols,
    pub kernel_exports: KernelSymbols,
    pub ramdisk_addr: Optional<u64>,
    pub ramdisk_len: u64,
    pub kernel_addr: u64,
    pub kernel_len: u64,
    pub kernel_image_offset: u64,
    pub kernel_image_base: u64,
    pub kernel_image_size: u64,
    pub kernel_entry: u64,
    pub kernel_text: Optional<KernelTextSection>,
    pub kernel_sections: KernelSections,
    pub boot_packages: BootPackages,
    pub stub_base: u64,
    pub stub_size: u64,
}

impl<A: BootArchInfo> BootInfo<A> {
    pub const fn empty() -> Self {
        Self {
            magic: RUSTOS_BOOT_INFO_MAGIC,
            version: RUSTOS_BOOT_INFO_VERSION,
            flags: 0,
            rsdp_addr: Optional::None,
            arch_info: A::EMPTY,
            memory_regions: MemoryRegions {
                ptr: core::ptr::null_mut(),
                len: 0,
            },
            framebuffer: Optional::None,
            fdt_header: Optional::None,
            kernel_imports: KernelSymbols {
                ptr: core::ptr::null(),
                len: 0,
            },
            kernel_exports: KernelSymbols {
                ptr: core::ptr::null(),
                len: 0,
            },
            ramdisk_addr: Optional::None,
            ramdisk_len: 0,
            kernel_addr: 0,
            kernel_len: 0,
            kernel_image_offset: 0,
            kernel_image_base: 0,
            kernel_image_size: 0,
            kernel_entry: 0,
            kernel_text: Optional::None,
            kernel_sections: KernelSections {
                ptr: core::ptr::null(),
                len: 0,
            },
            boot_packages: BootPackages::empty(),
            stub_base: 0,
            stub_size: 0,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BootByteSlice {
    ptr: *const u8,
    len: usize,
}

// `BootByteSlice` is immutable handoff metadata. Its constructors only expose
// shared byte ranges, and consumers must validate the range before reading it.
unsafe impl Sync for BootByteSlice {}

impl BootByteSlice {
    pub const fn from_static(bytes: &'static [u8]) -> Self {
        Self {
            ptr: bytes.as_ptr(),
            len: bytes.len(),
        }
    }

    pub const fn as_ptr(&self) -> *const u8 {
        self.ptr
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// # Safety
    /// The descriptor must point to `len` readable bytes.
    pub unsafe fn as_slice<'a>(&self) -> &'a [u8] {
        slice::from_raw_parts(self.ptr, self.len)
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BootPackage {
    pub name: BootByteSlice,
    pub configuration: BootByteSlice,
    pub image: BootByteSlice,
}

impl BootPackage {
    pub const fn from_static(
        name: &'static [u8],
        configuration: &'static [u8],
        image: &'static [u8],
    ) -> Self {
        Self {
            name: BootByteSlice::from_static(name),
            configuration: BootByteSlice::from_static(configuration),
            image: BootByteSlice::from_static(image),
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BootPackages {
    ptr: *const BootPackage,
    len: usize,
}

impl BootPackages {
    pub const fn empty() -> Self {
        Self {
            ptr: core::ptr::null(),
            len: 0,
        }
    }

    pub const fn from_static(packages: &'static [BootPackage]) -> Self {
        Self {
            ptr: packages.as_ptr(),
            len: packages.len(),
        }
    }

    pub const fn as_ptr(&self) -> *const BootPackage {
        self.ptr
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// # Safety
    /// The descriptor must point to `len` initialized `BootPackage` values.
    pub unsafe fn as_slice<'a>(&self) -> &'a [BootPackage] {
        slice::from_raw_parts(self.ptr, self.len)
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FdtHeader {
    pub magic: u32,
    pub totalsize: u32,
    pub off_dt_struct: u32,
    pub off_dt_strings: u32,
    pub off_mem_rsvmap: u32,
    pub version: u32,
    pub last_comp_version: u32,
    pub boot_cpuid_phys: u32,
    pub size_dt_strings: u32,
    pub size_dt_struct: u32,
}

#[derive(Debug)]
#[repr(C)]
pub struct MemoryRegions {
    ptr: *mut MemoryRegion,
    len: usize,
}

impl MemoryRegions {
    /// # Safety
    ///
    /// `ptr` must reference `len` initialized `MemoryRegion` values for the
    /// entire lifetime of this handoff object and must be exclusively borrowed
    /// whenever the returned value is mutably dereferenced.
    pub const unsafe fn from_raw_parts(ptr: *mut MemoryRegion, len: usize) -> Self {
        Self { ptr, len }
    }

    pub const fn as_ptr(&self) -> *const MemoryRegion {
        self.ptr.cast_const()
    }

    pub const fn as_mut_ptr(&mut self) -> *mut MemoryRegion {
        self.ptr
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl ops::Deref for MemoryRegions {
    type Target = [MemoryRegion];

    fn deref(&self) -> &Self::Target {
        if self.len == 0 {
            return &[];
        }
        unsafe { slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl ops::DerefMut for MemoryRegions {
    fn deref_mut(&mut self) -> &mut Self::Target {
        if self.len == 0 {
            return &mut [];
        }
        unsafe { slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(C)]
pub struct MemoryRegion {
    pub start: u64,
    pub end: u64,
    pub kind: MemoryRegionKind,
}

impl MemoryRegion {
    pub const fn empty() -> Self {
        Self {
            start: 0,
            end: 0,
            kind: MemoryRegionKind::Bootloader,
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(C)]
pub enum MemoryRegionKind {
    Usable,
    Bootloader,
    Reserved,
    Unknown(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(C)]
pub enum Optional<T> {
    Some(T),
    None,
}

impl<T> Optional<T> {
    pub fn into_option(self) -> Option<T> {
        self.into()
    }

    pub const fn as_ref(&self) -> Option<&T> {
        match self {
            Self::Some(value) => Some(value),
            Self::None => None,
        }
    }

    pub fn as_mut(&mut self) -> Option<&mut T> {
        match self {
            Self::Some(value) => Some(value),
            Self::None => None,
        }
    }
}

impl<T> From<Option<T>> for Optional<T> {
    fn from(value: Option<T>) -> Self {
        match value {
            Some(value) => Self::Some(value),
            None => Self::None,
        }
    }
}

impl<T> From<Optional<T>> for Option<T> {
    fn from(value: Optional<T>) -> Self {
        match value {
            Optional::Some(value) => Some(value),
            Optional::None => None,
        }
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct FrameBuffer {
    buffer_start: u64,
    info: FrameBufferInfo,
}

impl FrameBuffer {
    /// # Safety
    /// `buffer_start` must identify an exclusively owned writable framebuffer
    /// of at least `info.byte_len` bytes for every borrow produced from it.
    pub const unsafe fn new(buffer_start: u64, info: FrameBufferInfo) -> Self {
        Self { buffer_start, info }
    }

    pub fn buffer(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.buffer_start as *const u8, self.info.byte_len) }
    }

    pub fn buffer_mut(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.buffer_start as *mut u8, self.info.byte_len) }
    }

    /// Consumes the descriptor and returns a mutable slice with caller-chosen
    /// lifetime.
    ///
    /// # Safety
    /// The framebuffer allocation must remain live and exclusively borrowed
    /// for the full returned lifetime.
    pub unsafe fn into_buffer_mut<'a>(self) -> &'a mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.buffer_start as *mut u8, self.info.byte_len) }
    }

    pub const fn info(&self) -> FrameBufferInfo {
        self.info
    }

    pub const fn buffer_start(&self) -> u64 {
        self.buffer_start
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FrameBufferInfo {
    pub byte_len: usize,
    pub width: usize,
    pub height: usize,
    pub pixel_format: PixelFormat,
    pub bytes_per_pixel: usize,
    pub stride: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum PixelFormat {
    Rgb,
    Bgr,
    U8,
    Unknown {
        red_position: u8,
        green_position: u8,
        blue_position: u8,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct KernelSymbolString {
    ptr: *const u8,
    len: usize,
}

impl KernelSymbolString {
    pub const fn empty() -> Self {
        Self {
            ptr: core::ptr::null(),
            len: 0,
        }
    }

    /// # Safety
    ///
    /// `ptr` must reference `len` bytes of valid UTF-8 that remain alive for
    /// every borrow produced from this value.
    pub const unsafe fn from_raw_parts(ptr: *const u8, len: usize) -> Self {
        Self { ptr, len }
    }

    pub const fn as_ptr(&self) -> *const u8 {
        self.ptr
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_str(&self) -> &str {
        if self.len == 0 {
            return "";
        }
        unsafe {
            let bytes = slice::from_raw_parts(self.ptr, self.len);
            core::str::from_utf8_unchecked(bytes)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct KernelSymbol {
    pub name: KernelSymbolString,
    pub module: KernelSymbolString,
}

impl KernelSymbol {
    pub const fn empty() -> Self {
        Self {
            name: KernelSymbolString::empty(),
            module: KernelSymbolString::empty(),
        }
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct KernelSymbols {
    ptr: *const KernelSymbol,
    len: usize,
}

impl KernelSymbols {
    /// # Safety
    ///
    /// `ptr` must reference `len` initialized `KernelSymbol` values that remain
    /// alive for every borrow produced from this value.
    pub const unsafe fn from_raw_parts(ptr: *const KernelSymbol, len: usize) -> Self {
        Self { ptr, len }
    }

    pub const fn as_ptr(&self) -> *const KernelSymbol {
        self.ptr
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_slice(&self) -> &[KernelSymbol] {
        if self.len == 0 {
            return &[];
        }
        unsafe { slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl ops::Deref for KernelSymbols {
    type Target = [KernelSymbol];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct KernelTextSection {
    pub base: u64,
    pub size: u64,
}

#[derive(Debug)]
#[repr(C)]
pub struct KernelSections {
    ptr: *const KernelSection,
    len: usize,
}

impl KernelSections {
    /// # Safety
    ///
    /// `ptr` must reference `len` initialized `KernelSection` values that
    /// remain alive for every borrow produced from this value.
    pub const unsafe fn from_raw_parts(ptr: *const KernelSection, len: usize) -> Self {
        Self { ptr, len }
    }

    pub const fn as_ptr(&self) -> *const KernelSection {
        self.ptr
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_slice(&self) -> &[KernelSection] {
        if self.len == 0 {
            return &[];
        }
        unsafe { slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl ops::Deref for KernelSections {
    type Target = [KernelSection];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct KernelSection {
    pub name: [u8; 8],
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_offset: u32,
    pub raw_size: u32,
    pub characteristics: u32,
    pub loaded_address: u64,
}

impl KernelSection {
    pub const fn empty() -> Self {
        Self {
            name: [0; 8],
            virtual_address: 0,
            virtual_size: 0,
            raw_offset: 0,
            raw_size: 0,
            characteristics: 0,
            loaded_address: 0,
        }
    }
}
