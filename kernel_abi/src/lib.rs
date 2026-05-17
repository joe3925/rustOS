#![no_std]

use core::{ops, slice};

pub const RUSTOS_BOOT_INFO_MAGIC: u64 = 0x5255_5354_4F53_5045;
pub const RUSTOS_BOOT_INFO_VERSION: u32 = 1;

pub const PHYSICAL_MEMORY_OFFSET: u64 = 0xFFFF_8000_0000_0000;
pub const KERNEL_PE_BASE: u64 = 0xFFFF_8500_0000_0000;
pub const STUB_IMAGE_BASE: u64 = 0xFFFF_8800_0000_0000;

// Keep the bootloader's dynamic mappings out of the fixed stub image P4 slot.
// The bootloader reserves dynamic virtual space in whole P4 entries, so this
// band deliberately spans several entries for the stack, boot info, framebuffer,
// and any other early mappings it creates before the stub runs.
pub const STUB_DYNAMIC_RANGE_START: u64 = 0xFFFF_8900_0000_0000;
pub const STUB_DYNAMIC_RANGE_END: u64 = 0xFFFF_9000_0000_0000;

pub const MAX_BOOT_MEMORY_REGIONS: usize = 256;
pub const MAX_KERNEL_SECTIONS: usize = 96;

#[derive(Debug)]
#[repr(C)]
pub struct BootInfo {
    pub magic: u64,
    pub version: u32,
    pub flags: u32,
    pub memory_regions: MemoryRegions,
    pub framebuffer: Optional<FrameBuffer>,
    pub physical_memory_offset: Optional<u64>,
    pub recursive_index: Optional<u16>,
    pub rsdp_addr: Optional<u64>,
    pub tls_template: Optional<TlsTemplate>,
    pub ramdisk_addr: Optional<u64>,
    pub ramdisk_len: u64,
    pub kernel_addr: u64,
    pub kernel_len: u64,
    pub kernel_image_offset: u64,
    pub kernel_image_base: u64,
    pub kernel_image_size: u64,
    pub kernel_entry: u64,
    pub kernel_sections: KernelSections,
    pub stub_base: u64,
    pub stub_size: u64,
}

impl BootInfo {
    pub const fn empty() -> Self {
        Self {
            magic: RUSTOS_BOOT_INFO_MAGIC,
            version: RUSTOS_BOOT_INFO_VERSION,
            flags: 0,
            memory_regions: MemoryRegions {
                ptr: core::ptr::null_mut(),
                len: 0,
            },
            framebuffer: Optional::None,
            physical_memory_offset: Optional::None,
            recursive_index: Optional::None,
            rsdp_addr: Optional::None,
            tls_template: Optional::None,
            ramdisk_addr: Optional::None,
            ramdisk_len: 0,
            kernel_addr: 0,
            kernel_len: 0,
            kernel_image_offset: 0,
            kernel_image_base: 0,
            kernel_image_size: 0,
            kernel_entry: 0,
            kernel_sections: KernelSections {
                ptr: core::ptr::null(),
                len: 0,
            },
            stub_base: 0,
            stub_size: 0,
        }
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct MemoryRegions {
    pub ptr: *mut MemoryRegion,
    pub len: usize,
}

impl ops::Deref for MemoryRegions {
    type Target = [MemoryRegion];

    fn deref(&self) -> &Self::Target {
        unsafe { slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl ops::DerefMut for MemoryRegions {
    fn deref_mut(&mut self) -> &mut Self::Target {
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
    UnknownUefi(u32),
    UnknownBios(u32),
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
    pub buffer_start: u64,
    pub info: FrameBufferInfo,
}

impl FrameBuffer {
    pub const unsafe fn new(buffer_start: u64, info: FrameBufferInfo) -> Self {
        Self { buffer_start, info }
    }

    pub fn buffer(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.buffer_start as *const u8, self.info.byte_len) }
    }

    pub fn buffer_mut(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.buffer_start as *mut u8, self.info.byte_len) }
    }

    pub const fn info(&self) -> FrameBufferInfo {
        self.info
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
pub struct TlsTemplate {
    pub start_addr: u64,
    pub file_size: u64,
    pub mem_size: u64,
}

#[derive(Debug)]
#[repr(C)]
pub struct KernelSections {
    pub ptr: *const KernelSection,
    pub len: usize,
}

impl KernelSections {
    pub fn as_slice(&self) -> &[KernelSection] {
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
