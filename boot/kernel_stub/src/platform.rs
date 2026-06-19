use goblin::pe::tls::ImageTlsDirectory;
use kernel_abi::{
    BootArchInfo as KernelBootArchInfo, BootInfo, FdtHeader, FrameBuffer, MemoryRegionKind,
    Optional,
};

pub type ActivePlatform = crate::arch::PlatformImpl;

#[derive(Clone, Copy)]
pub struct LoadedKernel {
    pub image_base: u64,
    pub image_size: u64,
    pub entry: u64,
    pub section_count: usize,
}

#[derive(Clone, Copy)]
pub struct PhysRange {
    pub start: u64,
    pub end: u64,
}

impl PhysRange {
    pub const fn empty() -> Self {
        Self { start: 0, end: 0 }
    }
}

#[derive(Clone, Copy)]
pub struct BootloaderMemoryRegion {
    pub start: u64,
    pub end: u64,
    pub kind: MemoryRegionKind,
}

#[derive(Clone, Copy)]
pub struct KernelImagePermissions {
    pub writable: bool,
    pub executable: bool,
}

pub trait Platform {
    type BootArchInfo: KernelBootArchInfo;

    const NAME: &'static str;

    fn init_debug();
    fn write_debug_byte(byte: u8);
    fn halt() -> !;
}

pub trait KernelImagePlatform: Platform {
    type ImageMapper;
    type FrameAllocator;
    type TlsDirectory: Copy;

    fn base_page_size() -> u64;
    fn kernel_image_base() -> u64;

    fn validate_kernel_machine(machine: u16) -> Result<(), &'static str>;

    fn map_kernel_image_range(
        mapper: &mut Self::ImageMapper,
        frame_allocator: &mut Self::FrameAllocator,
        base: u64,
        size: u64,
    ) -> Result<(), &'static str>;

    fn set_kernel_image_permissions(
        mapper: &mut Self::ImageMapper,
        base: u64,
        size: u64,
        permissions: KernelImagePermissions,
    ) -> Result<(), &'static str>;

    fn tls_directory_from_pe(directory: ImageTlsDirectory) -> Self::TlsDirectory;
    fn validate_tls_directory(
        image_base: u64,
        image_size: u64,
        directory: &Self::TlsDirectory,
    ) -> Result<(), &'static str>;
    fn prepare_tls_directory(directory: &Self::TlsDirectory) -> Result<(), &'static str>;

    unsafe fn enter_kernel(entry: u64, boot_info: *const BootInfo<Self::BootArchInfo>) -> !;
}

pub trait BootloaderPlatform: KernelImagePlatform {
    type BootloaderInfo;

    fn init_mapper(
        bootloader_info: &Self::BootloaderInfo,
    ) -> Result<Self::ImageMapper, &'static str>;

    fn init_frame_allocator(bootloader_info: &Self::BootloaderInfo) -> Self::FrameAllocator;

    fn for_each_memory_region(
        bootloader_info: &Self::BootloaderInfo,
        f: impl FnMut(BootloaderMemoryRegion) -> Result<(), &'static str>,
    ) -> Result<(), &'static str>;

    fn for_each_reserved_memory_range(
        _f: impl FnMut(PhysRange) -> Result<(), &'static str>,
    ) -> Result<(), &'static str> {
        Ok(())
    }

    fn framebuffer(bootloader_info: &mut Self::BootloaderInfo) -> Optional<FrameBuffer>;
    fn fdt_header(bootloader_info: &Self::BootloaderInfo) -> Optional<*const FdtHeader>;
    fn ramdisk(bootloader_info: &Self::BootloaderInfo) -> (Optional<u64>, u64);
    fn stub_image_base() -> u64;
    fn stub_image_size(bootloader_info: &Self::BootloaderInfo) -> u64;

    fn finalize_boot_info(
        bootloader_info: &mut Self::BootloaderInfo,
        boot_info: BootInfo<Self::BootArchInfo>,
        tls_directory: Optional<Self::TlsDirectory>,
    ) -> Result<BootInfo<Self::BootArchInfo>, &'static str>;
}
