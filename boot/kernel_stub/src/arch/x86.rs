use core::arch::asm;

use bootloader_api::config::Mapping;
use bootloader_api::info::{
    MemoryRegionKind as BootMemoryRegionKind, PixelFormat as BootPixelFormat,
};
use bootloader_api::{entry_point, BootInfo as BootloaderBootInfo, BootloaderConfig};
use goblin::pe::header::COFF_MACHINE_X86_64;
use kernel_abi::arch::{
    ArchInfo, PeTlsDirectory, KERNEL_PE_BASE, STUB_DYNAMIC_RANGE_END, STUB_DYNAMIC_RANGE_START,
    STUB_IMAGE_BASE,
};
use kernel_abi::{
    BootInfo, FdtHeader, FrameBuffer, FrameBufferInfo, MemoryRegionKind, Optional, PixelFormat,
};
use x86_64::instructions::port::Port;
use x86_64::structures::paging::{
    mapper::RecursivePageTable, mapper::TranslateError, FrameAllocator, Mapper, Page, PageTable,
    PageTableFlags, PageTableIndex, PhysFrame, Size4KiB,
};
use x86_64::{PhysAddr, VirtAddr};

use crate::platform::{
    BootloaderMemoryRegion, BootloaderPlatform, KernelImagePermissions, KernelImagePlatform,
    PhysRange, Platform,
};

pub struct X86Platform;

pub type PlatformImpl = X86Platform;

const PAGE_SIZE: u64 = 0x1000;
const LOW_RESERVED_END: u64 = 0x20_0000;

static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();
    config.mappings.physical_memory = None;
    config.mappings.page_table_recursive = Some(Mapping::Dynamic);
    config.kernel_stack_size = 1 * 1024 * 1024;
    config.mappings.kernel_stack = Mapping::Dynamic;
    config.mappings.framebuffer = Mapping::Dynamic;
    config.mappings.dynamic_range_start = Some(STUB_DYNAMIC_RANGE_START);
    config.mappings.dynamic_range_end = Some(STUB_DYNAMIC_RANGE_END);
    config
};

entry_point!(stub_start, config = &BOOTLOADER_CONFIG);

fn stub_start(boot_info: &'static mut BootloaderBootInfo) -> ! {
    crate::start::<X86Platform>(boot_info)
}

impl Platform for X86Platform {
    const NAME: &'static str = "x86_64";

    fn init_debug() {
        unsafe {
            let mut data = Port::<u8>::new(0x3F8);
            let mut interrupt_enable = Port::<u8>::new(0x3F9);
            let mut fifo_control = Port::<u8>::new(0x3FA);
            let mut line_control = Port::<u8>::new(0x3FB);
            let mut modem_control = Port::<u8>::new(0x3FC);

            interrupt_enable.write(0x00);
            line_control.write(0x80);
            data.write(0x03);
            interrupt_enable.write(0x00);
            line_control.write(0x03);
            fifo_control.write(0xC7);
            modem_control.write(0x0B);
        }
    }

    fn write_debug_byte(byte: u8) {
        unsafe {
            let mut line_status = Port::<u8>::new(0x3FD);
            while line_status.read() & 0x20 == 0 {
                core::hint::spin_loop();
            }
            let mut data = Port::<u8>::new(0x3F8);
            data.write(byte);
        }
    }

    fn halt() -> ! {
        loop {
            x86_64::instructions::hlt();
        }
    }
}

impl KernelImagePlatform for X86Platform {
    type ImageMapper = RecursivePageTable<'static>;
    type FrameAllocator = BootFrameAllocator;
    type TlsDirectory = PeTlsDirectory;

    fn base_page_size() -> u64 {
        PAGE_SIZE
    }

    fn kernel_image_base() -> u64 {
        KERNEL_PE_BASE
    }

    fn validate_kernel_machine(machine: u16) -> Result<(), &'static str> {
        if machine == COFF_MACHINE_X86_64 {
            Ok(())
        } else {
            Err("kernel_stub: kernel PE machine is not x86_64")
        }
    }

    fn map_kernel_image_range(
        mapper: &mut Self::ImageMapper,
        frame_allocator: &mut Self::FrameAllocator,
        base: u64,
        size: u64,
    ) -> Result<(), &'static str> {
        if size == 0 || base & (PAGE_SIZE - 1) != 0 {
            return Err("kernel_stub: invalid PE image range");
        }

        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;
        let start = Page::<Size4KiB>::containing_address(VirtAddr::new(base));
        let end = Page::<Size4KiB>::containing_address(VirtAddr::new(base + size - 1));

        for page in Page::range_inclusive(start, end) {
            match mapper.translate_page(page) {
                Ok(_) => return Err("kernel_stub: kernel PE preferred base is already mapped"),
                Err(TranslateError::PageNotMapped) => {}
                Err(_) => {
                    return Err("kernel_stub: kernel PE preferred base overlaps a huge mapping")
                }
            }

            let frame = frame_allocator
                .allocate_frame()
                .ok_or("kernel_stub: out of physical memory while mapping PE kernel")?;
            unsafe {
                mapper
                    .map_to(page, frame, flags, frame_allocator)
                    .map_err(|_| "kernel_stub: failed to map PE kernel page")?
                    .flush();
            }
        }

        Ok(())
    }

    fn set_kernel_image_permissions(
        mapper: &mut Self::ImageMapper,
        base: u64,
        size: u64,
        permissions: KernelImagePermissions,
    ) -> Result<(), &'static str> {
        let start = Page::<Size4KiB>::containing_address(VirtAddr::new(base));
        let end = Page::<Size4KiB>::containing_address(VirtAddr::new(base + size - 1));

        let mut flags = PageTableFlags::PRESENT;
        if permissions.writable {
            flags |= PageTableFlags::WRITABLE;
        }
        if !permissions.executable {
            flags |= PageTableFlags::NO_EXECUTE;
        }

        for page in Page::range_inclusive(start, end) {
            unsafe {
                mapper
                    .update_flags(page, flags)
                    .map_err(|_| "kernel_stub: failed to update PE page permissions")?
                    .flush();
            }
        }

        Ok(())
    }

    fn tls_directory_from_pe(directory: goblin::pe::tls::ImageTlsDirectory) -> Self::TlsDirectory {
        PeTlsDirectory {
            start_address_of_raw_data: directory.start_address_of_raw_data,
            end_address_of_raw_data: directory.end_address_of_raw_data,
            address_of_index: directory.address_of_index,
            address_of_callbacks: directory.address_of_callbacks,
            size_of_zero_fill: directory.size_of_zero_fill,
            characteristics: directory.characteristics,
        }
    }

    fn validate_tls_directory(
        image_base: u64,
        image_size: u64,
        directory: &Self::TlsDirectory,
    ) -> Result<(), &'static str> {
        let image_end = image_base
            .checked_add(image_size)
            .ok_or("kernel_stub: PE image range overflow")?;

        if directory.start_address_of_raw_data != 0 || directory.end_address_of_raw_data != 0 {
            if directory.start_address_of_raw_data > directory.end_address_of_raw_data {
                return Err("kernel_stub: PE TLS raw data range is backwards");
            }
            if directory.start_address_of_raw_data < image_base
                || directory.end_address_of_raw_data > image_end
            {
                return Err("kernel_stub: PE TLS raw data is outside the kernel image");
            }
        }

        if directory.address_of_index != 0 {
            let index_end = directory
                .address_of_index
                .checked_add(core::mem::size_of::<u32>() as u64)
                .ok_or("kernel_stub: PE TLS index address overflow")?;
            if directory.address_of_index < image_base || index_end > image_end {
                return Err("kernel_stub: PE TLS index is outside the kernel image");
            }
        }

        if directory.address_of_callbacks != 0
            && (directory.address_of_callbacks < image_base
                || directory.address_of_callbacks >= image_end)
        {
            return Err("kernel_stub: PE TLS callbacks pointer is outside the kernel image");
        }

        Ok(())
    }

    fn prepare_tls_directory(directory: &Self::TlsDirectory) -> Result<(), &'static str> {
        if directory.address_of_index != 0 {
            unsafe {
                (directory.address_of_index as *mut u32).write(0);
            }
        }
        Ok(())
    }

    unsafe fn enter_kernel(entry: u64, boot_info: *const BootInfo) -> ! {
        unsafe {
            asm!(
                "cld",
                "and rsp, -16",
                "sub rsp, 40",
                "mov qword ptr [rsp], 0",
                "jmp rax",
                in("rax") entry,
                in("rcx") boot_info,
                options(noreturn)
            )
        }
    }
}

impl BootloaderPlatform for X86Platform {
    type BootloaderInfo = BootloaderBootInfo;

    fn init_mapper(
        bootloader_info: &Self::BootloaderInfo,
    ) -> Result<Self::ImageMapper, &'static str> {
        let recursive_index = bootloader_info
            .recursive_index
            .into_option()
            .ok_or("kernel_stub: bootloader did not map page tables recursively")?;
        Ok(unsafe { init_recursive_mapper(recursive_index) })
    }

    fn init_frame_allocator(bootloader_info: &Self::BootloaderInfo) -> Self::FrameAllocator {
        BootFrameAllocator::new(bootloader_info)
    }

    fn for_each_memory_region(
        bootloader_info: &Self::BootloaderInfo,
        mut f: impl FnMut(BootloaderMemoryRegion) -> Result<(), &'static str>,
    ) -> Result<(), &'static str> {
        for region in bootloader_info.memory_regions.iter() {
            f(BootloaderMemoryRegion {
                start: region.start,
                end: region.end,
                kind: translate_memory_kind(region.kind),
            })?;
        }
        Ok(())
    }

    fn for_each_reserved_memory_range(
        mut f: impl FnMut(PhysRange) -> Result<(), &'static str>,
    ) -> Result<(), &'static str> {
        f(PhysRange {
            start: 0,
            end: LOW_RESERVED_END,
        })
    }

    fn framebuffer(bootloader_info: &mut Self::BootloaderInfo) -> Optional<FrameBuffer> {
        match bootloader_info.framebuffer.as_mut() {
            Some(fb) => {
                let info = fb.info();
                let buffer = fb.buffer_mut();
                Optional::Some(unsafe {
                    FrameBuffer::new(
                        buffer.as_mut_ptr() as u64,
                        FrameBufferInfo {
                            byte_len: info.byte_len,
                            width: info.width,
                            height: info.height,
                            pixel_format: translate_pixel_format(info.pixel_format),
                            bytes_per_pixel: info.bytes_per_pixel,
                            stride: info.stride,
                        },
                    )
                })
            }
            None => Optional::None,
        }
    }

    fn fdt_header(_bootloader_info: &Self::BootloaderInfo) -> Optional<*const FdtHeader> {
        Optional::None
    }

    fn ramdisk(bootloader_info: &Self::BootloaderInfo) -> (Optional<u64>, u64) {
        (
            translate_optional(bootloader_info.ramdisk_addr),
            bootloader_info.ramdisk_len,
        )
    }

    fn stub_image_base() -> u64 {
        STUB_IMAGE_BASE
    }

    fn stub_image_size(bootloader_info: &Self::BootloaderInfo) -> u64 {
        crate::align_up(
            bootloader_info.kernel_len.max(Self::base_page_size()),
            Self::base_page_size(),
        )
    }

    fn finalize_boot_info(
        bootloader_info: &mut Self::BootloaderInfo,
        mut boot_info: BootInfo,
        tls_directory: Optional<Self::TlsDirectory>,
    ) -> Result<(BootInfo, ArchInfo), &'static str> {
        let arch_info = ArchInfo {
            recursive_index: translate_optional(bootloader_info.recursive_index),
            pe_tls_directory: tls_directory,
        };
        boot_info.rsdp_addr = translate_optional(bootloader_info.rsdp_addr);
        boot_info.arch_info = arch_info;
        Ok((boot_info, arch_info))
    }
}

pub struct BootFrameAllocator {
    regions: *const bootloader_api::info::MemoryRegion,
    len: usize,
    next_frame: u64,
}

impl BootFrameAllocator {
    fn new(boot_info: &BootloaderBootInfo) -> Self {
        Self {
            regions: boot_info.memory_regions.as_ptr(),
            len: boot_info.memory_regions.len(),
            next_frame: LOW_RESERVED_END / PAGE_SIZE,
        }
    }

    fn regions(&self) -> &[bootloader_api::info::MemoryRegion] {
        unsafe { core::slice::from_raw_parts(self.regions, self.len) }
    }
}

unsafe impl FrameAllocator<Size4KiB> for BootFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        let mut best: Option<u64> = None;

        for region in self.regions() {
            if region.kind != BootMemoryRegionKind::Usable || region.end <= region.start {
                continue;
            }

            let start = crate::align_up(region.start, PAGE_SIZE).max(self.next_frame * PAGE_SIZE);
            let end = region.end & !(PAGE_SIZE - 1);
            if start < end {
                best = Some(best.map_or(start, |current| current.min(start)));
            }
        }

        let phys = best?;
        self.next_frame = phys / PAGE_SIZE + 1;
        crate::record_allocated_frame(phys).ok()?;
        Some(PhysFrame::containing_address(PhysAddr::new(phys)))
    }
}

fn translate_memory_kind(kind: BootMemoryRegionKind) -> MemoryRegionKind {
    match kind {
        BootMemoryRegionKind::Usable => MemoryRegionKind::Usable,
        BootMemoryRegionKind::Bootloader => MemoryRegionKind::Bootloader,
        BootMemoryRegionKind::UnknownUefi(value) | BootMemoryRegionKind::UnknownBios(value) => {
            MemoryRegionKind::Unknown(value)
        }
        _ => MemoryRegionKind::Reserved,
    }
}

fn translate_pixel_format(pixel_format: BootPixelFormat) -> PixelFormat {
    match pixel_format {
        BootPixelFormat::Rgb => PixelFormat::Rgb,
        BootPixelFormat::Bgr => PixelFormat::Bgr,
        BootPixelFormat::U8 => PixelFormat::U8,
        BootPixelFormat::Unknown {
            red_position,
            green_position,
            blue_position,
        } => PixelFormat::Unknown {
            red_position,
            green_position,
            blue_position,
        },
        _ => PixelFormat::Rgb,
    }
}

fn translate_optional<T>(value: bootloader_api::info::Optional<T>) -> Optional<T> {
    match value.into_option() {
        Some(value) => Optional::Some(value),
        None => Optional::None,
    }
}

unsafe fn init_recursive_mapper(recursive_index: u16) -> RecursivePageTable<'static> {
    let recursive_index = PageTableIndex::new(recursive_index);
    let level_4_table = unsafe { active_level_4_table(recursive_index) };
    unsafe { RecursivePageTable::new_unchecked(level_4_table, recursive_index) }
}

unsafe fn active_level_4_table(recursive_index: PageTableIndex) -> &'static mut PageTable {
    let virt =
        kernel_types::arch::recursive_level_4_table_addr(u64::from(recursive_index) as u16);
    unsafe { &mut *virt.as_mut_ptr() }
}
