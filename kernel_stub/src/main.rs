#![feature(alloc_error_handler)]
#![no_std]
#![no_main]

extern crate alloc;

use alloc::alloc::{GlobalAlloc, Layout};
use bootloader_api::config::Mapping;
use bootloader_api::info::{
    MemoryRegion as BootMemoryRegion, MemoryRegionKind as BootMemoryRegionKind,
};
use bootloader_api::{entry_point, BootInfo as BootloaderBootInfo, BootloaderConfig};
use core::arch::asm;
use core::fmt::{self, Write};
use core::panic::PanicInfo;
use core::ptr::{addr_of_mut, copy_nonoverlapping};
use goblin::pe::data_directories::DataDirectory;
use goblin::pe::header::COFF_MACHINE_X86_64;
use goblin::pe::optional_header::MAGIC_64;
use goblin::pe::section_table::{SectionTable, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE};
use goblin::pe::PE;
use kernel_abi::{
    BootInfo, FrameBuffer, FrameBufferInfo, KernelSection, KernelSections, KernelSymbol,
    KernelSymbolString, KernelSymbols, KernelTextSection, MemoryRegion, MemoryRegionKind,
    MemoryRegions, Optional, PeTlsDirectory, PixelFormat, KERNEL_PE_BASE, MAX_BOOT_MEMORY_REGIONS,
    MAX_KERNEL_EXPORT_SYMBOLS, MAX_KERNEL_IMPORT_SYMBOLS, MAX_KERNEL_SECTIONS,
    MAX_KERNEL_SYMBOL_STRING_BYTES, PHYSICAL_MEMORY_OFFSET, RUSTOS_BOOT_INFO_MAGIC,
    RUSTOS_BOOT_INFO_VERSION, STUB_DYNAMIC_RANGE_END, STUB_DYNAMIC_RANGE_START, STUB_IMAGE_BASE,
};
use x86_64::instructions::{hlt, port::Port};
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::{
    mapper::TranslateError, FrameAllocator, Mapper, OffsetPageTable, Page, PageTable,
    PageTableFlags, PhysFrame, Size4KiB,
};
use x86_64::{PhysAddr, VirtAddr};

const KERNEL_PE: &[u8] = include_bytes!(env!("KERNEL_PE_PATH"));
const PAGE_SIZE: u64 = 0x1000;
const LOW_RESERVED_END: u64 = 0x20_0000;
const STUB_HEAP_SIZE: usize = 2 * 1024 * 1024;
const MAX_ALLOCATED_RANGES: usize = 128;

pub static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();
    config.mappings.physical_memory = Some(Mapping::FixedAddress(PHYSICAL_MEMORY_OFFSET));
    config.kernel_stack_size = 1024 * 1024;
    config.mappings.kernel_stack = Mapping::Dynamic;
    config.mappings.framebuffer = Mapping::Dynamic;
    config.mappings.dynamic_range_start = Some(STUB_DYNAMIC_RANGE_START);
    config.mappings.dynamic_range_end = Some(STUB_DYNAMIC_RANGE_END);
    config
};

entry_point!(stub_start, config = &BOOTLOADER_CONFIG);

#[repr(align(16))]
struct Heap([u8; STUB_HEAP_SIZE]);

struct BumpAllocator;

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator;

static mut HEAP: Heap = Heap([0; STUB_HEAP_SIZE]);
static NEXT_HEAP_OFFSET: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

unsafe impl GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let heap_start = addr_of_mut!(HEAP.0).cast::<u8>() as usize;
        let align_mask = layout.align().saturating_sub(1);
        let size = layout.size();

        let mut current = NEXT_HEAP_OFFSET.load(core::sync::atomic::Ordering::Relaxed);
        loop {
            let aligned = (heap_start + current + align_mask) & !align_mask;
            let next = aligned
                .checked_add(size)
                .and_then(|end| end.checked_sub(heap_start));
            let Some(next) = next else {
                return core::ptr::null_mut();
            };
            if next > STUB_HEAP_SIZE {
                return core::ptr::null_mut();
            }
            match NEXT_HEAP_OFFSET.compare_exchange(
                current,
                next,
                core::sync::atomic::Ordering::SeqCst,
                core::sync::atomic::Ordering::SeqCst,
            ) {
                Ok(_) => return aligned as *mut u8,
                Err(actual) => current = actual,
            }
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[alloc_error_handler]
fn alloc_error(_layout: Layout) -> ! {
    fatal("kernel_stub: allocation failed")
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println_fmt(format_args!("kernel_stub panic: {info}"));
    halt_loop()
}

static mut ABI_MEMORY_REGIONS: [MemoryRegion; MAX_BOOT_MEMORY_REGIONS] =
    [MemoryRegion::empty(); MAX_BOOT_MEMORY_REGIONS];
static mut ABI_KERNEL_SECTIONS: [KernelSection; MAX_KERNEL_SECTIONS] =
    [KernelSection::empty(); MAX_KERNEL_SECTIONS];
static mut ABI_KERNEL_IMPORT_SYMBOLS: [KernelSymbol; MAX_KERNEL_IMPORT_SYMBOLS] =
    [KernelSymbol::empty(); MAX_KERNEL_IMPORT_SYMBOLS];
static mut ABI_KERNEL_EXPORT_SYMBOLS: [KernelSymbol; MAX_KERNEL_EXPORT_SYMBOLS] =
    [KernelSymbol::empty(); MAX_KERNEL_EXPORT_SYMBOLS];
static mut ABI_KERNEL_SYMBOL_STRING_BYTES: [u8; MAX_KERNEL_SYMBOL_STRING_BYTES] =
    [0; MAX_KERNEL_SYMBOL_STRING_BYTES];
static mut ABI_KERNEL_SYMBOL_STRING_LEN: usize = 0;
static mut ABI_BOOT_INFO: BootInfo = BootInfo::empty();
static mut ALLOCATED_RANGES: [PhysRange; MAX_ALLOCATED_RANGES] =
    [PhysRange::empty(); MAX_ALLOCATED_RANGES];
static mut ALLOCATED_RANGE_COUNT: usize = 0;

#[derive(Clone, Copy)]
struct PhysRange {
    start: u64,
    end: u64,
}

impl PhysRange {
    const fn empty() -> Self {
        Self { start: 0, end: 0 }
    }
}

#[derive(Clone, Copy)]
struct LoadedKernel {
    image_base: u64,
    image_size: u64,
    entry: u64,
    section_count: usize,
}

unsafe fn enter_kernel_pe(entry: u64, boot_info: *const BootInfo) -> ! {
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

fn stub_start(boot_info: &'static mut BootloaderBootInfo) -> ! {
    init_serial();
    serial_println("kernel_stub: loading embedded PE kernel");

    let phys_offset = boot_info
        .physical_memory_offset
        .into_option()
        .unwrap_or_else(|| fatal("kernel_stub: bootloader did not map physical memory"));

    let mut frame_allocator = BootFrameAllocator::new(&boot_info.memory_regions);
    let mut mapper = unsafe { init_mapper(VirtAddr::new(phys_offset)) };

    let loaded = load_kernel_pe(&mut mapper, &mut frame_allocator).unwrap_or_else(|err| fatal(err));
    let handoff = build_handoff(boot_info, loaded).unwrap_or_else(|err| fatal(err));

    serial_println("kernel_stub: jumping to PE kernel");

    unsafe { enter_kernel_pe(loaded.entry, handoff as *const BootInfo) }
}

fn load_kernel_pe(
    mapper: &mut OffsetPageTable<'static>,
    frame_allocator: &mut BootFrameAllocator,
) -> Result<LoadedKernel, &'static str> {
    let pe = PE::parse(KERNEL_PE).map_err(|_| "kernel_stub: embedded kernel is not a PE image")?;
    validate_kernel_pe(&pe)?;

    let opt = pe
        .header
        .optional_header
        .as_ref()
        .ok_or("kernel_stub: PE optional header missing")?;
    let image_size = align_up_4k(opt.windows_fields.size_of_image as u64);
    let headers_size = opt.windows_fields.size_of_headers as usize;
    let image_base = opt.windows_fields.image_base;

    map_image_range(mapper, frame_allocator, image_base, image_size)?;

    unsafe {
        core::ptr::write_bytes(image_base as *mut u8, 0, image_size as usize);
        let header_copy_len = headers_size.min(KERNEL_PE.len()).min(image_size as usize);
        copy_nonoverlapping(KERNEL_PE.as_ptr(), image_base as *mut u8, header_copy_len);
    }

    for section in &pe.sections {
        copy_section(image_base, image_size, section)?;
    }

    prepare_kernel_pe_tls(image_base, image_size, &pe)?;
    apply_section_permissions(mapper, image_base, image_size, &pe.sections)?;

    let entry = image_base
        .checked_add(pe.entry as u64)
        .ok_or("kernel_stub: PE entry address overflow")?;

    Ok(LoadedKernel {
        image_base,
        image_size,
        entry,
        section_count: pe.sections.len(),
    })
}

fn validate_kernel_pe(pe: &PE<'_>) -> Result<(), &'static str> {
    let opt = pe
        .header
        .optional_header
        .as_ref()
        .ok_or("kernel_stub: PE optional header missing")?;

    if !pe.is_64 || opt.standard_fields.magic != MAGIC_64 {
        return Err("kernel_stub: kernel PE must be PE32+");
    }
    if pe.header.coff_header.machine != COFF_MACHINE_X86_64 {
        return Err("kernel_stub: kernel PE machine is not x86_64");
    }
    if pe.image_base != KERNEL_PE_BASE || opt.windows_fields.image_base != KERNEL_PE_BASE {
        return Err("kernel_stub: kernel PE preferred base does not match the kernel layout");
    }
    if pe.entry == 0 {
        return Err("kernel_stub: kernel PE has no entry point");
    }
    if pe.relocation_data.is_some()
        || directory_present(opt.data_directories.get_base_relocation_table())
    {
        return Err("kernel_stub: kernel PE relocations are not supported");
    }
    if directory_present(opt.data_directories.get_delay_import_descriptor()) {
        return Err("kernel_stub: kernel PE delay imports are not supported");
    }
    if pe.sections.len() > MAX_KERNEL_SECTIONS {
        return Err("kernel_stub: kernel PE has too many sections");
    }

    Ok(())
}

fn prepare_kernel_pe_tls(
    image_base: u64,
    image_size: u64,
    pe: &PE<'_>,
) -> Result<(), &'static str> {
    let Some(tls) = pe.tls_data.as_ref() else {
        return Ok(());
    };

    let directory = pe_tls_directory_from_goblin(tls.image_tls_directory);
    validate_pe_tls_directory(image_base, image_size, &directory)?;

    if directory.address_of_index != 0 {
        unsafe {
            (directory.address_of_index as *mut u32).write(0);
        }
    }

    Ok(())
}

fn directory_present(dir: Option<&DataDirectory>) -> bool {
    dir.is_some_and(|dir| dir.virtual_address != 0 && dir.size != 0)
}

fn map_image_range(
    mapper: &mut OffsetPageTable<'static>,
    frame_allocator: &mut BootFrameAllocator,
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
            Err(_) => return Err("kernel_stub: kernel PE preferred base overlaps a huge mapping"),
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

fn copy_section(base: u64, image_size: u64, section: &SectionTable) -> Result<(), &'static str> {
    let virt_offset = section.virtual_address as u64;
    let virt_size = section.virtual_size as usize;
    let raw_offset = section.pointer_to_raw_data as usize;
    let raw_size = section.size_of_raw_data as usize;
    let section_end = virt_offset
        .checked_add(raw_size.max(virt_size) as u64)
        .ok_or("kernel_stub: PE section range overflow")?;

    if section_end > image_size {
        return Err("kernel_stub: PE section exceeds SizeOfImage");
    }
    if raw_size != 0
        && raw_offset
            .checked_add(raw_size)
            .is_none_or(|end| end > KERNEL_PE.len())
    {
        return Err("kernel_stub: PE section raw data is truncated");
    }

    let dst = (base + virt_offset) as *mut u8;
    unsafe {
        if raw_size != 0 {
            copy_nonoverlapping(KERNEL_PE.as_ptr().add(raw_offset), dst, raw_size);
        }
        if virt_size > raw_size {
            dst.add(raw_size).write_bytes(0, virt_size - raw_size);
        }
    }

    Ok(())
}

fn apply_section_permissions(
    mapper: &mut OffsetPageTable<'static>,
    base: u64,
    image_size: u64,
    sections: &[SectionTable],
) -> Result<(), &'static str> {
    set_page_flags(
        mapper,
        base,
        image_size,
        PageTableFlags::PRESENT | PageTableFlags::NO_EXECUTE,
    )?;

    for section in sections {
        let section_size = core::cmp::max(section.virtual_size, section.size_of_raw_data) as u64;
        if section_size == 0 {
            continue;
        }

        let mut flags = PageTableFlags::PRESENT;
        if section.characteristics & IMAGE_SCN_MEM_WRITE != 0 {
            flags |= PageTableFlags::WRITABLE;
        }
        if section.characteristics & IMAGE_SCN_MEM_EXECUTE == 0 {
            flags |= PageTableFlags::NO_EXECUTE;
        }

        set_page_flags(
            mapper,
            base + section.virtual_address as u64,
            section_size,
            flags,
        )?;
    }

    Ok(())
}

fn set_page_flags(
    mapper: &mut OffsetPageTable<'static>,
    base: u64,
    size: u64,
    flags: PageTableFlags,
) -> Result<(), &'static str> {
    let start = Page::<Size4KiB>::containing_address(VirtAddr::new(base));
    let end = Page::<Size4KiB>::containing_address(VirtAddr::new(base + size - 1));

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

fn build_handoff(
    boot_info: &'static mut BootloaderBootInfo,
    loaded: LoadedKernel,
) -> Result<&'static mut BootInfo, &'static str> {
    let memory_region_count = translate_memory_regions(&boot_info.memory_regions)?;
    let section_count = translate_kernel_sections(loaded.image_base, loaded.section_count)?;
    let kernel_text = translate_kernel_text_section(loaded.image_base)?;
    let pe_tls_directory = translate_kernel_tls_directory(loaded.image_base, loaded.image_size)?;
    let (kernel_import_count, kernel_export_count) = translate_kernel_symbols()?;

    let framebuffer = match boot_info.framebuffer.as_mut() {
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
    };

    unsafe {
        ABI_BOOT_INFO = BootInfo {
            magic: RUSTOS_BOOT_INFO_MAGIC,
            version: RUSTOS_BOOT_INFO_VERSION,
            flags: 0,
            memory_regions: MemoryRegions {
                ptr: addr_of_mut!(ABI_MEMORY_REGIONS).cast::<MemoryRegion>(),
                len: memory_region_count,
            },
            framebuffer,
            physical_memory_offset: Optional::Some(PHYSICAL_MEMORY_OFFSET),
            recursive_index: translate_optional(boot_info.recursive_index),
            rsdp_addr: translate_optional(boot_info.rsdp_addr),
            tls_template: Optional::None,
            pe_tls_directory,
            kernel_imports: KernelSymbols {
                ptr: addr_of_mut!(ABI_KERNEL_IMPORT_SYMBOLS).cast::<KernelSymbol>(),
                len: kernel_import_count,
            },
            kernel_exports: KernelSymbols {
                ptr: addr_of_mut!(ABI_KERNEL_EXPORT_SYMBOLS).cast::<KernelSymbol>(),
                len: kernel_export_count,
            },
            ramdisk_addr: translate_optional(boot_info.ramdisk_addr),
            ramdisk_len: boot_info.ramdisk_len,
            kernel_addr: 0,
            kernel_len: loaded.image_size,
            kernel_image_offset: 0,
            kernel_image_base: loaded.image_base,
            kernel_image_size: loaded.image_size,
            kernel_entry: loaded.entry,
            kernel_text,
            kernel_sections: KernelSections {
                ptr: addr_of_mut!(ABI_KERNEL_SECTIONS).cast::<KernelSection>(),
                len: section_count,
            },
            stub_base: STUB_IMAGE_BASE,
            stub_size: align_up_4k(boot_info.kernel_len.max(PAGE_SIZE)),
        };

        Ok(&mut *addr_of_mut!(ABI_BOOT_INFO))
    }
}

fn translate_memory_regions(boot_regions: &[BootMemoryRegion]) -> Result<usize, &'static str> {
    let mut out_len = 0usize;

    for region in boot_regions {
        if region.end <= region.start {
            continue;
        }

        let mut cursor = region.start;
        let kind = translate_memory_kind(region.kind);
        let ranges = unsafe {
            core::slice::from_raw_parts(
                addr_of_mut!(ALLOCATED_RANGES).cast::<PhysRange>(),
                ALLOCATED_RANGE_COUNT,
            )
        };

        if cursor < LOW_RESERVED_END && region.end > 0 {
            let end = region.end.min(LOW_RESERVED_END);
            push_translated_region(&mut out_len, cursor, end, MemoryRegionKind::Bootloader)?;
            cursor = end;
        }

        for reserved in ranges {
            let start = reserved.start.max(region.start).max(cursor);
            let end = reserved.end.min(region.end);
            if end <= start {
                continue;
            }

            if cursor < start {
                push_translated_region(&mut out_len, cursor, start, kind)?;
            }
            push_translated_region(&mut out_len, start, end, MemoryRegionKind::Bootloader)?;
            cursor = end;
        }

        if cursor < region.end {
            push_translated_region(&mut out_len, cursor, region.end, kind)?;
        }
    }

    Ok(out_len)
}

fn push_translated_region(
    out_len: &mut usize,
    start: u64,
    end: u64,
    kind: MemoryRegionKind,
) -> Result<(), &'static str> {
    if end <= start {
        return Ok(());
    }

    unsafe {
        if *out_len > 0 {
            let prev = &mut ABI_MEMORY_REGIONS[*out_len - 1];
            if prev.end == start && prev.kind == kind {
                prev.end = end;
                return Ok(());
            }
        }

        if *out_len >= MAX_BOOT_MEMORY_REGIONS {
            return Err("kernel_stub: translated memory map is too large");
        }
        ABI_MEMORY_REGIONS[*out_len] = MemoryRegion { start, end, kind };
        *out_len += 1;
    }

    Ok(())
}

fn translate_kernel_sections(image_base: u64, section_count: usize) -> Result<usize, &'static str> {
    let pe = PE::parse(KERNEL_PE).map_err(|_| "kernel_stub: failed to reparse PE sections")?;
    if section_count != pe.sections.len() {
        return Err("kernel_stub: PE section count changed unexpectedly");
    }

    for (idx, section) in pe.sections.iter().enumerate() {
        if idx >= MAX_KERNEL_SECTIONS {
            return Err("kernel_stub: too many PE sections for handoff");
        }
        unsafe {
            ABI_KERNEL_SECTIONS[idx] = KernelSection {
                name: section.name,
                virtual_address: section.virtual_address,
                virtual_size: section.virtual_size,
                raw_offset: section.pointer_to_raw_data,
                raw_size: section.size_of_raw_data,
                characteristics: section.characteristics,
                loaded_address: image_base + section.virtual_address as u64,
            };
        }
    }

    Ok(section_count)
}

fn translate_kernel_text_section(
    image_base: u64,
) -> Result<Optional<KernelTextSection>, &'static str> {
    let pe = PE::parse(KERNEL_PE).map_err(|_| "kernel_stub: failed to reparse PE .text")?;

    for section in &pe.sections {
        if section.name == *b".text\0\0\0" {
            let size = core::cmp::max(section.virtual_size, section.size_of_raw_data) as u64;
            return Ok(Optional::Some(KernelTextSection {
                base: image_base + section.virtual_address as u64,
                size,
            }));
        }
    }

    Ok(Optional::None)
}

fn translate_kernel_tls_directory(
    image_base: u64,
    image_size: u64,
) -> Result<Optional<PeTlsDirectory>, &'static str> {
    let pe = PE::parse(KERNEL_PE).map_err(|_| "kernel_stub: failed to reparse PE TLS")?;
    let Some(tls) = pe.tls_data.as_ref() else {
        return Ok(Optional::None);
    };

    let directory = pe_tls_directory_from_goblin(tls.image_tls_directory);
    validate_pe_tls_directory(image_base, image_size, &directory)?;
    Ok(Optional::Some(directory))
}

fn pe_tls_directory_from_goblin(directory: goblin::pe::tls::ImageTlsDirectory) -> PeTlsDirectory {
    PeTlsDirectory {
        start_address_of_raw_data: directory.start_address_of_raw_data,
        end_address_of_raw_data: directory.end_address_of_raw_data,
        address_of_index: directory.address_of_index,
        address_of_callbacks: directory.address_of_callbacks,
        size_of_zero_fill: directory.size_of_zero_fill,
        characteristics: directory.characteristics,
    }
}

fn validate_pe_tls_directory(
    image_base: u64,
    image_size: u64,
    directory: &PeTlsDirectory,
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

fn translate_kernel_symbols() -> Result<(usize, usize), &'static str> {
    let pe = PE::parse(KERNEL_PE).map_err(|_| "kernel_stub: failed to reparse PE symbols")?;

    unsafe {
        ABI_KERNEL_SYMBOL_STRING_LEN = 0;
    }

    let mut import_count = 0usize;
    for import in &pe.imports {
        if import_count >= MAX_KERNEL_IMPORT_SYMBOLS {
            return Err("kernel_stub: kernel PE has too many imported symbols");
        }

        let name = store_kernel_symbol_string(import.name.as_ref())?;
        let module = store_kernel_symbol_string(import.dll)?;
        unsafe {
            ABI_KERNEL_IMPORT_SYMBOLS[import_count] = KernelSymbol { name, module };
        }
        import_count += 1;
    }

    let export_module = pe.name.unwrap_or("kernel");
    let mut export_count = 0usize;
    for export in &pe.exports {
        if export_count >= MAX_KERNEL_EXPORT_SYMBOLS {
            return Err("kernel_stub: kernel PE has too many exported symbols");
        }

        let name = store_kernel_symbol_string(export.name.unwrap_or(""))?;
        let module = store_kernel_symbol_string(export_module)?;
        unsafe {
            ABI_KERNEL_EXPORT_SYMBOLS[export_count] = KernelSymbol { name, module };
        }
        export_count += 1;
    }

    Ok((import_count, export_count))
}

fn store_kernel_symbol_string(value: &str) -> Result<KernelSymbolString, &'static str> {
    if value.is_empty() {
        return Ok(KernelSymbolString::empty());
    }

    let bytes = value.as_bytes();
    unsafe {
        let start = ABI_KERNEL_SYMBOL_STRING_LEN;
        let end = start
            .checked_add(bytes.len())
            .ok_or("kernel_stub: kernel symbol string storage overflow")?;
        if end > MAX_KERNEL_SYMBOL_STRING_BYTES {
            return Err("kernel_stub: kernel symbol strings exceed handoff storage");
        }

        let dst = addr_of_mut!(ABI_KERNEL_SYMBOL_STRING_BYTES)
            .cast::<u8>()
            .add(start);
        copy_nonoverlapping(bytes.as_ptr(), dst, bytes.len());
        ABI_KERNEL_SYMBOL_STRING_LEN = end;

        Ok(KernelSymbolString {
            ptr: dst.cast_const(),
            len: bytes.len(),
        })
    }
}

fn translate_memory_kind(kind: BootMemoryRegionKind) -> MemoryRegionKind {
    match kind {
        BootMemoryRegionKind::Usable => MemoryRegionKind::Usable,
        BootMemoryRegionKind::Bootloader => MemoryRegionKind::Bootloader,
        BootMemoryRegionKind::UnknownUefi(value) => MemoryRegionKind::UnknownUefi(value),
        BootMemoryRegionKind::UnknownBios(value) => MemoryRegionKind::UnknownBios(value),
        _ => MemoryRegionKind::Bootloader,
    }
}

fn translate_pixel_format(pixel_format: bootloader_api::info::PixelFormat) -> PixelFormat {
    match pixel_format {
        bootloader_api::info::PixelFormat::Rgb => PixelFormat::Rgb,
        bootloader_api::info::PixelFormat::Bgr => PixelFormat::Bgr,
        bootloader_api::info::PixelFormat::U8 => PixelFormat::U8,
        bootloader_api::info::PixelFormat::Unknown {
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

struct BootFrameAllocator {
    regions: *const BootMemoryRegion,
    len: usize,
    next_frame: u64,
}

impl BootFrameAllocator {
    fn new(regions: &[BootMemoryRegion]) -> Self {
        Self {
            regions: regions.as_ptr(),
            len: regions.len(),
            next_frame: LOW_RESERVED_END / PAGE_SIZE,
        }
    }

    fn regions(&self) -> &[BootMemoryRegion] {
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

            let start = align_up_4k(region.start).max(self.next_frame * PAGE_SIZE);
            let end = region.end & !(PAGE_SIZE - 1);
            if start < end {
                best = Some(best.map_or(start, |current| current.min(start)));
            }
        }

        let phys = best?;
        self.next_frame = phys / PAGE_SIZE + 1;
        record_allocated_frame(phys).ok()?;
        Some(PhysFrame::containing_address(PhysAddr::new(phys)))
    }
}

fn record_allocated_frame(phys: u64) -> Result<(), &'static str> {
    unsafe {
        let end = phys + PAGE_SIZE;
        if ALLOCATED_RANGE_COUNT > 0 {
            let last = &mut ALLOCATED_RANGES[ALLOCATED_RANGE_COUNT - 1];
            if last.end == phys {
                last.end = end;
                return Ok(());
            }
        }

        if ALLOCATED_RANGE_COUNT >= MAX_ALLOCATED_RANGES {
            return Err("kernel_stub: too many physical allocation ranges");
        }
        ALLOCATED_RANGES[ALLOCATED_RANGE_COUNT] = PhysRange { start: phys, end };
        ALLOCATED_RANGE_COUNT += 1;
    }
    Ok(())
}

unsafe fn init_mapper(physical_memory_offset: VirtAddr) -> OffsetPageTable<'static> {
    let level_4_table = active_level_4_table(physical_memory_offset);
    OffsetPageTable::new(level_4_table, physical_memory_offset)
}

unsafe fn active_level_4_table(physical_memory_offset: VirtAddr) -> &'static mut PageTable {
    let (level_4_table_frame, _) = Cr3::read();
    let phys = level_4_table_frame.start_address();
    let virt = physical_memory_offset + phys.as_u64();
    &mut *virt.as_mut_ptr()
}

fn align_up_4k(value: u64) -> u64 {
    (value + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

fn init_serial() {
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

struct Serial;

impl Write for Serial {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            serial_write_byte(byte);
        }
        Ok(())
    }
}

fn serial_write_byte(byte: u8) {
    unsafe {
        let mut line_status = Port::<u8>::new(0x3FD);
        while line_status.read() & 0x20 == 0 {
            core::hint::spin_loop();
        }
        let mut data = Port::<u8>::new(0x3F8);
        data.write(byte);
    }
}

fn serial_println(message: &str) {
    let mut serial = Serial;
    let _ = serial.write_str(message);
    let _ = serial.write_str("\r\n");
}

fn serial_println_fmt(args: fmt::Arguments) {
    let mut serial = Serial;
    let _ = serial.write_fmt(args);
    let _ = serial.write_str("\r\n");
}

fn fatal(message: &'static str) -> ! {
    serial_println(message);
    halt_loop()
}

fn halt_loop() -> ! {
    loop {
        hlt();
    }
}
