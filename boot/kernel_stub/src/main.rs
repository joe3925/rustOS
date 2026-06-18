#![feature(alloc_error_handler)]
#![no_std]
#![no_main]

extern crate alloc;

mod arch;
mod platform;

use alloc::alloc::{GlobalAlloc, Layout};
use core::fmt::{self, Write};
use core::panic::PanicInfo;
use core::ptr::{addr_of_mut, copy_nonoverlapping};
use goblin::pe::data_directories::DataDirectory;
use goblin::pe::optional_header::MAGIC_64;
use goblin::pe::section_table::{SectionTable, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE};
use goblin::pe::PE;
use kernel_abi::{
    BootInfo, KernelSection, KernelSections, KernelSymbol, KernelSymbolString, KernelSymbols,
    KernelTextSection, MemoryRegion, MemoryRegionKind, MemoryRegions, Optional,
    MAX_BOOT_MEMORY_REGIONS, MAX_KERNEL_EXPORT_SYMBOLS, MAX_KERNEL_IMPORT_SYMBOLS,
    MAX_KERNEL_SECTIONS, MAX_KERNEL_SYMBOL_STRING_BYTES, RUSTOS_BOOT_INFO_MAGIC,
    RUSTOS_BOOT_INFO_VERSION,
};
use platform::{
    ActivePlatform, BootloaderMemoryRegion, BootloaderPlatform, KernelImagePermissions,
    KernelImagePlatform, LoadedKernel, PhysRange, Platform,
};

const KERNEL_PE: &[u8] = include_bytes!(env!("KERNEL_PE_PATH"));
const STUB_HEAP_SIZE: usize = 2 * 1024 * 1024;
const MAX_ALLOCATED_RANGES: usize = 128;

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
    fatal::<ActivePlatform>("kernel_stub: allocation failed")
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println_fmt(format_args!("kernel_stub panic: {info}"));
    ActivePlatform::halt()
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

pub fn start<P>(boot_info: &'static mut P::BootloaderInfo) -> !
where
    P: BootloaderPlatform,
{
    P::init_debug();
    serial_println("kernel_stub: loading embedded PE kernel");

    let mut frame_allocator = P::init_frame_allocator(boot_info);
    let mut mapper = P::init_mapper(boot_info).unwrap_or_else(|err| fatal::<P>(err));

    let loaded = load_kernel_pe::<P>(&mut mapper, &mut frame_allocator)
        .unwrap_or_else(|err| fatal::<P>(err));
    let handoff = build_handoff::<P>(boot_info, loaded).unwrap_or_else(|err| fatal::<P>(err));

    serial_println("kernel_stub: jumping to PE kernel");

    unsafe { P::enter_kernel(loaded.entry, handoff as *const BootInfo) }
}

fn load_kernel_pe<P>(
    mapper: &mut P::ImageMapper,
    frame_allocator: &mut P::FrameAllocator,
) -> Result<LoadedKernel, &'static str>
where
    P: KernelImagePlatform,
{
    let pe = PE::parse(KERNEL_PE).map_err(|_| "kernel_stub: embedded kernel is not a PE image")?;
    validate_kernel_pe::<P>(&pe)?;

    let opt = pe
        .header
        .optional_header
        .as_ref()
        .ok_or("kernel_stub: PE optional header missing")?;
    let image_size = align_up(opt.windows_fields.size_of_image as u64, P::base_page_size());
    let headers_size = opt.windows_fields.size_of_headers as usize;
    let image_base = opt.windows_fields.image_base;

    P::map_kernel_image_range(mapper, frame_allocator, image_base, image_size)?;

    unsafe {
        core::ptr::write_bytes(image_base as *mut u8, 0, image_size as usize);
        let header_copy_len = headers_size.min(KERNEL_PE.len()).min(image_size as usize);
        copy_nonoverlapping(KERNEL_PE.as_ptr(), image_base as *mut u8, header_copy_len);
    }

    for section in &pe.sections {
        copy_section(image_base, image_size, section)?;
    }

    prepare_kernel_pe_tls::<P>(image_base, image_size, &pe)?;
    apply_section_permissions::<P>(mapper, image_base, image_size, &pe.sections)?;

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

fn validate_kernel_pe<P>(pe: &PE<'_>) -> Result<(), &'static str>
where
    P: KernelImagePlatform,
{
    let opt = pe
        .header
        .optional_header
        .as_ref()
        .ok_or("kernel_stub: PE optional header missing")?;

    if !pe.is_64 || opt.standard_fields.magic != MAGIC_64 {
        return Err("kernel_stub: kernel PE must be PE32+");
    }
    P::validate_kernel_machine(pe.header.coff_header.machine)?;
    if pe.image_base != P::kernel_image_base()
        || opt.windows_fields.image_base != P::kernel_image_base()
    {
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

fn prepare_kernel_pe_tls<P>(
    image_base: u64,
    image_size: u64,
    pe: &PE<'_>,
) -> Result<(), &'static str>
where
    P: KernelImagePlatform,
{
    let Some(tls) = pe.tls_data.as_ref() else {
        return Ok(());
    };

    let directory = P::tls_directory_from_pe(tls.image_tls_directory);
    P::validate_tls_directory(image_base, image_size, &directory)?;
    P::prepare_tls_directory(&directory)?;

    Ok(())
}

fn directory_present(dir: Option<&DataDirectory>) -> bool {
    dir.is_some_and(|dir| dir.virtual_address != 0 && dir.size != 0)
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

fn apply_section_permissions<P>(
    mapper: &mut P::ImageMapper,
    base: u64,
    image_size: u64,
    sections: &[SectionTable],
) -> Result<(), &'static str>
where
    P: KernelImagePlatform,
{
    P::set_kernel_image_permissions(
        mapper,
        base,
        image_size,
        KernelImagePermissions {
            writable: false,
            executable: false,
        },
    )?;

    for section in sections {
        let section_size = core::cmp::max(section.virtual_size, section.size_of_raw_data) as u64;
        if section_size == 0 {
            continue;
        }

        P::set_kernel_image_permissions(
            mapper,
            base + section.virtual_address as u64,
            section_size,
            KernelImagePermissions {
                writable: section.characteristics & IMAGE_SCN_MEM_WRITE != 0,
                executable: section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0,
            },
        )?;
    }

    Ok(())
}

fn build_handoff<P>(
    boot_info: &'static mut P::BootloaderInfo,
    loaded: LoadedKernel,
) -> Result<&'static mut BootInfo, &'static str>
where
    P: BootloaderPlatform,
{
    let memory_region_count = translate_memory_regions::<P>(boot_info)?;
    let section_count = translate_kernel_sections(loaded.image_base, loaded.section_count)?;
    let kernel_text = translate_kernel_text_section(loaded.image_base)?;
    let tls_directory = translate_kernel_tls_directory::<P>(loaded.image_base, loaded.image_size)?;
    let (kernel_import_count, kernel_export_count) = translate_kernel_symbols()?;
    let (ramdisk_addr, ramdisk_len) = P::ramdisk(boot_info);

    unsafe {
        let common_boot_info = BootInfo {
            magic: RUSTOS_BOOT_INFO_MAGIC,
            version: RUSTOS_BOOT_INFO_VERSION,
            flags: 0,
            rsdp_addr: Optional::None,
            arch_info: kernel_abi::arch::ArchInfo::empty(),
            memory_regions: MemoryRegions {
                ptr: addr_of_mut!(ABI_MEMORY_REGIONS).cast::<MemoryRegion>(),
                len: memory_region_count,
            },
            framebuffer: P::framebuffer(boot_info),
            fdt_header: P::fdt_header(boot_info),
            tls_template: Optional::None,
            kernel_imports: KernelSymbols {
                ptr: addr_of_mut!(ABI_KERNEL_IMPORT_SYMBOLS).cast::<KernelSymbol>(),
                len: kernel_import_count,
            },
            kernel_exports: KernelSymbols {
                ptr: addr_of_mut!(ABI_KERNEL_EXPORT_SYMBOLS).cast::<KernelSymbol>(),
                len: kernel_export_count,
            },
            ramdisk_addr,
            ramdisk_len,
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
            stub_base: P::stub_image_base(),
            stub_size: P::stub_image_size(boot_info),
        };

        let (boot_info, _) = P::finalize_boot_info(boot_info, common_boot_info, tls_directory)?;
        ABI_BOOT_INFO = boot_info;

        Ok(&mut *addr_of_mut!(ABI_BOOT_INFO))
    }
}

fn translate_memory_regions<P>(boot_info: &P::BootloaderInfo) -> Result<usize, &'static str>
where
    P: BootloaderPlatform,
{
    let mut out_len = 0usize;

    P::for_each_memory_region(boot_info, |region| {
        if region.end <= region.start {
            return Ok(());
        }

        let mut cursor = region.start;
        let kind = region.kind;

        P::for_each_reserved_memory_range(|reserved| {
            cursor = translate_reserved_range(&mut out_len, region, cursor, kind, reserved)?;
            Ok(())
        })?;

        for reserved in allocated_ranges() {
            cursor = translate_reserved_range(&mut out_len, region, cursor, kind, *reserved)?;
        }

        if cursor < region.end {
            push_translated_region(&mut out_len, cursor, region.end, kind)?;
        }

        Ok(())
    })?;
    Ok(out_len)
}

fn translate_reserved_range(
    out_len: &mut usize,
    region: BootloaderMemoryRegion,
    cursor: u64,
    kind: MemoryRegionKind,
    reserved: PhysRange,
) -> Result<u64, &'static str> {
    let start = reserved.start.max(region.start).max(cursor);
    let end = reserved.end.min(region.end);
    if end <= start {
        return Ok(cursor);
    }

    if cursor < start {
        push_translated_region(out_len, cursor, start, kind)?;
    }
    push_translated_region(out_len, start, end, MemoryRegionKind::Bootloader)?;
    Ok(end)
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

fn translate_kernel_tls_directory<P>(
    image_base: u64,
    image_size: u64,
) -> Result<Optional<P::TlsDirectory>, &'static str>
where
    P: KernelImagePlatform,
{
    let pe = PE::parse(KERNEL_PE).map_err(|_| "kernel_stub: failed to reparse PE TLS")?;
    let Some(tls) = pe.tls_data.as_ref() else {
        return Ok(Optional::None);
    };

    let directory = P::tls_directory_from_pe(tls.image_tls_directory);
    P::validate_tls_directory(image_base, image_size, &directory)?;
    Ok(Optional::Some(directory))
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

pub(crate) fn record_allocated_frame(phys: u64) -> Result<(), &'static str> {
    unsafe {
        let end = phys
            .checked_add(ActivePlatform::base_page_size())
            .ok_or("kernel_stub: physical allocation range overflow")?;
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

fn allocated_ranges() -> &'static [PhysRange] {
    unsafe {
        core::slice::from_raw_parts(
            addr_of_mut!(ALLOCATED_RANGES).cast::<PhysRange>(),
            ALLOCATED_RANGE_COUNT,
        )
    }
}

pub(crate) fn align_up(value: u64, align: u64) -> u64 {
    debug_assert!(align.is_power_of_two());
    (value + align - 1) & !(align - 1)
}

struct Serial;

impl Write for Serial {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            ActivePlatform::write_debug_byte(byte);
        }
        Ok(())
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

fn fatal<P: Platform>(message: &'static str) -> ! {
    serial_println(message);
    P::halt()
}
