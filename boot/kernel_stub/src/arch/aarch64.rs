use core::arch::asm;
use core::marker::PhantomData;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering};

use aarch64_vmsa::address::{TranslationGranule, VirtAddr};
use aarch64_vmsa::attrs::{
    AllocationHints, CachePolicy, Cacheability, DataAccess, DirtyBitManagement, DirtyControl,
    MemoryAttributes, MemoryTransience, SemanticLeafAttrs, SemanticTableAttrs,
    SemanticVmsa64Stage1LeafControls, SemanticVmsa64Stage1TableControls, Shareability,
    SoftwareMetadata, Stage1EffectivePermissions, Stage1MemoryConfig, Stage1PermissionConfig,
    TwoPrivilegeTablePermissionLimits,
};
use aarch64_vmsa::config::format::Vmsa64;
use aarch64_vmsa::config::granule::{Granule16KiB, Granule4KiB, Granule64KiB};
use aarch64_vmsa::config::regime::NonSecureEl1Stage1;
use aarch64_vmsa::descriptor::{DescriptorFormat, HasLayout};
use aarch64_vmsa::mapper::{Live, Mapper, MapperInvalidation};
use aarch64_vmsa::table::{
    RecursiveTableAccess, RootTableGeometry, TableAccessLocation, TableAddr, TableAllocLayout,
    TableReclaim,
};
use aarch64_vmsa::translation::{WalkInputAddr, WalkOutputAddr};
use bootloader_api::{
    BootInfo as LoaderBootInfo, GranuleKind, Optional as LoaderOptional,
    PixelFormat as LoaderPixelFormat,
};
use goblin::pe::header::COFF_MACHINE_ARM64;
use kernel_abi::arch::{
    Aarch64BootArchInfo, Aarch64PeTlsDirectory, RawTableFrameProvider, RecursiveFrameZeroProvider,
    KERNEL_PE_BASE,
};
use kernel_abi::{
    BootInfo, FdtHeader, FrameBuffer, FrameBufferInfo, MemoryRegionKind, Optional, PixelFormat,
    RUSTOS_BOOT_INFO_MAGIC,
};

use crate::platform::{
    BootFrameSource, BootInfoParts, BootloaderMemoryRegion, BootloaderPlatform,
    KernelImagePermissions, KernelImagePlatform, Platform,
};

pub struct Aarch64Platform;

pub type PlatformImpl = Aarch64Platform;

static PAGE_SIZE: AtomicU64 = AtomicU64::new(0x1000);
static MAIR: AtomicU64 = AtomicU64::new(0xff);

type GranuleMapper<G> = Mapper<
    Vmsa64,
    NonSecureEl1Stage1,
    G,
    RecursiveTableAccess<Vmsa64, G>,
    RecursiveFrameZeroProvider<TableFrameSource<G>, G>,
    Live<StubInvalidation>,
>;

pub enum ImageMapper {
    Size4KiB(GranuleMapper<Granule4KiB>),
    Size16KiB(GranuleMapper<Granule16KiB>),
    Size64KiB(GranuleMapper<Granule64KiB>),
}

pub struct FrameAllocator {
    source: BootFrameSource<Aarch64Platform>,
    frame_size: u64,
}

impl FrameAllocator {
    fn allocate(&mut self) -> Option<u64> {
        self.source.allocate(self.frame_size)
    }
}

pub struct TableFrameSource<G: TranslationGranule> {
    source: BootFrameSource<Aarch64Platform>,
    granule: PhantomData<G>,
}

unsafe impl<G: TranslationGranule> RawTableFrameProvider<G> for TableFrameSource<G> {
    type Error = ();

    fn allocate_table_frame(
        &mut self,
        layout: TableAllocLayout,
    ) -> Result<TableAddr<G>, Self::Error> {
        if layout.bytes() as u64 > G::SIZE || layout.align() as u64 > G::SIZE {
            return Err(());
        }
        let frame = self.source.allocate(G::SIZE).ok_or(())?;
        TableAddr::new(frame).map_err(|_| ())
    }

    fn reclaim_table_frame(&mut self, _reclaim: TableReclaim<G>) -> Result<(), Self::Error> {
        Ok(())
    }
}

pub struct StubInvalidation;

unsafe impl<G: TranslationGranule> MapperInvalidation<Vmsa64, G> for StubInvalidation {
    fn leaf_inserted(&mut self, _: TableAccessLocation<Vmsa64, G>, _: usize, _: u64, _: u64) {}
    fn leaf_removed(&mut self, _: TableAccessLocation<Vmsa64, G>, _: usize, _: u64) {}
    fn table_descriptor_inserted(
        &mut self,
        _: TableAccessLocation<Vmsa64, G>,
        _: usize,
        _: u64,
        _: u64,
    ) {
    }
    fn table_descriptor_removed(&mut self, _: TableAccessLocation<Vmsa64, G>, _: usize, _: u64) {}
    fn before_table_frame_reclaim(&mut self, _: TableAddr<G>, _: TableAllocLayout) {}
    fn synchronize(&mut self) {
        unsafe {
            asm!(
                "dsb ishst",
                "tlbi vmalle1is",
                "dsb ish",
                "isb",
                options(nostack, preserves_flags)
            );
        }
    }
}

#[derive(Clone, Copy)]
pub struct MapperConfig {
    mair: u64,
}

impl Stage1MemoryConfig for MapperConfig {
    fn mair(&self) -> u64 {
        self.mair
    }
}

impl Stage1PermissionConfig for MapperConfig {}

#[no_mangle]
pub extern "C" fn _start(boot_info: &'static mut LoaderBootInfo) -> ! {
    crate::start(boot_info)
}

impl Platform for Aarch64Platform {
    type BootArchInfo = Aarch64BootArchInfo;

    const NAME: &'static str = "aarch64";

    fn init_debug() {}

    fn write_debug_byte(byte: u8) {
        let uart = 0x0900_0000 as *mut u32;
        unsafe {
            while uart.add(6).read_volatile() & (1 << 5) != 0 {
                core::hint::spin_loop();
            }
            uart.write_volatile(byte as u32);
        }
    }

    fn halt() -> ! {
        loop {
            unsafe { asm!("wfe", options(nomem, nostack, preserves_flags)) }
        }
    }
}

impl KernelImagePlatform for Aarch64Platform {
    type ImageMapper = ImageMapper;
    type FrameAllocator = FrameAllocator;
    type TlsDirectory = Aarch64PeTlsDirectory;

    fn base_page_size() -> u64 {
        PAGE_SIZE.load(Ordering::Relaxed)
    }

    fn kernel_image_base() -> u64 {
        KERNEL_PE_BASE
    }

    fn validate_kernel_machine(machine: u16) -> Result<(), &'static str> {
        if machine == COFF_MACHINE_ARM64 {
            Ok(())
        } else {
            Err("kernel_stub: kernel PE machine is not aarch64")
        }
    }

    fn map_kernel_image_range(
        mapper: &mut Self::ImageMapper,
        frame_allocator: &mut Self::FrameAllocator,
        base: u64,
        size: u64,
    ) -> Result<(), &'static str> {
        match mapper {
            ImageMapper::Size4KiB(mapper) => map_range(mapper, frame_allocator, base, size),
            ImageMapper::Size16KiB(mapper) => map_range(mapper, frame_allocator, base, size),
            ImageMapper::Size64KiB(mapper) => map_range(mapper, frame_allocator, base, size),
        }
    }

    fn set_kernel_image_permissions(
        mapper: &mut Self::ImageMapper,
        base: u64,
        size: u64,
        permissions: KernelImagePermissions,
    ) -> Result<(), &'static str> {
        match mapper {
            ImageMapper::Size4KiB(mapper) => set_permissions(mapper, base, size, permissions),
            ImageMapper::Size16KiB(mapper) => set_permissions(mapper, base, size, permissions),
            ImageMapper::Size64KiB(mapper) => set_permissions(mapper, base, size, permissions),
        }
    }

    fn tls_directory_from_pe(directory: goblin::pe::tls::ImageTlsDirectory) -> Self::TlsDirectory {
        Aarch64PeTlsDirectory {
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
        validate_tls(image_base, image_size, directory)
    }

    fn prepare_tls_directory(directory: &Self::TlsDirectory) -> Result<(), &'static str> {
        if directory.address_of_index != 0 {
            unsafe { (directory.address_of_index as *mut u32).write(0) }
        }
        Ok(())
    }

    unsafe fn enter_kernel(entry: u64, boot_info: *const BootInfo<Self::BootArchInfo>) -> ! {
        unsafe {
            asm!(
                "br {entry}",
                in("x0") boot_info,
                entry = in(reg) entry,
                options(noreturn)
            )
        }
    }
}

impl BootloaderPlatform for Aarch64Platform {
    type BootloaderInfo = LoaderBootInfo;

    fn init_mapper(
        bootloader_info: &Self::BootloaderInfo,
    ) -> Result<Self::ImageMapper, &'static str> {
        PAGE_SIZE.store(
            bootloader_info.translation.granule_kind.size(),
            Ordering::Relaxed,
        );
        MAIR.store(bootloader_info.translation.mair_el1, Ordering::Relaxed);
        unsafe {
            bootloader_info
                .translation
                .scratch_descriptor
                .write_volatile(0);
            asm!(
                "dsb ishst",
                "tlbi vmalle1is",
                "dsb ish",
                "isb",
                options(nostack, preserves_flags)
            );
        }
        match bootloader_info.translation.granule_kind {
            GranuleKind::Size4KiB => {
                init_mapper_for::<Granule4KiB>(bootloader_info).map(ImageMapper::Size4KiB)
            }
            GranuleKind::Size16KiB => {
                init_mapper_for::<Granule16KiB>(bootloader_info).map(ImageMapper::Size16KiB)
            }
            GranuleKind::Size64KiB => {
                init_mapper_for::<Granule64KiB>(bootloader_info).map(ImageMapper::Size64KiB)
            }
        }
    }

    fn init_frame_allocator(bootloader_info: &Self::BootloaderInfo) -> Self::FrameAllocator {
        PAGE_SIZE.store(
            bootloader_info.translation.granule_kind.size(),
            Ordering::Relaxed,
        );
        FrameAllocator {
            source: BootFrameSource::new(bootloader_info, 0),
            frame_size: bootloader_info.translation.granule_kind.size(),
        }
    }

    fn for_each_memory_region(
        bootloader_info: &Self::BootloaderInfo,
        mut f: impl FnMut(BootloaderMemoryRegion) -> Result<(), &'static str>,
    ) -> Result<(), &'static str> {
        for descriptor in bootloader_info.memory_map.iter() {
            let byte_len = descriptor
                .page_count
                .checked_mul(0x1000)
                .ok_or("kernel_stub: UEFI memory region overflow")?;
            let end = descriptor
                .phys_start
                .checked_add(byte_len)
                .ok_or("kernel_stub: UEFI memory region overflow")?;
            f(BootloaderMemoryRegion {
                start: descriptor.phys_start,
                end,
                kind: memory_kind(descriptor.memory_type),
            })?;
        }
        Ok(())
    }

    fn finalize_boot_info(
        bootloader_info: &mut Self::BootloaderInfo,
        parts: BootInfoParts<Self::TlsDirectory>,
    ) -> Result<BootInfo<Self::BootArchInfo>, &'static str> {
        let translation = bootloader_info.translation;
        let arch_info = Aarch64BootArchInfo {
            root_table: translation.root_table,
            recursive_base: translation.recursive_base,
            recursive_index: translation
                .recursive_index
                .try_into()
                .map_err(|_| "kernel_stub: recursive index overflow")?,
            granule_shift: translation.granule_kind.shift(),
            input_addr_bits: translation.input_addr_bits,
            output_addr_bits: translation.output_addr_bits,
            mair_el1: translation.mair_el1,
            tcr_el1: translation.tcr_el1,
            tcr2_el1: translation.tcr2_el1,
            ttbr1_el1: translation.ttbr1_el1,
            pe_tls_directory: parts.tls_directory,
        };
        Ok(BootInfo {
            magic: RUSTOS_BOOT_INFO_MAGIC,
            flags: 0,
            rsdp_addr: optional_address(bootloader_info.rsdp_addr),
            arch_info,
            memory_regions: parts.memory_regions,
            framebuffer: match &bootloader_info.framebuffer {
                LoaderOptional::Some(framebuffer) => {
                    let info = framebuffer.info();
                    Optional::Some(unsafe {
                        FrameBuffer::new(
                            framebuffer.buffer_start(),
                            FrameBufferInfo {
                                byte_len: info.byte_len,
                                width: info.width,
                                height: info.height,
                                pixel_format: pixel_format(info.pixel_format),
                                bytes_per_pixel: info.bytes_per_pixel,
                                stride: info.stride,
                            },
                        )
                    })
                }
                LoaderOptional::None => Optional::None,
            },
            fdt_header: if bootloader_info.fdt_addr == 0 {
                Optional::None
            } else {
                Optional::Some(bootloader_info.fdt_addr as *const FdtHeader)
            },
            kernel_imports: parts.kernel_imports,
            kernel_exports: parts.kernel_exports,
            ramdisk_addr: Optional::None,
            ramdisk_len: 0,
            kernel_addr: 0,
            kernel_len: parts.loaded_kernel.image_size,
            kernel_image_offset: 0,
            kernel_image_base: parts.loaded_kernel.image_base,
            kernel_image_size: parts.loaded_kernel.image_size,
            kernel_entry: parts.loaded_kernel.entry,
            kernel_text: parts.kernel_text,
            kernel_sections: parts.kernel_sections,
            boot_packages: parts.boot_packages,
            stub_base: bootloader_info.stub_virt_base,
            stub_size: bootloader_info.stub_virt_size,
        })
    }
}

fn init_mapper_for<G>(boot_info: &LoaderBootInfo) -> Result<GranuleMapper<G>, &'static str>
where
    G: TranslationGranule,
    Vmsa64: HasLayout<<NonSecureEl1Stage1 as aarch64_vmsa::regime::TranslationRegime>::Stage, G>,
{
    let translation = boot_info.translation;
    let root_addr = TableAddr::<G>::new(translation.root_table)
        .map_err(|_| "kernel_stub: invalid root table")?;
    let geometry = RootTableGeometry::<Vmsa64, G>::new(
        root_addr,
        translation.input_addr_bits,
        translation.output_addr_bits,
    )
    .map_err(|_| "kernel_stub: invalid translation geometry")?;
    let root = geometry.with_regime::<NonSecureEl1Stage1>();
    let access = unsafe {
        RecursiveTableAccess::new(
            translation.recursive_index,
            VirtAddr(translation.recursive_base),
            root_addr,
            root.level(),
        )
    }
    .map_err(|_| "kernel_stub: invalid recursive mapping")?;
    let source = TableFrameSource::<G> {
        source: BootFrameSource::new(boot_info, 0),
        granule: PhantomData,
    };
    let provider = unsafe {
        RecursiveFrameZeroProvider::new(
            source,
            translation.scratch_page,
            NonNull::new(translation.scratch_descriptor)
                .ok_or("kernel_stub: missing scratch descriptor")?,
        )
    };
    Mapper::new_live(root, access, provider, StubInvalidation)
        .map_err(|_| "kernel_stub: failed to initialize mapper")
}

fn map_range<G>(
    mapper: &mut GranuleMapper<G>,
    allocator: &mut FrameAllocator,
    base: u64,
    size: u64,
) -> Result<(), &'static str>
where
    G: TranslationGranule,
    Vmsa64: HasLayout<<NonSecureEl1Stage1 as aarch64_vmsa::regime::TranslationRegime>::Stage, G>,
{
    if size == 0 || base & (G::SIZE - 1) != 0 || size & (G::SIZE - 1) != 0 {
        return Err("kernel_stub: invalid PE image range");
    }
    let config = MapperConfig {
        mair: MAIR.load(Ordering::Relaxed),
    };
    let mut offset = 0;
    while offset < size {
        let address = base + offset;
        let input = WalkInputAddr::from_canonical(address, mapper.root().addr_bits())
            .map_err(|_| "kernel_stub: non-canonical PE address")?;
        if mapper
            .translate(input)
            .map_err(|_| "kernel_stub: failed to inspect PE mapping")?
            .is_some()
        {
            return Err("kernel_stub: kernel PE preferred base is already mapped");
        }
        let frame = allocator
            .allocate()
            .ok_or("kernel_stub: out of physical memory while mapping PE kernel")?;
        mapper
            .map_semantic_leaf(
                &config,
                input,
                WalkOutputAddr::new(frame),
                Vmsa64::FINAL_LEVEL,
                leaf_attributes(true, false),
                table_attributes(),
            )
            .map_err(|_| "kernel_stub: failed to map PE kernel page")?;
        offset += G::SIZE;
    }
    Ok(())
}

fn set_permissions<G>(
    mapper: &mut GranuleMapper<G>,
    base: u64,
    size: u64,
    permissions: KernelImagePermissions,
) -> Result<(), &'static str>
where
    G: TranslationGranule,
    Vmsa64: HasLayout<<NonSecureEl1Stage1 as aarch64_vmsa::regime::TranslationRegime>::Stage, G>,
{
    let start = base & !(G::SIZE - 1);
    let end = crate::align_up(
        base.checked_add(size)
            .ok_or("kernel_stub: PE permission range overflow")?,
        G::SIZE,
    );
    let config = MapperConfig {
        mair: MAIR.load(Ordering::Relaxed),
    };
    let mut address = start;
    while address < end {
        let input = WalkInputAddr::from_canonical(address, mapper.root().addr_bits())
            .map_err(|_| "kernel_stub: non-canonical PE address")?;
        let mapping = mapper
            .translate(input)
            .map_err(|_| "kernel_stub: failed to inspect PE mapping")?
            .ok_or("kernel_stub: PE page is not mapped")?;
        let output = mapping.output_base();
        let level = mapping.level();
        unsafe { mapper.unmap(input) }.map_err(|_| "kernel_stub: failed to remove PE mapping")?;
        mapper
            .map_semantic_leaf(
                &config,
                input,
                output,
                level,
                leaf_attributes(permissions.writable, permissions.executable),
                table_attributes(),
            )
            .map_err(|_| "kernel_stub: failed to update PE permissions")?;
        address += G::SIZE;
    }
    Ok(())
}
type LeafAttrs = SemanticLeafAttrs<Vmsa64, NonSecureEl1Stage1>;
type TableAttrs = SemanticTableAttrs<Vmsa64, NonSecureEl1Stage1>;

fn leaf_attributes(
    writable: bool,
    executable: bool,
) -> SemanticLeafAttrs<Vmsa64, NonSecureEl1Stage1> {
    let cache = Cacheability::Cacheable {
        policy: CachePolicy::WriteBack,
        transience: MemoryTransience::NonTransient,
        allocation: AllocationHints::ReadWriteAllocate,
    };
    LeafAttrs {
        memory: MemoryAttributes::Normal {
            inner: cache,
            outer: cache,
        },
        permissions: Stage1EffectivePermissions {
            privileged_data: if writable {
                DataAccess::ReadWrite
            } else {
                DataAccess::ReadOnly
            },
            unprivileged_data: DataAccess::None,
            privileged_execute: executable,
            unprivileged_execute: false,
            privileged_gcs: false,
            unprivileged_gcs: false,
        },
        pas: (),
        controls: SemanticVmsa64Stage1LeafControls {
            shareability: Shareability::InnerShareable,
            access_flag: true,
            global: true,
            dirty: DirtyControl::Direct(DirtyBitManagement::SoftwareManaged),
            contiguous: false,
            guarded: false,
            software: SoftwareMetadata::new(0),
        },
    }
}

fn table_attributes() -> SemanticTableAttrs<Vmsa64, NonSecureEl1Stage1> {
    TableAttrs {
        permission_limits: TwoPrivilegeTablePermissionLimits {
            privileged_data_limit: DataAccess::ReadWrite,
            unprivileged_data_limit: DataAccess::None,
            privileged_execute_limit: true,
            unprivileged_execute_limit: false,
        },
        pas: (),
        controls: SemanticVmsa64Stage1TableControls {
            access_flag: true,
            software: SoftwareMetadata::new(0),
        },
    }
}

fn memory_kind(memory_type: u32) -> MemoryRegionKind {
    match memory_type {
        3 | 4 | 7 => MemoryRegionKind::Usable,
        1 | 2 => MemoryRegionKind::Bootloader,
        0 | 5 | 6 | 8..=14 => MemoryRegionKind::Reserved,
        value => MemoryRegionKind::Unknown(value),
    }
}

fn optional_address(address: u64) -> Optional<u64> {
    if address == 0 {
        Optional::None
    } else {
        Optional::Some(address)
    }
}

fn pixel_format(format: LoaderPixelFormat) -> PixelFormat {
    match format {
        LoaderPixelFormat::Rgb => PixelFormat::Rgb,
        LoaderPixelFormat::Bgr => PixelFormat::Bgr,
        LoaderPixelFormat::Bitmask {
            red, green, blue, ..
        } => PixelFormat::Unknown {
            red_position: red.trailing_zeros() as u8,
            green_position: green.trailing_zeros() as u8,
            blue_position: blue.trailing_zeros() as u8,
        },
    }
}

fn validate_tls(
    base: u64,
    size: u64,
    directory: &Aarch64PeTlsDirectory,
) -> Result<(), &'static str> {
    let end = base
        .checked_add(size)
        .ok_or("kernel_stub: PE image range overflow")?;
    if directory.start_address_of_raw_data > directory.end_address_of_raw_data
        || (directory.start_address_of_raw_data != 0 && directory.start_address_of_raw_data < base)
        || directory.end_address_of_raw_data > end
    {
        return Err("kernel_stub: invalid PE TLS raw data range");
    }
    if directory.address_of_index != 0
        && (directory.address_of_index < base
            || directory
                .address_of_index
                .checked_add(4)
                .is_none_or(|value| value > end))
    {
        return Err("kernel_stub: PE TLS index is outside the kernel image");
    }
    if directory.address_of_callbacks != 0
        && (directory.address_of_callbacks < base || directory.address_of_callbacks >= end)
    {
        return Err("kernel_stub: PE TLS callbacks pointer is outside the kernel image");
    }
    Ok(())
}
