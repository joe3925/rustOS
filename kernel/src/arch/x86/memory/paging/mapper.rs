use kernel_types::arch::{
    PageFlags, PagingPlatform as KernelTypesPagingPlatform, PhysAddr,
    Platform as KernelTypesPlatform, VirtAddr,
};
use kernel_types::memory::PhysicalMappingCache;
use kernel_types::status::PageMapError;
use x86_64::structures::paging::{
    FrameAllocator, Mapper, Page, PageSize, PageTableFlags, PhysFrame, Size1GiB, Size2MiB, Size4KiB,
};
use x86_64::{PhysAddr as X86PhysAddr, VirtAddr as X86VirtAddr};

use crate::memory::paging::{
    KernelFrameAllocator, LocalTlbFlush, MappingSize, ResolvedMapping, UnmapFrameDisposition,
};
use crate::platform::PageTableFrameAllocator;
use crate::util::boot_info;

use super::flags::page_flags_to_x86;
use super::tables::init_mapper;

pub unsafe fn map_leaf<A: PageTableFrameAllocator>(
    allocator: &mut A,
    virt: VirtAddr,
    phys: PhysAddr,
    size: MappingSize,
    flags: PageFlags,
    cache: Option<PhysicalMappingCache>,
    flush: LocalTlbFlush,
) -> Result<(), PageMapError> {
    let recursive_index = boot_info()
        .arch_info
        .recursive_index
        .into_option()
        .ok_or(PageMapError::NoMemoryMap())?;
    let mut mapper = init_mapper(recursive_index);
    let mut table_allocator = X86PageTableFrameAllocator { inner: allocator };
    let flags = page_flags_to_x86(flags, cache) | PageTableFlags::PRESENT;
    let virt = X86VirtAddr::new(virt.as_u64());
    let phys = X86PhysAddr::new(phys.as_u64());

    match size.bytes {
        Size4KiB::SIZE => unsafe {
            map_existing_frame::<Size4KiB, A>(
                &mut mapper,
                &mut table_allocator,
                virt,
                phys,
                flags,
                flush,
            )
            .map_err(PageMapError::from)
        },
        Size2MiB::SIZE => unsafe {
            map_existing_frame::<Size2MiB, A>(
                &mut mapper,
                &mut table_allocator,
                virt,
                phys,
                flags,
                flush,
            )
            .map_err(PageMapError::from)
        },
        Size1GiB::SIZE => unsafe {
            map_existing_frame::<Size1GiB, A>(
                &mut mapper,
                &mut table_allocator,
                virt,
                phys,
                flags,
                flush,
            )
            .map_err(PageMapError::from)
        },
        _ => Err(PageMapError::TranslationFailed()),
    }
}

pub unsafe fn unmap_leaf<A: PageTableFrameAllocator>(
    _allocator: &mut A,
    virt: VirtAddr,
    size: MappingSize,
    disposition: UnmapFrameDisposition,
    flush: LocalTlbFlush,
) -> Result<Option<PhysAddr>, PageMapError> {
    let recursive_index = boot_info()
        .arch_info
        .recursive_index
        .into_option()
        .ok_or(PageMapError::NoMemoryMap())?;
    let mut mapper = init_mapper(recursive_index);
    let virt = X86VirtAddr::new(virt.as_u64());

    match size.bytes {
        Size4KiB::SIZE => unmap_leaf_inner::<Size4KiB>(&mut mapper, virt, disposition, flush),
        Size2MiB::SIZE => unmap_leaf_inner::<Size2MiB>(&mut mapper, virt, disposition, flush),
        Size1GiB::SIZE => unmap_leaf_inner::<Size1GiB>(&mut mapper, virt, disposition, flush),
        _ => Err(PageMapError::TranslationFailed()),
    }
}

pub fn resolve_mapping(virt: VirtAddr) -> Option<ResolvedMapping> {
    let translated = <KernelTypesPlatform as KernelTypesPagingPlatform>::translate_addr(virt)?;
    Some(ResolvedMapping {
        mapping_size: translated.block_size,
        phys_addr: translated.phys_addr,
    })
}

pub fn resolve_virtual_range_frame(addr: X86VirtAddr) -> Option<(u64, X86PhysAddr)> {
    let translated =
        <KernelTypesPlatform as KernelTypesPagingPlatform>::translate_addr(addr.into())?;
    Some((translated.block_size, translated.phys_addr.into()))
}

unsafe fn map_existing_frame<S, A>(
    mapper: &mut impl Mapper<S>,
    allocator: &mut X86PageTableFrameAllocator<'_, A>,
    virt: X86VirtAddr,
    phys: X86PhysAddr,
    flags: PageTableFlags,
    flush: LocalTlbFlush,
) -> Result<(), x86_64::structures::paging::mapper::MapToError<S>>
where
    S: PageSize,
    A: PageTableFrameAllocator,
{
    let page = Page::<S>::containing_address(virt);
    let frame = PhysFrame::<S>::containing_address(phys);
    let effective_flags = if S::SIZE > Size4KiB::SIZE && !flags.contains(PageTableFlags::HUGE_PAGE)
    {
        flags | PageTableFlags::HUGE_PAGE
    } else {
        flags
    };

    let map_flush = unsafe { mapper.map_to(page, frame, effective_flags, allocator) }?;
    finish_mapping(map_flush, flush);
    Ok(())
}

fn unmap_leaf_inner<S>(
    mapper: &mut impl Mapper<S>,
    virt: X86VirtAddr,
    disposition: UnmapFrameDisposition,
    flush: LocalTlbFlush,
) -> Result<Option<PhysAddr>, PageMapError>
where
    S: PageSize,
{
    let page = Page::<S>::containing_address(virt);
    match mapper.unmap(page) {
        Ok((frame, map_flush)) => {
            finish_mapping(map_flush, flush);
            let phys = frame.start_address();
            let abi = PhysAddr::new(phys.as_u64());
            match disposition {
                UnmapFrameDisposition::FreeMappedFrame => {
                    KernelFrameAllocator::free_mapping_frame(abi, MappingSize { bytes: S::SIZE })
                }
                UnmapFrameDisposition::ReleaseReservedFrame => {
                    KernelFrameAllocator::release_reserved_mapping_frame(
                        abi,
                        MappingSize { bytes: S::SIZE },
                    )
                }
                UnmapFrameDisposition::KeepFrame => {}
            }
            Ok(Some(abi))
        }
        Err(_) => Err(PageMapError::TranslationFailed()),
    }
}

fn finish_mapping<S: PageSize>(
    flush: x86_64::structures::paging::mapper::MapperFlush<S>,
    mode: LocalTlbFlush,
) {
    match mode {
        LocalTlbFlush::Flush => flush.flush(),
        LocalTlbFlush::Defer => flush.ignore(),
    }
}

pub struct X86PageTableFrameAllocator<'a, A: PageTableFrameAllocator> {
    inner: &'a mut A,
}

unsafe impl<A: PageTableFrameAllocator> FrameAllocator<Size4KiB>
    for X86PageTableFrameAllocator<'_, A>
{
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        self.inner
            .allocate_page_table_frame()
            .map(|phys| PhysFrame::containing_address(X86PhysAddr::new(phys.as_u64())))
    }
}

pub struct X86KernelFrameAllocator;

unsafe impl FrameAllocator<Size4KiB> for X86KernelFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        KernelFrameAllocator::allocate_mapping_frame(MappingSize {
            bytes: Size4KiB::SIZE,
        })
        .map(|phys| PhysFrame::containing_address(X86PhysAddr::new(phys.as_u64())))
    }
}

unsafe impl FrameAllocator<Size2MiB> for X86KernelFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size2MiB>> {
        KernelFrameAllocator::allocate_mapping_frame(MappingSize {
            bytes: Size2MiB::SIZE,
        })
        .map(|phys| PhysFrame::containing_address(X86PhysAddr::new(phys.as_u64())))
    }
}

unsafe impl FrameAllocator<Size1GiB> for X86KernelFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size1GiB>> {
        KernelFrameAllocator::allocate_mapping_frame(MappingSize {
            bytes: Size1GiB::SIZE,
        })
        .map(|phys| PhysFrame::containing_address(X86PhysAddr::new(phys.as_u64())))
    }
}
