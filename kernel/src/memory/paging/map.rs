use kernel_types::arch::{PageFlags, PhysAddr as AbiPhysAddr, VirtAddr as AbiVirtAddr};
use kernel_types::memory::PhysicalMappingCache;
use kernel_types::status::{PageMapError, PageMapFailure};

use crate::platform::{ActivePlatform, PagingPlatform};

use super::frame_alloc::{KernelFrameAllocator, KernelPageTableFrameAllocator};
use super::layout::{
    align_up_to_base_page, base_page_size, is_aligned, largest_mapping_size_for,
    supported_mapping_sizes,
};
use super::tlb::trigger_tlb_shootdown_range;
use super::types::{LocalTlbFlush, MappingSize, UnmapFrameDisposition};
use super::virt_tracker::{
    allocate_auto_kernel_range, allocate_auto_kernel_range_aligned, allocate_kernel_range,
    deallocate_kernel_range,
};

pub fn allocate_auto_kernel_range_mapped(
    size: u64,
    flags: PageFlags,
) -> Result<AbiVirtAddr, PageMapError> {
    let aligned_size = align_up_to_base_page(size).ok_or(PageMapError::NoMemory())?;
    let addr = allocate_auto_kernel_range(aligned_size).ok_or(PageMapError::NoMemory())?;

    if let Err(err) = unsafe { map_range(addr, aligned_size, flags, false) } {
        deallocate_kernel_range(addr, aligned_size);
        return Err(err);
    }

    Ok(addr)
}

pub fn allocate_auto_kernel_range_mapped_contiguous(
    size: u64,
    flags: PageFlags,
) -> Result<AbiVirtAddr, PageMapError> {
    let aligned_size = align_up_to_base_page(size).ok_or(PageMapError::NoMemory())?;
    if aligned_size == 0 {
        return Err(PageMapError::NoMemory());
    }

    let frame_count = frame_count_for_bytes(aligned_size).ok_or(PageMapError::NoMemory())?;
    let mapping_size = largest_mapping_size_for(aligned_size, None);
    let phys_align_frames = frame_count_for_bytes(mapping_size).ok_or(PageMapError::NoMemory())?;

    let addr = allocate_auto_kernel_range_aligned(aligned_size, mapping_size)
        .ok_or(PageMapError::NoMemory())?;

    let phys_base =
        KernelFrameAllocator::allocate_contiguous_frames_aligned(frame_count, phys_align_frames)
            .ok_or(PageMapError::NoMemory())?;

    if let Err(err) = unsafe {
        map_contiguous_physical_range(
            addr,
            phys_base,
            aligned_size,
            flags,
            None,
            LocalTlbFlush::Flush,
        )
    } {
        KernelFrameAllocator::release_reserved_mapping_frame(
            phys_base,
            MappingSize {
                bytes: aligned_size,
            },
        );
        deallocate_kernel_range(addr, aligned_size);
        return Err(err);
    }

    Ok(addr)
}

pub fn allocate_kernel_range_mapped(
    base: u64,
    size: u64,
    flags: PageFlags,
) -> Result<AbiVirtAddr, PageMapError> {
    let aligned_size = align_up_to_base_page(size).ok_or(PageMapError::NoMemory())?;
    let addr = allocate_kernel_range(base, aligned_size).map_err(|_| PageMapError::NoMemory())?;

    if let Err(err) = unsafe { map_range(addr, aligned_size, flags, false) } {
        deallocate_kernel_range(addr, aligned_size);
        return Err(err);
    }

    Ok(addr)
}

pub unsafe fn map_range(
    addr: AbiVirtAddr,
    size: u64,
    flags: PageFlags,
    ignore_already_mapped: bool,
) -> Result<(), PageMapError> {
    unsafe {
        map_range_with_flush(
            addr,
            size,
            flags,
            ignore_already_mapped,
            LocalTlbFlush::Flush,
        )
    }
}

pub unsafe fn map_fresh_kernel_range_no_flush(
    addr: AbiVirtAddr,
    size: u64,
    flags: PageFlags,
    ignore_already_mapped: bool,
) -> Result<(), PageMapError> {
    unsafe {
        map_range_with_flush(
            addr,
            size,
            flags,
            ignore_already_mapped,
            LocalTlbFlush::Defer,
        )
    }
}

unsafe fn map_range_with_flush(
    addr: AbiVirtAddr,
    size: u64,
    flags: PageFlags,
    ignore_already_mapped: bool,
    flush: LocalTlbFlush,
) -> Result<(), PageMapError> {
    let mut virt = addr.as_u64();
    let mut remaining = align_up_to_base_page(size).ok_or(PageMapError::NoMemory())?;
    let mut mapped_bytes = 0u64;
    let mut allocator = KernelPageTableFrameAllocator;

    while remaining > 0 {
        let mut mapped_this_leaf = false;

        for mapping_size in supported_mapping_sizes() {
            if !legal_mapping_size_for_virtual(*mapping_size, virt, remaining) {
                continue;
            }

            let Some(phys) = KernelFrameAllocator::allocate_mapping_frame(*mapping_size) else {
                continue;
            };

            match unsafe {
                <ActivePlatform as PagingPlatform>::map_leaf(
                    &mut allocator,
                    AbiVirtAddr::new(virt),
                    phys,
                    *mapping_size,
                    flags,
                    None,
                    flush,
                )
            } {
                Ok(()) => {
                    virt += mapping_size.bytes;
                    remaining -= mapping_size.bytes;
                    mapped_bytes += mapping_size.bytes;
                    mapped_this_leaf = true;
                    break;
                }
                Err(err) if ignore_already_mapped && is_already_mapped(&err) => {
                    KernelFrameAllocator::release_reserved_mapping_frame(phys, *mapping_size);
                    virt += mapping_size.bytes;
                    remaining -= mapping_size.bytes;
                    mapped_this_leaf = true;
                    break;
                }
                Err(err) if is_frame_allocation_failure(&err) => {
                    KernelFrameAllocator::release_reserved_mapping_frame(phys, *mapping_size);
                    continue;
                }
                Err(err) => {
                    KernelFrameAllocator::release_reserved_mapping_frame(phys, *mapping_size);
                    if !ignore_already_mapped {
                        unsafe {
                            rollback_mapped_range(
                                &mut allocator,
                                addr,
                                mapped_bytes,
                                UnmapFrameDisposition::FreeMappedFrame,
                            );
                        }
                    }
                    return Err(err);
                }
            }
        }

        if !mapped_this_leaf {
            unsafe {
                rollback_mapped_range(
                    &mut allocator,
                    addr,
                    mapped_bytes,
                    UnmapFrameDisposition::FreeMappedFrame,
                );
            }
            return Err(PageMapError::NoMemory());
        }
    }

    Ok(())
}

pub unsafe fn map_contiguous_physical_range(
    virt_base: AbiVirtAddr,
    phys_base: AbiPhysAddr,
    size: u64,
    flags: PageFlags,
    cache: Option<PhysicalMappingCache>,
    flush: LocalTlbFlush,
) -> Result<(), PageMapError> {
    let mut cur_virt = virt_base.as_u64();
    let mut cur_phys = phys_base.as_u64();
    let mut remaining = align_up_to_base_page(size).ok_or(PageMapError::NoMemory())?;
    let mut mapped_bytes = 0u64;
    let mut allocator = KernelPageTableFrameAllocator;

    while remaining > 0 {
        let mut mapped_this_leaf = false;

        for mapping_size in supported_mapping_sizes() {
            if !legal_mapping_size_for_existing(*mapping_size, cur_virt, cur_phys, remaining) {
                continue;
            }

            match unsafe {
                <ActivePlatform as PagingPlatform>::map_leaf(
                    &mut allocator,
                    AbiVirtAddr::new(cur_virt),
                    AbiPhysAddr::new(cur_phys),
                    *mapping_size,
                    flags,
                    cache,
                    flush,
                )
            } {
                Ok(()) => {
                    cur_virt += mapping_size.bytes;
                    cur_phys += mapping_size.bytes;
                    remaining -= mapping_size.bytes;
                    mapped_bytes += mapping_size.bytes;
                    mapped_this_leaf = true;
                    break;
                }
                Err(err) if is_frame_allocation_failure(&err) => continue,
                Err(err) => {
                    unsafe {
                        rollback_mapped_range(
                            &mut allocator,
                            virt_base,
                            mapped_bytes,
                            UnmapFrameDisposition::KeepFrame,
                        );
                    }
                    return Err(err);
                }
            }
        }

        if !mapped_this_leaf {
            unsafe {
                rollback_mapped_range(
                    &mut allocator,
                    virt_base,
                    mapped_bytes,
                    UnmapFrameDisposition::KeepFrame,
                );
            }
            return Err(PageMapError::NoMemory());
        }
    }

    Ok(())
}

pub unsafe fn map_allocated_range(
    virt_base: AbiVirtAddr,
    phys_base: AbiPhysAddr,
    size: u64,
    flags: PageFlags,
) -> Result<(), PageMapError> {
    unsafe {
        map_contiguous_physical_range(
            virt_base,
            phys_base,
            size,
            flags,
            None,
            LocalTlbFlush::Flush,
        )
    }
}

pub fn unmap_range(addr: AbiVirtAddr, size: u64) {
    deallocate_kernel_range(addr, size);
    unsafe {
        unmap_range_with_disposition(addr, size, UnmapFrameDisposition::FreeMappedFrame);
    }
}

pub unsafe fn unmap_range_unchecked(addr: AbiVirtAddr, size: u64) {
    unsafe {
        unmap_range_with_disposition(addr, size, UnmapFrameDisposition::FreeMappedFrame);
    }
}

pub unsafe fn unmap_range_keep_frames_unchecked(addr: AbiVirtAddr, size: u64) {
    unsafe {
        unmap_range_with_disposition(addr, size, UnmapFrameDisposition::KeepFrame);
    }
}

pub unsafe fn unmap_reserved_range_unchecked(addr: AbiVirtAddr, size: u64) {
    unsafe {
        unmap_range_with_disposition(addr, size, UnmapFrameDisposition::ReleaseReservedFrame);
    }
}

pub(crate) unsafe fn unmap_range_with_disposition(
    addr: AbiVirtAddr,
    size: u64,
    disposition: UnmapFrameDisposition,
) {
    let mut virt = addr.as_u64();
    let mut remaining = match align_up_to_base_page(size) {
        Some(size) => size,
        None => return,
    };
    let mut allocator = KernelPageTableFrameAllocator;

    while remaining > 0 {
        let mut unmapped = false;

        for mapping_size in supported_mapping_sizes() {
            if !legal_mapping_size_for_virtual(*mapping_size, virt, remaining) {
                continue;
            }

            if unsafe {
                <ActivePlatform as PagingPlatform>::unmap_leaf(
                    &mut allocator,
                    AbiVirtAddr::new(virt),
                    *mapping_size,
                    disposition,
                    LocalTlbFlush::Flush,
                )
            }
            .is_ok()
            {
                virt += mapping_size.bytes;
                remaining -= mapping_size.bytes;
                unmapped = true;
                break;
            }
        }

        if !unmapped {
            let page = base_page_size();
            virt += page;
            remaining = remaining.saturating_sub(page);
        }
    }
}

pub fn identity_map_page(
    phys: AbiPhysAddr,
    range: usize,
    flags: PageFlags,
) -> Result<(), PageMapError> {
    unsafe {
        map_contiguous_physical_range(
            AbiVirtAddr::new(phys.as_u64()),
            phys,
            range as u64,
            flags,
            None,
            LocalTlbFlush::Flush,
        )
    }
}

pub fn virt_to_phys(addr: AbiVirtAddr) -> Option<(u64, AbiPhysAddr)> {
    let resolved = <ActivePlatform as PagingPlatform>::resolve_mapping(addr)?;
    Some((resolved.mapping_size, resolved.phys_addr))
}

pub fn resolve_virtual_range_frame(addr: AbiVirtAddr) -> Option<(u64, AbiPhysAddr)> {
    virt_to_phys(addr)
}

pub(crate) fn flush_after_unmap(addr: AbiVirtAddr, size: u64) {
    trigger_tlb_shootdown_range(addr, size);
}

fn legal_mapping_size_for_virtual(mapping_size: MappingSize, virt: u64, remaining: u64) -> bool {
    remaining >= mapping_size.bytes && is_aligned(virt, mapping_size.bytes)
}

fn legal_mapping_size_for_existing(
    mapping_size: MappingSize,
    virt: u64,
    phys: u64,
    remaining: u64,
) -> bool {
    legal_mapping_size_for_virtual(mapping_size, virt, remaining)
        && is_aligned(phys, mapping_size.bytes)
}

fn frame_count_for_bytes(bytes: u64) -> Option<usize> {
    let base = base_page_size();
    if bytes == 0 || bytes % base != 0 {
        return None;
    }
    usize::try_from(bytes / base).ok()
}

unsafe fn rollback_mapped_range(
    allocator: &mut KernelPageTableFrameAllocator,
    addr: AbiVirtAddr,
    size: u64,
    disposition: UnmapFrameDisposition,
) {
    if size == 0 {
        return;
    }

    let mut virt = addr.as_u64();
    let mut remaining = size;
    while remaining > 0 {
        let mut unmapped = false;
        for mapping_size in supported_mapping_sizes() {
            if !legal_mapping_size_for_virtual(*mapping_size, virt, remaining) {
                continue;
            }

            if unsafe {
                <ActivePlatform as PagingPlatform>::unmap_leaf(
                    allocator,
                    AbiVirtAddr::new(virt),
                    *mapping_size,
                    disposition,
                    LocalTlbFlush::Defer,
                )
            }
            .is_ok()
            {
                virt += mapping_size.bytes;
                remaining -= mapping_size.bytes;
                unmapped = true;
                break;
            }
        }

        if unmapped {
            continue;
        }

        let page = base_page_size();
        let _ = unsafe {
            <ActivePlatform as PagingPlatform>::unmap_leaf(
                allocator,
                AbiVirtAddr::new(virt),
                MappingSize { bytes: page },
                disposition,
                LocalTlbFlush::Defer,
            )
        };
        virt += page;
        remaining = remaining.saturating_sub(page);
    }
}

fn is_frame_allocation_failure(err: &PageMapError) -> bool {
    matches!(
        err,
        PageMapError::Page4KiB(PageMapFailure::FrameAllocationFailed)
            | PageMapError::Page2MiB(PageMapFailure::FrameAllocationFailed)
            | PageMapError::Page1GiB(PageMapFailure::FrameAllocationFailed)
            | PageMapError::NoMemory()
    )
}

fn is_already_mapped(err: &PageMapError) -> bool {
    matches!(
        err,
        PageMapError::Page4KiB(PageMapFailure::PageAlreadyMapped)
            | PageMapError::Page2MiB(PageMapFailure::PageAlreadyMapped)
            | PageMapError::Page1GiB(PageMapFailure::PageAlreadyMapped)
            | PageMapError::Page4KiB(PageMapFailure::ParentEntryHugePage)
            | PageMapError::Page2MiB(PageMapFailure::ParentEntryHugePage)
            | PageMapError::Page1GiB(PageMapFailure::ParentEntryHugePage)
    )
}
