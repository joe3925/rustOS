use alloc::vec::Vec;
use kernel_types::arch::{PageFlags, PhysAddr, VirtAddr};
use kernel_types::memory::PhysicalMappingCache;
use kernel_types::memory::{KernelMapping, RangeReservation};
use kernel_types::status::{PageMapError, PageMapFailure};

use crate::platform::{ActivePlatform, PageTableFrameAllocator, PagingPlatform};

use super::address_space::{AddressSpaceRoot, kernel_address_space_root};
use super::frame_alloc::{KernelFrameAllocator, KernelPageTableFrameAllocator};
use super::layout::{
    align_up_to_base_page, base_page_size, heap_range_end, heap_range_start, is_aligned,
    largest_mapping_size_for, supported_mapping_sizes,
};
use super::tlb::trigger_tlb_shootdown_range;
use super::types::{MappingSize, UnmapFrameDisposition};
use super::virt_tracker::{reserve_auto_kernel_range, reserve_auto_kernel_range_aligned};

pub(crate) fn allocate_auto_kernel_mapping(
    size: u64,
    flags: PageFlags,
) -> Result<KernelMapping, PageMapError> {
    let aligned_size = align_up_to_base_page(size).ok_or(PageMapError::NoMemory())?;
    let reservation =
        reserve_auto_kernel_range(aligned_size).map_err(|_| PageMapError::NoMemory())?;
    allocate_kernel_mapping(reservation, 0, aligned_size, flags).map_err(|(_, error)| error)
}

pub(crate) fn allocate_auto_contiguous_kernel_mapping(
    size: u64,
    flags: PageFlags,
) -> Result<KernelMapping, PageMapError> {
    let aligned_size = align_up_to_base_page(size).ok_or(PageMapError::NoMemory())?;
    if aligned_size == 0 {
        return Err(PageMapError::NoMemory());
    }

    let frame_count = frame_count_for_bytes(aligned_size).ok_or(PageMapError::NoMemory())?;
    let mapping_size = largest_mapping_size_for(aligned_size, None);
    let phys_align_frames = frame_count_for_bytes(mapping_size).ok_or(PageMapError::NoMemory())?;

    let reservation = reserve_auto_kernel_range_aligned(aligned_size, mapping_size)
        .map_err(|_| PageMapError::NoMemory())?;
    let addr = reservation.start();

    let phys_base =
        KernelFrameAllocator::allocate_contiguous_frames_aligned(frame_count, phys_align_frames)
            .ok_or(PageMapError::NoMemory())?;

    if let Err(err) = unsafe {
        map_contiguous_physical_range(
            kernel_address_space_root(),
            addr,
            phys_base,
            aligned_size,
            flags,
            None,
        )
    } {
        unsafe {
            KernelFrameAllocator::release_reserved_mapping_frame(
                phys_base,
                MappingSize {
                    bytes: aligned_size,
                },
            );
        }
        return Err(err);
    }

    match reservation.into_allocated_mapping(0, aligned_size) {
        Ok(mapping) => Ok(mapping),
        Err(reservation) => {
            unsafe { unmap_kernel_range_unchecked(addr, aligned_size) };
            Err({
                drop(reservation);
                PageMapError::TranslationFailed()
            })
        }
    }
}

pub(crate) unsafe fn commit_heap_range(
    addr: VirtAddr,
    size: u64,
    flags: PageFlags,
    ignore_already_mapped: bool,
) -> Result<(), PageMapError> {
    let end = addr
        .as_u64()
        .checked_add(size)
        .ok_or(PageMapError::NoMemory())?;
    if addr.as_u64() < heap_range_start().as_u64() || end > heap_range_end().as_u64() {
        return Err(PageMapError::NoMemory());
    }
    unsafe {
        map_range_inner(
            kernel_address_space_root(),
            addr,
            size,
            flags,
            ignore_already_mapped,
        )
    }
}

pub(crate) unsafe fn decommit_heap_range(
    addr: VirtAddr,
    size: u64,
) -> Result<(), PageMapError> {
    let end = addr
        .as_u64()
        .checked_add(size)
        .ok_or(PageMapError::NoMemory())?;
    if addr.as_u64() < heap_range_start().as_u64() || end > heap_range_end().as_u64() {
        return Err(PageMapError::NoMemory());
    }
    unsafe {
        unmap_range_with_disposition(
            kernel_address_space_root(),
            addr,
            size,
            UnmapFrameDisposition::FreeMappedFrame,
        )
    }
}

pub(in crate::memory) unsafe fn map_user_range_locked(
    root: AddressSpaceRoot,
    addr: VirtAddr,
    size: u64,
    flags: PageFlags,
    ignore_already_mapped: bool,
) -> Result<(), PageMapError> {
    unsafe { map_range_inner(root, addr, size, flags, ignore_already_mapped) }
}

pub(crate) unsafe fn map_kernel_range(
    addr: VirtAddr,
    size: u64,
    flags: PageFlags,
    ignore_already_mapped: bool,
) -> Result<(), PageMapError> {
    unsafe {
        map_range_inner(
            kernel_address_space_root(),
            addr,
            size,
            flags,
            ignore_already_mapped,
        )
    }
}

unsafe fn map_range_inner(
    root: AddressSpaceRoot,
    addr: VirtAddr,
    size: u64,
    flags: PageFlags,
    ignore_already_mapped: bool,
) -> Result<(), PageMapError> {
    unsafe {
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
                        root,
                        &mut allocator,
                        VirtAddr::new(virt),
                        phys,
                        *mapping_size,
                        flags,
                        None,
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
                                    root,
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
                        root,
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
}

pub(crate) unsafe fn map_contiguous_physical_range(
    root: AddressSpaceRoot,
    virt_base: VirtAddr,
    phys_base: PhysAddr,
    size: u64,
    flags: PageFlags,
    cache: Option<PhysicalMappingCache>,
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
                    root,
                    &mut allocator,
                    VirtAddr::new(cur_virt),
                    PhysAddr::new(cur_phys),
                    *mapping_size,
                    flags,
                    cache,
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
                            root,
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
                    root,
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

pub(crate) fn map_physical_into_reservation(
    reservation: RangeReservation,
    offset: u64,
    physical: PhysAddr,
    size: u64,
    flags: PageFlags,
    cache: Option<PhysicalMappingCache>,
) -> Result<KernelMapping, (RangeReservation, PageMapError)> {
    if !reservation.contains(offset, size) {
        return Err((reservation, PageMapError::TranslationFailed()));
    }
    let virtual_address = VirtAddr::new(reservation.start().as_u64() + offset);
    if let Err(error) = unsafe {
        map_contiguous_physical_range(
            kernel_address_space_root(),
            virtual_address,
            physical,
            size,
            flags,
            cache,
        )
    } {
        return Err((reservation, error));
    }
    match reservation.into_borrowed_mapping(offset, size) {
        Ok(mapping) => Ok(mapping),
        Err(reservation) => {
            unsafe { unmap_kernel_range_keep_frames_unchecked(virtual_address, size) };
            Err((reservation, PageMapError::TranslationFailed()))
        }
    }
}

pub(crate) fn allocate_kernel_mapping(
    reservation: RangeReservation,
    offset: u64,
    size: u64,
    flags: PageFlags,
) -> Result<KernelMapping, (RangeReservation, PageMapError)> {
    if !reservation.contains(offset, size) {
        return Err((reservation, PageMapError::TranslationFailed()));
    }
    let virtual_address = VirtAddr::new(reservation.start().as_u64() + offset);
    if let Err(error) = unsafe { map_kernel_range(virtual_address, size, flags, false) } {
        return Err((reservation, error));
    }
    match reservation.into_allocated_mapping(offset, size) {
        Ok(mapping) => Ok(mapping),
        Err(reservation) => {
            unsafe { unmap_kernel_range_unchecked(virtual_address, size) };
            Err((reservation, PageMapError::TranslationFailed()))
        }
    }
}

/// # Safety
/// `addr..addr + size` must be a live kernel mapping owned by the caller and
/// no references into it may survive this call.
pub(in crate::memory) unsafe fn unmap_user_range_locked(
    root: AddressSpaceRoot,
    addr: VirtAddr,
    size: u64,
) -> Result<(), PageMapError> {
    unsafe {
        unmap_range_with_disposition(root, addr, size, UnmapFrameDisposition::FreeMappedFrame)
    }
}

pub(crate) unsafe fn unmap_kernel_range_unchecked(addr: VirtAddr, size: u64) {
    unsafe {
        unmap_range_with_disposition(
            kernel_address_space_root(),
            addr,
            size,
            UnmapFrameDisposition::FreeMappedFrame,
        )
        .expect("failed to unmap unchecked kernel virtual range");
    }
}

pub(crate) unsafe fn unmap_kernel_range_keep_frames_unchecked(addr: VirtAddr, size: u64) {
    unsafe {
        unmap_range_with_disposition(
            kernel_address_space_root(),
            addr,
            size,
            UnmapFrameDisposition::KeepFrame,
        )
        .expect("failed to unmap kernel virtual range while preserving mapped frames");
    }
}

pub(crate) unsafe fn unmap_kernel_reserved_range_unchecked(addr: VirtAddr, size: u64) {
    unsafe {
        unmap_range_with_disposition(
            kernel_address_space_root(),
            addr,
            size,
            UnmapFrameDisposition::ReleaseReservedFrame,
        )
        .expect("failed to unmap reserved kernel virtual range");
    }
}

unsafe fn unmap_range_with_disposition(
    root: AddressSpaceRoot,
    addr: VirtAddr,
    size: u64,
    disposition: UnmapFrameDisposition,
) -> Result<(), PageMapError> {
    let mut virt = addr.as_u64();
    let mut remaining = align_up_to_base_page(size).ok_or(PageMapError::NoMemory())?;

    let mut allocator = KernelPageTableFrameAllocator;
    let mut leaf_reclaims = Vec::new();
    let mut table_reclaims = Vec::new();

    while remaining > 0 {
        let mut unmapped = false;
        let mut last_error = None;

        for mapping_size in supported_mapping_sizes() {
            if !legal_mapping_size_for_virtual(*mapping_size, virt, remaining) {
                continue;
            }

            match unsafe {
                leaf_reclaims
                    .try_reserve(1)
                    .map_err(|_| PageMapError::NoMemory())?;
                table_reclaims
                    .try_reserve(4)
                    .map_err(|_| PageMapError::NoMemory())?;
                <ActivePlatform as PagingPlatform>::unmap_leaf(
                    root,
                    &mut allocator,
                    VirtAddr::new(virt),
                    *mapping_size,
                    &mut table_reclaims,
                )
            } {
                Ok(Some(physical_address)) => {
                    leaf_reclaims.push((physical_address, *mapping_size));
                    virt += mapping_size.bytes;
                    remaining -= mapping_size.bytes;
                    unmapped = true;
                    break;
                }

                Ok(None) => {
                    virt += mapping_size.bytes;
                    remaining -= mapping_size.bytes;
                    unmapped = true;
                    break;
                }

                Err(error) => {
                    last_error = Some(error);
                }
            }
        }

        if !unmapped {
            finish_unmap(
                root,
                addr,
                virt.saturating_sub(addr.as_u64()),
                disposition,
                &mut allocator,
                &leaf_reclaims,
                &table_reclaims,
            );
            return Err(last_error.unwrap_or(PageMapError::TranslationFailed()));
        }
    }

    finish_unmap(
        root,
        addr,
        virt.saturating_sub(addr.as_u64()),
        disposition,
        &mut allocator,
        &leaf_reclaims,
        &table_reclaims,
    );

    Ok(())
}

pub(crate) fn identity_map_kernel_page(
    phys: PhysAddr,
    range: usize,
    flags: PageFlags,
) -> Result<(), PageMapError> {
    unsafe {
        map_contiguous_physical_range(
            kernel_address_space_root(),
            VirtAddr::new(phys.as_u64()),
            phys,
            range as u64,
            flags,
            None,
        )
    }
}

pub(crate) fn virt_to_phys(root: AddressSpaceRoot, addr: VirtAddr) -> Option<(u64, PhysAddr)> {
    let resolved = <ActivePlatform as PagingPlatform>::resolve_mapping(root, addr)?;
    Some((resolved.mapping_size, resolved.phys_addr))
}

pub(crate) fn kernel_virt_to_phys(addr: VirtAddr) -> Option<(u64, PhysAddr)> {
    virt_to_phys(kernel_address_space_root(), addr)
}

fn finish_unmap(
    root: AddressSpaceRoot,
    addr: VirtAddr,
    size: u64,
    disposition: UnmapFrameDisposition,
    allocator: &mut KernelPageTableFrameAllocator,
    leaf_reclaims: &[(PhysAddr, MappingSize)],
    table_reclaims: &[PhysAddr],
) {
    if size != 0 {
        trigger_tlb_shootdown_range(root, addr, size);
    }

    for (physical_address, mapping_size) in leaf_reclaims {
        match disposition {
            UnmapFrameDisposition::FreeMappedFrame => unsafe {
                KernelFrameAllocator::free_mapping_frame(*physical_address, *mapping_size)
            },
            UnmapFrameDisposition::ReleaseReservedFrame => unsafe {
                KernelFrameAllocator::release_reserved_mapping_frame(
                    *physical_address,
                    *mapping_size,
                )
            },
            UnmapFrameDisposition::KeepFrame => {}
        }
    }

    for physical_address in table_reclaims {
        allocator.free_page_table_frame(*physical_address);
    }
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
    root: AddressSpaceRoot,
    addr: VirtAddr,
    size: u64,
    disposition: UnmapFrameDisposition,
) {
    if size != 0 {
        let _ = unsafe { unmap_range_with_disposition(root, addr, size, disposition) };
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
