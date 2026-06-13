pub mod address_space;
pub mod frame_alloc;
pub mod frame_bitmap;
pub mod layout;
pub mod map;
pub mod mmio;
pub mod stack;
pub mod tlb;
pub mod types;
pub mod virt_tracker;

pub use address_space::{
    address_space_root_phys, create_user_address_space, current_address_space_root,
    destroy_user_address_space, init_kernel_address_space_root, kernel_address_space_root,
    switch_address_space_root, AddressSpaceRoot,
};
pub use frame_alloc::{
    boot_usable_bytes, resize_bitmap_for_ram, total_usable_bytes, used_bytes, KernelFrameAllocator,
    KernelPageTableFrameAllocator,
};
pub use layout::{
    align_up_to_base_page, base_page_size, kernel_space_base, kernel_virtual_layout,
    low_physical_reserve_bytes, managed_kernel_range_end, managed_kernel_range_start, mmio_base,
    paging_capabilities, supported_mapping_sizes,
};
pub use map::{
    allocate_auto_kernel_range_mapped, allocate_auto_kernel_range_mapped_contiguous,
    allocate_kernel_range_mapped, identity_map_page, map_allocated_range,
    map_contiguous_physical_range, map_fresh_kernel_range_no_flush, map_range,
    resolve_virtual_range_frame, unmap_range, unmap_range_keep_frames_unchecked,
    unmap_range_unchecked, unmap_reserved_range_unchecked, virt_to_phys,
};
pub use mmio::{map_physical_pages, map_physical_pages_aligned, unmap_physical_pages};
pub use stack::{
    allocate_kernel_stack, deallocate_kernel_stack, kernel_stack_max_bytes,
    kernel_stack_reservation_bytes, StackSize,
};
pub use tlb::{
    handle_remote_tlb_shootdown, trigger_tlb_shootdown, trigger_tlb_shootdown_range,
    trigger_tlb_shootdown_ranges,
};
pub use types::{
    KernelVirtualLayout, LocalTlbFlush, MappingSize, PagingCapabilities, ResolvedMapping,
    TlbShootdownRange, UnmapFrameDisposition,
};
pub use virt_tracker::{
    allocate_auto_kernel_range, allocate_auto_kernel_range_aligned, allocate_kernel_range,
    deallocate_kernel_range,
};

pub fn init_paging() {
    init_kernel_address_space_root();
}
