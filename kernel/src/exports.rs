use crate::alloc::string::ToString;
use crate::export;
use crate::file_system::file::File;
use crate::function;
use crate::get_rva;
use crate::memory::paging::mmio::map_mmio_region;
use crate::memory::paging::paging::identity_map_page;
use crate::memory::paging::virt_tracker::allocate_auto_kernel_range_mapped;
use crate::memory::paging::virt_tracker::allocate_kernel_range_mapped;
use crate::memory::paging::virt_tracker::deallocate_kernel_range;
use crate::memory::paging::virt_tracker::unmap_range;
use crate::static_handlers::*;
use crate::vec;
use alloc::string::String;
use alloc::vec::Vec;

export! {
    function,
    create_kernel_task,
    allocate_auto_kernel_range_mapped,
    allocate_kernel_range_mapped,
    deallocate_kernel_range,
    unmap_range,
    identity_map_page,
    map_mmio_region,
    kernel_alloc,
    kernel_free,

    file_open,
    fs_list_dir,
    fs_remove_dir,
    fs_make_dir,
    file_read,
    file_write,
    file_delete,
}
