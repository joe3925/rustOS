use crate::alloc::string::ToString;
use crate::export;
use crate::file_system::file::File;
use crate::function;
use crate::get_rva;
use crate::idt::*;
use crate::memory::paging::mmio::map_mmio_region;
use crate::memory::paging::paging::identity_map_page;
use crate::memory::paging::tables::virt_to_phys;
use crate::memory::paging::virt_tracker::allocate_auto_kernel_range_mapped;
use crate::memory::paging::virt_tracker::allocate_kernel_range_mapped;
use crate::memory::paging::virt_tracker::deallocate_kernel_range;
use crate::memory::paging::virt_tracker::unmap_range;
use crate::scheduling::runtime::runtime::try_steal_blocking_one;
use crate::static_handlers::*;
use crate::util::panic_common;
use crate::util::random_number;
use crate::vec;
use alloc::string::String;
use alloc::vec::Vec;

export! {
    function,
    print,
    wait_duration,
    create_kernel_task,
    kill_kernel_task_by_id,
    sleep_self,
    sleep_self_and_yield,
    wake_task,
    switch_to_vfs_async,
    panic_common,
    submit_runtime_internal,
    submit_blocking_internal,
    try_steal_blocking_one,
    get_rsdp,
    get_acpi_tables,
    task_yield,
    allocate_auto_kernel_range_mapped,
    allocate_kernel_range_mapped,
    deallocate_kernel_range,
    unmap_range,
    identity_map_page,
    map_mmio_region,
    virt_to_phys,
    get_current_cpu_id,

    kernel_alloc,
    kernel_free,
    kernel_irq_register,
    kernel_irq_signal,
    kernel_irq_signal_n,
    irq_handle_create,
    irq_handle_clone,
    irq_handle_drop,
    irq_handle_unregister,
    irq_handle_is_closed,
    irq_handle_set_user_ctx,
    irq_handle_get_user_ctx,
    irq_handle_wait_ffi,

    file_open,
    fs_list_dir,
    fs_remove_dir,
    fs_make_dir,

    pnp_create_pdo,
    pnp_bind_and_start,
    pnp_get_device_target,
    pnp_complete_request,
    pnp_queue_dpc,
    pnp_send_request,
    pnp_create_child_devnode_and_pdo_with_init,
    pnp_create_symlink,
    pnp_replace_symlink,
    pnp_create_device_symlink_top,
    pnp_remove_symlink,
    pnp_send_request_via_symlink,
    pnp_ioctl_via_symlink,
    pnp_load_service,
    pnp_add_class_listener,
    pnp_create_control_device_with_init,
    pnp_create_control_device_and_link,
    pnp_create_devnode_over_pdo_with_function,
    pnp_forward_request_to_next_lower,
    pnp_forward_request_to_next_upper,
    pnp_send_request_to_stack_top,
    InvalidateDeviceRelations,

    driver_get_name,
    driver_get_flags,
    driver_set_evt_device_add,
    driver_set_evt_driver_unload,
    random_number,

    reg_get_value,
    reg_set_value,
    reg_create_key,
    reg_delete_key,
    reg_delete_value,
    reg_list_keys,
    reg_list_values,

    kernel_spawn_ffi,
    kernel_async_submit,

    bench_kernel_span_end,
    bench_kernel_span_begin,
    bench_kernel_submit_rip_sample,
    bench_kernel_window_persist,
    bench_kernel_window_stop,
    bench_kernel_window_start,
    bench_kernel_window_destroy,
    bench_kernel_window_create,
}
