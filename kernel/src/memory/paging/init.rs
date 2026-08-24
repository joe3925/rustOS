use super::address_space::init_kernel_address_space_root;

pub fn init_paging() {
    init_kernel_address_space_root();
}
