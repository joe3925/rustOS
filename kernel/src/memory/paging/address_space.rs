use kernel_types::arch::PhysAddr as AbiPhysAddr;
use kernel_types::status::PageMapError;

use crate::platform::{ActivePlatform, AddressSpacePlatform};

use super::frame_alloc::KernelPageTableFrameAllocator;

pub type AddressSpaceRoot = <ActivePlatform as AddressSpacePlatform>::Root;

pub fn init_kernel_address_space_root() {
    <ActivePlatform as AddressSpacePlatform>::init_kernel_root();
}

pub fn kernel_address_space_root() -> AddressSpaceRoot {
    <ActivePlatform as AddressSpacePlatform>::kernel_root()
}

pub fn current_address_space_root() -> AddressSpaceRoot {
    <ActivePlatform as AddressSpacePlatform>::current_root()
}

pub unsafe fn switch_address_space_root(root: AddressSpaceRoot) {
    unsafe {
        <ActivePlatform as AddressSpacePlatform>::switch_root(root);
    }
}

pub fn address_space_root_phys(root: AddressSpaceRoot) -> AbiPhysAddr {
    <ActivePlatform as AddressSpacePlatform>::root_to_phys(root)
}

pub fn create_user_address_space() -> Result<AddressSpaceRoot, PageMapError> {
    let mut allocator = KernelPageTableFrameAllocator;
    <ActivePlatform as AddressSpacePlatform>::create_user_root(&mut allocator)
}

pub unsafe fn destroy_user_address_space(root: AddressSpaceRoot) -> Result<(), PageMapError> {
    let mut allocator = KernelPageTableFrameAllocator;
    unsafe { <ActivePlatform as AddressSpacePlatform>::destroy_user_root(root, &mut allocator) }
}
