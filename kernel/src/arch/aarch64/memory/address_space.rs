use kernel_types::arch::PhysAddr;
use kernel_types::status::PageMapError;

use crate::platform::{AddressSpacePlatform, PageTableFrameAllocator};

use super::super::platform::Aarch64Platform;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Root(u64);

impl AddressSpacePlatform for Aarch64Platform {
    type Root = Root;

    fn init_kernel_root() {
        todo!()
    }
    fn kernel_root() -> Self::Root {
        todo!()
    }
    fn current_root() -> Self::Root {
        todo!()
    }
    unsafe fn switch_root(_root: Self::Root) {
        todo!()
    }
    fn root_to_phys(_root: Self::Root) -> PhysAddr {
        todo!()
    }
    fn create_user_root<A: PageTableFrameAllocator>(
        _allocator: &mut A,
    ) -> Result<Self::Root, PageMapError> {
        todo!()
    }
    unsafe fn destroy_user_root<A: PageTableFrameAllocator>(
        _root: Self::Root,
        _allocator: &mut A,
    ) -> Result<(), PageMapError> {
        todo!()
    }
}
