use crate::memory::paging::paging::align_up_4k;
use x86_64::VirtAddr;

pub const HEAP_START: usize = 0xFFFF_8600_0000_0000;
pub const HEAP_SIZE: usize = 0x0000_00FF_FFFF_FFFF;
