pub(crate) const RESERVE_MIB: usize = 2;           

pub(crate) const FRAMES_PER_MIB: usize = 0x1_00000 / 0x1000;  

pub(crate) const LOW_FRAMES: usize = RESERVE_MIB * FRAMES_PER_MIB; 

pub(crate) const FRAMES_PER_2M: usize = 512; // 2 MiB / 4 KiB
pub(crate) const FRAMES_PER_1G: usize = 1 << 18; // 1 GiB / 4 KiB
pub(crate) const WORDS_PER_2M: usize = FRAMES_PER_2M / 64; // 8
pub(crate) const WORDS_PER_1G: usize = FRAMES_PER_1G / 64; // 4096

pub const MMIO_BASE: u64 = 0xFFFF_9000_0000_0000;

pub(crate) const MANAGED_KERNEL_RANGE_START: u64 = MMIO_BASE;
pub(crate)const MANAGED_KERNEL_RANGE_END: u64 = 0xFFFF_FFFF_8000_0000;

pub const BOOT_MEMORY_SIZE: usize = 1024 * 1024 * 1024 * 16;
pub const KERNEL_STACK_SIZE: u64 = 1024 * 1024 * 5;
