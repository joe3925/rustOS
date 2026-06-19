use core::ops::{Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, Not, Sub};

#[cfg(target_arch = "x86_64")]
#[path = "arch/x86_64.rs"]
pub mod x86;

#[cfg(target_arch = "x86_64")]
pub use x86::{PagingInfo, Platform};

#[cfg(not(target_arch = "x86_64"))]
compile_error!("kernel_types does not have an implementation for this target architecture");

pub trait PlatformInfo {
    const NAME: &'static str;
    fn cycle_counter() -> u64;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TranslatedBlock {
    pub phys_addr: PhysAddr,
    pub block_size: u64,
}

pub trait PagingPlatform: PlatformInfo {
    fn paging_info() -> Option<PagingInfo>;
    fn translate_addr(addr: VirtAddr) -> Option<TranslatedBlock>;
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VirtAddr(u64);

impl VirtAddr {
    pub const fn new(addr: u64) -> Self {
        Self(addr)
    }

    pub const fn as_u64(self) -> u64 {
        self.0
    }

    pub fn from_ptr<T>(ptr: *const T) -> Self {
        Self(ptr as u64)
    }

    pub const fn as_ptr<T>(self) -> *const T {
        self.0 as *const T
    }

    pub const fn as_mut_ptr<T>(self) -> *mut T {
        self.0 as *mut T
    }
}

impl Add<u64> for VirtAddr {
    type Output = Self;

    fn add(self, rhs: u64) -> Self::Output {
        Self(self.0 + rhs)
    }
}

impl AddAssign<u64> for VirtAddr {
    fn add_assign(&mut self, rhs: u64) {
        self.0 += rhs;
    }
}

impl Sub for VirtAddr {
    type Output = u64;

    fn sub(self, rhs: Self) -> Self::Output {
        self.0 - rhs.0
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PhysAddr(u64);

impl PhysAddr {
    pub const fn new(addr: u64) -> Self {
        Self(addr)
    }

    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PageFlags(u64);

impl PageFlags {
    pub const PRESENT: Self = Self(1 << 0);
    pub const WRITABLE: Self = Self(1 << 1);
    pub const USER_ACCESSIBLE: Self = Self(1 << 2);
    pub const WRITE_THROUGH: Self = Self(1 << 3);
    pub const NO_CACHE: Self = Self(1 << 4);
    pub const ACCESSED: Self = Self(1 << 5);
    pub const DIRTY: Self = Self(1 << 6);
    pub const HUGE_PAGE: Self = Self(1 << 7);
    pub const GLOBAL: Self = Self(1 << 8);
    pub const NO_EXECUTE: Self = Self(1 << 63);

    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn from_bits_truncate(bits: u64) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u64 {
        self.0
    }

    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl BitOr for PageFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for PageFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl BitAnd for PageFlags {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl BitAndAssign for PageFlags {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

impl Not for PageFlags {
    type Output = Self;

    fn not(self) -> Self::Output {
        Self(!self.0)
    }
}
