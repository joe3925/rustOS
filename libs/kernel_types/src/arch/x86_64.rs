use crate::arch::{PageFlags, PagingPlatform, PhysAddr, PlatformInfo, TranslatedBlock, VirtAddr};
use crate::port::PortAccess;
use crate::status::{PageMapError, PageMapFailure};
use x86_64::structures::paging::{
    PageSize, PageTable, PageTableFlags, Size1GiB, Size2MiB, Size4KiB,
};

pub struct Platform;

pub type X86Platform = Platform;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PagingInfo {
    pub recursive_index: u16,
}

impl PlatformInfo for Platform {
    const NAME: &'static str = "x86_64";

    fn cycle_counter() -> u64 {
        let lo: u32;
        let hi: u32;
        unsafe {
            core::arch::asm!(
                "rdtsc",
                out("eax") lo,
                out("edx") hi,
                options(nomem, nostack, preserves_flags)
            );
        }
        ((hi as u64) << 32) | (lo as u64)
    }
}

impl PagingPlatform for Platform {
    fn paging_info() -> Option<PagingInfo> {
        paging_info()
    }

    fn translate_addr(addr: VirtAddr) -> Option<TranslatedBlock> {
        translate_addr_with_paging_info(Self::paging_info()?, addr)
    }
}

fn translate_addr_with_paging_info(info: PagingInfo, addr: VirtAddr) -> Option<TranslatedBlock> {
    let rec = u64::from(info.recursive_index);
    let v_u64 = addr.as_u64();

    let p4_idx = (v_u64 >> 39) & 0x1FF;
    let p3_idx = (v_u64 >> 30) & 0x1FF;
    let p2_idx = (v_u64 >> 21) & 0x1FF;
    let p1_idx = (v_u64 >> 12) & 0x1FF;

    let p4_table = unsafe { &*(recursive_table_addr(rec, rec, rec, rec) as *const PageTable) };
    let p4_entry = &p4_table[p4_idx as usize];
    if !p4_entry.flags().contains(PageTableFlags::PRESENT) {
        return None;
    }

    let p3_table = unsafe { &*(recursive_table_addr(rec, rec, rec, p4_idx) as *const PageTable) };
    let p3_entry = &p3_table[p3_idx as usize];
    if !p3_entry.flags().contains(PageTableFlags::PRESENT) {
        return None;
    }
    if p3_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
        return Some(TranslatedBlock {
            phys_addr: PhysAddr::new(p3_entry.addr().as_u64() + (v_u64 & (Size1GiB::SIZE - 1))),
            block_size: Size1GiB::SIZE,
        });
    }

    let p2_table =
        unsafe { &*(recursive_table_addr(rec, rec, p4_idx, p3_idx) as *const PageTable) };
    let p2_entry = &p2_table[p2_idx as usize];
    if !p2_entry.flags().contains(PageTableFlags::PRESENT) {
        return None;
    }
    if p2_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
        return Some(TranslatedBlock {
            phys_addr: PhysAddr::new(p2_entry.addr().as_u64() + (v_u64 & (Size2MiB::SIZE - 1))),
            block_size: Size2MiB::SIZE,
        });
    }

    let p1_table =
        unsafe { &*(recursive_table_addr(rec, p4_idx, p3_idx, p2_idx) as *const PageTable) };
    let p1_entry = &p1_table[p1_idx as usize];
    if !p1_entry.flags().contains(PageTableFlags::PRESENT) {
        return None;
    }

    Some(TranslatedBlock {
        phys_addr: PhysAddr::new(p1_entry.addr().as_u64() + (v_u64 & (Size4KiB::SIZE - 1))),
        block_size: Size4KiB::SIZE,
    })
}

#[cfg(any(test, feature = "hosted-tests"))]
fn paging_info() -> Option<PagingInfo> {
    None
}

#[cfg(not(any(test, feature = "hosted-tests")))]
fn paging_info() -> Option<PagingInfo> {
    unsafe extern "C" {
        fn kernel_paging_info() -> Option<PagingInfo>;
    }

    unsafe { kernel_paging_info() }
}

pub const fn recursive_table_addr(p4: u64, p3: u64, p2: u64, p1: u64) -> u64 {
    let mut addr = (p4 << 39) | (p3 << 30) | (p2 << 21) | (p1 << 12);
    if addr & (1 << 47) != 0 {
        addr |= 0xFFFF_0000_0000_0000;
    }
    addr
}

pub const fn recursive_level_4_table_addr(recursive_index: u16) -> VirtAddr {
    let idx = recursive_index as u64;
    VirtAddr::new(recursive_table_addr(idx, idx, idx, idx))
}

impl PortAccess for Platform {
    #[inline]
    unsafe fn read_u8(port: u16) -> u8 {
        let mut port = x86_64::instructions::port::Port::<u8>::new(port);
        unsafe { port.read() }
    }

    #[inline]
    unsafe fn read_u16(port: u16) -> u16 {
        let mut port = x86_64::instructions::port::Port::<u16>::new(port);
        unsafe { port.read() }
    }

    #[inline]
    unsafe fn read_u32(port: u16) -> u32 {
        let mut port = x86_64::instructions::port::Port::<u32>::new(port);
        unsafe { port.read() }
    }

    #[inline]
    unsafe fn write_u8(port: u16, value: u8) {
        let mut port = x86_64::instructions::port::Port::<u8>::new(port);
        unsafe { port.write(value) }
    }

    #[inline]
    unsafe fn write_u16(port: u16, value: u16) {
        let mut port = x86_64::instructions::port::Port::<u16>::new(port);
        unsafe { port.write(value) }
    }

    #[inline]
    unsafe fn write_u32(port: u16, value: u32) {
        let mut port = x86_64::instructions::port::Port::<u32>::new(port);
        unsafe { port.write(value) }
    }
}

impl From<x86_64::VirtAddr> for VirtAddr {
    fn from(value: x86_64::VirtAddr) -> Self {
        Self::new(value.as_u64())
    }
}

impl From<VirtAddr> for x86_64::VirtAddr {
    fn from(value: VirtAddr) -> Self {
        x86_64::VirtAddr::new(value.as_u64())
    }
}

impl From<x86_64::PhysAddr> for PhysAddr {
    fn from(value: x86_64::PhysAddr) -> Self {
        Self::new(value.as_u64())
    }
}

impl From<PhysAddr> for x86_64::PhysAddr {
    fn from(value: PhysAddr) -> Self {
        x86_64::PhysAddr::new(value.as_u64())
    }
}

impl From<PageTableFlags> for PageFlags {
    fn from(value: PageTableFlags) -> Self {
        Self::from_bits_truncate(value.bits())
    }
}

impl From<PageFlags> for PageTableFlags {
    fn from(value: PageFlags) -> Self {
        PageTableFlags::from_bits_truncate(value.bits())
    }
}

impl From<x86_64::structures::paging::mapper::MapToError<Size4KiB>> for PageMapError {
    fn from(e: x86_64::structures::paging::mapper::MapToError<Size4KiB>) -> Self {
        PageMapError::Page4KiB(PageMapFailure::from(e))
    }
}

impl From<x86_64::structures::paging::mapper::MapToError<Size2MiB>> for PageMapError {
    fn from(e: x86_64::structures::paging::mapper::MapToError<Size2MiB>) -> Self {
        PageMapError::Page2MiB(PageMapFailure::from(e))
    }
}

impl From<x86_64::structures::paging::mapper::MapToError<Size1GiB>> for PageMapError {
    fn from(e: x86_64::structures::paging::mapper::MapToError<Size1GiB>) -> Self {
        PageMapError::Page1GiB(PageMapFailure::from(e))
    }
}

impl<S> From<x86_64::structures::paging::mapper::MapToError<S>> for PageMapFailure
where
    S: x86_64::structures::paging::page::PageSize,
{
    fn from(e: x86_64::structures::paging::mapper::MapToError<S>) -> Self {
        match e {
            x86_64::structures::paging::mapper::MapToError::FrameAllocationFailed => {
                PageMapFailure::FrameAllocationFailed
            }
            x86_64::structures::paging::mapper::MapToError::PageAlreadyMapped(_) => {
                PageMapFailure::PageAlreadyMapped
            }
            x86_64::structures::paging::mapper::MapToError::ParentEntryHugePage => {
                PageMapFailure::ParentEntryHugePage
            }
        }
    }
}

#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __chkstk() {
    core::arch::naked_asm!(
        "test rax, rax",
        "jnz 2f",
        "mov rax, rcx",
        "2:",
        "mov r10, rax",
        "mov r11, rsp",
        "cmp r10, 0x1000",
        "jb 4f",
        "3:",
        "sub r11, 0x1000",
        "test byte ptr [r11], 0",
        "sub r10, 0x1000",
        "cmp r10, 0x1000",
        "jae 3b",
        "4:",
        "sub r11, r10",
        "test byte ptr [r11], 0",
        "ret"
    );
}

#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __chkstk_ms() {
    core::arch::naked_asm!(
        "test rax, rax",
        "jnz 2f",
        "mov rax, rcx",
        "2:",
        "mov r10, rax",
        "mov r11, rsp",
        "cmp r10, 0x1000",
        "jb 4f",
        "3:",
        "sub r11, 0x1000",
        "test byte ptr [r11], 0",
        "sub r10, 0x1000",
        "cmp r10, 0x1000",
        "jae 3b",
        "4:",
        "sub r11, r10",
        "test byte ptr [r11], 0",
        "ret"
    );
}
