use crate::arch::{PageFlags, PagingPlatform, PhysAddr, PlatformInfo, TranslatedBlock, VirtAddr};
use crate::port::PortAccess;
use crate::status::{PageMapError, PageMapFailure};
use x86_64::structures::paging::{PageTableFlags, Size1GiB, Size2MiB, Size4KiB};

pub struct Platform;

pub type X86Platform = Platform;

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
    fn translate_addr(addr: VirtAddr) -> Option<TranslatedBlock> {
        resolve_virtual_range_frame(addr).map(|(block_size, phys_addr)| TranslatedBlock {
            phys_addr,
            block_size,
        })
    }
}

#[cfg(any(test, feature = "hosted-tests"))]
fn resolve_virtual_range_frame(addr: VirtAddr) -> Option<(u64, PhysAddr)> {
    Some((Size4KiB::SIZE, PhysAddr::new(addr.as_u64())))
}

#[cfg(not(any(test, feature = "hosted-tests")))]
fn resolve_virtual_range_frame(addr: VirtAddr) -> Option<(u64, PhysAddr)> {
    unsafe extern "C" {
        #[link_name = "resolve_virtual_range_frame"]
        fn sys_resolve_virtual_range_frame(addr: VirtAddr) -> Option<(u64, PhysAddr)>;
    }

    unsafe { sys_resolve_virtual_range_frame(addr) }
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
