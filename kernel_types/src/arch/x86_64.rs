use x86_64::registers::control::Cr3;

use crate::arch::{
    AddressSpacePlatform, PageTranslation, PhysAddr, Platform, PortIoPlatform, SIZE_1GIB,
    SIZE_2MIB, SIZE_4KIB, VirtAddr,
};
use crate::port::PortAccess;

pub struct X86Platform;

impl Platform for X86Platform {
    const NAME: &'static str = "x86_64";
}

impl AddressSpacePlatform for X86Platform {
    #[inline]
    fn current_page_table_root() -> Option<PhysAddr> {
        Some(PhysAddr::new(Cr3::read().0.start_address().as_u64()))
    }

    #[inline]
    fn translate_virtual_address(
        physical_memory_offset: VirtAddr,
        page_table_root: PhysAddr,
        virt_addr: VirtAddr,
    ) -> Option<PageTranslation> {
        translate_virtual_address(physical_memory_offset, page_table_root, virt_addr)
    }
}

impl PortIoPlatform for X86Platform {
    #[inline]
    unsafe fn read_port_u8(port: u16) -> u8 {
        let mut port = x86_64::instructions::port::Port::<u8>::new(port);
        unsafe { port.read() }
    }

    #[inline]
    unsafe fn read_port_u16(port: u16) -> u16 {
        let mut port = x86_64::instructions::port::Port::<u16>::new(port);
        unsafe { port.read() }
    }

    #[inline]
    unsafe fn read_port_u32(port: u16) -> u32 {
        let mut port = x86_64::instructions::port::Port::<u32>::new(port);
        unsafe { port.read() }
    }

    #[inline]
    unsafe fn write_port_u8(port: u16, value: u8) {
        let mut port = x86_64::instructions::port::Port::<u8>::new(port);
        unsafe { port.write(value) }
    }

    #[inline]
    unsafe fn write_port_u16(port: u16, value: u16) {
        let mut port = x86_64::instructions::port::Port::<u16>::new(port);
        unsafe { port.write(value) }
    }

    #[inline]
    unsafe fn write_port_u32(port: u16, value: u32) {
        let mut port = x86_64::instructions::port::Port::<u32>::new(port);
        unsafe { port.write(value) }
    }
}

impl PortAccess for X86Platform {
    #[inline]
    unsafe fn read_u8(port: u16) -> u8 {
        unsafe { <Self as PortIoPlatform>::read_port_u8(port) }
    }

    #[inline]
    unsafe fn read_u16(port: u16) -> u16 {
        unsafe { <Self as PortIoPlatform>::read_port_u16(port) }
    }

    #[inline]
    unsafe fn read_u32(port: u16) -> u32 {
        unsafe { <Self as PortIoPlatform>::read_port_u32(port) }
    }

    #[inline]
    unsafe fn write_u8(port: u16, value: u8) {
        unsafe { <Self as PortIoPlatform>::write_port_u8(port, value) }
    }

    #[inline]
    unsafe fn write_u16(port: u16, value: u16) {
        unsafe { <Self as PortIoPlatform>::write_port_u16(port, value) }
    }

    #[inline]
    unsafe fn write_u32(port: u16, value: u32) {
        unsafe { <Self as PortIoPlatform>::write_port_u32(port, value) }
    }
}

const PRESENT: u64 = 1 << 0;
const HUGE_PAGE: u64 = 1 << 7;

const ADDR_MASK_4K: u64 = 0x000f_ffff_ffff_f000;
const ADDR_MASK_2M: u64 = 0x000f_ffff_ffe0_0000;
const ADDR_MASK_1G: u64 = 0x000f_ffff_c000_0000;

#[inline(always)]
fn p4_index(addr: u64) -> usize {
    ((addr >> 39) & 0x1ff) as usize
}

#[inline(always)]
fn p3_index(addr: u64) -> usize {
    ((addr >> 30) & 0x1ff) as usize
}

#[inline(always)]
fn p2_index(addr: u64) -> usize {
    ((addr >> 21) & 0x1ff) as usize
}

#[inline(always)]
fn p1_index(addr: u64) -> usize {
    ((addr >> 12) & 0x1ff) as usize
}

#[inline]
unsafe fn read_pte(physical_memory_offset: VirtAddr, table_phys: PhysAddr, index: usize) -> u64 {
    let table = (physical_memory_offset.as_u64() + table_phys.as_u64()) as *const u64;
    unsafe { core::ptr::read(table.add(index)) }
}

fn translate_virtual_address(
    physical_memory_offset: VirtAddr,
    page_table_root: PhysAddr,
    virt_addr: VirtAddr,
) -> Option<PageTranslation> {
    let virt = virt_addr.as_u64();

    unsafe {
        let pml4e = read_pte(physical_memory_offset, page_table_root, p4_index(virt));
        if pml4e & PRESENT == 0 {
            return None;
        }

        let pdpt_phys = PhysAddr::new(pml4e & ADDR_MASK_4K);
        let pdpte = read_pte(physical_memory_offset, pdpt_phys, p3_index(virt));
        if pdpte & PRESENT == 0 {
            return None;
        }

        if pdpte & HUGE_PAGE != 0 {
            let offset = virt & (SIZE_1GIB - 1);
            return Some(PageTranslation {
                phys_addr: PhysAddr::new((pdpte & ADDR_MASK_1G) + offset),
                byte_len: SIZE_1GIB,
                offset,
            });
        }

        let pd_phys = PhysAddr::new(pdpte & ADDR_MASK_4K);
        let pde = read_pte(physical_memory_offset, pd_phys, p2_index(virt));
        if pde & PRESENT == 0 {
            return None;
        }

        if pde & HUGE_PAGE != 0 {
            let offset = virt & (SIZE_2MIB - 1);
            return Some(PageTranslation {
                phys_addr: PhysAddr::new((pde & ADDR_MASK_2M) + offset),
                byte_len: SIZE_2MIB,
                offset,
            });
        }

        let pt_phys = PhysAddr::new(pde & ADDR_MASK_4K);
        let pte = read_pte(physical_memory_offset, pt_phys, p1_index(virt));
        if pte & PRESENT == 0 {
            return None;
        }

        let offset = virt & (SIZE_4KIB - 1);
        Some(PageTranslation {
            phys_addr: PhysAddr::new((pte & ADDR_MASK_4K) + offset),
            byte_len: SIZE_4KIB,
            offset,
        })
    }
}
