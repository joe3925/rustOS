use core::sync::atomic::{AtomicU64, Ordering};

use kernel_types::status::PageMapError;
use x86_64::{
    registers::control::Cr3,
    structures::paging::{
        PageTable, PageTableFlags, PageTableIndex, PhysFrame, RecursivePageTable, Size4KiB,
        Translate,
    },
    PhysAddr, VirtAddr,
};

use crate::{memory::paging::virt_tracker::allocate_auto_kernel_range_mapped, util::boot_info};

pub static KERNEL_CR3_U64: AtomicU64 = AtomicU64::new(0);

pub fn init_kernel_cr3() {
    let (frame, _) = Cr3::read();
    KERNEL_CR3_U64.store(frame.start_address().as_u64(), Ordering::SeqCst);
}

pub fn kernel_cr3() -> PhysFrame<Size4KiB> {
    PhysFrame::containing_address(x86_64::PhysAddr::new(KERNEL_CR3_U64.load(Ordering::SeqCst)))
}

use x86_64::structures::paging::mapper::MappedFrame;
use x86_64::structures::paging::mapper::MapperAllSizes;
use x86_64::structures::paging::mapper::TranslateResult;

#[inline(always)]
pub extern "C" fn resolve_virtual_range_frame(addr: VirtAddr) -> Option<(u64, PhysAddr)> {
    let recursive_index = boot_info().recursive_index.into_option()?;
    let rec = u64::from(recursive_index);
    let v_u64 = addr.as_u64();

    let p4_idx = (v_u64 >> 39) & 0x1FF;
    let p3_idx = (v_u64 >> 30) & 0x1FF;
    let p2_idx = (v_u64 >> 21) & 0x1FF;
    let p1_idx = (v_u64 >> 12) & 0x1FF;

    // PML4
    let mut p4_addr = (rec << 39) | (rec << 30) | (rec << 21) | (rec << 12);
    if p4_addr & (1 << 47) != 0 {
        p4_addr |= 0xFFFF_0000_0000_0000;
    }
    let p4_table = unsafe { &*(p4_addr as *const PageTable) };
    let p4_entry = &p4_table[p4_idx as usize];
    if !p4_entry.flags().contains(PageTableFlags::PRESENT) {
        return None;
    }

    // PDPT
    let mut p3_addr = (rec << 39) | (rec << 30) | (rec << 21) | (p4_idx << 12);
    if p3_addr & (1 << 47) != 0 {
        p3_addr |= 0xFFFF_0000_0000_0000;
    }
    let p3_table = unsafe { &*(p3_addr as *const PageTable) };
    let p3_entry = &p3_table[p3_idx as usize];
    if !p3_entry.flags().contains(PageTableFlags::PRESENT) {
        return None;
    }
    if p3_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
        let phys_base = p3_entry.addr();
        return Some((
            1024 * 1024 * 1024,
            phys_base + (v_u64 & ((1024 * 1024 * 1024) - 1)),
        ));
    }

    // PD
    let mut p2_addr = (rec << 39) | (rec << 30) | (p4_idx << 21) | (p3_idx << 12);
    if p2_addr & (1 << 47) != 0 {
        p2_addr |= 0xFFFF_0000_0000_0000;
    }
    let p2_table = unsafe { &*(p2_addr as *const PageTable) };
    let p2_entry = &p2_table[p2_idx as usize];
    if !p2_entry.flags().contains(PageTableFlags::PRESENT) {
        return None;
    }
    if p2_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
        let phys_base = p2_entry.addr();
        return Some((
            2 * 1024 * 1024,
            phys_base + (v_u64 & ((2 * 1024 * 1024) - 1)),
        ));
    }

    // PT
    let mut p1_addr = (rec << 39) | (p4_idx << 30) | (p3_idx << 21) | (p2_idx << 12);
    if p1_addr & (1 << 47) != 0 {
        p1_addr |= 0xFFFF_0000_0000_0000;
    }
    let p1_table = unsafe { &*(p1_addr as *const PageTable) };
    let p1_entry = &p1_table[p1_idx as usize];
    if !p1_entry.flags().contains(PageTableFlags::PRESENT) {
        return None;
    }

    let phys_base = p1_entry.addr();
    Some((4096, phys_base + (v_u64 & 4095)))
}

#[inline(always)]
pub extern "C" fn virt_to_phys(addr: VirtAddr) -> Option<(u64, PhysAddr)> {
    let recursive_index = boot_info().recursive_index.into_option()?;
    let mapper = init_mapper(recursive_index);
    let res = mapper.translate(addr);
    match res {
        TranslateResult::Mapped { frame, offset, .. } => {
            let size = match frame {
                MappedFrame::Size4KiB(_) => 4096,
                MappedFrame::Size2MiB(_) => 2 * 1024 * 1024,
                MappedFrame::Size1GiB(_) => 1024 * 1024 * 1024,
            };
            Some((size, frame.start_address() + offset))
        }
        _ => None,
    }
}

fn get_level4_page_table(recursive_index: PageTableIndex) -> &'static mut PageTable {
    let virt_addr = recursive_level_4_table_addr(recursive_index);
    unsafe { &mut *virt_addr.as_mut_ptr() }
}

pub fn init_mapper(recursive_index: u16) -> RecursivePageTable<'static> {
    let recursive_index = PageTableIndex::new(recursive_index);
    let level_4_table = get_level4_page_table(recursive_index);
    unsafe { RecursivePageTable::new_unchecked(level_4_table, recursive_index) }
}

fn recursive_level_4_table_addr(recursive_index: PageTableIndex) -> VirtAddr {
    let idx = u64::from(recursive_index);
    let mut addr = (idx << 39) | (idx << 30) | (idx << 21) | (idx << 12);
    if addr & (1 << 47) != 0 {
        addr |= 0xFFFF_0000_0000_0000;
    }
    VirtAddr::new(addr)
}

pub fn new_user_mode_page_table() -> Result<(PhysAddr, VirtAddr), PageMapError> {
    let recursive_index = boot_info()
        .recursive_index
        .into_option()
        .ok_or(PageMapError::NoMemoryMap())?;

    let table_virt = allocate_auto_kernel_range_mapped(
        size_of::<PageTable>() as u64,
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_CACHE,
    )?;

    let (_, table_phys_addr) = virt_to_phys(table_virt).ok_or(PageMapError::TranslationFailed())?;
    let kernel_pml4 = get_level4_page_table(PageTableIndex::new(recursive_index));

    let new_table: &mut PageTable = unsafe { &mut *(table_virt.as_mut_ptr()) };
    new_table.zero();

    for i in 256..512 {
        new_table[i] = kernel_pml4[i].clone();
    }

    Ok((table_phys_addr, table_virt))
}
