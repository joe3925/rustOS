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
