use core::sync::atomic::{AtomicU64, Ordering};

use x86_64::registers::control::Cr3;
use x86_64::structures::paging::{
    PageTable, PageTableIndex, PhysFrame, RecursivePageTable, Size4KiB,
};

pub static KERNEL_CR3_U64: AtomicU64 = AtomicU64::new(0);

pub fn init_kernel_cr3() {
    let (frame, _) = Cr3::read();
    KERNEL_CR3_U64.store(frame.start_address().as_u64(), Ordering::SeqCst);
}

pub fn kernel_cr3() -> PhysFrame<Size4KiB> {
    PhysFrame::containing_address(x86_64::PhysAddr::new(KERNEL_CR3_U64.load(Ordering::SeqCst)))
}

pub fn init_mapper(recursive_index: u16) -> RecursivePageTable<'static> {
    let recursive_index = PageTableIndex::new(recursive_index);
    let level_4_table = get_level4_page_table(recursive_index);
    unsafe { RecursivePageTable::new_unchecked(level_4_table, recursive_index) }
}

pub fn get_level4_page_table(recursive_index: PageTableIndex) -> &'static mut PageTable {
    let virt_addr =
        kernel_types::arch::recursive_level_4_table_addr(u64::from(recursive_index) as u16);
    unsafe { &mut *virt_addr.as_mut_ptr() }
}
