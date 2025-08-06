use core::sync::atomic::{AtomicU64, Ordering};

use x86_64::{
    registers::control::Cr3,
    structures::paging::{
        FrameAllocator, OffsetPageTable, PageTable, PageTableFlags, PageTableIndex, PhysFrame,
        Size4KiB,
    },
    PhysAddr, VirtAddr,
};

use crate::{
    memory::paging::{paging::PageMapError, virt_tracker::allocate_auto_kernel_range_mapped},
    util::boot_info,
};

pub static KERNEL_CR3_U64: AtomicU64 = AtomicU64::new(0);

pub fn init_kernel_cr3() {
    let (frame, _) = Cr3::read();
    KERNEL_CR3_U64.store(frame.start_address().as_u64(), Ordering::SeqCst);
}

pub fn kernel_cr3() -> PhysFrame<Size4KiB> {
    PhysFrame::containing_address(x86_64::PhysAddr::new(KERNEL_CR3_U64.load(Ordering::SeqCst)))
}

fn get_level4_page_table(mem_offset: VirtAddr) -> &'static mut PageTable {
    let (table_frame, _) = Cr3::read();
    let virt_addr = mem_offset + table_frame.start_address().as_u64();
    let page_table_ptr: *mut PageTable = virt_addr.as_mut_ptr();
    unsafe { &mut *page_table_ptr }
}

fn get_level3_page_table(mem_offset: VirtAddr, to_phys: VirtAddr) -> &'static mut PageTable {
    let l4_table = get_level4_page_table(mem_offset);
    let l3_table_addr = l4_table[to_phys.p4_index()].addr().as_u64();
    let virt_addr = mem_offset + l3_table_addr;
    let page_table_ptr: *mut PageTable = virt_addr.as_mut_ptr();
    unsafe { &mut *page_table_ptr }
}

fn get_level2_page_table(mem_offset: VirtAddr, to_phys: VirtAddr) -> &'static mut PageTable {
    let l3_table = get_level3_page_table(mem_offset, to_phys);
    let l2_table_addr = l3_table[to_phys.p3_index()].addr().as_u64();
    let virt_addr = mem_offset + l2_table_addr;
    let page_table_ptr: *mut PageTable = virt_addr.as_mut_ptr();
    unsafe { &mut *page_table_ptr }
}

fn get_level1_page_table(mem_offset: VirtAddr, to_phys: VirtAddr) -> &'static mut PageTable {
    let l2_table = get_level2_page_table(mem_offset, to_phys);
    let l1_table_addr = l2_table[to_phys.p2_index()].addr().as_u64();
    let virt_addr = mem_offset + l1_table_addr;
    let page_table_ptr: *mut PageTable = virt_addr.as_mut_ptr();
    unsafe { &mut *page_table_ptr }
}

pub(crate) fn virt_to_phys(to_phys: VirtAddr) -> PhysAddr {
    let mem_offset = VirtAddr::new(boot_info().physical_memory_offset.into_option().unwrap());
    let l1_table = get_level1_page_table(mem_offset, to_phys);
    let page_entry = &l1_table[to_phys.p1_index()];
    page_entry.addr()
}
pub fn init_mapper(physical_memory_offset: VirtAddr) -> OffsetPageTable<'static> {
    let level_4_table = get_level4_page_table(physical_memory_offset);
    unsafe { OffsetPageTable::new(level_4_table, physical_memory_offset) }
}

pub fn new_user_mode_page_table() -> Result<(PhysAddr, VirtAddr), PageMapError> {
    let mem_offset = boot_info()
        .physical_memory_offset
        .into_option()
        .ok_or(PageMapError::NoMemoryMap())?;

    let table_virt = allocate_auto_kernel_range_mapped(
        size_of::<PageTable>() as u64,
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_CACHE,
    )?;

    let table_phys_addr = virt_to_phys(table_virt);
    let kernel_pml4 = get_level4_page_table(VirtAddr::new(mem_offset));

    let new_table: &mut PageTable = unsafe { &mut *(table_virt.as_mut_ptr()) };
    new_table.zero();

    for i in 256..512 {
        new_table[i] = kernel_pml4[i].clone();
    }

    Ok((table_phys_addr, table_virt))
}

fn get_or_create_table(
    parent: &mut PageTable,
    index: PageTableIndex,
    mem_offset: VirtAddr,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) -> &'static mut PageTable {
    let entry = &mut parent[index];

    if entry.flags().contains(PageTableFlags::PRESENT) {
        let phys = entry.frame().unwrap().start_address();
        let virt = mem_offset + phys.as_u64();
        unsafe { &mut *(virt.as_mut_ptr()) }
    } else {
        let frame = frame_allocator
            .allocate_frame()
            .expect("Frame allocation failed");
        let virt = mem_offset + frame.start_address().as_u64();
        let table = unsafe {
            let ptr: *mut PageTable = virt.as_mut_ptr();
            ptr.write(PageTable::new());
            &mut *ptr
        };
        entry.set_frame(frame, PageTableFlags::PRESENT | PageTableFlags::WRITABLE);
        table
    }
}
