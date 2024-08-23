use x86_64::structures::paging::PageTable;
use x86_64::registers::control::Cr3;
use x86_64::{PhysAddr, VirtAddr};
use crate::println;

fn get_table4_index(virtual_address: VirtAddr) -> usize {
    ((virtual_address.as_u64() >> 39) & 0x1FF) as usize
}

fn get_table3_index(virtual_address: VirtAddr) -> usize {
    ((virtual_address.as_u64() >> 30) & 0x1FF) as usize
}

fn get_table2_index(virtual_address: VirtAddr) -> usize {
    ((virtual_address.as_u64() >> 21) & 0x1FF) as usize
}

fn get_table1_index(virtual_address: VirtAddr) -> usize {
    ((virtual_address.as_u64() >> 12) & 0x1FF) as usize
}

fn get_level4_page_table(mem_offset: VirtAddr) -> &'static mut PageTable {
    println!("getting page 4");
    let (table_frame, _) = Cr3::read();
    let virt_addr = mem_offset + table_frame.start_address().as_u64();
    let page_table_ptr: *mut PageTable = virt_addr.as_mut_ptr();
    unsafe { &mut *page_table_ptr }
}

fn get_level3_page_table(mem_offset: VirtAddr, to_phys: VirtAddr) -> &'static mut PageTable {
    println!("getting page 3");
    let l4_table = get_level4_page_table(mem_offset);
    let l3_table_addr = l4_table[get_table4_index(to_phys)].addr().as_u64();
    let virt_addr = mem_offset + l3_table_addr;
    let page_table_ptr: *mut PageTable = virt_addr.as_mut_ptr();
    unsafe { &mut *page_table_ptr }
}

fn get_level2_page_table(mem_offset: VirtAddr, to_phys: VirtAddr) -> &'static mut PageTable {
    println!("getting page 2");

    let l3_table = get_level3_page_table(mem_offset, to_phys);
    let l2_table_addr = l3_table[get_table3_index(to_phys)].addr().as_u64();
    let virt_addr = mem_offset + l2_table_addr;
    let page_table_ptr: *mut PageTable = virt_addr.as_mut_ptr();
    unsafe { &mut *page_table_ptr }
}

fn get_level1_page_table(mem_offset: VirtAddr, to_phys: VirtAddr) -> &'static mut PageTable {
    println!("getting page 1");
    let l2_table = get_level2_page_table(mem_offset, to_phys);
    let l1_table_addr = l2_table[get_table2_index(to_phys)].addr().as_u64();
    let virt_addr = mem_offset + l1_table_addr;
    let page_table_ptr: *mut PageTable = virt_addr.as_mut_ptr();
    unsafe { &mut *page_table_ptr }
}

pub(crate) fn virtual_to_phys(mem_offset: VirtAddr, to_phys: VirtAddr) -> PhysAddr {
    println!("getting page addr");
    let l1_table = get_level1_page_table(mem_offset, to_phys);
    let page_entry = &l1_table[get_table1_index(to_phys)];
    page_entry.addr()
}