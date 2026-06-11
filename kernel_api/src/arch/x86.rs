use kernel_types::arch::{PhysAddr, VirtAddr};

use x86_64::{registers::control::Cr3, structures::paging::PageTable};

#[inline(always)]
fn get_level4_page_table(mem_offset: VirtAddr) -> *mut PageTable {
    let (table_frame, _) = Cr3::read();
    let virt_addr =
        x86_64::VirtAddr::new(mem_offset.as_u64() + table_frame.start_address().as_u64());
    virt_addr.as_mut_ptr()
}

#[inline(always)]
pub fn virt_to_phys(mem_offset: VirtAddr, to_phys: VirtAddr) -> Option<PhysAddr> {
    let to_phys = x86_64::VirtAddr::new(to_phys.as_u64());
    let l4 = get_level4_page_table(mem_offset);
    let l4e = unsafe { &(&*l4)[to_phys.p4_index()] };
    if !l4e
        .flags()
        .contains(x86_64::structures::paging::PageTableFlags::PRESENT)
    {
        return None;
    }

    let l3_virt = mem_offset + l4e.addr().as_u64();
    let l3_table: *const PageTable = l3_virt.as_ptr();
    let l3e = unsafe { &(&*l3_table)[to_phys.p3_index()] };
    if !l3e
        .flags()
        .contains(x86_64::structures::paging::PageTableFlags::PRESENT)
    {
        return None;
    }
    if l3e
        .flags()
        .contains(x86_64::structures::paging::PageTableFlags::HUGE_PAGE)
    {
        let base = l3e.addr().as_u64();
        let offset = to_phys.as_u64() & ((1u64 << 30) - 1);
        return Some(PhysAddr::new(base + offset));
    }

    let l2_virt = mem_offset + l3e.addr().as_u64();
    let l2_table: *const PageTable = l2_virt.as_ptr();
    let l2e = unsafe { &(&*l2_table)[to_phys.p2_index()] };
    if !l2e
        .flags()
        .contains(x86_64::structures::paging::PageTableFlags::PRESENT)
    {
        return None;
    }
    if l2e
        .flags()
        .contains(x86_64::structures::paging::PageTableFlags::HUGE_PAGE)
    {
        let base = l2e.addr().as_u64();
        let offset = to_phys.as_u64() & ((1u64 << 21) - 1);
        return Some(PhysAddr::new(base + offset));
    }

    let l1_virt = mem_offset + l2e.addr().as_u64();
    let l1_table: *const PageTable = l1_virt.as_ptr();
    let l1e = unsafe { &(&*l1_table)[to_phys.p1_index()] };
    if !l1e
        .flags()
        .contains(x86_64::structures::paging::PageTableFlags::PRESENT)
    {
        return None;
    }
    let base = l1e.addr().as_u64();
    let offset = to_phys.as_u64() & 0xFFF;
    Some(PhysAddr::new(base + offset))
}
