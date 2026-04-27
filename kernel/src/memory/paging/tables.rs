use core::sync::atomic::{AtomicU64, Ordering};

use kernel_types::status::PageMapError;
use x86_64::{
    registers::control::Cr3,
    structures::paging::{
        FrameAllocator, OffsetPageTable, PageTable, PageTableFlags, PageTableIndex, PhysFrame,
        Size4KiB,
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

#[inline(always)]
unsafe fn read_pte(mem_offset: u64, table_phys: u64, index: usize) -> u64 {
    let table = (mem_offset + table_phys) as *const u64;
    unsafe { core::ptr::read(table.add(index)) }
}

#[inline(always)]
pub(crate) extern "win64" fn virt_to_phys(addr: VirtAddr) -> Option<PhysAddr> {
    let virt = addr.as_u64();
    let cr3_phys = Cr3::read().0.start_address().as_u64();
    let mem_offset = boot_info().physical_memory_offset.into_option().unwrap();

    unsafe {
        let pml4e = read_pte(mem_offset, cr3_phys, p4_index(virt));
        if pml4e & PRESENT == 0 {
            return None;
        }

        let pdpt_phys = pml4e & ADDR_MASK_4K;
        let pdpte = read_pte(mem_offset, pdpt_phys, p3_index(virt));
        if pdpte & PRESENT == 0 {
            return None;
        }

        if pdpte & HUGE_PAGE != 0 {
            let base = pdpte & ADDR_MASK_1G;
            let offset = virt & ((1 << 30) - 1);
            return Some(PhysAddr::new(base + offset));
        }

        let pd_phys = pdpte & ADDR_MASK_4K;
        let pde = read_pte(mem_offset, pd_phys, p2_index(virt));
        if pde & PRESENT == 0 {
            return None;
        }

        if pde & HUGE_PAGE != 0 {
            let base = pde & ADDR_MASK_2M;
            let offset = virt & ((1 << 21) - 1);
            return Some(PhysAddr::new(base + offset));
        }

        let pt_phys = pde & ADDR_MASK_4K;
        let pte = read_pte(mem_offset, pt_phys, p1_index(virt));
        if pte & PRESENT == 0 {
            return None;
        }

        let base = pte & ADDR_MASK_4K;
        let offset = virt & 0xfff;

        Some(PhysAddr::new(base + offset))
    }
}
fn get_level4_page_table(mem_offset: VirtAddr) -> &'static mut PageTable {
    let (table_frame, _) = Cr3::read();
    let virt_addr = mem_offset + table_frame.start_address().as_u64();
    let page_table_ptr: *mut PageTable = virt_addr.as_mut_ptr();
    unsafe { &mut *page_table_ptr }
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

    let table_phys_addr = virt_to_phys(table_virt).ok_or(PageMapError::TranslationFailed())?;
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
