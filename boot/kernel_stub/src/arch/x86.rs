use core::arch::asm;

use goblin::pe::header::COFF_MACHINE_X86_64;

pub use x86_64::instructions::port::Port;
pub use x86_64::structures::paging::{
    mapper::RecursivePageTable, mapper::TranslateError, FrameAllocator, Mapper, Page, PageTable,
    PageTableFlags, PageTableIndex, PhysFrame, Size4KiB,
};
pub use x86_64::{PhysAddr, VirtAddr};

pub fn validate_kernel_machine(machine: u16) -> Result<(), &'static str> {
    if machine == COFF_MACHINE_X86_64 {
        Ok(())
    } else {
        Err("kernel_stub: kernel PE machine is not x86_64")
    }
}

pub unsafe fn enter_kernel_pe(entry: u64, boot_info: *const kernel_abi::BootInfo) -> ! {
    unsafe {
        asm!(
            "cld",
            "and rsp, -16",
            "sub rsp, 40",
            "mov qword ptr [rsp], 0",
            "jmp rax",
            in("rax") entry,
            in("rcx") boot_info,
            options(noreturn)
        )
    }
}

pub fn halt() -> ! {
    loop {
        x86_64::instructions::hlt();
    }
}

pub unsafe fn init_mapper(recursive_index: u16) -> RecursivePageTable<'static> {
    let recursive_index = PageTableIndex::new(recursive_index);
    let level_4_table = unsafe { active_level_4_table(recursive_index) };
    unsafe { RecursivePageTable::new_unchecked(level_4_table, recursive_index) }
}

unsafe fn active_level_4_table(recursive_index: PageTableIndex) -> &'static mut PageTable {
    let virt = recursive_level_4_table_addr(recursive_index);
    unsafe { &mut *virt.as_mut_ptr() }
}

fn recursive_level_4_table_addr(recursive_index: PageTableIndex) -> VirtAddr {
    let idx = u64::from(recursive_index);
    let mut addr = (idx << 39) | (idx << 30) | (idx << 21) | (idx << 12);
    if addr & (1 << 47) != 0 {
        addr |= 0xFFFF_0000_0000_0000;
    }
    VirtAddr::new(addr)
}
