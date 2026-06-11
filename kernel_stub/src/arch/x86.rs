use core::arch::asm;

use goblin::pe::header::COFF_MACHINE_X86_64;

pub use x86_64::instructions::port::Port;
pub use x86_64::structures::paging::{
    mapper::TranslateError, FrameAllocator, Mapper, OffsetPageTable, Page, PageTable,
    PageTableFlags, PhysFrame, Size4KiB,
};
pub use x86_64::{PhysAddr, VirtAddr};

use x86_64::registers::control::Cr3;

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

pub unsafe fn init_mapper(physical_memory_offset: VirtAddr) -> OffsetPageTable<'static> {
    let level_4_table = unsafe { active_level_4_table(physical_memory_offset) };
    unsafe { OffsetPageTable::new(level_4_table, physical_memory_offset) }
}

unsafe fn active_level_4_table(physical_memory_offset: VirtAddr) -> &'static mut PageTable {
    let (level_4_table_frame, _) = Cr3::read();
    let phys = level_4_table_frame.start_address();
    let virt = physical_memory_offset + phys.as_u64();
    unsafe { &mut *virt.as_mut_ptr() }
}
