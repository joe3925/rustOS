pub mod cpu;
pub mod exception_handlers;
pub mod gdt;
pub mod idt;
pub mod memory;
pub(crate) mod scheduling;

pub mod drivers {
    pub(crate) mod interrupt_index;
    pub(crate) mod timer_driver;
}

pub mod syscalls {
    use core::arch::asm;

    pub(crate) mod syscall;

    pub unsafe fn task_yield_interrupt() {
        unsafe {
            asm!("int 0x80");
        }
    }
}

pub mod control {
    pub use x86_64::registers::control::Cr3;
}

pub mod idt_types {
    pub use x86_64::structures::idt::InterruptDescriptorTable;
}

pub mod interrupts {
    pub use x86_64::instructions::hlt;
    pub use x86_64::instructions::interrupts::*;
}

pub mod instructions {
    use core::arch::asm;

    pub unsafe fn trigger_guard_page_overflow(target: u64) -> ! {
        unsafe {
            asm!(
                "mov rsp, {0}",
                "mov qword ptr [rsp], 0",
                in(reg) target,
                options(noreturn)
            );
        }
    }

    pub fn invalid_opcode() -> ! {
        unsafe {
            asm!("ud2", options(noreturn));
        }
    }

    pub fn breakpoint() {
        unsafe {
            asm!("int 3");
        }
    }
}

pub mod paging {
    pub use x86_64::structures::paging::mapper::MapToError;
    pub use x86_64::structures::paging::{
        PageSize, PageTable, PageTableFlags, PhysFrame, Size1GiB, Size2MiB, Size4KiB,
    };
}

pub use x86_64::align_up;
pub use x86_64::structures::paging::PageTableFlags as PageFlags;
pub use x86_64::{PhysAddr, VirtAddr};

pub const MAX_CPUS: usize = 256;
