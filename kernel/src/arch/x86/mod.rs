pub mod cpu;
pub(crate) mod debug;
pub mod exception_handlers;
pub mod gdt;
pub mod idt;
pub mod interrupts;
pub(crate) mod machine;
pub mod memory;
pub(crate) mod pci;
pub mod platform;
pub(crate) mod scheduling;
pub(crate) mod serial;
pub(crate) mod timer;
pub(crate) mod unwind;

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

pub mod instructions {
    use core::arch::asm;

    pub fn invalid_opcode() -> ! {
        unsafe {
            asm!("ud2", options(noreturn));
        }
    }
}

pub mod paging {
    pub use x86_64::structures::paging::mapper::MapToError;
    pub use x86_64::structures::paging::{
        PageSize, PageTable, PageTableFlags, PhysFrame, Size1GiB, Size2MiB, Size4KiB,
    };
}

pub type PlatformImpl = platform::X86Platform;

pub const MAX_CPUS: usize = 256;
