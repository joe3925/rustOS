pub mod cpu;
pub mod exception_handlers;
pub mod gdt;
pub mod idt;
pub(crate) mod machine;
pub mod memory;
pub mod platform;
pub(crate) mod serial;
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
    use x86_64::structures::idt::InterruptDescriptorTable;

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

    pub fn triple_fault() -> ! {
        static EMPTY_IDT: InterruptDescriptorTable = InterruptDescriptorTable::new();

        unsafe {
            EMPTY_IDT.load();
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

#[macro_export]
macro_rules! platform_driver_target_dir {
    () => {
        "x86_64-rustos-driver"
    };
}
