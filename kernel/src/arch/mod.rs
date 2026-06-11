#[cfg(not(feature = "arch-x86_64"))]
compile_error!("kernel requires an architecture feature; enable `arch-x86_64`");

#[cfg(feature = "arch-x86_64")]
pub mod x86;

#[cfg(feature = "arch-x86_64")]
pub use x86::{cpu, drivers, exception_handlers, gdt, idt, memory, syscalls};

#[cfg(feature = "arch-x86_64")]
pub(crate) use x86::scheduling;

#[cfg(feature = "arch-x86_64")]
pub use x86::{PhysAddr, VirtAddr};

#[cfg(feature = "arch-x86_64")]
pub use x86::{align_up, control, idt_types, instructions, interrupts, paging, PageFlags};

#[cfg(feature = "arch-x86_64")]
pub use x86::MAX_CPUS;
