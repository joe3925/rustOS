#[cfg(not(target_arch = "x86_64"))]
compile_error!("kernel does not have an implementation for this target architecture");

#[cfg(target_arch = "x86_64")]
pub mod x86;

#[cfg(target_arch = "x86_64")]
pub use x86::{cpu, drivers, exception_handlers, gdt, idt, memory, syscalls};

#[cfg(target_arch = "x86_64")]
pub(crate) use x86::scheduling;

#[cfg(target_arch = "x86_64")]
pub use x86::{PhysAddr, VirtAddr};

#[cfg(target_arch = "x86_64")]
pub use x86::{PageFlags, align_up, control, idt_types, instructions, interrupts, paging};

#[cfg(target_arch = "x86_64")]
pub use x86::MAX_CPUS;

#[cfg(target_arch = "x86_64")]
pub use x86::PlatformImpl;

#[cfg(target_arch = "x86_64")]
#[macro_export]
macro_rules! platform_driver_target_dir {
    () => {
        "x86_64-rustos-driver"
    };
}
