pub mod ACPI;
pub mod drive;
pub mod driver_install;
pub(crate) mod pnp;
#[allow(dead_code)]
pub(crate) use crate::arch::drivers::interrupt_index;
#[allow(dead_code)]
pub(crate) use crate::arch::drivers::timer_driver;
