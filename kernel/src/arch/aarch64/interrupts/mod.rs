mod controller;
mod discovery;
mod entry;
mod gicv3;
mod init;
mod platform;

pub(crate) use init::{init_boot_interrupts, init_current_cpu_interrupts};
