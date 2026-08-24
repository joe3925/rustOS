pub use x86_64::instructions::hlt;
pub use x86_64::instructions::interrupts::*;

mod apic;
mod platform;

pub(crate) use apic::{
    APIC, APICOffset, ApicErrors, ApicImpl, IpiDest, IpiKind, LAPIC_BASE_VA, LocalApic, send_eoi,
    send_eoi_timer,
};
