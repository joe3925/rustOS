#[cfg(not(target_arch = "x86_64"))]
compile_error!("kernel_stub does not have an implementation for this target architecture");

#[cfg(target_arch = "x86_64")]
mod x86;

#[cfg(target_arch = "x86_64")]
pub use x86::*;
