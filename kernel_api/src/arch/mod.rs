#[cfg(not(feature = "arch-x86_64"))]
compile_error!("kernel_api requires an architecture feature; enable `arch-x86_64`");

#[cfg(feature = "arch-x86_64")]
mod x86;

#[cfg(feature = "arch-x86_64")]
pub use x86::*;
