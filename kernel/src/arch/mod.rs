pub(crate) mod unwind;
pub(crate) mod debug_transport;
pub(crate) mod tls;

#[cfg(target_arch = "x86_64")]
pub(crate) mod x86;

#[cfg(target_arch = "aarch64")]
pub(crate) mod aarch64;

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("kernel does not have an implementation for this target architecture");
