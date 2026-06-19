#[cfg(not(target_arch = "x86_64"))]
compile_error!("kernel does not have an implementation for this target architecture");

#[cfg(target_arch = "x86_64")]
mod x86;

#[cfg(target_arch = "x86_64")]
pub use self::x86::PlatformImpl;
