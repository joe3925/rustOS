#[cfg(target_arch = "x86_64")]
mod x86;

#[cfg(target_arch = "x86_64")]
pub use self::x86::PlatformImpl;

#[cfg(target_arch = "x86_64")]
pub(crate) fn serial_write_bytes(bytes: &[u8]) {
    self::x86::serial::write_bytes(bytes);
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn init_debug_metadata_transport() {
    self::x86::debug_meta::init_debug_metadata_transport();
}

#[cfg(target_arch = "aarch64")]
mod aarch64;

#[cfg(target_arch = "aarch64")]
pub use self::aarch64::PlatformImpl;

#[cfg(target_arch = "aarch64")]
pub(crate) fn serial_write_bytes(_bytes: &[u8]) {}

#[cfg(target_arch = "aarch64")]
pub(crate) fn init_debug_metadata_transport() {}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("kernel does not have an implementation for this target architecture");
