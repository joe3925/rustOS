#[cfg(target_arch = "x86_64")]
pub mod x86;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("kernel_stub does not have an implementation for this target architecture");

fn validate_tls_fields(
    image_base: u64,
    image_size: u64,
    raw_start: u64,
    raw_end: u64,
    index: u64,
    callbacks: u64,
) -> Result<(), &'static str> {
    let image_end = image_base
        .checked_add(image_size)
        .ok_or("kernel_stub: PE image range overflow")?;
    if raw_start != 0 || raw_end != 0 {
        if raw_start == 0
            || raw_start > raw_end
            || raw_start < image_base
            || raw_end > image_end
        {
            return Err("kernel_stub: invalid PE TLS raw data range");
        }
    }
    if index != 0
        && (index < image_base
            || index
                .checked_add(core::mem::size_of::<u32>() as u64)
                .is_none_or(|end| end > image_end))
    {
        return Err("kernel_stub: PE TLS index is outside the kernel image");
    }
    if callbacks != 0 && (callbacks < image_base || callbacks >= image_end) {
        return Err("kernel_stub: PE TLS callbacks pointer is outside the kernel image");
    }
    Ok(())
}
