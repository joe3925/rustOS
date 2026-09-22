use crate::arch::tls::TlsDirectory;
use crate::util::boot_info;

pub use crate::arch::tls::KernelTls;

pub fn for_kernel_thread() -> Option<KernelTls> {
    let directory = boot_info().arch_info.pe_tls_directory.as_ref().copied()?;
    KernelTls::new(TlsDirectory {
        start: directory.start_address_of_raw_data,
        end: directory.end_address_of_raw_data,
        zero_fill: directory.size_of_zero_fill,
        characteristics: directory.characteristics,
    })
}
