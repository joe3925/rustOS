pub use kernel_types::disk_profile::*;

#[inline(always)]
pub fn begin_size(size: usize) {
    unsafe { kernel_sys::disk_profile_begin_size(size as u64) };
}

#[inline(always)]
pub fn add_counter(id: usize, value: u64) {
    unsafe { kernel_sys::disk_profile_add_counter(id as u32, value) };
}

#[inline(always)]
pub fn add_bucket_ns(id: usize, value: u64) {
    unsafe { kernel_sys::disk_profile_add_bucket_ns(id as u32, value) };
}

#[inline(always)]
pub fn set_enabled(enabled: bool) {
    unsafe { kernel_sys::disk_profile_set_enabled(enabled) };
}

#[inline(always)]
pub fn timestamp_ns() -> u64 {
    unsafe { kernel_sys::disk_profile_timestamp_ns() }
}

#[inline(always)]
pub fn elapsed_since(start_ns: u64) -> u64 {
    timestamp_ns().saturating_sub(start_ns)
}

#[inline(always)]
pub fn add_elapsed(id: usize, start_ns: u64) {
    add_bucket_ns(id, elapsed_since(start_ns));
}

pub fn snapshot() -> DiskProfileSnapshot {
    let mut out = DiskProfileSnapshot::default();
    unsafe { kernel_sys::disk_profile_snapshot(&mut out) };
    out
}
