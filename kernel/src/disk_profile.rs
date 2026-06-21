use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use kernel_types::disk_profile::{
    DiskProfileSnapshot, DISK_PROFILE_BUCKETS, DISK_PROFILE_COUNTERS,
};

use crate::util::TOTAL_TIME;

static ENABLED: AtomicBool = AtomicBool::new(false);
static ACTIVE_SIZE: AtomicU64 = AtomicU64::new(0);
static COUNTERS: [AtomicU64; DISK_PROFILE_COUNTERS] =
    [const { AtomicU64::new(0) }; DISK_PROFILE_COUNTERS];
static BUCKETS_NS: [AtomicU64; DISK_PROFILE_BUCKETS] =
    [const { AtomicU64::new(0) }; DISK_PROFILE_BUCKETS];

#[inline(always)]
pub fn begin_size(size: u64) {
    ACTIVE_SIZE.store(size, Ordering::Relaxed);
    for counter in &COUNTERS {
        counter.store(0, Ordering::Relaxed);
    }
    for bucket in &BUCKETS_NS {
        bucket.store(0, Ordering::Relaxed);
    }
    ENABLED.store(true, Ordering::Release);
}

#[inline(always)]
pub fn set_enabled(enabled: bool) {
    ENABLED.store(enabled, Ordering::Release);
}

#[inline(always)]
pub fn is_enabled() -> bool {
    ENABLED.load(Ordering::Acquire)
}

#[inline(always)]
pub fn add_counter(id: usize, value: u64) {
    if is_enabled() && id < DISK_PROFILE_COUNTERS {
        COUNTERS[id].fetch_add(value, Ordering::Relaxed);
    }
}

#[inline(always)]
pub fn add_bucket_ns(id: usize, value: u64) {
    if is_enabled() && id < DISK_PROFILE_BUCKETS {
        BUCKETS_NS[id].fetch_add(value, Ordering::Relaxed);
    }
}

#[inline(always)]
pub fn timestamp_ns() -> u64 {
    TOTAL_TIME
        .get()
        .map(|t| t.elapsed().as_nanos().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

#[inline(always)]
pub fn add_elapsed(id: usize, start_ns: u64) {
    add_bucket_ns(id, timestamp_ns().saturating_sub(start_ns));
}

pub fn snapshot(out: &mut DiskProfileSnapshot) {
    out.active_size = ACTIVE_SIZE.load(Ordering::Relaxed);
    for (dst, src) in out.counters.iter_mut().zip(COUNTERS.iter()) {
        *dst = src.load(Ordering::Relaxed);
    }
    for (dst, src) in out.buckets_ns.iter_mut().zip(BUCKETS_NS.iter()) {
        *dst = src.load(Ordering::Relaxed);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn disk_profile_begin_size(size: u64) {
    begin_size(size);
}

#[unsafe(no_mangle)]
pub extern "C" fn disk_profile_set_enabled(enabled: bool) {
    set_enabled(enabled);
}

#[unsafe(no_mangle)]
pub extern "C" fn disk_profile_add_counter(id: u32, value: u64) {
    add_counter(id as usize, value);
}

#[unsafe(no_mangle)]
pub extern "C" fn disk_profile_add_bucket_ns(id: u32, value: u64) {
    add_bucket_ns(id as usize, value);
}

#[unsafe(no_mangle)]
pub extern "C" fn disk_profile_timestamp_ns() -> u64 {
    timestamp_ns()
}

#[unsafe(no_mangle)]
pub extern "C" fn disk_profile_snapshot(out: &mut DiskProfileSnapshot) {
    snapshot(out);
}
