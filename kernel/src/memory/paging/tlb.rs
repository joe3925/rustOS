use core::ptr::null_mut;
use core::sync::atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering};

use kernel_types::arch::VirtAddr as AbiVirtAddr;

use crate::KERNEL_INITIALIZED;
use crate::arch::MAX_CPUS;
use crate::platform::{ActivePlatform, PagingPlatform};

use super::layout::base_page_size;
use super::types::TlbShootdownRange;

const TLB_SHOOTDOWN_MODE_FULL: usize = 0;
const TLB_SHOOTDOWN_MODE_RANGES: usize = 1;
const TLB_SHOOTDOWN_RANGE_FLUSH_LIMIT: u64 = MAX_CPUS as u64 * u64::BITS as u64 / 4;

static TLB_SHOOTDOWN_LOCK: spin::Mutex<()> = spin::Mutex::new(());
static TLB_SHOOTDOWN_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static TLB_SHOOTDOWN_ACKS: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
static TLB_SHOOTDOWN_MODE: AtomicUsize = AtomicUsize::new(TLB_SHOOTDOWN_MODE_FULL);
static TLB_SHOOTDOWN_RANGES: AtomicPtr<TlbShootdownRange> = AtomicPtr::new(null_mut());
static TLB_SHOOTDOWN_RANGE_COUNT: AtomicUsize = AtomicUsize::new(0);

pub fn trigger_tlb_shootdown() {
    trigger_tlb_shootdown_request(None);
}

pub fn trigger_tlb_shootdown_range(start: AbiVirtAddr, size: u64) {
    let range = TlbShootdownRange::new(start, size);
    trigger_tlb_shootdown_ranges(core::slice::from_ref(&range));
}

pub fn trigger_tlb_shootdown_ranges(ranges: &[TlbShootdownRange]) {
    if matches!(tlb_ranges_page_count(ranges), Some(0)) {
        return;
    }
    trigger_tlb_shootdown_request(Some(ranges));
}

pub fn handle_remote_tlb_shootdown() {
    flush_current_tlb_shootdown_request();

    let cpu = crate::platform::current_cpu_id();
    if cpu < MAX_CPUS {
        let sequence = TLB_SHOOTDOWN_SEQUENCE.load(Ordering::SeqCst);
        TLB_SHOOTDOWN_ACKS[cpu].store(sequence, Ordering::SeqCst);
    }
}

fn trigger_tlb_shootdown_request(ranges: Option<&[TlbShootdownRange]>) {
    let cpu_count = crate::platform::processor_count();
    if cpu_count <= 1 || !KERNEL_INITIALIZED.load(Ordering::Acquire) {
        flush_tlb_shootdown_request(ranges);
        return;
    }

    assert!(
        cpu_count <= MAX_CPUS,
        "TLB shootdown CPU count {} exceeds ack table size {}",
        cpu_count,
        MAX_CPUS
    );
    assert!(
        crate::platform::interrupts_enabled(),
        "synchronous TLB shootdown attempted with interrupts disabled"
    );

    let _guard = TLB_SHOOTDOWN_LOCK.lock();
    match ranges {
        Some(ranges) => {
            TLB_SHOOTDOWN_RANGES.store(ranges.as_ptr() as *mut TlbShootdownRange, Ordering::SeqCst);
            TLB_SHOOTDOWN_RANGE_COUNT.store(ranges.len(), Ordering::SeqCst);
            TLB_SHOOTDOWN_MODE.store(TLB_SHOOTDOWN_MODE_RANGES, Ordering::SeqCst);
        }
        None => clear_tlb_shootdown_request(),
    }

    let sequence = TLB_SHOOTDOWN_SEQUENCE.fetch_add(1, Ordering::SeqCst) + 1;
    let current_cpu = crate::platform::current_cpu_id();

    let sent = <ActivePlatform as PagingPlatform>::broadcast_tlb_shootdown();
    flush_tlb_shootdown_request(ranges);
    if current_cpu < MAX_CPUS {
        TLB_SHOOTDOWN_ACKS[current_cpu].store(sequence, Ordering::SeqCst);
    }

    if !sent {
        clear_tlb_shootdown_request();
        return;
    }

    for cpu in 0..cpu_count {
        if cpu == current_cpu {
            continue;
        }

        while TLB_SHOOTDOWN_ACKS[cpu].load(Ordering::SeqCst) < sequence {
            core::hint::spin_loop();
        }
    }

    clear_tlb_shootdown_request();
}

fn flush_tlb_shootdown_request(ranges: Option<&[TlbShootdownRange]>) {
    match ranges {
        Some(ranges) => flush_tlb_ranges_or_all(ranges),
        None => <ActivePlatform as PagingPlatform>::local_flush_tlb_all(),
    }
}

fn flush_current_tlb_shootdown_request() {
    if TLB_SHOOTDOWN_MODE.load(Ordering::SeqCst) != TLB_SHOOTDOWN_MODE_RANGES {
        <ActivePlatform as PagingPlatform>::local_flush_tlb_all();
        return;
    }

    let count = TLB_SHOOTDOWN_RANGE_COUNT.load(Ordering::SeqCst);
    if count == 0 {
        return;
    }

    let ptr = TLB_SHOOTDOWN_RANGES.load(Ordering::SeqCst);
    if ptr.is_null() {
        <ActivePlatform as PagingPlatform>::local_flush_tlb_all();
        return;
    }

    let ranges = unsafe { core::slice::from_raw_parts(ptr as *const TlbShootdownRange, count) };
    flush_tlb_ranges_or_all(ranges);
}

fn flush_tlb_ranges_or_all(ranges: &[TlbShootdownRange]) {
    if should_flush_all_for_tlb_ranges(ranges) {
        <ActivePlatform as PagingPlatform>::local_flush_tlb_all();
        return;
    }

    for range in ranges {
        if tlb_range_bounds(*range).is_none() {
            <ActivePlatform as PagingPlatform>::local_flush_tlb_all();
            return;
        }

        <ActivePlatform as PagingPlatform>::local_flush_tlb_range(
            range.start,
            range.size,
            range.stride,
        );
    }
}

fn clear_tlb_shootdown_request() {
    TLB_SHOOTDOWN_MODE.store(TLB_SHOOTDOWN_MODE_FULL, Ordering::SeqCst);
    TLB_SHOOTDOWN_RANGES.store(null_mut(), Ordering::SeqCst);
    TLB_SHOOTDOWN_RANGE_COUNT.store(0, Ordering::SeqCst);
}

fn should_flush_all_for_tlb_ranges(ranges: &[TlbShootdownRange]) -> bool {
    match tlb_ranges_page_count(ranges) {
        Some(pages) => pages > TLB_SHOOTDOWN_RANGE_FLUSH_LIMIT,
        None => true,
    }
}

fn tlb_ranges_page_count(ranges: &[TlbShootdownRange]) -> Option<u64> {
    let mut total = 0u64;
    for range in ranges {
        total = total.checked_add(tlb_range_page_count(*range)?)?;
    }
    Some(total)
}

fn tlb_range_page_count(range: TlbShootdownRange) -> Option<u64> {
    let (start, end) = tlb_range_bounds(range)?;
    Some((end - start) / range.stride)
}

fn tlb_range_bounds(range: TlbShootdownRange) -> Option<(u64, u64)> {
    let stride = if range.stride == 0 {
        base_page_size()
    } else {
        range.stride
    };
    if !stride.is_power_of_two() {
        return None;
    }

    let start = range.start.as_u64() & !(stride - 1);
    if range.size == 0 {
        return Some((start, start));
    }

    let end_unaligned = range.start.as_u64().checked_add(range.size)?;
    let end = end_unaligned
        .checked_add(stride - 1)
        .map(|x| x & !(stride - 1))?;
    if end < start {
        return None;
    }

    Some((start, end))
}
