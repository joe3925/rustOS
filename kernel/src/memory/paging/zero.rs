use alloc::string::ToString;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::{Mutex, Once};

use kernel_sync::Platform;
use kernel_types::arch::PhysAddr;
use kernel_types::status::PageMapError;

use crate::memory::paging::frame_alloc::KernelFrameAllocator;
use crate::memory::paging::stack::StackSize;
use crate::platform::{ActivePlatform, PagingPlatform};
use crate::scheduling::runtime::runtime::yield_now;
use crate::scheduling::scheduler::SCHEDULER;
use crate::scheduling::task::Task;
use crate::structs::per_cpu::percpu_by_id;
use crate::sync_platform::{KernelPlatform, WaitQueue};

use super::layout::base_page_size;
use super::virt_tracker::allocate_auto_kernel_range_aligned;

static ZERO_PAGE_WAIT_QUEUE: Once<WaitQueue> = Once::new();
static BOOTSTRAP_ZERO_LOCK: Mutex<()> = Mutex::new(());
static EMERGENCY_ZERO_READY: AtomicBool = AtomicBool::new(false);

struct EmergencyZeroGuard<'a>(&'a AtomicBool);

impl Drop for EmergencyZeroGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

pub fn init_emergency_zero_mappings() -> Result<(), PageMapError> {
    let cpu_count = crate::platform::processor_count();
    let page_size = base_page_size();
    let range_size = page_size
        .checked_mul(cpu_count as u64)
        .ok_or(PageMapError::NoMemory())?;
    let base =
        allocate_auto_kernel_range_aligned(range_size, page_size).ok_or(PageMapError::NoMemory())?;

    for cpu_id in 0..cpu_count {
        let percpu = percpu_by_id(cpu_id).ok_or(PageMapError::NoMemoryMap())?;
        let offset = page_size
            .checked_mul(cpu_id as u64)
            .ok_or(PageMapError::NoMemory())?;
        let address = kernel_types::arch::VirtAddr::new(
            base.as_u64()
                .checked_add(offset)
                .ok_or(PageMapError::NoMemory())?,
        );
        unsafe { <ActivePlatform as PagingPlatform>::prepare_emergency_zero_mapping(address)? };
        percpu.emergency_zero_address.call_once(|| address);
    }

    EMERGENCY_ZERO_READY.store(true, Ordering::Release);
    Ok(())
}

pub fn emergency_zero_physical_frame(physical_address: PhysAddr) -> Result<(), PageMapError> {
    if physical_address.as_u64() % base_page_size() != 0 {
        return Err(PageMapError::TranslationFailed());
    }

    crate::platform::with_interrupts_disabled(|| {
        if !EMERGENCY_ZERO_READY.load(Ordering::Acquire) {
            let address = <ActivePlatform as PagingPlatform>::bootstrap_emergency_zero_address()
                .ok_or(PageMapError::NoMemoryMap())?;
            let _guard = BOOTSTRAP_ZERO_LOCK.lock();
            return unsafe {
                <ActivePlatform as PagingPlatform>::emergency_zero_physical_frame(
                    address,
                    physical_address,
                )
            };
        }

        let percpu = crate::platform::current_percpu();
        if percpu
            .emergency_zero_in_use
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return Err(PageMapError::NoMemory());
        }
        let _guard = EmergencyZeroGuard(&percpu.emergency_zero_in_use);

        match percpu.emergency_zero_address.get().copied() {
            Some(address) => unsafe {
                <ActivePlatform as PagingPlatform>::emergency_zero_physical_frame(
                    address,
                    physical_address,
                )
            },
            None => Err(PageMapError::NoMemoryMap()),
        }
    })
}

pub fn start_zero_page_worker() {
    ZERO_PAGE_WAIT_QUEUE.call_once(WaitQueue::new);
    SCHEDULER.add_task(Task::new_kernel_mode(
        zero_page_worker,
        0,
        StackSize::Tiny,
        "zero-page".to_string(),
        0,
    ));
}

pub fn wake_zero_page_worker() {
    let Some(queue) = ZERO_PAGE_WAIT_QUEUE.get() else {
        return;
    };
    let Some(task) = queue.dequeue_one() else {
        return;
    };

    <KernelPlatform as Platform>::unpark(&task);
}

extern "C" fn zero_page_worker(_: usize) {
    let queue = ZERO_PAGE_WAIT_QUEUE.get().unwrap();

    loop {
        if KernelFrameAllocator::zero_one_free_frame() {
            yield_now();
            continue;
        }

        if !queue.enqueue_current() {
            yield_now();
            continue;
        }

        if KernelFrameAllocator::has_dirty_free_frames() {
            queue.clear_current_if_queued();
            continue;
        }

        <KernelPlatform as Platform>::park_current();
    }
}
