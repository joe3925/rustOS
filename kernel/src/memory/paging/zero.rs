use alloc::string::ToString;
use spin::Once;

use kernel_sync::Platform;
use kernel_types::arch::PhysAddr;
use kernel_types::status::PageMapError;

use crate::memory::paging::frame_alloc::KernelFrameAllocator;
use crate::memory::paging::stack::StackSize;
use crate::scheduling::fifo_scheduler::{FifoPriority, fifo_task_sched_binding};
use crate::scheduling::runtime::runtime::yield_now;
use crate::scheduling::scheduler::SCHEDULER;
use crate::scheduling::task::Task;
use crate::sync_platform::{KernelPlatform, WaitQueue};

use super::layout::base_page_size;

static ZERO_PAGE_WAIT_QUEUE: Once<WaitQueue> = Once::new();

pub fn zero_physical_frame(physical_address: PhysAddr) -> Result<(), PageMapError> {
    let page_size = base_page_size();
    if physical_address.as_u64() % page_size != 0 {
        return Err(PageMapError::TranslationFailed());
    }
    let info = &crate::util::boot_info().arch_info;
    let end = physical_address
        .as_u64()
        .checked_add(page_size)
        .ok_or(PageMapError::TranslationFailed())?;
    if end > info.physical_memory_len {
        return Err(PageMapError::NoMemoryMap());
    }
    let address = info
        .physical_memory_offset
        .checked_add(physical_address.as_u64())
        .ok_or(PageMapError::TranslationFailed())?;
    unsafe { core::ptr::write_bytes(address as *mut u8, 0, page_size as usize) };
    Ok(())
}

pub fn start_zero_page_worker() {
    ZERO_PAGE_WAIT_QUEUE.call_once(WaitQueue::new);
    SCHEDULER.add_task(Task::new_kernel_mode_with_sched_binding(
        zero_page_worker,
        0,
        StackSize::Tiny,
        "zero-page".to_string(),
        0,
        fifo_task_sched_binding(FifoPriority::Low),
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
