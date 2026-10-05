use alloc::string::ToString;
use spin::Once;

use kernel_types::arch::PhysAddr;
use kernel_types::status::PageMapError;

use crate::memory::paging::frame_alloc::KernelFrameAllocator;
use crate::memory::paging::stack::StackSize;
use crate::scheduling::fifo_scheduler::{FifoPriority, fifo_task_sched_binding};
use crate::scheduling::runtime::runtime::yield_now;
use crate::scheduling::scheduler::SCHEDULER;
use crate::scheduling::task::{Task, TaskHandle};

use super::layout::base_page_size;

static ZERO_PAGE_WORKER: Once<TaskHandle> = Once::new();

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
    let task = Task::new_kernel_mode_with_sched_binding(
        zero_page_worker,
        0,
        StackSize::Tiny,
        "zero-page".to_string(),
        0,
        fifo_task_sched_binding(FifoPriority::Low),
    );
    ZERO_PAGE_WORKER.call_once(|| task.clone());
    SCHEDULER.add_task(task);
}

pub fn wake_zero_page_worker() {
    if let Some(task) = ZERO_PAGE_WORKER.get() {
        SCHEDULER.unpark(task);
    }
}

extern "C" fn zero_page_worker(_: usize) {
    loop {
        if KernelFrameAllocator::zero_one_free_frame() {
            yield_now();
            continue;
        }
        SCHEDULER.park_current();
    }
}
