use crate::console::CONSOLE;
use crate::drivers::drive::generic_drive::{DriveController, DRIVECOLLECTION};
use crate::drivers::drive::ide_disk_driver::IdeController;
use crate::drivers::interrupt_index;
use crate::drivers::pci::pci_bus::PCIBUS;
use crate::idt::load_idt;
use crate::memory::heap::init_heap;
use crate::memory::paging::{init_mapper, BootInfoFrameAllocator};
use crate::scheduling::scheduler::SCHEDULER;
use crate::syscalls::syscall::set_syscall_handler;
use crate::{gdt, println};
use alloc::string::ToString;
use bootloader::BootInfo;
use core::arch::asm;
use x86_64::VirtAddr;

pub(crate) static mut KERNEL_INITIALIZED: bool = false;

pub unsafe fn init(boot_info: &'static BootInfo) {
    gdt::init();
    unsafe { interrupt_index::PICS.lock().initialize() };
    load_idt();


    let mem_offset: VirtAddr = VirtAddr::new(boot_info.physical_memory_offset);
    let mut mapper = init_mapper(mem_offset);
    let mut frame_allocator = unsafe {
        BootInfoFrameAllocator::init(&boot_info.memory_map)
    };
    //The heap needs to be rewritten it is not pretty
    init_heap(&mut mapper, &mut frame_allocator.clone(), &mut frame_allocator);
    unsafe {
        PCIBUS.lock().enumerate_pci();
    }
    IdeController::enumerate_drives();
    if let Some(drive) = DRIVECOLLECTION.lock().find_drive("B:".to_string()) {
        DRIVECOLLECTION.force_unlock();
        drive.format().expect("format failed");
    }
    //set_syscall_handler();
    println!("Init Done");
    KERNEL_INITIALIZED = true;
}
#[no_mangle]
#[allow(unconditional_recursion)]
pub extern "C" fn trigger_stack_overflow() {
    trigger_stack_overflow();
}
pub fn trigger_breakpoint() {
    unsafe {
        asm!("int 3");
    }
}
//will unlock kernel mode statics during a context switch from a kernel mode task
pub fn unlock_statics() {
    unsafe {
        DRIVECOLLECTION.force_unlock();
        CONSOLE.force_unlock();
        SCHEDULER.force_unlock();
    }
}