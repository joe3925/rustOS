use alloc::string::ToString;
use bootloader::BootInfo;
use x86_64::VirtAddr;
use crate::drivers::drive::generic_drive::{DriveController, DRIVECOLLECTION};
use crate::drivers::drive::ide_disk_driver::IdeController;
use crate::drivers::interrupt_index;
use crate::drivers::pci::pci_bus::PCIBUS;
use crate::{gdt, BOOT_INFO};
use crate::idt::load_idt;
use crate::memory::heap::init_heap;
use crate::memory::paging::{init_mapper, BootInfoFrameAllocator};

pub unsafe fn init(boot_info: &'static BootInfo){
    gdt::init();
    load_idt();
    unsafe { interrupt_index::PICS.lock().initialize() };

    let mem_offset: VirtAddr = VirtAddr::new(boot_info.physical_memory_offset);
    let mut mapper = init_mapper(mem_offset);
    let mut frame_allocator = unsafe {
        BootInfoFrameAllocator::init(&boot_info.memory_map)
    };
    init_heap(&mut mapper, &mut frame_allocator);
    unsafe {
        PCIBUS.lock().enumerate_pci();
    }
    IdeController::enumerate_drives();

    DRIVECOLLECTION.lock().find_drive("B:".to_string()).unwrap().format().expect("format failed");
}