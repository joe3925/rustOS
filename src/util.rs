use crate::drivers::drive::generic_drive::{DriveController, DRIVECOLLECTION};
use crate::drivers::drive::gpt::PARTITIONS;
use crate::drivers::interrupt_index;
use crate::drivers::pci::pci_bus::PCIBUS;
use crate::file_system::file::{File, OpenFlags};
use crate::idt::load_idt;
use crate::memory::heap::{init_heap, HEAP_SIZE};
use crate::memory::paging::{init_mapper, BootInfoFrameAllocator};
use crate::{gdt, println};
use alloc::string::ToString;
use alloc::vec::Vec;
use bootloader::BootInfo;
use core::arch::asm;
use spin::Mutex;
use x86_64::VirtAddr;

pub(crate) static KERNEL_INITIALIZED: Mutex<bool> = Mutex::new(false);

pub unsafe fn init(boot_info: &'static BootInfo) {
    let mut partitions = PARTITIONS.lock();
    let mut drives = DRIVECOLLECTION.lock();

    let mem_offset: VirtAddr = VirtAddr::new(boot_info.physical_memory_offset);
    let mut mapper = init_mapper(mem_offset);
    let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_map);

    gdt::init();
    println!("GDT loaded");

    interrupt_index::PICS.lock().initialize();
    load_idt();
    init_heap(&mut mapper, &mut frame_allocator.clone());
    println!("IDT loaded");

    test_full_heap();

    PCIBUS.lock().enumerate_pci();
    println!("PCI BUS enumerated");
    drives.enumerate_drives();
    partitions.enumerate_parts();
    println!("Drives enumerated");
    //drives.print_drives();
    //partitions.print_parts();


    if let Some(part) = partitions.find_volume("B:".to_string()) {
        PARTITIONS.force_unlock();
        match part.force_format() {
            Ok(_) => {
                println!("Drive {} formatted successfully", part.label.clone());
                part.is_fat = true;
            }
            Err(err) => println!("Error formatting drive {} {}", part.label.clone(), err.to_str()),
        }
    } else {
        println!("failed to find drive B:");
    }
    println!("Init Done");
    let path = "B:\\folder\\home\\test.txt";
    let flags = [OpenFlags::ReadWrite, OpenFlags::CreateNew];
    println!("{:#?}", File::open(path, &flags));

    *KERNEL_INITIALIZED.lock() = true;
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

pub fn test_full_heap() {
    let element_count = (HEAP_SIZE / 4) / size_of::<u64>();

    let mut vec: Vec<u64> = Vec::with_capacity(1);

    for i in 0..element_count {
        vec.push(i as u64);
    }
    // Verify the data
    for i in 0..element_count {
        if (i != vec[i] as usize) {
            println!("Heap data verification failed at index {}", i);
        }
    }

    println!(
        "Heap test passed: allocated and verified {} elements in the heap",
        element_count
    );
}
