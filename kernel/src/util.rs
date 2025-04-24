extern crate rand_xoshiro;

use crate::drivers::drive::generic_drive::{DriveController, DRIVECOLLECTION};
use crate::drivers::drive::gpt::VOLUMES;
use crate::drivers::interrupt_index::ApicImpl;
use crate::drivers::interrupt_index::PICS;
use alloc::string::ToString;

use crate::drivers::drive::gpt::GptPartitionType::MicrosoftBasicData;
use crate::file_system::file::{File, OpenFlags};
use crate::idt::load_idt;
use crate::memory::heap::{init_heap, HEAP_SIZE};
use crate::memory::paging::{init_mapper, BootInfoFrameAllocator};
use crate::{cpu, gdt, println, BOOT_INFO};
use alloc::vec::Vec;
use bootloader_api::BootInfo;
use core::arch::asm;
use core::sync::atomic::{AtomicBool, Ordering};
use rand_core::{RngCore, SeedableRng};
use rand_xoshiro::Xoshiro256PlusPlus;
use x86_64::VirtAddr;

pub(crate) static KERNEL_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub unsafe fn init() {
    let boot_info = boot_info();

    let mem_offset: VirtAddr = VirtAddr::new(boot_info.physical_memory_offset.into_option().unwrap());

    let mut mapper = init_mapper(mem_offset);
    let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_regions);
    init_heap(&mut mapper, &mut frame_allocator.clone());


    gdt::init();
    println!("GDT loaded");

    PICS.lock().initialize();
    load_idt();
    println!("PIC loaded");

    match ApicImpl::init_apic_full() {
        Ok(_) => { println!("APIC transition successful!"); }
        Err(err) => { println!("APIC transition failed {}!", err.to_str()); }
    }
    test_full_heap();

    {
        let mut drives = DRIVECOLLECTION.lock();
        drives.enumerate_drives();

        match drives.drives[1].format_gpt() {
            Ok(_) => {
                println!("Drive init successful");
                drives.drives[1].add_partition(1024 * 1024 * 1024 * 9, MicrosoftBasicData.to_u8_16(), "MAIN VOLUME".to_string()).expect("TODO: panic message");
            }
            Err(err) => { println!("Error init drive {} {}", (drives.drives)[1].info.model, err.to_str()) }
        }
    }
    println!("Drives enumerated");
    {
        let mut partitions = VOLUMES.lock();
        partitions.enumerate_parts();
        if let Some(part) = partitions.find_volume("C:".to_string()) {
            match part.format() {
                Ok(_) => {
                    println!("volume {} formatted successfully", part.label.clone());
                    part.is_fat = true;
                }
                Err(err) => println!("Error formatting volume {} {}", part.label.clone(), err.to_str()),
            }
        } else {
            println!("failed to find drive C:");
        }
        partitions.print_parts();
    }

    println!("Volumes enumerated");

    let open_flags = [OpenFlags::Create, OpenFlags::ReadWrite];
    println!("{:#?}", File::open("C:\\FLDR\\TEST\\TE.TXT", &open_flags).unwrap());

    println!("Init Done");
    KERNEL_INITIALIZED.fetch_xor(true, Ordering::SeqCst);
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
pub fn random_number() -> u64 {
    let mut rng = Random::new(cpu::get_cycles());
    rng.next_u64()
}

pub fn boot_info() -> &'static mut BootInfo {
    unsafe {
        BOOT_INFO
            .as_mut()
            .expect("BOOT_INFO not initialized")
    }
}

pub fn generate_guid() -> [u8; 16] {
    let start: [u8; 8] = random_number().to_le_bytes();
    let end: [u8; 8] = random_number().to_le_bytes();

    let mut guid = [0u8; 16];
    guid[..8].copy_from_slice(&start);
    guid[8..].copy_from_slice(&end);

    // Set UUID version (v4: bits 12-15 should be `0100`)
    guid[6] = (guid[6] & 0x0F) | 0x40;

    // Set UUID variant (RFC 4122: bits 6-7 should be `10`)
    guid[8] = (guid[8] & 0x3F) | 0x80;

    guid
}


pub struct Random {
    rng: Xoshiro256PlusPlus,
}

impl Random {
    pub fn new(seed: u64) -> Self {
        let rng = Xoshiro256PlusPlus::seed_from_u64(seed);
        Self { rng }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    pub fn next_u32(&mut self) -> u32 {
        (self.rng.next_u64() & 0xFFFF_FFFF) as u32
    }
}
pub fn name_to_utf16_fixed(name: &str) -> [u16; 36] {
    let mut buffer = [0x0000; 36]; // Fill with null terminators
    let utf16_iter = name.encode_utf16();

    for (i, c) in utf16_iter.take(36).enumerate() {
        buffer[i] = c;
    }

    buffer
}