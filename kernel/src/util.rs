extern crate rand_xoshiro;
use crate::drivers::drive::generic_drive::{DriveController, DRIVECOLLECTION};
use crate::drivers::drive::gpt::VOLUMES;
use crate::drivers::interrupt_index;
use crate::drivers::pci::pci_bus::PCIBUS;
use crate::idt::load_idt;
use crate::memory::heap::{init_heap, HEAP_SIZE};
use crate::memory::paging::{init_mapper, BootInfoFrameAllocator};
use crate::{cpu, gdt, println, BOOT_INFO};
use alloc::vec::Vec;
use bootloader_api::BootInfo;
use core::arch::asm;
use rand_core::{RngCore, SeedableRng};
use rand_xoshiro::Xoshiro256PlusPlus;
use spin::Mutex;
use x86_64::VirtAddr;
// For seedinguse

pub(crate) static KERNEL_INITIALIZED: Mutex<bool> = Mutex::new(false);

pub unsafe fn init() {
    let boot_info = boot_info();
    let mut partitions = VOLUMES.lock();
    let mut drives = DRIVECOLLECTION.lock();

    let mem_offset: VirtAddr = VirtAddr::new(boot_info.physical_memory_offset.into_option().unwrap());

    let mut mapper = init_mapper(mem_offset);
    let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_regions);

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

    println!("Init Done");
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

    // Combine into a 16-byte GUID
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