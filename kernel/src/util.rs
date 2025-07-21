extern crate rand_xoshiro;

use crate::drivers::drive::generic_drive::DRIVECOLLECTION;
use crate::drivers::drive::gpt::VOLUMES;
use crate::drivers::interrupt_index::{calibrate_tsc, wait_using_pit_50ms, ApicImpl};
use crate::drivers::interrupt_index::{APIC, PICS};
use crate::executable::program::{Program, PROGRAM_MANAGER};
use crate::file_system::file::File;
use crate::gdt::PER_CPU_GDT;
use crate::scheduling::scheduler::SCHEDULER;
use alloc::string::{String, ToString};
use spin::Mutex;

use crate::drivers::drive::gpt::GptPartitionType::MicrosoftBasicData;
use crate::idt::load_idt;
use crate::memory::heap::{init_heap, HEAP_SIZE};
use crate::memory::paging::{
    init_kernel_cr3, init_mapper, kernel_cr3, BootInfoFrameAllocator, KERNEL_RANGE_TRACKER,
};
use crate::{cpu, println, BOOT_INFO};
use alloc::vec::Vec;
use bootloader_api::BootInfo;
use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use rand_core::{RngCore, SeedableRng};
use rand_xoshiro::Xoshiro256PlusPlus;
use x86_64::VirtAddr;
pub static AP_STARTUP_CODE: &[u8] = include_bytes!("../../target/ap_startup.bin");

pub(crate) static KERNEL_INITIALIZED: AtomicBool = AtomicBool::new(false);
pub static CORE_LOCK: AtomicUsize = AtomicUsize::new(0);

pub unsafe fn init() {
    {
        let boot_info = boot_info();

        let mem_offset: VirtAddr =
            VirtAddr::new(boot_info.physical_memory_offset.into_option().unwrap());

        let mut mapper = init_mapper(mem_offset);
        let frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_regions);
        init_heap(&mut mapper, &mut frame_allocator.clone());

        init_kernel_cr3();

        PER_CPU_GDT.lock().init_gdt();
        PICS.lock().initialize();
        load_idt();

        println!("PIC loaded");

        // TSC calibration
        let tsc_start = cpu::get_cycles();
        wait_using_pit_50ms();
        let tsc_end = cpu::get_cycles();
        calibrate_tsc(tsc_start, tsc_end, 50);

        match ApicImpl::init_apic_full() {
            Ok(_) => {
                println!("APIC transition successful!");

                x86_64::instructions::interrupts::disable();
                APIC.lock().as_ref().unwrap().start_aps();
                x86_64::instructions::interrupts::enable();
            }
            Err(err) => {
                println!("APIC transition failed {}!", err.to_str());
            }
        }

        test_full_heap();

        {
            let mut drives = DRIVECOLLECTION.lock();
            drives.enumerate_drives();

            match drives.drives[1].format_gpt() {
                Ok(_) => {
                    println!("Drive init successful");
                    drives.drives[1]
                        .add_partition(
                            1024 * 1024 * 1024 * 9,
                            MicrosoftBasicData.to_u8_16(),
                            "MAIN VOLUME".to_string(),
                        )
                        .expect("TODO: panic message");
                }
                Err(err) => {
                    println!(
                        "Error init drive {} {}",
                        (drives.drives)[1].info.model,
                        err.to_str()
                    )
                }
            }
        }
        {
            let mut partitions = VOLUMES.lock();
            partitions.enumerate_parts();

            match partitions
                .find_partition_by_name("MAIN VOLUME")
                .unwrap()
                .format()
            {
                Ok(_) => println!("Formatted"),
                Err(e) => println!("{:#?}", e),
            }
            partitions.print_parts();
        }
        println!("Init Done");
    }
    while (CORE_LOCK.load(Ordering::SeqCst) != 0) {
        asm!("hlt");
    }
    KERNEL_INITIALIZED.store(true, Ordering::SeqCst);
    loop {
        asm!("hlt");
    }
}

// Things to be tested after kernel init go here
pub fn kernel_main() {
    let program = Program {
        title: "".to_string(),
        image_path: "".to_string(),
        pid: 0,
        image_base: VirtAddr::new(0xFFFF850000000000),
        main_thread: Some(SCHEDULER.lock().get_current_task().clone()),
        managed_threads: Mutex::new(Vec::new()),
        modules: Mutex::new(Vec::new()),
        cr3: kernel_cr3(),
        tracker: KERNEL_RANGE_TRACKER.clone(),
    };
    let pid = PROGRAM_MANAGER.write().add_program(program);

    // Extract label and drop the VOLUMES lock early
    let label = {
        let mut volumes = VOLUMES.lock();
        if let Some(system_volume) = volumes.find_partition_by_name("MAIN VOLUME") {
            system_volume.label.clone()
        } else {
            panic!("System Volume unavailable or corrupted")
        }
    };

    let base_path = "\\SYSTEM\\MOD";
    let mut path_buffer = String::new();

    let full_path = {
        let mut s = String::with_capacity(label.len() + base_path.len());
        s.push_str(&label);
        s.push_str(base_path);
        s
    };

    let entries = File::list_dir(&full_path).expect("Failed to load system mod directory");

    for name in entries {
        if !name.to_ascii_lowercase().ends_with(".dll") {
            continue;
        }
        path_buffer.clear();
        path_buffer.push_str(&label);
        path_buffer.push_str(base_path);
        path_buffer.push_str("\\");
        path_buffer.push_str(&name);

        match PROGRAM_MANAGER
            .write()
            .get_mut(pid)
            .unwrap()
            .load_module(path_buffer.clone())
        {
            Ok(_) => {
                println!("Loaded module: {}", name);
            }
            Err(e) => {
                println!("Failed to load module '{}': {:?}", name, e);
            }
        }
    }

    // if let Some(mut loadable) = pe_loadable::PELoader::new("C:\\BIN\\TEST.EXE") {
    //     loadable.load();
    // }
    loop {}
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
    unsafe { BOOT_INFO.as_mut().expect("BOOT_INFO not initialized") }
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
