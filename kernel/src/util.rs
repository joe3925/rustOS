extern crate rand_xoshiro;

use crate::drivers::drive::generic_drive::DRIVECOLLECTION;
use crate::drivers::drive::gpt::VOLUMES;
use crate::drivers::interrupt_index::{
    calibrate_tsc, get_current_logical_id, wait_millis, wait_millis_idle, wait_using_pit_50ms,
    ApicImpl,
};
use crate::drivers::interrupt_index::{APIC, PICS};
use crate::drivers::timer_driver::TIMER_TIME;
use crate::executable::pe_loadable;
use crate::executable::program::{HandleTable, Module, Program, PROGRAM_MANAGER};
use crate::exports::EXPORTS;
use crate::file_system::file::File;
use crate::gdt::PER_CPU_GDT;
use crate::memory::allocator::ALLOCATOR;
use crate::memory::paging::frame_alloc::{total_usable_bytes, BootInfoFrameAllocator, USED_MEMORY};
use crate::memory::paging::tables::{init_kernel_cr3, kernel_cr3};
use crate::memory::paging::virt_tracker::KERNEL_RANGE_TRACKER;
use crate::scheduling::scheduler::SCHEDULER;
use crate::structs::stopwatch::Stopwatch;
use crate::syscalls::syscall::syscall_init;
use alloc::string::{String, ToString};
use spin::{Mutex, Once, RwLock};
use x86_64::instructions::interrupts;

use crate::drivers::drive::gpt::GptPartitionType::MicrosoftBasicData;
use crate::idt::load_idt;
use crate::memory::heap::{init_heap, HEAP_SIZE};
use crate::{cpu, println, BOOT_INFO};
use alloc::{vec, vec::Vec};
use bootloader_api::BootInfo;
use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use rand_core::{RngCore, SeedableRng};
use rand_xoshiro::Xoshiro256PlusPlus;
use x86_64::VirtAddr;
pub static AP_STARTUP_CODE: &[u8] = include_bytes!("../../target/ap_startup.bin");

pub(crate) static KERNEL_INITIALIZED: AtomicBool = AtomicBool::new(false);
pub static CORE_LOCK: AtomicUsize = AtomicUsize::new(0);
pub static INIT_LOCK: Mutex<usize> = Mutex::new(0);

static TOTAL_TIME: Once<Stopwatch> = Once::new();

pub unsafe fn init() {
    init_kernel_cr3();
    let memory_map = &boot_info().memory_regions;
    BootInfoFrameAllocator::init_start(memory_map);
    {
        let init_lock = INIT_LOCK.lock();
        init_heap();
        test_full_heap();

        init_kernel_cr3();

        PER_CPU_GDT.lock().init_gdt();
        PICS.lock().initialize();

        load_idt();
        println!("PIC loaded");
        syscall_init();
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
    TOTAL_TIME.call_once(Stopwatch::start);
    KERNEL_INITIALIZED.store(true, Ordering::SeqCst);
    loop {
        asm!("hlt");
    }
}

pub fn kernel_main() {
    let mut program = Program::new(
        "KRNL".to_string(),
        "".to_string(),
        VirtAddr::new(0xFFFF8500_0000_0000),
        kernel_cr3(),
        KERNEL_RANGE_TRACKER.clone(),
    );

    program.main_thread = Some(SCHEDULER.lock().get_current_task());

    program.modules = Mutex::new(
        vec![Module {
            title: "KRNL.DLL".into(),
            image_path: "".into(),
            parent_pid: 0,
            image_base: VirtAddr::new(0xFFFF8500_0000_0000),
            symbols: EXPORTS.to_vec(),
        }]
        .into(),
    );

    let pid = PROGRAM_MANAGER.add_program(program);

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
    println!("{:#?}", entries);

    for name in entries {
        if !name.to_ascii_lowercase().ends_with(".dll") {
            continue;
        }

        path_buffer.clear();
        path_buffer.push_str(&label);
        path_buffer.push_str(base_path);
        path_buffer.push('\\');
        path_buffer.push_str(&name);

        let handle = PROGRAM_MANAGER.get(pid).expect("invalid PID");

        {
            let mut prog = handle.write();
            match prog.load_module(path_buffer.clone()) {
                Ok(_) => println!("Loaded module: {}", name),
                Err(e) => println!("Failed to load module '{}': {:?}", name, e),
            }
        }

        type DriverEntryFn = unsafe extern "C" fn();

        if let Some(handle) = PROGRAM_MANAGER.get(pid) {
            let prog = handle.read();
            for module in prog.modules.lock().iter() {
                if let Some((_, rva)) = module.symbols.iter().find(|(sym, _)| sym == "driver_entry")
                {
                    let entry_addr = (module.image_base.as_u64() + *rva as u64) as *const ();
                    let driver_entry: DriverEntryFn = unsafe { core::mem::transmute(entry_addr) };
                    println!("Calling driver_entry for module {}", module.image_path);
                    unsafe { driver_entry() };
                } else {
                    println!("No driver_entry found in {}", module.title);
                }
            }
        } else {
            println!("invalid PID {}", pid);
        }
        print_mem_report();
        println!("");
        loop {
            wait_millis_idle(300000);
            let timer_ms = TIMER_TIME
                .lock()
                .get(get_current_logical_id() as usize)
                .unwrap()
                .load(Ordering::SeqCst);
            let total_ms = TOTAL_TIME.wait().elapsed_millis();
            let percent_x10 = (timer_ms as u128 * 100_000) / total_ms as u128; // 0‑1000
            let int_part = percent_x10 / 1000;
            let frac_part = percent_x10 % 1000;

            println!(
                "Timer time per core: {}s, Timer time total {}s, Total: {}m, % in timer: {}.{}%",
                timer_ms / 1000,
                timer_ms * 4 / 1000,
                total_ms / 1000 / 60,
                int_part,
                frac_part
            );
            print_mem_report();
            println!("\n");
        }
    }
}
pub fn used_memory() -> usize {
    let allocator = unsafe { ALLOCATOR.lock() };
    HEAP_SIZE - allocator.free_memory()
}
pub fn print_mem_report() {
    interrupts::without_interrupts(move || {
        let used_bytes = USED_MEMORY.load(Ordering::SeqCst);
        let total_bytes = total_usable_bytes();

        let used_mb = used_bytes / 1_048_576;
        let total_mb = total_bytes / 1_048_576;

        let percent_x10 = (used_bytes as u128 * 1000) / total_bytes as u128;
        let int_part = percent_x10 / 10;
        let frac_part = percent_x10 % 10;

        println!(
            "Used memory {} MB / {} MB ({}.{})%",
            used_mb, total_mb, int_part, frac_part
        );

        let heap_used = used_memory();
        let heap_used_kb = heap_used / 1000;
        let heap_total_kb = HEAP_SIZE / 1000;

        let heap_percent_x10 = (heap_used as u128 * 1000) / HEAP_SIZE as u128;
        let heap_int_part = heap_percent_x10 / 10;
        let heap_frac_part = heap_percent_x10 % 10;

        println!(
            "Heap usage: {} KB / {} KB ({}.{})%",
            heap_used_kb, heap_total_kb, heap_int_part, heap_frac_part
        );
    });
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
