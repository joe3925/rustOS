extern crate rand_xoshiro;

use crate::alloc::format;
use crate::benchmarking::run_stats_loop;
use crate::boot_packages;
use crate::drivers::driver_install::install_prepacked_drivers;
use crate::drivers::interrupt_index::{
    apic_calibrate_ticks_per_ns_via_wait, apic_program_period_ms, apic_program_period_ns,
    calibrate_tsc, current_cpu_id, get_current_logical_id, init_percpu_gs, set_current_cpu_id,
    wait_millis_idle, wait_using_pit_50ms, ApicImpl, IpiDest, IpiKind, LocalApic,
};
use crate::drivers::interrupt_index::{APIC, PICS};
use crate::drivers::pnp::manager::PNP_MANAGER;
use crate::drivers::timer_driver::{
    NUM_CORES, PER_CORE_SWITCHES, ROT_TICKET, TIMER, TIMER_TIME_SCHED,
};
use crate::executable::program::{Program, PROGRAM_MANAGER};
use crate::exports::EXPORTS;
use crate::file_system::file::File;
use crate::file_system::file_provider::install_file_provider;
use crate::file_system::{bootstrap_filesystem::BootstrapProvider, file_provider};
use crate::gdt::PER_CPU_GDT;
use crate::idt::load_idt;
use crate::memory::allocator::ALLOCATOR;
use crate::memory::heap::{init_heap, HEAP_SIZE};
use crate::memory::paging::constants::KERNEL_STACK_SIZE;
use crate::memory::paging::frame_alloc::{total_usable_bytes, BootInfoFrameAllocator, USED_MEMORY};
use crate::memory::paging::tables::{init_kernel_cr3, kernel_cr3};
use crate::memory::paging::virt_tracker::KERNEL_RANGE_TRACKER;
use crate::registry::is_first_boot;
use crate::scheduling::scheduler::SCHEDULER;
use crate::scheduling::task::Task;
use crate::static_handlers::wait_ms;
use crate::structs::stopwatch::Stopwatch;
use crate::syscalls::syscall::syscall_init;
use crate::{cpu, println, BOOT_INFO};
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::{vec, vec::Vec};
use bootloader_api::BootInfo;
use core::arch::asm;
use core::mem::size_of;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use kernel_types::memory::Module;
use nostd_runtime::{block_on, spawn};
use rand_core::{RngCore, SeedableRng};
use rand_xoshiro::Xoshiro256PlusPlus;
use spin::rwlock::RwLock;
use spin::{Mutex, Once};
use x86_64::instructions::interrupts;
use x86_64::registers::control::Cr3;
use x86_64::VirtAddr;

pub static AP_STARTUP_CODE: &[u8] = include_bytes!("../../target/ap_startup.bin");

pub(crate) static KERNEL_INITIALIZED: AtomicBool = AtomicBool::new(false);
pub static CORE_LOCK: AtomicUsize = AtomicUsize::new(0);
pub static INIT_LOCK: Mutex<usize> = Mutex::new(0);
pub static CPU_ID: AtomicUsize = AtomicUsize::new(0);
pub static TOTAL_TIME: Once<Stopwatch> = Once::new();
pub const APIC_START_PERIOD: u64 = 106_800;
pub static BOOTSET: &[BootPkg] =
    boot_packages!["acpi", "pci", "ide", "disk", "partmgr", "volmgr", "mountmgr", "fat32", "i8042"];
static PANIC_ACTIVE: AtomicBool = AtomicBool::new(false);
static PANIC_OWNER: Mutex<Option<u32>> = Mutex::new(None);
pub unsafe fn init() {
    init_kernel_cr3();
    let memory_map = &boot_info().memory_regions;
    BootInfoFrameAllocator::init_start(memory_map);
    {
        let _init_lock = INIT_LOCK.lock();
        init_heap();
        //test_full_heap();

        init_kernel_cr3();

        PER_CPU_GDT.lock().init_gdt();
        PICS.lock().initialize();

        load_idt();
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
                apic_calibrate_ticks_per_ns_via_wait(10);
                apic_program_period_ns(APIC_START_PERIOD);
            }
            Err(err) => {
                println!("APIC transition failed {}!", err.to_str());
            }
        }

        println!("Init Done");
    }
    while CORE_LOCK.load(Ordering::SeqCst) != 0 {}
    TOTAL_TIME.call_once(Stopwatch::start);

    init_percpu_gs(CPU_ID.fetch_add(1, Ordering::Acquire) as u32);
    SCHEDULER.init(NUM_CORES.load(Ordering::Acquire));
    x86_64::instructions::interrupts::enable();
    KERNEL_INITIALIZED.store(true, Ordering::SeqCst);
    loop {
        asm!("hlt");
    }
}

pub extern "win64" fn kernel_main(ctx: usize) {
    install_file_provider(Box::new(BootstrapProvider::new(BOOTSET)));

    let mut program = Program::new(
        "KRNL".to_string(),
        "".to_string(),
        VirtAddr::new(0xFFFF_8500_0000_0000),
        kernel_cr3(),
        KERNEL_RANGE_TRACKER.clone(),
    );

    program.main_thread = Some(SCHEDULER.get_current_task(current_cpu_id()).unwrap());

    program.modules = RwLock::new(vec![Arc::new(RwLock::new(Module {
        title: "KRNL.DLL".into(),
        image_path: "".into(),
        parent_pid: 0,
        image_base: VirtAddr::new(0xFFFF_8500_0000_0000),
        symbols: EXPORTS.to_vec(),
    }))]);
    let _pid = PROGRAM_MANAGER.add_program(program);
    spawn(async move {
        install_prepacked_drivers().await;

        PNP_MANAGER.init_from_registry().await;
    });

    println!("");
    nostd_runtime::spawn_blocking(run_stats_loop);
}
#[inline(always)]
fn halt_loop() -> ! {
    unsafe {
        loop {
            asm!("hlt;", options(nomem, nostack, preserves_flags));
        }
    }
}
#[no_mangle]
pub extern "win64" fn panic_common(mod_name: &'static str, info: &PanicInfo) -> ! {
    if PANIC_ACTIVE.swap(true, Ordering::SeqCst) {
        halt_loop()
    }

    x86_64::instructions::interrupts::disable();
    unsafe { Cr3::write(kernel_cr3(), Cr3::read().1) }
    crate::KERNEL_INITIALIZED.store(false, Ordering::SeqCst);

    let me = get_current_logical_id() as u32;
    let i_am_owner = match PANIC_OWNER.try_lock() {
        Some(mut g) => {
            if g.is_none() {
                *g = Some(me);
                true
            } else {
                g.as_ref() == Some(&me)
            }
        }
        None => false,
    };

    if i_am_owner {
        println!("\n=== KERNEL PANIC [{}] ===", mod_name);
        println!("\n{}", info);
        unsafe {
            APIC.lock()
                .as_ref()
                .map(|a| a.lapic.send_ipi(IpiDest::AllExcludingSelf, IpiKind::Nmi));
        }

        halt_loop()
    } else {
        halt_loop()
    }
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
    for i in 0..element_count {
        if i != vec[i] as usize {
            println!("Heap data verification failed at index {}", i);
        }
    }

    println!(
        "Heap test passed: allocated and verified {} elements in the heap",
        element_count
    );
}

pub extern "win64" fn random_number() -> u64 {
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

    // Set UUID version (v4)
    guid[6] = (guid[6] & 0x0F) | 0x40;
    // Set UUID variant (RFC 4122)
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
    let mut buffer = [0x0000; 36];
    for (i, c) in name.encode_utf16().take(36).enumerate() {
        buffer[i] = c;
    }
    buffer
}

#[derive(Clone, Copy)]
pub struct BootPkg {
    pub name: &'static str,
    pub toml: &'static [u8],
    pub image: &'static [u8],
}

#[macro_export]
macro_rules! boot_packages {
    ($($name:literal),+ $(,)?) => {{
        &[
            $(
                $crate::util::BootPkg {
                    name: $name,
                    toml: include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/../target/DRIVERS/",
                        $name, "/", $name, ".toml"
                    )),
                    image: include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/../target/DRIVERS/",
                        $name, "/", $name, ".dll"
                    )),
                },
            )+
        ] as &[ $crate::util::BootPkg ]
    }};
}
