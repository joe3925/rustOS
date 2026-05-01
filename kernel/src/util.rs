extern crate rand_xoshiro;

use crate::benchmarking::BenchWindow;
use crate::boot_packages;
use crate::console::Screen;
use crate::drivers::driver_install::install_prepacked_drivers;
use crate::drivers::interrupt_index::{
    apic_calibrate_ticks_per_ns_via_wait, apic_program_period_ns, calibrate_tsc, current_cpu_id,
    get_current_logical_id, init_percpu_gs, wait_using_pit_50ms, ApicImpl, IpiDest, IpiKind,
    LocalApic,
};
use crate::drivers::interrupt_index::{APIC, PICS};
use crate::drivers::pnp::manager::PNP_MANAGER;
use crate::drivers::timer_driver::NUM_CORES;
use crate::executable::program::{Program, PROGRAM_MANAGER};
use crate::exports::EXPORTS;
use crate::file_system::file_provider::{install_file_provider, ProviderKind};
use crate::gdt::PER_CPU_GDT;
use crate::idt::load_idt;
use crate::lazy_static;
use crate::memory::dma::init_dma_manager;
use crate::memory::heap::{init_heap, HEAP_SIZE};
use crate::memory::iommu::init_iommu;
use crate::memory::paging::frame_alloc::BootInfoFrameAllocator;
use crate::memory::paging::stack::StackSize;
use crate::memory::paging::tables::{init_kernel_cr3, kernel_cr3};
use crate::memory::paging::virt_tracker::KERNEL_RANGE_TRACKER;
use crate::scheduling::global_async::GlobalAsyncExecutor;
use crate::scheduling::runtime::runtime::yield_now;
use crate::scheduling::runtime::runtime::{init_executor_platform, spawn_detached};
use crate::scheduling::scheduler::{dump_scheduler, task_name_panic, SCHEDULER};
use crate::scheduling::task::Task;
use crate::structs::stopwatch::Stopwatch;
use crate::syscalls::syscall::syscall_init;
use crate::{cpu, println, BOOT_INFO};
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::{vec, vec::Vec};
use bootloader_api::BootInfo;
use core::arch::asm;
use core::marker::PhantomData;
use core::mem::size_of;
use core::panic::PanicInfo;
use core::sync::atomic::AtomicU8;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use kernel_types::benchmark::BenchWindowConfig;
use kernel_types::fs::Path;
use kernel_types::memory::Module;
use kernel_types::request::{BorrowedHandle, RequestDataView, RequestHandle, RequestType};
use rand_core::{RngCore, SeedableRng};
use rand_xoshiro::Xoshiro256PlusPlus;
use spin::rwlock::RwLock;
use spin::{Mutex, Once};
use x86_64::registers::control::Cr3;
use x86_64::structures::idt::InterruptDescriptorTable;
use x86_64::VirtAddr;
pub(crate) static KERNEL_INITIALIZED: AtomicBool = AtomicBool::new(false);
pub static CORE_LOCK: AtomicUsize = AtomicUsize::new(0);
pub static INIT_LOCK: Mutex<usize> = Mutex::new(0);
pub static CPU_ID: AtomicUsize = AtomicUsize::new(0);
pub static TOTAL_TIME: Once<Stopwatch> = Once::new();
pub const APIC_START_PERIOD: u64 = 250_000;
pub static BOOTSET: &[BootPkg] = boot_packages![
    "acpi", "pci", "ide", "disk", "partmgr", "volmgr", "mountmgr", "fat32", "i8042", "virtio"
];
pub static PANIC_ACTIVE: AtomicBool = AtomicBool::new(false);
static PANIC_OWNER: Mutex<Option<u32>> = Mutex::new(None);
lazy_static! {
    pub static ref DRIVE_WINDOW: BenchWindow = BenchWindow::new(BenchWindowConfig {
        name: "drive",
        folder: "C:\\system\\logs",
        log_samples: false,
        log_spans: true,
        log_mem_on_persist: true,
        end_on_drop: false,
        timeout_ms: None,
        auto_persist_secs: None,
        sample_reserve: 256,
        span_reserve: 256,
        disable_per_core: true
    });
}
const TLS_SELF_TEST_PENDING: u8 = 0;
const TLS_SELF_TEST_PASS: u8 = 1;
const TLS_SELF_TEST_FAIL: u8 = 2;

static TLS_SELF_TEST_BUSY: AtomicBool = AtomicBool::new(false);
static TLS_SELF_TEST_RESULT: AtomicU8 = AtomicU8::new(TLS_SELF_TEST_PENDING);

const TLS_TEMPLATE_U64: u64 = 0x1122_3344_5566_7788;
const TLS_MAIN_U64: u64 = 0xA1A2_A3A4_A5A6_A7A8;
const TLS_WORKER_U64: u64 = 0xB1B2_B3B4_B5B6_B7B8;
const TLS_TEMPLATE_BYTES: [u8; 16] = *b"KERNEL_TLS_CHECK";
const TLS_MAIN_BYTES: [u8; 16] = *b"KERNEL_TLS_MAIN!";
const TLS_WORKER_BYTES: [u8; 16] = *b"KERNEL_TLS_WORK!";
const TLS_MAIN_ZERO_BYTES: [u8; 16] = [0x4Du8; 16];
const TLS_WORKER_ZERO_BYTES: [u8; 16] = [0x57u8; 16];

#[thread_local]
static mut TLS_TEST_INIT_U64: u64 = TLS_TEMPLATE_U64;
#[thread_local]
static mut TLS_TEST_INIT_BYTES: [u8; 16] = TLS_TEMPLATE_BYTES;
#[thread_local]
static mut TLS_TEST_ZERO_U64: u64 = 0;
#[thread_local]
static mut TLS_TEST_ZERO_BYTES: [u8; 16] = [0; 16];
pub unsafe fn init() {
    init_kernel_cr3();
    let memory_map = &boot_info().memory_regions;
    BootInfoFrameAllocator::init_start(memory_map);
    {
        let _init_lock = INIT_LOCK.lock();
        init_heap();
        Screen::clear_framebuffer();
        load_idt();

        init_kernel_cr3();

        PER_CPU_GDT.lock().init_gdt();
        PICS.lock().initialize();
        x86_64::instructions::interrupts::enable();
        syscall_init();
        init_dma_manager();
        init_iommu();

        // TSC calibration
        let tsc_start = cpu::get_cycles();
        wait_using_pit_50ms();
        let tsc_end = cpu::get_cycles();
        calibrate_tsc(tsc_start, tsc_end, 50);
        TOTAL_TIME.call_once(Stopwatch::start);
        let apic_time = Stopwatch::start();
        match ApicImpl::init_apic_full() {
            Ok(_) => {
                x86_64::instructions::interrupts::disable();
                APIC.lock().as_ref().unwrap().start_aps();
                println!(
                    "APIC init and AP start successful in {} s!",
                    apic_time.elapsed_sec()
                );
            }
            Err(err) => {
                println!("APIC transition failed {}!", err.to_str());
            }
        }
    }
    while CORE_LOCK.load(Ordering::SeqCst) != 0 {}

    init_percpu_gs(CPU_ID.fetch_add(1, Ordering::Acquire) as u32);

    apic_calibrate_ticks_per_ns_via_wait(10);
    apic_program_period_ns(APIC_START_PERIOD);
    SCHEDULER.init_core(current_cpu_id());
    SCHEDULER.add_task(Task::new_kernel_mode(
        kernel_main,
        0,
        StackSize::Tiny,
        "kernel".into(),
        0,
    ));

    x86_64::instructions::interrupts::enable();
    println!("Init Done");
    KERNEL_INITIALIZED.store(true, Ordering::SeqCst);
    loop {
        asm!("hlt");
    }
}
pub extern "win64" fn kernel_main(ctx: usize) {
    init_executor_platform();
    GlobalAsyncExecutor::global().init(NUM_CORES.load(Ordering::Acquire));
    install_file_provider(ProviderKind::Bootstrap);
    test_kernel_tls_runtime();
    let mut program = Program::new(
        "KRNL".to_string(),
        Path::from_string(""),
        VirtAddr::new(0xFFFF_8500_0000_0000),
        kernel_cr3(),
        KERNEL_RANGE_TRACKER.clone(),
    );

    program.main_thread = Some(SCHEDULER.get_current_task(current_cpu_id()).unwrap());

    program.modules = RwLock::new(vec![Arc::new(RwLock::new(Module {
        title: "KRNL.DLL".into(),
        image_path: Path::from_string(""),
        parent_pid: 0,
        image_base: VirtAddr::new(0xFFFF_8500_0000_0000),
        symbols: EXPORTS.to_vec(),
    }))]);
    let _pid = PROGRAM_MANAGER.add_program(program);

    spawn_detached(async move {
        let _ = install_prepacked_drivers().await;
        // BOOT_WINDOW.start();
        let _ = PNP_MANAGER.init_from_registry().await;
        // bench_async_vs_sync_call_latency_async().await;

        // benchmark_async_async().await;
    });
    println!("");
}
#[no_mangle]
#[inline(never)]
pub extern "win64" fn trigger_guard_page_overflow() -> ! {
    let task = SCHEDULER
        .get_current_task(current_cpu_id())
        .expect("no current task");
    let guard = task.guard_page.load(core::sync::atomic::Ordering::Acquire);
    let target = (guard + 0x800) & !0xFu64;
    unsafe {
        asm!(
            "mov rsp, {0}",
            "mov qword ptr [rsp], 0",
            in(reg) target,
            options(noreturn)
        );
    }
}
#[inline(never)]
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
    let is_owner = match PANIC_OWNER.try_lock() {
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
    if is_owner {
        println!("=== KERNEL PANIC [{}] ===", mod_name);
        println!("{}", info);

        // let dump = dump_scheduler();
        // println!("--- Running tasks at panic ---");
        // for (cpu_id, slot) in dump.current_tasks.iter().enumerate().take(dump.num_cores) {
        //     if let Some(task) = slot {
        //         let name = unsafe { task_name_panic(task) };
        //         println!(
        //             "  CPU {}: \"{}\" (id={})",
        //             cpu_id,
        //             name,
        //             task.id.load(Ordering::Relaxed)
        //         );
        //     } else {
        //         println!("  CPU {}: <idle>", cpu_id);
        //     }
        // }
        // println!("--- Tasks in run queue and ipi queue ---");
        // for (cpu_id, queue) in dump.run_queues.iter().enumerate().take(dump.num_cores) {
        //     let some_count = queue.tasks.iter().filter(|task| task.is_some()).count();
        //     println!(
        //         "  CPU {}: run_queue={} (captured={}, total_before_drain={})",
        //         cpu_id, some_count, queue.captured, queue.total_before_drain
        //     );
        // }

        // for (cpu_id, queue) in dump.ipi_queues.iter().enumerate().take(dump.num_cores) {
        //     let some_count = queue.tasks.iter().filter(|task| task.is_some()).count();
        //     println!(
        //         "  CPU {}: ipi_queue={} (captured={}, total_before_drain={})",
        //         cpu_id, some_count, queue.captured, queue.total_before_drain
        //     );
        // }
        // for (cpu_id, task) in dump.current_tasks.iter().enumerate().take(dump.num_cores) {
        //     match task {
        //         Some(task) => {
        //             let stack_size = task.stack_size.load(core::sync::atomic::Ordering::Acquire);
        //             let guard_page = task.guard_page.load(core::sync::atomic::Ordering::Acquire);

        //             println!(
        //                 "  CPU {}: current_task stack_size={} guard_page={:#x}",
        //                 cpu_id, stack_size, guard_page
        //             );
        //         }
        //         None => {
        //             println!("  CPU {}: current_task=None", cpu_id);
        //         }
        //     }
        // }
        unsafe {
            if let Some(a) = APIC.lock().as_ref() {
                a.lapic.send_ipi(IpiDest::AllExcludingSelf, IpiKind::Nmi)
            }
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

#[no_mangle]
#[inline(never)]
pub extern "win64" fn trigger_triple_fault() -> ! {
    static EMPTY_IDT: InterruptDescriptorTable = InterruptDescriptorTable::new();

    x86_64::instructions::interrupts::disable();
    unsafe {
        EMPTY_IDT.load();
        asm!("ud2", options(noreturn));
    }
}

pub fn trigger_breakpoint() {
    unsafe {
        asm!("int 3");
    }
}

pub fn test_full_heap() {
    let element_count = (HEAP_SIZE as usize / 4) / size_of::<u64>();

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
                {
                    #[cfg(debug_assertions)]
                    const IMAGE: &[u8] = include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/../drivers/target/x86_64-rustos-driver/debug/",
                        $name,
                        ".dll"
                    ));
                    #[cfg(not(debug_assertions))]
                    const IMAGE: &[u8] = include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/../drivers/target/x86_64-rustos-driver/release/",
                        $name,
                        ".dll"
                    ));

                    $crate::util::BootPkg {
                        name: $name,
                        toml: include_bytes!(concat!(
                            env!("CARGO_MANIFEST_DIR"),
                            "/../drivers/",
                            $name,
                            "/src/",
                            $name,
                            ".toml"
                        )),
                        image: IMAGE,
                    }
                },
            )+
        ] as &[ $crate::util::BootPkg ]
    }};
}
unsafe fn tls_test_snapshot() -> (u64, [u8; 16], u64, [u8; 16]) {
    (
        TLS_TEST_INIT_U64,
        TLS_TEST_INIT_BYTES,
        TLS_TEST_ZERO_U64,
        TLS_TEST_ZERO_BYTES,
    )
}

unsafe fn tls_test_write(init_u64: u64, init_bytes: [u8; 16], zero_u64: u64, zero_bytes: [u8; 16]) {
    TLS_TEST_INIT_U64 = init_u64;
    TLS_TEST_INIT_BYTES = init_bytes;
    TLS_TEST_ZERO_U64 = zero_u64;
    TLS_TEST_ZERO_BYTES = zero_bytes;
}

extern "win64" fn kernel_tls_self_test_worker(_ctx: usize) {
    let expected = unsafe { tls_test_snapshot() };
    if expected != (TLS_TEMPLATE_U64, TLS_TEMPLATE_BYTES, 0, [0; 16]) {
        TLS_SELF_TEST_RESULT.store(TLS_SELF_TEST_FAIL, Ordering::Release);
        return;
    }

    unsafe {
        tls_test_write(
            TLS_WORKER_U64,
            TLS_WORKER_BYTES,
            TLS_WORKER_U64,
            TLS_WORKER_ZERO_BYTES,
        );
    }

    let worker_snapshot = unsafe { tls_test_snapshot() };
    let ok = worker_snapshot
        == (
            TLS_WORKER_U64,
            TLS_WORKER_BYTES,
            TLS_WORKER_U64,
            TLS_WORKER_ZERO_BYTES,
        );

    TLS_SELF_TEST_RESULT.store(
        if ok {
            TLS_SELF_TEST_PASS
        } else {
            TLS_SELF_TEST_FAIL
        },
        Ordering::Release,
    );
}

pub fn test_kernel_tls_runtime() {
    let current = SCHEDULER
        .get_current_task(current_cpu_id())
        .expect("kernel TLS self-test requires a scheduled task");
    assert!(
        current.is_kernel_mode.load(Ordering::Acquire),
        "kernel TLS self-test requires a scheduled kernel task"
    );

    let initial = unsafe { tls_test_snapshot() };
    if initial != (TLS_TEMPLATE_U64, TLS_TEMPLATE_BYTES, 0, [0; 16]) {
        panic!(
            "kernel TLS self-test saw wrong initial state: {:?}",
            initial
        );
    }

    unsafe {
        tls_test_write(
            TLS_MAIN_U64,
            TLS_MAIN_BYTES,
            TLS_MAIN_U64,
            TLS_MAIN_ZERO_BYTES,
        );
    }

    SCHEDULER.add_task(Task::new_kernel_mode(
        kernel_tls_self_test_worker,
        0,
        StackSize::Tiny,
        "kernel-tls-self-test".into(),
        0,
    ));

    let mut completed = false;
    for _ in 0..4096 {
        if TLS_SELF_TEST_RESULT.load(Ordering::Acquire) != TLS_SELF_TEST_PENDING {
            completed = true;
            break;
        }
        yield_now();
    }

    let current_snapshot = unsafe { tls_test_snapshot() };
    unsafe {
        tls_test_write(TLS_TEMPLATE_U64, TLS_TEMPLATE_BYTES, 0, [0; 16]);
    }
    let worker_result = TLS_SELF_TEST_RESULT.load(Ordering::Acquire);
    TLS_SELF_TEST_BUSY.store(false, Ordering::Release);

    assert!(completed, "kernel TLS self-test worker did not complete");
    assert!(
        worker_result == TLS_SELF_TEST_PASS,
        "kernel TLS self-test worker failed with state {}",
        worker_result
    );
    assert!(
        current_snapshot
            == (
                TLS_MAIN_U64,
                TLS_MAIN_BYTES,
                TLS_MAIN_U64,
                TLS_MAIN_ZERO_BYTES,
            ),
        "kernel TLS self-test current thread state was clobbered: {:?}",
        current_snapshot
    );

    println!("Kernel TLS self-test passed");
}
