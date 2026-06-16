extern crate rand_xoshiro;

use crate::arch::VirtAddr;
use crate::benchmarking::BenchWindow;
use crate::boot_packages;
use crate::console::Screen;
use crate::drivers::driver_install::install_prepacked_drivers;
use crate::drivers::pnp::manager::PNP_MANAGER;
use crate::executable::program::{Program, PROGRAM_MANAGER};
use crate::exports::EXPORTS;
use crate::file_system::file_provider::{install_file_provider, ProviderKind};
use crate::lazy_static;
use crate::memory::dma::init_dma_manager;
use crate::memory::heap::allocator::test_full_heap_parallel;
use crate::memory::heap::{heap_capacity_bytes, init_heap};
use crate::memory::paging::stack::StackSize;
use crate::memory::paging::virt_tracker::KERNEL_RANGE_TRACKER;
use crate::memory::paging::{
    boot_usable_bytes, resize_bitmap_for_ram, unmap_reserved_range_unchecked, KernelFrameAllocator,
};
use crate::platform::{current_cpu_id, cycle_counter};
use crate::scheduling::global_async::GlobalAsyncExecutor;
use crate::scheduling::runtime::runtime::yield_now;
use crate::scheduling::runtime::runtime::{init_executor_platform, spawn_detached};
use crate::scheduling::scheduler::SCHEDULER;
use crate::scheduling::task::Task;
use crate::structs::stopwatch::Stopwatch;
use crate::{println, BOOT_INFO, BOOT_INFO_INITIALIZED};
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::{vec, vec::Vec};
use core::arch::asm;
use core::cmp::max;
use core::marker::PhantomData;
use core::mem::size_of;
use core::panic::PanicInfo;
use core::sync::atomic::AtomicU8;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use kernel_abi::BootInfo;
use kernel_types::benchmark::BenchWindowConfig;
use kernel_types::fs::Path;
use kernel_types::memory::Module;
use rand_core::{RngCore, SeedableRng};
use rand_xoshiro::Xoshiro256PlusPlus;
use spin::rwlock::RwLock;
use spin::{Mutex, Once};
pub(crate) static KERNEL_INITIALIZED: AtomicBool = AtomicBool::new(false);
pub static CORE_LOCK: AtomicUsize = AtomicUsize::new(0);
pub static INIT_LOCK: Mutex<usize> = Mutex::new(0);
pub static CPU_ID: AtomicUsize = AtomicUsize::new(0);
pub static TOTAL_TIME: Once<Stopwatch> = Once::new();
pub static BOOTSET: &[BootPkg] = boot_packages![
    "root",
    "devicetree",
    "acpi",
    "pci",
    "ide",
    "disk",
    "partmgr",
    "volmgr",
    "mountmgr",
    "fat32",
    "i8042",
    "virtio"
];
pub static PANIC_ACTIVE: AtomicBool = AtomicBool::new(false);
static PANIC_OWNER: Mutex<Option<u32>> = Mutex::new(None);

// lazy_static! {
//     pub static ref DRIVE_WINDOW: BenchWindow = BenchWindow::new(BenchWindowConfig {
//         name: "drive",
//         folder: "C:\\system\\logs",
//         log_samples: true,
//         log_spans: false,
//         log_mem_on_persist: false,
//         export_debug_metadata: true,
//         end_on_drop: false,
//         timeout_ms: None,
//         auto_persist_secs: None,
//         sample_reserve: 400000,
//         span_reserve: 0,
//         overflow_policy: Some(kernel_types::benchmark::BenchOverflowPolicy::Panic),
//         sample_capacity: None,
//         sample_chunk_capacity: None,
//         max_unwind_depth: None,
//         disable_per_core: true
//     });
// }
const TLS_SELF_TEST_PENDING: u8 = 0;
const TLS_SELF_TEST_PASS: u8 = 1;
const TLS_SELF_TEST_FAIL: u8 = 2;

static TLS_SELF_TEST_BUSY: AtomicBool = AtomicBool::new(false);
static TLS_SELF_TEST_RESULT: AtomicU8 = AtomicU8::new(TLS_SELF_TEST_PENDING);
static KERNEL_STUB_RECLAIMED: AtomicBool = AtomicBool::new(false);

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
    crate::memory::paging::init_kernel_address_space_root();
    let memory_map = &boot_info().memory_regions;
    KernelFrameAllocator::init_from_boot_memory_map();
    {
        let _init_lock = INIT_LOCK.lock();
        init_heap();
        {
            let boot = boot_info();
            crate::profiling::unwind::register_kernel_pe_unwind_module(
                boot.kernel_image_base,
                boot.kernel_image_size,
                boot.kernel_sections.as_slice(),
            );
        }
        reclaim_kernel_stub();
        Screen::clear_framebuffer();
        crate::platform::init_boot_processor();
        init_dma_manager();
        crate::platform::calibrate_boot_timer();
        TOTAL_TIME.call_once(Stopwatch::start);
        crate::platform::start_secondary_cpus();
    }

    while CORE_LOCK.load(Ordering::SeqCst) != 0 {
        core::hint::spin_loop();
    }

    crate::platform::init_current_cpu_local_state(CPU_ID.fetch_add(1, Ordering::Acquire) as u32);

    crate::platform::init_periodic_timer();
    SCHEDULER.init_core(current_cpu_id());
    SCHEDULER.add_task(Task::new_kernel_mode(
        kernel_main,
        0,
        StackSize::Tiny,
        "kernel".into(),
        0,
    ));

    crate::platform::enable_interrupts();
    println!("Init Done");
    KERNEL_INITIALIZED.store(true, Ordering::SeqCst);
    loop {
        crate::platform::enable_interrupts_and_halt();
    }
}
pub extern "C" fn kernel_main(ctx: usize) {
    crate::memory::heap::enable_mimalloc();
    resize_bitmap_for_ram(boot_usable_bytes()).expect(&alloc::format!(
        "Failed to resize phys frame bitmap to capacity {}",
        boot_usable_bytes()
    ));
    init_executor_platform();
    GlobalAsyncExecutor::global().init(max(4, crate::platform::processor_count()), 1_000_000);
    install_file_provider(ProviderKind::Bootstrap);
    test_kernel_tls_runtime();
    let mut program = Program::new(
        "kernel".to_string(),
        Path::from_string(""),
        VirtAddr::new(0xFFFF_8500_0000_0000),
        crate::memory::paging::kernel_address_space_root(),
        KERNEL_RANGE_TRACKER.clone(),
    );

    program.main_thread = Some(SCHEDULER.get_current_task(current_cpu_id()).unwrap());

    program.modules = RwLock::new(vec![Arc::new(RwLock::new(Module {
        title: "kernel.exe".into(),
        image_path: Path::from_string(""),
        parent_pid: 0,
        image_base: VirtAddr::new(0xFFFF_8500_0000_0000).into(),
        symbols: EXPORTS.to_vec(),
        pe_info: None,
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
pub extern "C" fn trigger_guard_page_overflow() -> ! {
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
    crate::platform::halt()
}
#[no_mangle]
pub extern "C" fn panic_common(mod_name: &'static str, info: &PanicInfo) -> ! {
    if PANIC_ACTIVE.swap(true, Ordering::SeqCst) {
        halt_loop()
    }

    crate::platform::disable_interrupts();
    unsafe {
        crate::memory::paging::switch_address_space_root(
            crate::memory::paging::kernel_address_space_root(),
        );
    }
    crate::KERNEL_INITIALIZED.store(false, Ordering::SeqCst);

    let me = crate::platform::current_logical_id() as u32;
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
        println!(
            "is in interrupt: {:#?}",
            crate::platform::current_is_in_interrupt()
        );
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
        crate::platform::broadcast_panic_stop();

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
pub extern "C" fn trigger_triple_fault() -> ! {
    crate::platform::disable_interrupts();
    crate::arch::instructions::triple_fault()
}

pub fn trigger_breakpoint() {
    crate::arch::instructions::breakpoint();
}

pub fn test_full_heap() {
    let time = Stopwatch::start();
    let element_count = (heap_capacity_bytes() as usize / 4) / size_of::<u64>();

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
        "Heap test passed in {:2}ms: allocated and verified {} elements in the heap",
        time.elapsed_millis(),
        element_count
    );
}

pub extern "C" fn random_number() -> u64 {
    let mut rng = Random::new(cycle_counter());
    rng.next_u64()
}

pub fn boot_info() -> &'static mut BootInfo {
    if !BOOT_INFO_INITIALIZED.load(Ordering::Acquire) {
        panic!("BOOT_INFO not initialized");
    }

    unsafe { &mut BOOT_INFO }
}

fn reclaim_kernel_stub() {
    if KERNEL_STUB_RECLAIMED.swap(true, Ordering::AcqRel) {
        return;
    }

    let boot = boot_info();
    if boot.stub_base == 0 || boot.stub_size == 0 {
        return;
    }

    unsafe {
        unmap_reserved_range_unchecked(VirtAddr::new(boot.stub_base).into(), boot.stub_size);
    }
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
                        "/../drivers/target/",
                        $crate::platform_driver_target_dir!(),
                        "/debug/",
                        $name,
                        ".dll"
                    ));
                    #[cfg(not(debug_assertions))]
                    const IMAGE: &[u8] = include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/../drivers/target/",
                        $crate::platform_driver_target_dir!(),
                        "/release/",
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

extern "C" fn kernel_tls_self_test_worker(_ctx: usize) {
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
        StackSize::Huge,
        "kernel-tls-self-test".into(),
        0,
    ));

    let mut completed = false;
    while TLS_SELF_TEST_RESULT.load(Ordering::Acquire) == TLS_SELF_TEST_PENDING {
        yield_now();
    }
    completed = true;

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
