// util.rs
extern crate rand_xoshiro;

use crate::alloc::format;
use crate::boot_packages;
use crate::drivers::interrupt_index::{
    apic_calibrate_ticks_per_ns_via_wait, apic_program_period_ms, apic_program_period_ns,
    calibrate_tsc, current_cpu_id, get_current_logical_id, init_percpu_gs, set_current_cpu_id,
    wait_millis_idle, wait_using_pit_50ms, ApicImpl,
};
use crate::drivers::interrupt_index::{APIC, PICS};
use crate::drivers::pnp::manager::PNP_MANAGER;
use crate::drivers::timer_driver::{
    NUM_CORES, PER_CORE_SWITCHES, ROT_TICKET, TIMER, TIMER_TIME_FAST, TIMER_TIME_SCHED,
};
use crate::executable::program::{Module, Program, PROGRAM_MANAGER};
use crate::exports::EXPORTS;
use crate::file_system::file::{File, FileStatus, OpenFlags};
use crate::file_system::file_provider::install_file_provider;
use crate::file_system::{bootstrap_filesystem::BootstrapProvider, file_provider};
use crate::gdt::PER_CPU_GDT;
use crate::idt::load_idt;
use crate::memory::allocator::ALLOCATOR;
use crate::memory::heap::{init_heap, HEAP_SIZE};
use crate::memory::paging::frame_alloc::{total_usable_bytes, BootInfoFrameAllocator, USED_MEMORY};
use crate::memory::paging::tables::{init_kernel_cr3, kernel_cr3};
use crate::memory::paging::virt_tracker::KERNEL_RANGE_TRACKER;
use crate::registry::is_first_boot;
use crate::scheduling::scheduler::SCHEDULER;
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
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use rand_core::{RngCore, SeedableRng};
use rand_xoshiro::Xoshiro256PlusPlus;
use spin::{Mutex, Once, RwLock};
use x86_64::instructions::interrupts;
use x86_64::VirtAddr;

pub static AP_STARTUP_CODE: &[u8] = include_bytes!("../../target/ap_startup.bin");

pub(crate) static KERNEL_INITIALIZED: AtomicBool = AtomicBool::new(false);
pub static CORE_LOCK: AtomicUsize = AtomicUsize::new(0);
pub static INIT_LOCK: Mutex<usize> = Mutex::new(0);
pub static CPU_ID: AtomicUsize = AtomicUsize::new(0);
static TOTAL_TIME: Once<Stopwatch> = Once::new();
pub const APIC_START_PERIOD: u64 = 560_000;
pub static BOOTSET: &[BootPkg] =
    boot_packages!["acpi", "pci", "ide", "disk", "partmgr", "volmgr", "mountmgr", "fat32"];

pub unsafe fn init() {
    init_kernel_cr3();
    let memory_map = &boot_info().memory_regions;
    BootInfoFrameAllocator::init_start(memory_map);
    {
        let _init_lock = INIT_LOCK.lock();
        init_heap();
        test_full_heap();

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

pub fn kernel_main() {
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

    if is_first_boot() {
        setup_file_layout().expect("Failed to create system volume layout");
        // Prepacked driver install reads from C:\INSTALL\DRIVERS\*\*.{toml,dll} (served by bootstrap FS)
        crate::drivers::driver_install::install_prepacked_drivers()
            .expect("Failed to install pre packed drivers");
    }

    PNP_MANAGER
        .init_from_registry()
        .expect("Driver init failed");

    print_mem_report();
    println!("");
    PNP_MANAGER.print_device_tree();
    run_stats_loop();
}

fn read_all_core_timer_ms() -> Vec<u128> {
    TIMER_TIME_SCHED
        .iter()
        .map(|a| {
            let ns = a.load(Ordering::SeqCst) as u128;
            (ns + 500_000) / 1_000_000
        })
        .collect()
}

fn read_all_core_sched_ns() -> Vec<u128> {
    TIMER_TIME_SCHED
        .iter()
        .map(|a| a.load(Ordering::SeqCst) as u128)
        .collect()
}

fn read_all_core_switches() -> Vec<u64> {
    PER_CORE_SWITCHES
        .iter()
        .map(|a| a.load(Ordering::SeqCst) as u64)
        .collect()
}

fn avg_ms_per_core(core_ms: &[u128]) -> u128 {
    if core_ms.is_empty() {
        return 0;
    }
    let n = core_ms.len() as u128;
    let sum: u128 = core_ms.iter().copied().sum();
    (sum + n / 2) / n
}

fn avg_ns_per_switch_global(delta_sum_ms: u128, total_delta_switches: u128) -> u128 {
    if total_delta_switches == 0 {
        0
    } else {
        (delta_sum_ms * 1_000_000u128 + (total_delta_switches / 2)) / total_delta_switches
    }
}

fn per_core_percent_x1000(total_ms: u128, core_ms: &[u128]) -> Vec<u128> {
    let mut out = Vec::with_capacity(core_ms.len());
    if total_ms == 0 {
        return out;
    }
    for &ms in core_ms {
        out.push((ms * 100_000 + total_ms / 2) / total_ms);
    }
    out
}

fn max_pairwise_gap_x1000(percs: &[u128]) -> (usize, usize, u128) {
    let mut ai = 0;
    let mut bi = 0;
    let mut md = 0u128;
    for i in 0..percs.len() {
        for j in (i + 1)..percs.len() {
            let d = if percs[i] >= percs[j] {
                percs[i] - percs[j]
            } else {
                percs[j] - percs[i]
            };
            if d > md {
                md = d;
                ai = i;
                bi = j;
            }
        }
    }
    (ai, bi, md)
}

fn percent_diff_range_over_mean_ms_x1000(core_ms: &[u128]) -> u128 {
    if core_ms.is_empty() {
        return 0;
    }
    let mut minv = core_ms[0];
    let mut maxv = core_ms[0];
    let mut sum = 0u128;
    for &v in core_ms {
        if v < minv {
            minv = v;
        }
        if v > maxv {
            maxv = v;
        }
        sum += v;
    }
    let mean = sum / core_ms.len() as u128;
    if mean == 0 {
        return 0;
    }
    ((maxv - minv) * 100_000 + mean / 2) / mean
}

fn isqrt_u128(n: u128) -> u128 {
    if n == 0 {
        return 0;
    }
    let mut x = n;
    let mut y = (x + n / x) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

fn stddev_percent_x1000(percs: &[u128]) -> u128 {
    if percs.is_empty() {
        return 0;
    }
    let n = percs.len() as u128;
    let sum: u128 = percs.iter().copied().sum();
    let mean = sum / n;
    let mut ssd: u128 = 0;
    for &p in percs {
        let d = if p >= mean { p - mean } else { mean - p };
        ssd = ssd.saturating_add(d * d);
    }
    isqrt_u128(ssd / n)
}

fn cv_x1000(percs: &[u128]) -> u128 {
    if percs.is_empty() {
        return 0;
    }
    let n = percs.len() as u128;
    let mean = percs.iter().copied().sum::<u128>() / n;
    if mean == 0 {
        return 0;
    }
    (stddev_percent_x1000(percs) * 1000) / mean
}

fn median_x1000(mut percs: Vec<u128>) -> u128 {
    if percs.is_empty() {
        return 0;
    }
    percs.sort_unstable();
    let n = percs.len();
    if n & 1 == 1 {
        percs[n / 2]
    } else {
        (percs[n / 2 - 1] + percs[n / 2]) / 2
    }
}

fn mad_percent_x1000(percs: &[u128]) -> u128 {
    if percs.is_empty() {
        return 0;
    }
    let mut v = percs.to_vec();
    v.sort_unstable();
    let n = v.len();
    let med = if n & 1 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2
    };
    let mut devs: Vec<u128> = v
        .into_iter()
        .map(|p| if p >= med { p - med } else { med - p })
        .collect();
    devs.sort_unstable();
    let m = devs.len();
    if m & 1 == 1 {
        devs[m / 2]
    } else {
        (devs[m / 2 - 1] + devs[m / 2]) / 2
    }
}

fn max_gap_x1000(percs: &[u128]) -> (usize, usize, u128) {
    if percs.len() < 2 {
        return (0, 0, 0);
    }
    let mut min_val = percs[0];
    let mut max_val = percs[0];
    let mut min_idx = 0;
    let mut max_idx = 0;
    for (i, &p) in percs.iter().enumerate().skip(1) {
        if p < min_val {
            min_val = p;
            min_idx = i;
        }
        if p > max_val {
            max_val = p;
            max_idx = i;
        }
    }
    (min_idx, max_idx, max_val - min_val)
}

pub fn run_stats_loop() {
    let mut prev_total_ms: u128 = 0;
    let mut prev_core_ms: Vec<u128> = read_all_core_timer_ms();
    let mut prev_core_sw: Vec<u64> = read_all_core_switches();
    let mut prev_sched_ns: Vec<u128> = read_all_core_sched_ns();

    loop {
        wait_millis_idle(60000);

        let core_ms_now = read_all_core_timer_ms();
        let total_ms_now = TOTAL_TIME.wait().elapsed_millis() as u128;
        let delta_total_ms = total_ms_now.saturating_sub(prev_total_ms);
        if delta_total_ms == 0 {
            continue;
        }

        let mut delta_core_ms = Vec::with_capacity(core_ms_now.len());
        for (i, &now) in core_ms_now.iter().enumerate() {
            let prev = *prev_core_ms.get(i).unwrap_or(&0);
            delta_core_ms.push(now.saturating_sub(prev));
        }

        let core_sw_now = read_all_core_switches();
        let mut delta_core_sw = Vec::with_capacity(core_sw_now.len());
        let mut total_delta_sw: u128 = 0;
        for (i, &now) in core_sw_now.iter().enumerate() {
            let prev = *prev_core_sw.get(i).unwrap_or(&0);
            let d = now.saturating_sub(prev);
            total_delta_sw += d as u128;
            delta_core_sw.push(d);
        }

        let sched_ns_now = read_all_core_sched_ns();
        let mut delta_sched_ns = Vec::new();
        let mut total_sched_ns: u128 = 0;

        let cores = core_ms_now.len().max(sched_ns_now.len());
        for i in 0..cores {
            let ns = *sched_ns_now.get(i).unwrap_or(&0);
            let ps = *prev_sched_ns.get(i).unwrap_or(&0);
            let ns_sched = ns.saturating_sub(ps);
            total_sched_ns += ns_sched;
            delta_sched_ns.push(ns_sched);
        }

        let percs = per_core_percent_x1000(delta_total_ms, &delta_core_ms);
        if percs.is_empty() {
            continue;
        }

        let ncores = percs.len() as u128;
        let avg_ms = delta_core_ms.iter().sum::<u128>() / ncores;
        let avg_util_x100000 = (avg_ms * 100_000) / delta_total_ms;

        let total_ctx_per_sec = (total_delta_sw * 1000) / delta_total_ms;
        let avg_ctx_per_sec_per_core = total_ctx_per_sec / ncores;
        let avg_ns_per_switch = if total_delta_sw == 0 {
            0
        } else {
            total_sched_ns / total_delta_sw
        };

        let total_timer_ns = total_sched_ns;
        let total_cpu_ns_window = delta_total_ms * ncores * 1_000_000;
        let timer_overhead_x100000 = if total_cpu_ns_window == 0 {
            0
        } else {
            (total_timer_ns * 100_000) / total_cpu_ns_window
        };

        let (min_core_idx, max_core_idx, max_gap) = max_gap_x1000(&percs);
        let sd = stddev_percent_x1000(&percs);
        let cv = cv_x1000(&percs);
        let median = median_x1000(percs.clone());
        let mad = mad_percent_x1000(&percs);

        println!(
            "\n{:=^120}",
            format!("[ System Summary | Window: {}ms ]", delta_total_ms)
        );
        println!(
            "Avg Util: {:>3}.{:01}% | Total Ctx/s: {:<7} | Avg Ctx/s/Core: {:<5} | Avg Sched Latency: {:>4} ns",
            avg_util_x100000 / 1000,
            (avg_util_x100000 % 1000) / 100,
            total_ctx_per_sec,
            avg_ctx_per_sec_per_core,
            avg_ns_per_switch
        );
        println!(
            "Timer Ovh: {:>2}.{:02}% | Total Scheduler Cost: {:>5} us",
            timer_overhead_x100000 / 1000,
            (timer_overhead_x100000 % 1000) / 10,
            total_timer_ns / 1000,
        );

        println!("{:-^120}", "[ Per-Core Utilization ]");
        const NUM_COLUMNS: usize = 4;
        let num_cores = percs.len();
        let num_rows = (num_cores + NUM_COLUMNS - 1) / NUM_COLUMNS;

        let header = format!(
            "{:<4} | {:>5} | {:>5} | {:>9} | {:>6}",
            "Core", "Util%", "Ctx/s", "Sched ns", "Ovh%"
        );
        let separator = "-".repeat(header.len());

        let mut headers = Vec::new();
        for _ in 0..NUM_COLUMNS {
            headers.push(header.as_str());
        }
        println!("| {} |", headers.join(" | "));

        let mut separators = Vec::new();
        for _ in 0..NUM_COLUMNS {
            separators.push(separator.as_str());
        }
        println!("| {} |", separators.join(" | "));

        for row in 0..num_rows {
            let mut row_segments = Vec::with_capacity(NUM_COLUMNS);
            for col in 0..NUM_COLUMNS {
                let core_idx = col * num_rows + row;
                if core_idx < num_cores {
                    let p = percs[core_idx];
                    let cps = (delta_core_sw.get(core_idx).copied().unwrap_or(0) as u128 * 1000)
                        / delta_total_ms;
                    let sw = delta_core_sw.get(core_idx).copied().unwrap_or(0) as u128;
                    let sns = delta_sched_ns.get(core_idx).copied().unwrap_or(0);
                    let sched_avg = if sw == 0 { 0 } else { sns / sw };

                    let core_cpu_ns = delta_total_ms * 1_000_000;
                    let tns = sns;
                    let overhead_x10000 = if core_cpu_ns == 0 {
                        0
                    } else {
                        (tns * 10000) / core_cpu_ns
                    };

                    row_segments.push(format!(
                        "C{:<3} | {:>3}.{:01}% | {:>5} | {:>9} | {:>2}.{:02}%",
                        core_idx,
                        p / 1000,
                        (p % 1000) / 100,
                        cps,
                        sched_avg,
                        overhead_x10000 / 100,
                        overhead_x10000 % 100
                    ));
                } else {
                    row_segments.push(" ".repeat(header.len()));
                }
            }
            println!("| {} |", row_segments.join(" | "));
        }

        println!("{:=^120}", "[ Distribution Analysis ]");
        println!(
            "Mean: {:>3}.{:01}% | Median: {:>3}.{:01}% | StdDev: {:>2}.{:01}% | MAD: {:>2}.{:01}% | CV: {}.{:03} | MaxGap(C{}vC{}): {:>2}.{:01}%",
            avg_util_x100000 / 1000, (avg_util_x100000 % 1000) / 100,
            median / 1000, (median % 1000) / 100,
            sd / 1000, (sd % 1000) / 100,
            mad / 1000, (mad % 1000) / 100,
            cv / 1000, cv % 1000,
            min_core_idx, max_core_idx,
            max_gap / 1000, (max_gap % 1000) / 100
        );

        print_mem_report();
        println!("\n");

        prev_core_ms = core_ms_now;
        prev_total_ms = total_ms_now;
        prev_core_sw = core_sw_now;
        prev_sched_ns = sched_ns_now;
    }
}

pub fn used_memory() -> usize {
    let allocator = unsafe { ALLOCATOR.lock() };
    HEAP_SIZE - allocator.free_memory()
}

pub fn print_mem_report() {
    let heap_used = interrupts::without_interrupts(move || used_memory());
    let mut used_bytes = USED_MEMORY.load(Ordering::SeqCst);
    used_bytes += boot_info().kernel_len as usize;
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

    let heap_used_kb = heap_used / 1000;
    let heap_total_kb = HEAP_SIZE / 1000;

    let heap_percent_x10 = (heap_used as u128 * 1000) / HEAP_SIZE as u128;
    let heap_int_part = heap_percent_x10 / 10;
    let heap_frac_part = heap_percent_x10 % 10;

    println!(
        "Heap usage: {} KB / {} KB ({}.{})%",
        heap_used_kb, heap_total_kb, heap_int_part, heap_frac_part
    );
}

pub fn setup_file_layout() -> Result<(), FileStatus> {
    // During bootstrap we force the system layout under C:\
    let drive_label = "C:".to_string();
    let mod_path = format!("{}\\SYSTEM\\MOD", drive_label);
    let inf_path = format!("{}\\SYSTEM\\TOML", drive_label);

    match File::make_dir(mod_path.clone()) {
        Ok(_) | Err(FileStatus::FileAlreadyExist) => {}
        e => return e,
    }

    match File::make_dir(inf_path.clone()) {
        Ok(_) | Err(FileStatus::FileAlreadyExist) => Ok(()),
        e => e,
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
