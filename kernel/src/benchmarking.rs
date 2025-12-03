use crate::alloc::format;
use crate::alloc::vec;
use crate::drivers::pnp::manager::PNP_MANAGER;
use crate::file_system::file::File;
use crate::memory::allocator::BuddyLocked;
use crate::println;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use kernel_types::fs::OpenFlags;
use nostd_runtime::block_on;
use spin::RwLock;
use x86_64::instructions::interrupts;

use crate::{
    drivers::{
        interrupt_index::wait_millis_idle,
        timer_driver::{PER_CORE_SWITCHES, TIMER_TIME_SCHED},
    },
    file_system::file_provider::provider,
    memory::{
        allocator::ALLOCATOR,
        heap::HEAP_SIZE,
        paging::frame_alloc::{total_usable_bytes, USED_MEMORY},
    },
    util::{boot_info, TOTAL_TIME},
};

pub struct LogConfig {
    pub log_util: bool,
    pub log_per_core: bool,
    pub log_dist: bool,
    pub log_mem: bool,
    pub log_window: usize, // minutes
    pub path: &'static str,
}

static LOG_CONFIG: RwLock<LogConfig> = RwLock::new(LogConfig {
    log_util: true,
    log_per_core: true,
    log_dist: true,
    log_mem: true,
    log_window: 1,
    path: "C:\\SYSTEM\\LOGS",
});

pub fn set_log_config(cfg: LogConfig) {
    *LOG_CONFIG.write() = cfg;
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

pub async fn run_stats_loop() {
    let mut prev_total_ms: u128 = 0;
    let mut prev_core_ms: Vec<u128> = read_all_core_timer_ms();
    let mut prev_core_sw: Vec<u64> = read_all_core_switches();
    let mut prev_sched_ns: Vec<u128> = read_all_core_sched_ns();

    let mut acc_minutes: usize = 0;
    let mut acc_total_ms: u128 = 0;
    let mut acc_core_ms: Vec<u128> = vec![0; prev_core_ms.len()];
    let mut acc_core_sw: Vec<u128> = vec![0; prev_core_sw.len()];
    let mut acc_total_sw: u128 = 0;
    let mut acc_sched_ns: Vec<u128> = vec![0; prev_sched_ns.len()];
    let mut acc_total_sched_ns: u128 = 0;
    wait_millis_idle(25000);
    //PNP_MANAGER.print_device_tree();
    loop {
        wait_millis_idle(10000);
        let core_ms_now = read_all_core_timer_ms();
        let total_ms_now = TOTAL_TIME.wait().elapsed_millis() as u128;
        let delta_total_ms = total_ms_now.saturating_sub(prev_total_ms);
        if delta_total_ms == 0 {
            continue;
        }

        let mut delta_core_ms = Vec::with_capacity(core_ms_now.len());
        for (i, &now) in core_ms_now.iter().enumerate() {
            let prev = *prev_core_ms.get(i).unwrap_or(&0);
            let d = now.saturating_sub(prev);
            delta_core_ms.push(d);
            acc_core_ms[i] = acc_core_ms[i].saturating_add(d);
        }

        let core_sw_now = read_all_core_switches();
        let mut delta_core_sw = Vec::with_capacity(core_sw_now.len());
        let mut total_delta_sw: u128 = 0;
        for (i, &now) in core_sw_now.iter().enumerate() {
            let prev = *prev_core_sw.get(i).unwrap_or(&0);
            let d = now.saturating_sub(prev);
            total_delta_sw += d as u128;
            delta_core_sw.push(d);
            acc_core_sw[i] = acc_core_sw[i].saturating_add(d as u128);
        }
        acc_total_sw = acc_total_sw.saturating_add(total_delta_sw);

        let sched_ns_now = read_all_core_sched_ns();
        let mut delta_sched_ns = Vec::with_capacity(sched_ns_now.len());
        let mut total_sched_ns: u128 = 0;
        for i in 0..sched_ns_now.len() {
            let ns = *sched_ns_now.get(i).unwrap_or(&0);
            let ps = *prev_sched_ns.get(i).unwrap_or(&0);
            let d = ns.saturating_sub(ps);
            total_sched_ns += d;
            delta_sched_ns.push(d);
            acc_sched_ns[i] = acc_sched_ns[i].saturating_add(d);
        }
        acc_total_sched_ns = acc_total_sched_ns.saturating_add(total_sched_ns);

        acc_total_ms = acc_total_ms.saturating_add(delta_total_ms);
        acc_minutes += 1;

        if acc_minutes >= LOG_CONFIG.read().log_window.max(1) {
            let cfg = LOG_CONFIG.read();
            if !cfg.path.is_empty() {
                let log = build_window_log(
                    acc_total_ms,
                    &acc_core_ms,
                    &acc_core_sw,
                    acc_total_sw,
                    &acc_sched_ns,
                    acc_total_sched_ns,
                    &cfg,
                );
                println!("{}", log);
                block_on(append_to_file(&cfg.path, log.as_bytes()));
            }
            acc_minutes = 0;
            acc_total_ms = 0;
            for v in acc_core_ms.iter_mut() {
                *v = 0;
            }
            for v in acc_core_sw.iter_mut() {
                *v = 0;
            }
            for v in acc_sched_ns.iter_mut() {
                *v = 0;
            }
            acc_total_sw = 0;
            acc_total_sched_ns = 0;
        }

        prev_core_ms = core_ms_now;
        prev_total_ms = total_ms_now;
        prev_core_sw = core_sw_now;
        prev_sched_ns = sched_ns_now;
    }
}

fn build_window_log(
    window_total_ms: u128,
    core_ms: &[u128],
    core_sw: &[u128],
    total_sw: u128,
    core_sched_ns: &[u128],
    total_sched_ns: u128,
    cfg: &LogConfig,
) -> String {
    let mut out = String::new();
    let percs = per_core_percent_x1000(window_total_ms, core_ms);
    let ncores = if percs.is_empty() {
        1
    } else {
        percs.len() as u128
    };
    let avg_ms = core_ms.iter().copied().sum::<u128>() / ncores;
    let avg_util_x100000 = if window_total_ms == 0 {
        0
    } else {
        (avg_ms * 100_000) / window_total_ms
    };
    let total_ctx_per_sec = if window_total_ms == 0 {
        0
    } else {
        (total_sw * 1000) / window_total_ms
    };
    let avg_ctx_per_sec_per_core = total_ctx_per_sec / ncores;
    let avg_ns_per_switch = if total_sw == 0 {
        0
    } else {
        total_sched_ns / total_sw
    };
    let total_cpu_ns_window = window_total_ms * (ncores as u128) * 1_000_000;
    let timer_overhead_x100000 = if total_cpu_ns_window == 0 {
        0
    } else {
        (total_sched_ns * 100_000) / total_cpu_ns_window
    };

    if cfg.log_util {
        out.push_str(&format!(
            "\n[System Summary | Window {} ms]\nAvg Util: {}.{}% | Total Ctx/s: {} | Avg Ctx/s/Core: {} | Avg Sched ns/switch: {}\nTimer Ovh: {}.{}% | Total Scheduler Cost: {} us\n",
            window_total_ms,
            avg_util_x100000 / 1000, (avg_util_x100000 % 1000) / 100,
            total_ctx_per_sec,
            avg_ctx_per_sec_per_core,
            avg_ns_per_switch,
            timer_overhead_x100000 / 1000, (timer_overhead_x100000 % 1000) / 10,
            total_sched_ns / 1000
        ));
    }

    if cfg.log_per_core && !percs.is_empty() {
        out.push_str("[Per-Core]\n");
        out.push_str("Core Util%  Ctx/s   Sched(ns)  Ovh%\n");
        for i in 0..percs.len() {
            let p = percs[i];
            let cps = if window_total_ms == 0 {
                0
            } else {
                (core_sw.get(i).copied().unwrap_or(0) * 1000) / window_total_ms
            };
            let sw = core_sw.get(i).copied().unwrap_or(0);
            let sns = core_sched_ns.get(i).copied().unwrap_or(0);
            let sched_avg = if sw == 0 { 0 } else { sns / sw };
            let core_cpu_ns = window_total_ms * 1_000_000;
            let overhead_x100 = if core_cpu_ns == 0 {
                0
            } else {
                (sns * 10000) / core_cpu_ns
            };
            out.push_str(&format!(
                "C{:<3} {:>3}.{:01}% {:>6} {:>10} {:>2}.{:02}%\n",
                i,
                p / 1000,
                (p % 1000) / 100,
                cps,
                sched_avg,
                overhead_x100 / 100,
                overhead_x100 % 100
            ));
        }
    }

    if cfg.log_dist && !percs.is_empty() {
        let sd = stddev_percent_x1000(&percs);
        let cv = cv_x1000(&percs);
        let median = median_x1000(percs.clone());
        let mad = mad_percent_x1000(&percs);
        let (min_core_idx, max_core_idx, max_gap) = max_gap_x1000(&percs);
        out.push_str(&format!(
            "[Distribution]\nMean: {}.{}% | Median: {}.{}% | StdDev: {}.{}% | MAD: {}.{}% | CV: {}.{:03} | MaxGap(C{} vs C{}): {}.{}%\n",
            avg_util_x100000 / 1000, (avg_util_x100000 % 1000) / 100,
            median / 1000, (median % 1000) / 100,
            sd / 1000, (sd % 1000) / 100,
            mad / 1000, (mad % 1000) / 100,
            cv / 1000, cv % 1000,
            min_core_idx, max_core_idx,
            max_gap / 1000, (max_gap % 1000) / 100
        ));
    }

    if cfg.log_mem {
        out.push_str(&mem_report_string());
    }

    out.push('\n');
    out
}

pub async fn append_to_file(path: &str, data: &[u8]) -> Result<(), ()> {
    File::make_dir(path.to_string()).await;

    let file_path = alloc::format!("{path}\\benchmark.txt");

    let mut file = match File::open(&file_path, &[OpenFlags::Create]).await {
        Ok(f) => f,
        Err(_) => File::open(&file_path, &[OpenFlags::Open])
            .await
            .map_err(|_| ())?,
    };

    let mut buf = match file.read().await {
        Ok(existing) => existing,
        Err(_) => Vec::new(),
    };

    buf.extend_from_slice(data);

    file.write(&buf).await.map_err(|_| ())?;

    Ok(())
}

pub fn used_memory() -> usize {
    HEAP_SIZE - ALLOCATOR.free_memory()
}

fn mem_report_string() -> String {
    let heap_used = interrupts::without_interrupts(move || used_memory());
    let mut used_bytes = USED_MEMORY.load(Ordering::SeqCst);
    used_bytes += boot_info().kernel_len as usize;
    let total_bytes = total_usable_bytes();

    let used_mb = used_bytes / 1_048_576;
    let total_mb = total_bytes / 1_048_576;

    let percent_x10 = if total_bytes == 0 {
        0
    } else {
        (used_bytes as u128 * 1000) / total_bytes as u128
    };
    let int_part = percent_x10 / 10;
    let frac_part = percent_x10 % 10;

    let heap_used_kb = heap_used / 1000;
    let heap_total_kb = HEAP_SIZE / 1000;

    let heap_percent_x10 = if HEAP_SIZE == 0 {
        0
    } else {
        (heap_used as u128 * 1000) / HEAP_SIZE as u128
    };
    let heap_int_part = heap_percent_x10 / 10;
    let heap_frac_part = heap_percent_x10 % 10;

    format!(
        "[Memory]\nUsed: {} MB / {} MB ({}.{})%\nHeap: {} KB / {} KB ({}.{})%\n",
        used_mb,
        total_mb,
        int_part,
        frac_part,
        heap_used_kb,
        heap_total_kb,
        heap_int_part,
        heap_frac_part
    )
}
