use crate::dev_ext::DevExtInner;
use crate::rdtsc;
use alloc::vec::Vec;
use core::hint::spin_loop;
use kernel_api::benchmark::{
    BENCH_PARAMS_VERSION_1, BenchLevelResult, BenchSweepParams, BenchSweepResult,
};
use kernel_api::println;
use kernel_api::status::DriverStatus;
pub const IOCTL_BLOCK_BENCH_SWEEP: u32 = 0xB000_8002;
pub const IOCTL_BLOCK_BENCH_SWEEP_POLLING: u32 = 0xB000_8003;

pub const IOCTL_BLOCK_BENCH_SWEEP_BOTH: u32 = 0xB000_8004;

struct BenchConfig {
    request_size: u32,
    requests_per_run: u32,
    max_queue_inflight: u16,
}

impl BenchConfig {
    fn from_inner_params(inner: &DevExtInner, params: &BenchSweepParams) -> Self {
        let request_size = params.request_size.max(512) & !511;
        let max_q = bench_max_inflight_queue0(inner, request_size, inner.indirect_desc_enabled);
        let max_queue_inflight = params.max_inflight.min(max_q as u16).max(1);

        let total_bytes = params.total_bytes.max(request_size as u64);
        let requests_per_run = total_bytes
            .div_ceil(request_size as u64)
            .max(1)
            .min(u32::MAX as u64) as u32;

        Self {
            request_size,
            requests_per_run,
            max_queue_inflight,
        }
    }
}

fn bench_descs_per_request(use_indirect: bool, request_size: u32) -> usize {
    if !use_indirect {
        return 2 + (request_size as usize).div_ceil(4096);
    }
    1 // indirect table uses a single virtqueue descriptor
}

fn bench_max_inflight_queue0(inner: &DevExtInner, request_size: u32, use_indirect: bool) -> usize {
    let q0 = inner.get_queue(0);
    let dpr = bench_descs_per_request(use_indirect, request_size);
    (q0.vq_ref().size as usize / dpr).max(1)
}

// TODO: rewrite bench_reads_direct to go through the drain-task-based IO path.
async fn bench_reads_direct(
    _inner: &DevExtInner,
    _start_sector: u64,
    inflight: usize,
    _bench_cfg: &BenchConfig,
    _use_interrupts: bool,
) -> Result<BenchLevelResult, DriverStatus> {
    let mut result = BenchLevelResult::default();
    result.inflight = inflight as u32;
    Err(DriverStatus::NotImplemented)
}

pub async fn bench_sweep_params(
    inner: &DevExtInner,
    params: &BenchSweepParams,
    use_interrupts: bool,
) -> Result<BenchSweepResult, DriverStatus> {
    let bench_cfg = BenchConfig::from_inner_params(inner, params);

    let max_inflight = (params.max_inflight as usize).max(1);
    let max_inflight = max_inflight
        .min(bench_cfg.max_queue_inflight as usize)
        .max(1);

    let mut levels: Vec<usize> = Vec::new();
    let mut lvl = 1usize;

    let max_levels = BenchSweepResult::default().levels.len();
    while lvl < max_inflight && levels.len() + 1 < max_levels {
        levels.push(lvl);
        let next = lvl.saturating_mul(2);
        if next == lvl {
            break;
        }
        lvl = next;
    }
    if levels.len() < max_levels && *levels.last().unwrap_or(&0) != max_inflight {
        levels.push(max_inflight);
    }

    let mut result = BenchSweepResult::default();
    let current_sector: u64 = params.start_sector;
    for level in levels {
        println!("Starting level: {}", level);
        if (result.used as usize) >= result.levels.len() {
            break;
        }

        let level_result =
            bench_reads_direct(inner, current_sector, level, &bench_cfg, use_interrupts).await?;

        result.levels[result.used as usize] = level_result;
        result.used += 1;

        if level >= max_inflight {
            break;
        }
    }

    Ok(result)
}

pub fn sanitize_bench_params(inner: &DevExtInner, mut p: BenchSweepParams) -> BenchSweepParams {
    if p.version != BENCH_PARAMS_VERSION_1 {
        p = BenchSweepParams::default();
    }

    if p.request_size == 0 {
        p.request_size = 64 * 1024;
    }
    p.request_size &= !511;
    if p.request_size < 512 {
        p.request_size = 512;
    }

    if p.total_bytes == 0 {
        p.total_bytes = p.request_size as u64;
    }
    if p.total_bytes < p.request_size as u64 {
        p.total_bytes = p.request_size as u64;
    }

    let max_auto =
        bench_max_inflight_queue0(inner, p.request_size, inner.indirect_desc_enabled) as u16;

    if max_auto == 0 {
        p.max_inflight = 1;
        return p;
    }

    if p.max_inflight == 0 {
        p.max_inflight = max_auto;
    } else {
        p.max_inflight = p.max_inflight.min(max_auto).max(1);
    }

    p
}

pub async fn bench_sweep(
    inner: &DevExtInner,
    use_interrupts: bool,
) -> Result<BenchSweepResult, DriverStatus> {
    let p = sanitize_bench_params(inner, BenchSweepParams::default());
    bench_sweep_params(inner, &p, use_interrupts).await
}

const BENCH_SPIN_CHUNK: u32 = 256;

#[inline]
pub fn bench_spin_chunk_and_count(busy_cycles: &mut u64) {
    let t0 = rdtsc();
    let mut i = 0u32;
    while i < BENCH_SPIN_CHUNK {
        spin_loop();
        i += 1;
    }
    let t1 = rdtsc();
    *busy_cycles = busy_cycles.saturating_add(t1.saturating_sub(t0));
}

#[inline]
fn percentile_index_permille(n: usize, permille: usize) -> usize {
    if n == 0 {
        return 0;
    }
    ((n - 1) * permille) / 1000
}
