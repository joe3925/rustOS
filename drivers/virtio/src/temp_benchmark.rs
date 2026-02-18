use alloc::vec::Vec;
use core::hint::spin_loop;

use kernel_api::benchmark::{
    BENCH_PARAMS_VERSION_1, BenchLevelResult, BenchSweepParams, BenchSweepResult,
};
use kernel_api::irq::irq_wait_ok;
use kernel_api::kernel_types::irq::IrqMeta;
use kernel_api::status::DriverStatus;

use crate::blk::{PREALLOCATED_DATA_SIZE, VIRTIO_BLK_S_OK, VIRTIO_BLK_T_IN};
use crate::dev_ext::DevExtInner;
use crate::{WaitTasksGuard, rdtsc};

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
    (q0.queue.try_lock().expect("queue not locked").size as usize / dpr).max(1)
}

async fn bench_reads_direct(
    inner: &DevExtInner,
    start_sector: u64,
    inflight: usize,
    bench_cfg: &BenchConfig,
    use_interrupts: bool,
) -> Result<BenchLevelResult, DriverStatus> {
    let mut result = BenchLevelResult::default();
    result.inflight = inflight as u32;
    struct BenchInflight<'a> {
        start_tsc: u64,
        head: u16,
        io_req: crate::blk::BlkIoRequestHandle<'a>,
    }

    let mut slots: Vec<Option<BenchInflight<'_>>> = Vec::with_capacity(inflight);
    slots.resize_with(inflight, || None);

    let bench_queue = inner.get_queue(0);
    let total_requests = bench_cfg.requests_per_run;
    let mut lat_samples: Vec<u64> = Vec::with_capacity(total_requests as usize);
    let mut current_sector = start_sector;
    let mut completed = 0u32;
    let mut irq_wait_wall_cycles = 0u64;
    let run_start_tsc = rdtsc();

    let meta = IrqMeta {
        tag: 0,
        data: [0; 3],
    };

    while completed < total_requests {
        // === Phase 1: Submit a full batch ===
        let batch_size = (total_requests - completed).min(inflight as u32) as usize;
        let mut batch_submitted = 0usize;

        for slot in slots.iter_mut().take(batch_size) {
            let io_req = match bench_queue.arena.new_request(
                VIRTIO_BLK_T_IN,
                current_sector,
                bench_cfg.request_size,
            ) {
                Some(r) => r,
                None => break,
            };

            let head = {
                let mut vq = bench_queue.queue.lock().await;
                let use_indirect = inner.indirect_desc_enabled;
                match io_req.submit(&mut vq, false, use_indirect) {
                    Some(h) => h,
                    None => break,
                }
            };

            let start_tsc = rdtsc();
            *slot = Some(BenchInflight {
                start_tsc,
                head,
                io_req,
            });
            current_sector = current_sector.saturating_add((bench_cfg.request_size as u64) >> 9);
            batch_submitted += 1;
        }

        if batch_submitted == 0 {
            break;
        }

        // === Phase 2: Notify once for the entire batch ===
        {
            let vq = bench_queue.queue.lock().await;
            vq.notify(inner.notify_base, inner.notify_off_multiplier);
        }

        // === Phase 3: Wait for ALL submitted requests to complete ===
        let mut batch_completed = 0usize;
        while batch_completed < batch_submitted {
            // Wait for the device to signal completions
            if use_interrupts {
                if let Some(irq_handle) = unsafe { &*bench_queue.irq_handle.get() } {
                    let _guard = WaitTasksGuard::new(&bench_queue.waiting_tasks);

                    let t0 = rdtsc();
                    let wait_result = irq_handle.wait(meta).await;
                    let t1 = rdtsc();

                    irq_wait_wall_cycles =
                        irq_wait_wall_cycles.saturating_add(t1.saturating_sub(t0));

                    if !irq_wait_ok(wait_result) {
                        return Err(DriverStatus::DeviceError);
                    }
                } else {
                    spin_loop();
                }
            } else {
                // Polling mode: spin until something appears in the used ring
                while !bench_queue.has_pending_used() {
                    spin_loop();
                }
            }

            // Drain and reap whatever completed
            bench_queue.drain_used_to_completions_lockfree();

            for slot in slots.iter_mut().take(batch_submitted) {
                let Some(s) = slot.take() else { continue };

                let len_opt = bench_queue.take_completion(s.head);
                if len_opt.is_none() {
                    *slot = Some(s);
                    continue;
                }

                let end_tsc = rdtsc();

                if s.io_req.status() != VIRTIO_BLK_S_OK {
                    bench_queue.defer_free_chain(s.head);
                    return Err(DriverStatus::DeviceError);
                }

                bench_queue.defer_free_chain(s.head);
                lat_samples.push(end_tsc.saturating_sub(s.start_tsc));

                batch_completed += 1;
                completed += 1;
            }
        }
    }

    let run_end_tsc = rdtsc();

    result.request_count = lat_samples.len() as u32;
    result.total_time_cycles = run_end_tsc.saturating_sub(run_start_tsc);
    result.total_cycles = result.total_time_cycles;

    if result.total_time_cycles != 0 {
        let pct = (irq_wait_wall_cycles as f64) * 100.0 / (result.total_time_cycles as f64);
        result.idle_pct = pct.clamp(0.0, 100.0);
    } else {
        result.idle_pct = 0.0;
    }

    if !lat_samples.is_empty() {
        let sum_lat: u64 = lat_samples.iter().copied().sum();
        lat_samples.sort_unstable();

        result.max_cycles = *lat_samples.last().unwrap_or(&0);
        result.min_cycles = *lat_samples.first().unwrap_or(&0);
        result.avg_cycles = sum_lat / lat_samples.len() as u64;

        let p50i = percentile_index_permille(lat_samples.len(), 500);
        let p99i = percentile_index_permille(lat_samples.len(), 990);
        let p999i = percentile_index_permille(lat_samples.len(), 999);

        result.p50_cycles = lat_samples[p50i];
        result.p99_cycles = lat_samples[p99i];
        result.p999_cycles = lat_samples[p999i];
    } else {
        result.min_cycles = 0;
    }

    Ok(result)
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
