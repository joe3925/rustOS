use crate::blk::{VIRTIO_BLK_S_OK, VIRTIO_BLK_T_IN};
use crate::dev_ext::{DevExtInner, QueueState};
use crate::{SubmitTasksGuard, drain_queue_completions, rdtsc};
use alloc::{sync::Arc, vec::Vec};
use core::future::Future;
use core::hint::spin_loop;
use core::pin::Pin;
use core::task::Poll;
use futures_channel::oneshot;
use kernel_api::benchmark::{
    BENCH_PARAMS_VERSION_1, BenchLevelResult, BenchSweepParams, BenchSweepResult,
};
use kernel_api::device::DeviceObject;
use kernel_api::kernel_types::dma::{
    Described, DmaMapped, DmaMappingStrategy, FromDevice, IOBUFFER_INLINE_PAGE_CAPACITY,
    IOBUFFER_PAGE_SIZE, IoBuffer, IoBufferDmaSegment,
};
use kernel_api::memory::{
    PageTableFlags, allocate_auto_kernel_range_mapped_contiguous, deallocate_kernel_range,
    unmap_range,
};
use kernel_api::println;
use kernel_api::status::DriverStatus;
use kernel_api::x86_64::VirtAddr;
pub const IOCTL_BLOCK_BENCH_SWEEP: u32 = 0xB000_8002;
pub const IOCTL_BLOCK_BENCH_SWEEP_POLLING: u32 = 0xB000_8003;

pub const IOCTL_BLOCK_BENCH_SWEEP_BOTH: u32 = 0xB000_8004;

struct BenchConfig {
    request_size: u32,
    requests_per_run: u32,
    max_queue_inflight: u16,
}

impl BenchConfig {
    fn from_inner_params(
        inner: &DevExtInner,
        params: &BenchSweepParams,
    ) -> Result<Self, DriverStatus> {
        let request_size = (params.request_size.max(512) & !511)
            .min(bench_max_request_size(inner))
            .max(512);

        if params.start_sector >= inner.capacity {
            return Err(DriverStatus::InvalidParameter);
        }

        let available_bytes = inner
            .capacity
            .saturating_sub(params.start_sector)
            .saturating_mul(512);
        if available_bytes < request_size as u64 {
            return Err(DriverStatus::InvalidParameter);
        }

        let max_q = bench_max_inflight_queue0(inner);
        let requested_inflight = if params.max_inflight == 0 {
            max_q as u16
        } else {
            params.max_inflight
        };
        let max_queue_inflight = requested_inflight.min(max_q as u16).max(1);

        let total_bytes = params
            .total_bytes
            .max(request_size as u64)
            .min(available_bytes);
        let requests_per_run = (total_bytes / request_size as u64)
            .max(1)
            .min(u32::MAX as u64) as u32;

        Ok(Self {
            request_size,
            requests_per_run,
            max_queue_inflight,
        })
    }
}

fn bench_max_request_size(inner: &DevExtInner) -> u32 {
    let q0 = inner.get_queue(0);
    let dma_max = (IOBUFFER_INLINE_PAGE_CAPACITY * IOBUFFER_PAGE_SIZE) as u32;
    (q0.max_request_bytes.min(dma_max).max(512)) & !511
}

fn bench_max_inflight_queue0(inner: &DevExtInner) -> usize {
    let q0 = inner.get_queue(0);
    (q0.vq_ref().size as usize).max(1)
}

struct BenchDmaBuffer {
    base_va: VirtAddr,
    alloc_bytes: usize,
    mapped: Option<IoBuffer<'static, DmaMapped, FromDevice>>,
}

impl BenchDmaBuffer {
    fn new_read(parent: &Arc<DeviceObject>, byte_len: u32) -> Result<Self, DriverStatus> {
        let byte_len = byte_len as usize;
        let alloc_bytes = byte_len.div_ceil(IOBUFFER_PAGE_SIZE) * IOBUFFER_PAGE_SIZE;
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        let base_va = allocate_auto_kernel_range_mapped_contiguous(alloc_bytes as u64, flags)
            .map_err(|_| DriverStatus::InsufficientResources)?;

        unsafe {
            core::ptr::write_bytes(base_va.as_u64() as *mut u8, 0, alloc_bytes);
        }

        let slice =
            unsafe { core::slice::from_raw_parts_mut(base_va.as_u64() as *mut u8, byte_len) };
        let described = IoBuffer::<Described, FromDevice>::new(slice);
        let mapped = match kernel_api::dma::map_buffer(
            parent,
            described,
            DmaMappingStrategy::SingleContiguous,
        ) {
            Ok(mapped) => mapped,
            Err((described, _)) => {
                drop(described);
                unsafe { unmap_range(base_va, alloc_bytes as u64) };
                deallocate_kernel_range(base_va, alloc_bytes as u64);
                return Err(DriverStatus::InsufficientResources);
            }
        };

        Ok(Self {
            base_va,
            alloc_bytes,
            mapped: Some(mapped),
        })
    }

    fn dma_segments(&self) -> &[IoBufferDmaSegment] {
        self.mapped
            .as_ref()
            .expect("virtio benchmark DMA buffer used after destroy")
            .dma_segments()
    }

    fn destroy(&mut self) {
        if let Some(mapped) = self.mapped.take() {
            let described = kernel_api::dma::unmap_buffer(mapped);
            drop(described);
        }

        if self.alloc_bytes == 0 {
            return;
        }

        unsafe { unmap_range(self.base_va, self.alloc_bytes as u64) };
        deallocate_kernel_range(self.base_va, self.alloc_bytes as u64);
        self.base_va = VirtAddr::new(0);
        self.alloc_bytes = 0;
    }
}

impl Drop for BenchDmaBuffer {
    fn drop(&mut self) {
        self.destroy();
    }
}

struct BenchInflight {
    start_tsc: u64,
    rx: oneshot::Receiver<u8>,
    _buffer: BenchDmaBuffer,
}

fn benchmark_device_error(message: &'static str) -> DriverStatus {
    DriverStatus::device_error(message)
}

fn benchmark_status_error(status: u8) -> DriverStatus {
    DriverStatus::device_error(alloc::format!(
        "virtio-blk: benchmark read failed with device status {status:#x}"
    ))
}

fn submit_bench_read(
    parent: &Arc<DeviceObject>,
    inner: &DevExtInner,
    bench_queue: &QueueState,
    sector: u64,
    request_size: u32,
) -> Result<Option<BenchInflight>, DriverStatus> {
    let dma_buffer = BenchDmaBuffer::new_read(parent, request_size)?;
    let (tx, rx) = oneshot::channel::<u8>();
    let mut tx = Some(tx);
    let mut start_tsc = 0u64;

    let submitted = {
        let mut vq = bench_queue.queue.write();
        match bench_queue.arena.submit_request(
            &mut vq,
            VIRTIO_BLK_T_IN,
            sector,
            dma_buffer.dma_segments(),
            false,
        ) {
            Some(head) => {
                *bench_queue.completion_slots[head as usize].lock() = tx.take();
                let queue_full = vq.num_free == 0;
                let _submit_guard = SubmitTasksGuard::new(
                    &bench_queue.submitting_tasks,
                    &vq,
                    inner.notify_base,
                    inner.notify_off_multiplier,
                    queue_full,
                );
                start_tsc = rdtsc();
                true
            }
            None => {
                vq.notify(inner.notify_base, inner.notify_off_multiplier);
                false
            }
        }
    };

    if submitted {
        Ok(Some(BenchInflight {
            start_tsc,
            rx,
            _buffer: dma_buffer,
        }))
    } else {
        Ok(None)
    }
}

fn record_completion(
    inflight: BenchInflight,
    status: u8,
    lat_samples: &mut Vec<u64>,
    completed: &mut u32,
    batch_completed: &mut usize,
    first_error: &mut Option<DriverStatus>,
) {
    let end_tsc = rdtsc();
    if status == VIRTIO_BLK_S_OK {
        lat_samples.push(end_tsc.saturating_sub(inflight.start_tsc));
    } else if first_error.is_none() {
        *first_error = Some(benchmark_status_error(status));
    }

    *completed = completed.saturating_add(1);
    *batch_completed = batch_completed.saturating_add(1);
    drop(inflight);
}

fn collect_ready_completions(
    slots: &mut [Option<BenchInflight>],
    batch_submitted: usize,
    lat_samples: &mut Vec<u64>,
    completed: &mut u32,
    batch_completed: &mut usize,
    first_error: &mut Option<DriverStatus>,
) -> Result<bool, DriverStatus> {
    let mut made_progress = false;
    for slot in slots.iter_mut().take(batch_submitted) {
        let status = match slot.as_mut() {
            Some(inflight) => match inflight.rx.try_recv() {
                Ok(Some(status)) => Some(status),
                Ok(None) => None,
                Err(_) => {
                    let _ = slot.take();
                    return Err(benchmark_device_error(
                        "virtio-blk: benchmark completion channel closed",
                    ));
                }
            },
            None => None,
        };

        if let Some(status) = status {
            let inflight = slot.take().expect("ready benchmark slot disappeared");
            record_completion(
                inflight,
                status,
                lat_samples,
                completed,
                batch_completed,
                first_error,
            );
            made_progress = true;
        }
    }

    Ok(made_progress)
}

async fn await_one_irq_completion(
    slots: &mut [Option<BenchInflight>],
    batch_submitted: usize,
) -> Result<(BenchInflight, u8), DriverStatus> {
    core::future::poll_fn(|cx| {
        let mut has_pending = false;
        for slot in slots.iter_mut().take(batch_submitted) {
            let poll_result = match slot.as_mut() {
                Some(inflight) => {
                    has_pending = true;
                    Pin::new(&mut inflight.rx).poll(cx)
                }
                None => continue,
            };

            match poll_result {
                Poll::Ready(Ok(status)) => {
                    let inflight = slot.take().expect("ready benchmark slot disappeared");
                    return Poll::Ready(Ok((inflight, status)));
                }
                Poll::Ready(Err(_)) => {
                    let _ = slot.take();
                    return Poll::Ready(Err(benchmark_device_error(
                        "virtio-blk: benchmark completion channel closed",
                    )));
                }
                Poll::Pending => {}
            }
        }

        if has_pending {
            Poll::Pending
        } else {
            Poll::Ready(Err(benchmark_device_error(
                "virtio-blk: benchmark waited with no pending requests",
            )))
        }
    })
    .await
}

async fn yield_once() {
    let mut done = false;
    core::future::poll_fn(|cx| {
        if done {
            Poll::Ready(())
        } else {
            done = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    })
    .await
}

async fn bench_reads_direct(
    parent: &Arc<DeviceObject>,
    inner: &DevExtInner,
    start_sector: u64,
    inflight: usize,
    bench_cfg: &BenchConfig,
    use_interrupts: bool,
) -> Result<BenchLevelResult, DriverStatus> {
    let mut result = BenchLevelResult::default();
    result.inflight = inflight as u32;

    let mut slots: Vec<Option<BenchInflight>> = Vec::with_capacity(inflight);
    slots.resize_with(inflight, || None);

    let bench_queue = inner.get_queue(0);
    let total_requests = bench_cfg.requests_per_run;
    let mut lat_samples: Vec<u64> = Vec::with_capacity(total_requests as usize);
    let mut current_sector = start_sector;
    let mut completed = 0u32;
    let mut irq_wait_wall_cycles = 0u64;
    let mut busy_cycles = 0u64;
    let run_start_tsc = rdtsc();

    while completed < total_requests {
        let batch_target = (total_requests - completed).min(inflight as u32) as usize;
        let mut batch_submitted = 0usize;

        while batch_submitted < batch_target {
            match submit_bench_read(
                parent,
                inner,
                bench_queue,
                current_sector,
                bench_cfg.request_size,
            )? {
                Some(inflight_req) => {
                    slots[batch_submitted] = Some(inflight_req);
                    current_sector =
                        current_sector.saturating_add((bench_cfg.request_size as u64) >> 9);
                    batch_submitted += 1;
                }
                None => {
                    let drained = drain_queue_completions(bench_queue);
                    if drained == 0 {
                        yield_once().await;
                    }
                    if batch_submitted == 0 {
                        continue;
                    }
                    break;
                }
            }
        }

        if batch_submitted == 0 {
            continue;
        }

        let mut batch_completed = 0usize;
        let mut first_error: Option<DriverStatus> = None;
        while batch_completed < batch_submitted {
            if collect_ready_completions(
                &mut slots,
                batch_submitted,
                &mut lat_samples,
                &mut completed,
                &mut batch_completed,
                &mut first_error,
            )? {
                continue;
            }

            if use_interrupts {
                let wait_start = rdtsc();
                let (inflight_req, status) =
                    await_one_irq_completion(&mut slots, batch_submitted).await?;
                let wait_end = rdtsc();
                irq_wait_wall_cycles =
                    irq_wait_wall_cycles.saturating_add(wait_end.saturating_sub(wait_start));

                record_completion(
                    inflight_req,
                    status,
                    &mut lat_samples,
                    &mut completed,
                    &mut batch_completed,
                    &mut first_error,
                );
            } else {
                let drained = drain_queue_completions(bench_queue);
                if drained == 0 {
                    bench_spin_chunk_and_count(&mut busy_cycles);
                }
            }
        }

        if let Some(error) = first_error {
            return Err(error);
        }
    }

    let run_end_tsc = rdtsc();

    result.request_count = lat_samples.len() as u32;
    result.total_time_cycles = run_end_tsc.saturating_sub(run_start_tsc);

    if result.total_time_cycles != 0 && use_interrupts {
        let pct = (irq_wait_wall_cycles as f64) * 100.0 / (result.total_time_cycles as f64);
        result.idle_pct = pct.clamp(0.0, 100.0);
    } else {
        result.idle_pct = 0.0;
    }

    if !lat_samples.is_empty() {
        let sum_lat = lat_samples
            .iter()
            .copied()
            .fold(0u64, |acc, sample| acc.saturating_add(sample));
        lat_samples.sort_unstable();

        result.total_cycles = sum_lat;
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
    parent: &Arc<DeviceObject>,
    inner: &DevExtInner,
    params: &BenchSweepParams,
    use_interrupts: bool,
) -> Result<BenchSweepResult, DriverStatus> {
    let bench_cfg = BenchConfig::from_inner_params(inner, params)?;

    let requested_inflight = if params.max_inflight == 0 {
        bench_cfg.max_queue_inflight as usize
    } else {
        params.max_inflight as usize
    };
    let max_inflight = requested_inflight
        .max(1)
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

        let level_result = bench_reads_direct(
            parent,
            inner,
            current_sector,
            level,
            &bench_cfg,
            use_interrupts,
        )
        .await?;

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
    p.request_size = p.request_size.min(bench_max_request_size(inner)).max(512) & !511;

    if p.total_bytes == 0 {
        p.total_bytes = p.request_size as u64;
    }
    if p.total_bytes < p.request_size as u64 {
        p.total_bytes = p.request_size as u64;
    }

    if p.start_sector >= inner.capacity {
        p.start_sector = 0;
    }

    let available_bytes = inner
        .capacity
        .saturating_sub(p.start_sector)
        .saturating_mul(512);
    if available_bytes >= p.request_size as u64 && p.total_bytes > available_bytes {
        p.total_bytes = available_bytes - (available_bytes % p.request_size as u64);
    }

    let max_auto = bench_max_inflight_queue0(inner) as u16;

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
    parent: &Arc<DeviceObject>,
    inner: &DevExtInner,
    use_interrupts: bool,
) -> Result<BenchSweepResult, DriverStatus> {
    let p = sanitize_bench_params(inner, BenchSweepParams::default());
    bench_sweep_params(parent, inner, &p, use_interrupts).await
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
