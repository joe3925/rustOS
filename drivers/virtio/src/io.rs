use crate::B_VIRTIO_QUEUE_NOTIFY;
use crate::C_VIRTIO_QUEUE_KICKS;
use crate::blk::{SubmitRequestError, VIRTIO_BLK_T_FLUSH, VIRTIO_BLK_T_IN, VIRTIO_BLK_T_OUT};
use crate::completion::CompletionToken;
use crate::dev_ext::{ChildExt, DevExt, DevExtInner, QueueState};
use crate::temp_benchmark::{
    IOCTL_BLOCK_BENCH_SWEEP, IOCTL_BLOCK_BENCH_SWEEP_BOTH, IOCTL_BLOCK_BENCH_SWEEP_POLLING,
    bench_sweep, bench_sweep_params, bench_sweep_params_request, sanitize_bench_params,
};
use crate::{
    IOCTL_BLOCK_FLUSH, SubmitTasksGuard, blk_status_to_driver_status, complete_req,
    drain_queue_completions, map_request_buffer, virtio_device_error, wait_completion_hybrid,
};
use alloc::{sync::Arc, vec::Vec};
use core::hint::{cold_path, unlikely};
use kernel_api::benchmark::{
    BENCH_FLAG_IRQ, BENCH_FLAG_POLL, BENCH_FLAG_REQUEST, BenchSweepBothResult, BenchSweepParams,
    BenchSweepResult,
};
use kernel_api::device::DeviceObject;
use kernel_api::disk_profile as dp;
use kernel_api::dma::dma::DmaMapped;
use kernel_api::dma::dma::IoBuffer;
use kernel_api::dma::dma::IoBufferAccess;
use kernel_api::dma::dma::PhysFramed;
use kernel_api::kernel_types::disk_profile::{C_FLUSH_BARRIER_REQUESTS, C_LOCK_ACQUISITIONS};
use kernel_api::kernel_types::dma::{FromDevice, IoBufferDmaSegment, ToDevice};
use kernel_api::kernel_types::io::{DeviceControlHandler, DeviceFlush, DeviceRead, DeviceWrite};
use kernel_api::pnp::DriverStep;
use kernel_api::request::{DeviceControl, Flush, Read, RequestHandle, Write};
use kernel_api::request_handler;
use kernel_api::status::DriverStatus;
pub(crate) struct VirtioPdoIo;

fn too_many_dma_segments_status(operation: &str) -> DriverStatus {
    virtio_device_error(alloc::format!(
        "virtio-blk: {operation} request has too many DMA segments"
    ))
}

impl DeviceRead for VirtioPdoIo {
    #[request_handler]
    async fn handler<'req, 'data, 'b>(
        pdo: &Arc<DeviceObject>,
        req: &'b mut RequestHandle<'req, Read<'data>>,
    ) -> DriverStep {
        virtio_pdo_read_impl(pdo, req).await
    }
}

impl DeviceWrite for VirtioPdoIo {
    #[request_handler]
    async fn handler<'req, 'data, 'b>(
        pdo: &Arc<DeviceObject>,
        req: &'b mut RequestHandle<'req, Write<'data>>,
    ) -> DriverStep {
        virtio_pdo_write_impl(pdo, req).await
    }
}

impl DeviceFlush for VirtioPdoIo {
    #[request_handler]
    async fn handler<'req, 'b>(
        pdo: &Arc<DeviceObject>,
        req: &'b mut RequestHandle<'req, Flush>,
    ) -> DriverStep {
        virtio_pdo_flush_impl(pdo, req).await
    }
}

impl DeviceControlHandler for VirtioPdoIo {
    #[request_handler]
    async fn handler<'req, 'data, 'b>(
        pdo: &Arc<DeviceObject>,
        req: &'b mut RequestHandle<'req, DeviceControl<'data>>,
    ) -> DriverStep {
        virtio_pdo_ioctl_impl(pdo, req).await
    }
}

async fn submit_virtio_no_data_request(
    inner: &DevExtInner,
    qs: &QueueState,
    req_type: u32,
    operation: &str,
) -> DriverStatus {
    if req_type == VIRTIO_BLK_T_FLUSH {
        dp::add_counter(C_FLUSH_BARRIER_REQUESTS, 1);
    }
    let completion = loop {
        let completion = match qs.completion_slots.alloc() {
            Some(completion) => completion,
            None => {
                cold_path();
                let drained = drain_queue_completions(qs);
                if unlikely(drained == 0) {
                    let mut done = false;
                    core::future::poll_fn(|cx| {
                        if done {
                            core::task::Poll::Ready(())
                        } else {
                            done = true;
                            cx.waker().wake_by_ref();
                            core::task::Poll::Pending
                        }
                    })
                    .await;
                }
                continue;
            }
        };
        let mut completion = Some(completion);
        let submitted = {
            dp::add_counter(C_LOCK_ACQUISITIONS, 1);
            let mut vq = qs.queue.write();
            match qs.arena.submit_request(
                &mut vq,
                req_type,
                0,
                core::iter::empty::<IoBufferDmaSegment>(),
                false,
            ) {
                Ok(h) => {
                    qs.completion_slots
                        .attach(h, completion.as_ref().expect("completion missing"));
                    let queue_full = vq.num_free == 0;
                    let _submit_guard = SubmitTasksGuard::new(
                        &qs.submitting_tasks,
                        &vq,
                        inner.notify_base,
                        inner.notify_off_multiplier,
                        queue_full,
                    );
                    true
                }
                Err(SubmitRequestError::QueueFull) => {
                    cold_path();
                    vq.notify(inner.notify_base, inner.notify_off_multiplier);
                    false
                }
                Err(SubmitRequestError::TooManyDataSegments) => {
                    cold_path();
                    return too_many_dma_segments_status(operation);
                }
            }
        };

        if submitted {
            break completion.take().expect("completion missing");
        }

        let mut done = false;
        core::future::poll_fn(|cx| {
            if done {
                core::task::Poll::Ready(())
            } else {
                done = true;
                cx.waker().wake_by_ref();
                core::task::Poll::Pending
            }
        })
        .await;
    };

    match wait_completion_hybrid(qs, completion, 0).await {
        Ok(device_status) => blk_status_to_driver_status(operation, device_status),
        Err(_) => virtio_device_error(alloc::format!(
            "virtio-blk: {operation} failed: completion canceled before device status"
        )),
    }
}

async fn flush_virtio_cache(pdo: &Arc<DeviceObject>) -> DriverStatus {
    let (_parent, inner) = match get_parent_inner(pdo) {
        Ok(v) => v,
        Err(s) => {
            cold_path();
            return s;
        }
    };

    if unlikely(!inner.flush_supported) {
        cold_path();
        return DriverStatus::NotImplemented;
    }

    let queue_idx = inner.select_queue();
    let qs = inner.get_queue(queue_idx);
    submit_virtio_no_data_request(&inner, qs, VIRTIO_BLK_T_FLUSH, "flush").await
}

fn get_parent_inner(
    pdo: &Arc<DeviceObject>,
) -> Result<(Arc<DeviceObject>, Arc<DevExtInner>), DriverStatus> {
    let cdx = pdo
        .try_devext::<ChildExt>()
        .map_err(|_| DriverStatus::NoSuchDevice)?;
    let parent = cdx
        .parent_device
        .upgrade()
        .ok_or(DriverStatus::NoSuchDevice)?;
    let dx = parent
        .try_devext::<DevExt>()
        .map_err(|_| DriverStatus::NoSuchDevice)?;
    let inner = dx.inner.get().ok_or(DriverStatus::DeviceNotReady)?.clone();
    Ok((parent, inner))
}
struct DmaSegmentByteWindow<I>
where
    I: Iterator<Item = IoBufferDmaSegment>,
{
    segments: I,
    skip_bytes: u64,
    remaining: u64,
}

impl<I> DmaSegmentByteWindow<I>
where
    I: Iterator<Item = IoBufferDmaSegment>,
{
    fn new(segments: I, byte_offset: usize, byte_len: usize) -> Self {
        Self {
            segments,
            skip_bytes: byte_offset as u64,
            remaining: byte_len as u64,
        }
    }
}

impl<I> Iterator for DmaSegmentByteWindow<I>
where
    I: Iterator<Item = IoBufferDmaSegment>,
{
    type Item = IoBufferDmaSegment;

    fn next(&mut self) -> Option<Self::Item> {
        while self.remaining != 0 {
            let seg = self.segments.next()?;
            let seg_len = seg.byte_len as u64;

            if seg_len == 0 {
                continue;
            }

            if self.skip_bytes >= seg_len {
                self.skip_bytes -= seg_len;
                continue;
            }

            let seg_offset = self.skip_bytes;
            self.skip_bytes = 0;

            let available = seg_len - seg_offset;
            let take = available.min(self.remaining);
            self.remaining -= take;

            return Some(IoBufferDmaSegment {
                dma_addr: seg.dma_addr + seg_offset,
                byte_len: take as u32,
                reserved: seg.reserved,
            });
        }

        None
    }
}

#[inline]
fn largest_sector_aligned_prefix(bytes_before: usize, seg_len: usize) -> Option<usize> {
    let rem = bytes_before & 0x1ff;

    if rem == 0 {
        let take = seg_len & !0x1ff;
        if take == 0 { None } else { Some(take) }
    } else {
        let first = 512 - rem;
        if seg_len < first {
            None
        } else {
            Some(first + ((seg_len - first) & !0x1ff))
        }
    }
}

fn next_indirect_chunk_len<D>(
    buffer: &IoBuffer<'_, '_, DmaMapped<PhysFramed>, D>,
    byte_offset: usize,
    remaining_len: usize,
) -> Result<usize, DriverStatus>
where
    D: IoBufferAccess,
{
    let mut desc_count = 0usize;
    let mut bytes = 0usize;
    let mut best = 0usize;

    let segments =
        DmaSegmentByteWindow::new(buffer.dma_segments().iter(), byte_offset, remaining_len);

    for seg in segments {
        if seg.byte_len == 0 {
            continue;
        }

        if desc_count == crate::blk::BLK_MAX_DATA_SEGMENTS_PER_REQUEST {
            break;
        }

        let seg_len = seg.byte_len as usize;
        desc_count += 1;

        if let Some(prefix) = largest_sector_aligned_prefix(bytes, seg_len) {
            best = bytes
                .checked_add(prefix)
                .ok_or(DriverStatus::InvalidParameter)?;
        }

        bytes = bytes
            .checked_add(seg_len)
            .ok_or(DriverStatus::InvalidParameter)?;

        if bytes.is_multiple_of(512) {
            best = bytes;
        }
    }

    if best == 0 {
        Err(DriverStatus::InvalidParameter)
    } else {
        Ok(best)
    }
}

const VIRTIO_QUEUE_BATCH_LIMIT: usize = 64;
struct SubmittedCompletion<'a> {
    completion: CompletionToken<'a>,
    byte_len: usize,
}
struct PendingBlockOp<'data, D>
where
    D: IoBufferAccess,
{
    sector: u64,
    len: usize,
    mapped_buffer: IoBuffer<'data, 'data, DmaMapped<PhysFramed>, D>,
}

#[derive(Clone, Copy)]
struct PendingBlockCursor {
    op_index: usize,
    byte_offset: usize,
    sector: u64,
}

impl PendingBlockCursor {
    fn new<D>(ops: &[PendingBlockOp<'_, D>]) -> Self
    where
        D: IoBufferAccess,
    {
        Self {
            op_index: 0,
            byte_offset: 0,
            sector: ops.first().map(|op| op.sector).unwrap_or(0),
        }
    }

    #[inline]
    fn done<D>(&self, ops: &[PendingBlockOp<'_, D>]) -> bool
    where
        D: IoBufferAccess,
    {
        self.op_index >= ops.len()
    }

    fn advance<D>(&mut self, ops: &[PendingBlockOp<'_, D>], chunk_len: usize)
    where
        D: IoBufferAccess,
    {
        self.byte_offset += chunk_len;
        self.sector += (chunk_len as u64) >> 9;

        if self.byte_offset == ops[self.op_index].len {
            self.op_index += 1;
            self.byte_offset = 0;

            if self.op_index < ops.len() {
                self.sector = ops[self.op_index].sector;
            }
        }
    }
}

#[inline]
fn notify_queue(inner: &DevExtInner, vq: &crate::virtqueue::Virtqueue) {
    dp::add_counter(C_VIRTIO_QUEUE_KICKS, 1);

    let profile_start = dp::timestamp_ns();
    vq.notify(inner.notify_base, inner.notify_off_multiplier);
    dp::add_elapsed(B_VIRTIO_QUEUE_NOTIFY, profile_start);
}

async fn yield_once() {
    let mut done = false;

    core::future::poll_fn(|cx| {
        if done {
            core::task::Poll::Ready(())
        } else {
            done = true;
            cx.waker().wake_by_ref();
            core::task::Poll::Pending
        }
    })
    .await;
}

async fn wait_submitted_batch(
    qs: &QueueState,
    completions: Vec<SubmittedCompletion<'_>>,
    operation: &str,
) -> DriverStatus {
    let mut final_status = DriverStatus::Success;

    for submitted in completions {
        let status =
            match wait_completion_hybrid(qs, submitted.completion, submitted.byte_len).await {
                Ok(device_status) => blk_status_to_driver_status(operation, device_status),
                Err(_) => virtio_device_error(alloc::format!(
                    "virtio-blk: {operation} failed: completion canceled before device status"
                )),
            };

        if final_status == DriverStatus::Success && status != DriverStatus::Success {
            final_status = status;
        }
    }

    final_status
}

async fn submit_block_ops_to_queue<D>(
    inner: &DevExtInner,
    qs: &QueueState,
    req_type: u32,
    ops: &[PendingBlockOp<'_, D>],
    is_write: bool,
    operation: &str,
) -> DriverStatus
where
    D: IoBufferAccess,
{
    if ops.is_empty() {
        return DriverStatus::Success;
    }

    let mut cursor = PendingBlockCursor::new(ops);

    while !cursor.done(ops) {
        let mut completions: Vec<SubmittedCompletion<'_>> = Vec::new();
        let mut submitted_any = false;
        let mut queue_or_slot_pressure = false;

        {
            dp::add_counter(C_LOCK_ACQUISITIONS, 1);

            let mut vq = qs.queue.write();

            while !cursor.done(ops) && completions.len() < VIRTIO_QUEUE_BATCH_LIMIT {
                if vq.num_free == 0 {
                    queue_or_slot_pressure = true;
                    break;
                }

                let op = &ops[cursor.op_index];
                let remaining = op.len - cursor.byte_offset;

                let chunk_len =
                    match next_indirect_chunk_len(&op.mapped_buffer, cursor.byte_offset, remaining)
                    {
                        Ok(chunk_len) => chunk_len,
                        Err(status) => {
                            cold_path();

                            if submitted_any {
                                notify_queue(inner, &vq);
                                drop(vq);

                                let wait_status =
                                    wait_submitted_batch(qs, completions, operation).await;

                                if wait_status != DriverStatus::Success {
                                    return wait_status;
                                }
                            }

                            return status;
                        }
                    };

                let completion = match qs.completion_slots.alloc() {
                    Some(completion) => completion,
                    None => {
                        cold_path();
                        queue_or_slot_pressure = true;
                        break;
                    }
                };

                let segments = DmaSegmentByteWindow::new(
                    op.mapped_buffer.dma_segments().iter(),
                    cursor.byte_offset,
                    chunk_len,
                );

                match qs
                    .arena
                    .submit_request(&mut vq, req_type, cursor.sector, segments, is_write)
                {
                    Ok(head) => {
                        qs.completion_slots.attach(head, &completion);
                        completions.push(SubmittedCompletion {
                            completion,
                            byte_len: chunk_len,
                        });

                        submitted_any = true;
                        cursor.advance(ops, chunk_len);

                        if vq.num_free == 0 {
                            queue_or_slot_pressure = true;
                            break;
                        }
                    }
                    Err(SubmitRequestError::QueueFull) => {
                        cold_path();
                        drop(completion);
                        queue_or_slot_pressure = true;
                        break;
                    }
                    Err(SubmitRequestError::TooManyDataSegments) => {
                        cold_path();
                        drop(completion);

                        if submitted_any {
                            notify_queue(inner, &vq);
                            drop(vq);

                            let wait_status =
                                wait_submitted_batch(qs, completions, operation).await;

                            if wait_status != DriverStatus::Success {
                                return wait_status;
                            }
                        }

                        return too_many_dma_segments_status(operation);
                    }
                }
            }

            if submitted_any || queue_or_slot_pressure {
                notify_queue(inner, &vq);
            }
        }

        if !submitted_any {
            let drained = drain_queue_completions(qs);
            if unlikely(drained == 0) {
                yield_once().await;
            }
            continue;
        }

        let status = wait_submitted_batch(qs, completions, operation).await;
        if status != DriverStatus::Success {
            return status;
        }
    }

    DriverStatus::Success
}

fn validate_common_block_io(offset: u64, len: usize) -> Result<(), DriverStatus> {
    if unlikely(len == 0) {
        return Ok(());
    }

    if unlikely((offset & 0x1ff) != 0 || (len & 0x1ff) != 0) {
        cold_path();
        return Err(DriverStatus::InvalidParameter);
    }

    Ok(())
}

#[inline(always)]
pub(crate) async fn virtio_pdo_read_impl<'req, 'data, 'b>(
    pdo: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'req, Read<'data>>,
) -> DriverStep {
    let (parent, inner) = match get_parent_inner(pdo) {
        Ok(v) => v,
        Err(status) => {
            cold_path();
            return complete_req(req, status);
        }
    };

    let queue_idx = inner.select_queue();
    let qs = inner.get_queue(queue_idx);

    let mut final_status = DriverStatus::Success;
    let mut pending: Vec<PendingBlockOp<'data, FromDevice>> = Vec::new();

    {
        let mut guard = req.write();

        for read in guard.body.iter_mut() {
            let offset = read.offset;
            let len = read.len;

            if unlikely(len == 0) {
                continue;
            }

            if let Err(status) = validate_common_block_io(offset, len) {
                final_status = status;
                break;
            }

            let Some(buffer) = read.buffer.take() else {
                cold_path();
                final_status = DriverStatus::InvalidParameter;
                break;
            };

            if unlikely(buffer.len() < len) {
                cold_path();
                final_status = DriverStatus::InvalidParameter;
                break;
            }

            let mapped_buffer = match map_request_buffer(&parent, buffer) {
                Ok(buffer) => buffer,
                Err(status) => {
                    cold_path();
                    final_status = status;
                    break;
                }
            };

            pending.push(PendingBlockOp {
                sector: offset >> 9,
                len,
                mapped_buffer,
            });
        }
    }

    if final_status != DriverStatus::Success {
        return complete_req(req, final_status);
    }

    final_status =
        submit_block_ops_to_queue(&inner, qs, VIRTIO_BLK_T_IN, &pending, false, "read").await;

    complete_req(req, final_status)
}

#[inline(always)]
pub(crate) async fn virtio_pdo_write_impl<'req, 'data, 'b>(
    pdo: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'req, Write<'data>>,
) -> DriverStep {
    let (parent, inner) = match get_parent_inner(pdo) {
        Ok(v) => v,
        Err(status) => {
            cold_path();
            return complete_req(req, status);
        }
    };

    let queue_idx = inner.select_queue();
    let qs = inner.get_queue(queue_idx);

    let mut final_status = DriverStatus::Success;
    let mut pending: Vec<PendingBlockOp<'data, ToDevice>> = Vec::new();

    {
        let mut guard = req.write();

        for write in guard.body.iter_mut() {
            let offset = write.offset;
            let len = write.len;

            if unlikely(len == 0) {
                continue;
            }

            if let Err(status) = validate_common_block_io(offset, len) {
                final_status = status;
                break;
            }

            let Some(buffer) = write.buffer.take() else {
                cold_path();
                final_status = DriverStatus::InvalidParameter;
                break;
            };

            if unlikely(buffer.len() < len) {
                cold_path();
                final_status = DriverStatus::InvalidParameter;
                break;
            }

            let mapped_buffer = match map_request_buffer(&parent, buffer) {
                Ok(buffer) => buffer,
                Err(status) => {
                    cold_path();
                    final_status = status;
                    break;
                }
            };

            pending.push(PendingBlockOp {
                sector: offset >> 9,
                len,
                mapped_buffer,
            });
        }
    }

    if final_status != DriverStatus::Success {
        return complete_req(req, final_status);
    }

    final_status =
        submit_block_ops_to_queue(&inner, qs, VIRTIO_BLK_T_OUT, &pending, true, "write").await;

    complete_req(req, final_status)
}
#[inline(always)]
pub(crate) async fn virtio_pdo_flush_impl<'req, 'b>(
    _pdo: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'req, Flush>,
) -> DriverStep {
    complete_req(req, DriverStatus::Success)
}
#[inline(always)]
pub(crate) async fn virtio_pdo_ioctl_impl<'req, 'data, 'b>(
    pdo: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'req, DeviceControl<'data>>,
) -> DriverStep {
    let code = req.read().body.code;

    match code {
        IOCTL_BLOCK_FLUSH => {
            let status = flush_virtio_cache(pdo).await;
            complete_req(req, status)
        }

        IOCTL_BLOCK_BENCH_SWEEP => {
            let (parent, inner) = match get_parent_inner(pdo) {
                Ok(v) => v,
                Err(s) => return complete_req(req, s),
            };

            match bench_sweep(&parent, &inner, true).await {
                Ok(r) => {
                    {
                        req.write().set_data_t(r);
                    }
                    complete_req(req, DriverStatus::Success)
                }
                Err(e) => complete_req(req, e),
            }
        }

        IOCTL_BLOCK_BENCH_SWEEP_POLLING => {
            let (parent, inner) = match get_parent_inner(pdo) {
                Ok(v) => v,
                Err(s) => return complete_req(req, s),
            };

            match bench_sweep(&parent, &inner, false).await {
                Ok(r) => {
                    {
                        req.write().set_data_t(r);
                    }
                    complete_req(req, DriverStatus::Success)
                }
                Err(e) => complete_req(req, e),
            }
        }

        IOCTL_BLOCK_BENCH_SWEEP_BOTH => {
            let (parent, inner) = match get_parent_inner(pdo) {
                Ok(v) => v,
                Err(s) => return complete_req(req, s),
            };

            let params_in = {
                req.data()
                    .read_only()
                    .view::<BenchSweepParams>()
                    .copied()
                    .unwrap_or_default()
            };
            let params_used = sanitize_bench_params(&inner, params_in);
            let request = if (params_used.flags & BENCH_FLAG_REQUEST) != 0 {
                match bench_sweep_params_request(pdo, &inner, &params_used).await {
                    Ok(r) => r,
                    Err(e) => return complete_req(req, e),
                }
            } else {
                BenchSweepResult::default()
            };

            let irq = if (params_used.flags & BENCH_FLAG_IRQ) != 0 {
                match bench_sweep_params(&parent, &inner, &params_used, true).await {
                    Ok(r) => r,
                    Err(e) => return complete_req(req, e),
                }
            } else {
                BenchSweepResult::default()
            };

            let poll = if (params_used.flags & BENCH_FLAG_POLL) != 0 {
                match bench_sweep_params(&parent, &inner, &params_used, false).await {
                    Ok(r) => r,
                    Err(e) => return complete_req(req, e),
                }
            } else {
                BenchSweepResult::default()
            };

            let qs0 = inner.get_queue(0);
            let qsz = qs0.vq_ref().size;

            let msix_enabled = inner.queues.iter().any(|q| q.msix_vector.is_some());

            let out = BenchSweepBothResult {
                params_used,
                irq,
                poll,
                request,
                queue_count: inner.queue_count as u16,
                queue0_size: qsz,
                indirect_enabled: if inner.indirect_desc_enabled { 1 } else { 0 },
                msix_enabled: if msix_enabled { 1 } else { 0 },
                _pad0: 0,
            };

            {
                req.write().set_data_t(out);
            }
            complete_req(req, DriverStatus::Success)
        }

        _ => complete_req(req, DriverStatus::NotImplemented),
    }
}
