use crate::blk::{SubmitRequestError, VIRTIO_BLK_T_FLUSH, VIRTIO_BLK_T_IN, VIRTIO_BLK_T_OUT};
use crate::dev_ext::{ChildExt, DevExt, DevExtInner, QueueState};
use crate::outstanding::{
    PendingBlockOp, PendingOpBatch, PendingOpLease, PendingOpPool, SubmittedCompletion,
    SubmittedCompletionBatch, VIRTIO_QUEUE_BATCH_LIMIT,
};
use crate::{
    IOCTL_BLOCK_FLUSH, SubmitTasksGuard, check_blk_status, drain_queue_completions,
    map_request_buffer, wait_completion_hybrid,
};
use alloc::format;
use alloc::sync::Arc;
use core::hint::{cold_path, unlikely};
use core::sync::atomic::{AtomicPtr, Ordering};
use kernel_api::benchmark::{
    BENCH_FLAG_IRQ, BENCH_FLAG_POLL, BENCH_FLAG_REQUEST, BenchSweepBothResult, BenchSweepParams,
    BenchSweepResult,
};
use kernel_api::device::DeviceObject;
use kernel_api::dma::dma::IoBuffer;
use kernel_api::dma::dma::IoBufferAccess;
use kernel_api::error::{
    DriverErrorKind, ErrorKind, KernelError, ResultErrorContext, error, error_with_message,
};
use kernel_api::kernel_types::dma::{FromDevice, IoBufferDmaSegment, ToDevice};
use kernel_api::kernel_types::io::{DeviceControlHandler, DeviceFlush, DeviceRead, DeviceWrite};
use kernel_api::pnp::DriverStep;
use kernel_api::request::{DeviceControl, Flush, Read, Write};
use kernel_api::request_handler;

pub(crate) struct VirtioPdoIo;

impl DeviceRead for VirtioPdoIo {
    #[request_handler]
    async fn handler<'req, 'data, 'b>(
        pdo: &Arc<DeviceObject>,
        req: &'b mut Read<'data>,
    ) -> Result<DriverStep, kernel_api::error::KernelError> {
        virtio_pdo_read_impl(pdo, req).await
    }
}

impl DeviceWrite for VirtioPdoIo {
    #[request_handler]
    async fn handler<'req, 'data, 'b>(
        pdo: &Arc<DeviceObject>,
        req: &'b mut Write<'data>,
    ) -> Result<DriverStep, kernel_api::error::KernelError> {
        virtio_pdo_write_impl(pdo, req).await
    }
}

impl DeviceFlush for VirtioPdoIo {
    #[request_handler]
    async fn handler<'req, 'b>(
        pdo: &Arc<DeviceObject>,
        req: &'b mut Flush,
    ) -> Result<DriverStep, kernel_api::error::KernelError> {
        virtio_pdo_flush_impl(pdo, req).await
    }
}

impl DeviceControlHandler for VirtioPdoIo {
    #[request_handler]
    async fn handler<'req, 'data, 'b>(
        pdo: &Arc<DeviceObject>,
        req: &'b mut DeviceControl<'data>,
    ) -> Result<DriverStep, kernel_api::error::KernelError> {
        Err(kernel_api::error::error(
            kernel_api::error::DriverErrorKind::NotImplemented,
        ))
        //virtio_pdo_ioctl_impl(pdo, req).await
    }
}

async fn submit_virtio_no_data_request(
    inner: &DevExtInner,
    qs: &QueueState,
    req_type: u32,
    operation: &str,
) -> Result<(), KernelError> {
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
                    unsafe { vq.notify(inner.notify_base, inner.notify_off_multiplier) };
                    false
                }
                Err(SubmitRequestError::TooManyDataSegments) => {
                    cold_path();
                    return Err(error_with_message(
                        DriverErrorKind::DeviceError,
                        format_args!("virtio-blk: {operation} request has too many DMA segments"),
                    ));
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
        Ok(device_status) => check_blk_status(operation, device_status),
        Err(_) => Err(error_with_message(
            DriverErrorKind::DeviceError,
            format_args!(
                "virtio-blk: {operation} failed: completion canceled before device status"
            ),
        )),
    }
}

async fn flush_virtio_cache(pdo: &Arc<DeviceObject>) -> Result<(), KernelError> {
    let (_parent, inner) = match get_parent_inner(pdo) {
        Ok(v) => v,
        Err(s) => {
            cold_path();
            return Err(error(s)).with_context(|| "locating the virtio block device for flush");
        }
    };

    if unlikely(!inner.flush_supported) {
        cold_path();
        return Err(error(DriverErrorKind::NotImplemented))
            .with_context(|| "flushing a virtio block device without flush support");
    }

    let queue_idx = inner.select_queue();
    let qs = inner.get_queue(queue_idx);
    submit_virtio_no_data_request(&inner, qs, VIRTIO_BLK_T_FLUSH, "flush").await
}

fn get_parent_inner(
    pdo: &Arc<DeviceObject>,
) -> Result<(Arc<DeviceObject>, Arc<DevExtInner>), DriverErrorKind> {
    let cdx = pdo
        .try_devext::<ChildExt>()
        .map_err(|_| DriverErrorKind::NoSuchDevice)?;
    let parent = cdx
        .parent_device
        .upgrade()
        .ok_or(DriverErrorKind::NoSuchDevice)?;
    let dx = parent
        .try_devext::<DevExt>()
        .map_err(|_| DriverErrorKind::NoSuchDevice)?;
    let inner = dx
        .inner
        .get()
        .ok_or(DriverErrorKind::DeviceNotReady)?
        .clone();

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
    buffer: &IoBuffer<'_, '_, D>,
    byte_offset: usize,
    remaining_len: usize,
) -> Result<usize, DriverErrorKind>
where
    D: IoBufferAccess,
{
    let mut desc_count = 0usize;
    let mut bytes = 0usize;
    let mut best = 0usize;

    let segments = DmaSegmentByteWindow::new(buffer.dma_segments(), byte_offset, remaining_len);

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
                .ok_or(DriverErrorKind::InvalidParameter)?;
        }

        bytes = bytes
            .checked_add(seg_len)
            .ok_or(DriverErrorKind::InvalidParameter)?;

        if bytes.is_multiple_of(512) {
            best = bytes;
        }
    }

    if best == 0 {
        Err(DriverErrorKind::InvalidParameter)
    } else {
        Ok(best)
    }
}

#[derive(Clone, Copy)]
struct PendingBlockCursor {
    op_index: usize,
    byte_offset: usize,
    sector: u64,
}

impl PendingBlockCursor {
    fn new<D>(ops: &PendingOpBatch<'_, '_, D>) -> Self
    where
        D: IoBufferAccess + 'static,
    {
        Self {
            op_index: 0,
            byte_offset: 0,
            sector: if ops.is_empty() { 0 } else { ops.get(0).sector },
        }
    }

    #[inline]
    fn done<D>(&self, ops: &PendingOpBatch<'_, '_, D>) -> bool
    where
        D: IoBufferAccess + 'static,
    {
        self.op_index >= ops.len()
    }

    fn advance<D>(&mut self, ops: &PendingOpBatch<'_, '_, D>, chunk_len: usize)
    where
        D: IoBufferAccess + 'static,
    {
        self.byte_offset += chunk_len;
        self.sector += (chunk_len as u64) >> 9;

        if self.byte_offset == ops.get(self.op_index).len {
            self.op_index += 1;
            self.byte_offset = 0;

            if self.op_index < ops.len() {
                self.sector = ops.get(self.op_index).sector;
            }
        }
    }
}

#[inline]
fn notify_queue(inner: &DevExtInner, vq: &crate::virtqueue::Virtqueue) {
    unsafe { vq.notify(inner.notify_base, inner.notify_off_multiplier) };
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

async fn wait_for_pending_op_slot<'pool, 'data, D>(
    qs: &QueueState,
    pool: &'pool PendingOpPool<D>,
) -> PendingOpLease<'pool, 'data, D>
where
    D: IoBufferAccess + 'static,
{
    loop {
        if let Some(lease) = pool.alloc() {
            return lease;
        }

        let drained = drain_queue_completions(qs);
        if unlikely(drained == 0) {
            yield_once().await;
        }
    }
}

async fn wait_submitted_batch(
    qs: &QueueState,
    completions: &mut SubmittedCompletionBatch<'_, '_>,
    operation: &str,
) -> Result<(), KernelError> {
    let mut first_error = None;

    while let Some(submitted) = completions.pop() {
        let result =
            match wait_completion_hybrid(qs, submitted.completion, submitted.byte_len).await {
                Ok(device_status) => check_blk_status(operation, device_status),
                Err(_) => Err(error_with_message(
                    DriverErrorKind::DeviceError,
                    format_args!(
                        "virtio-blk: {operation} failed: completion canceled before device status"
                    ),
                )),
            };

        if first_error.is_none() {
            first_error = result.err();
        }
    }

    match first_error {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

async fn submit_block_ops_to_queue<D>(
    inner: &DevExtInner,
    qs: &QueueState,
    req_type: u32,
    ops: &PendingOpBatch<'_, '_, D>,
    is_write: bool,
    operation: &str,
) -> Result<(), KernelError>
where
    D: IoBufferAccess + 'static,
{
    if ops.is_empty() {
        return Ok(());
    }

    let mut cursor = PendingBlockCursor::new(ops);

    while !cursor.done(ops) {
        let mut completions = SubmittedCompletionBatch::new(&qs.submitted_completions);
        let mut submitted_any = false;
        let mut queue_or_slot_pressure = false;

        {
            let mut vq = qs.queue.write();

            while !cursor.done(ops) && completions.len() < VIRTIO_QUEUE_BATCH_LIMIT {
                if vq.num_free == 0 {
                    queue_or_slot_pressure = true;
                    break;
                }

                let Some(mut submitted_slot) = qs.submitted_completions.alloc() else {
                    cold_path();
                    queue_or_slot_pressure = true;
                    break;
                };

                let completion = match qs.completion_slots.alloc() {
                    Some(completion) => completion,
                    None => {
                        cold_path();
                        drop(submitted_slot);
                        queue_or_slot_pressure = true;
                        break;
                    }
                };

                let op = ops.get(cursor.op_index);
                let remaining = op.len - cursor.byte_offset;

                let chunk_len = match next_indirect_chunk_len(
                    &op.mapped_buffer,
                    cursor.byte_offset,
                    remaining,
                ) {
                    Ok(chunk_len) => chunk_len,
                    Err(status) => {
                        cold_path();
                        drop(completion);
                        drop(submitted_slot);

                        if submitted_any {
                            notify_queue(inner, &vq);
                            drop(vq);

                            wait_submitted_batch(qs, &mut completions, operation).await?;
                        }

                        return Err(error(status)).with_context(|| {
                                alloc::format!(
                                    "building virtio-blk {operation} descriptors at sector {} for {} bytes",
                                    cursor.sector,
                                    remaining
                                )
                            });
                    }
                };

                let segments = DmaSegmentByteWindow::new(
                    op.mapped_buffer.dma_segments(),
                    cursor.byte_offset,
                    chunk_len,
                );

                match qs
                    .arena
                    .submit_request(&mut vq, req_type, cursor.sector, segments, is_write)
                {
                    Ok(head) => {
                        qs.completion_slots.attach(head, &completion);
                        submitted_slot.write(SubmittedCompletion {
                            completion,
                            byte_len: chunk_len,
                        });
                        completions.push(submitted_slot);

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
                        drop(submitted_slot);
                        queue_or_slot_pressure = true;
                        break;
                    }
                    Err(SubmitRequestError::TooManyDataSegments) => {
                        cold_path();
                        drop(completion);
                        drop(submitted_slot);

                        if submitted_any {
                            notify_queue(inner, &vq);
                            drop(vq);

                            wait_submitted_batch(qs, &mut completions, operation).await?;
                        }

                        return Err(error_with_message(
                            DriverErrorKind::DeviceError,
                            format_args!(
                                "virtio-blk: {operation} request has too many DMA segments"
                            ),
                        ));
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

        wait_submitted_batch(qs, &mut completions, operation).await?;
    }

    Ok(())
}

fn validate_common_block_io(offset: u64, len: usize) -> Result<(), DriverErrorKind> {
    if unlikely(len == 0) {
        return Ok(());
    }

    if unlikely((offset & 0x1ff) != 0 || (len & 0x1ff) != 0) {
        cold_path();
        return Err(DriverErrorKind::InvalidParameter);
    }

    Ok(())
}

#[inline(always)]
pub(crate) async fn virtio_pdo_read_impl<'req, 'data, 'b>(
    pdo: &Arc<DeviceObject>,
    req: &'b mut Read<'data>,
) -> Result<DriverStep, kernel_api::error::KernelError> {
    let (parent, inner) = match get_parent_inner(pdo) {
        Ok(v) => v,
        Err(status) => {
            cold_path();
            return Err(error(status)).with_context(|| "locating the virtio block device for read");
        }
    };

    let queue_idx = inner.select_queue();
    let qs = inner.get_queue(queue_idx);

    let mut final_error = None;
    let mut pending = PendingOpBatch::new(&qs.read_ops);

    {
        let request = &mut *req;

        for read in request.iter_mut() {
            if pending.is_full() {
                let result =
                    submit_block_ops_to_queue(&inner, qs, VIRTIO_BLK_T_IN, &pending, false, "read")
                        .await;
                pending.clear();

                if let Err(err) = result {
                    final_error = Some(err);
                    break;
                }
            }

            let offset = read.offset;
            let len = read.len;

            if unlikely(len == 0) {
                continue;
            }

            match validate_common_block_io(offset, len) {
                Ok(()) => {}
                Err(error_kind) => {
                    final_error = Some(error(error_kind).with_context(alloc::format!(
                        "validating virtio-blk read at offset {offset} with length {len}: offset and length must be 512-byte aligned"
                    )));
                    break;
                }
            }

            match read.buffer.as_ref() {
                Some(buffer) if buffer.len() >= len => {}
                Some(_) | None => {
                    cold_path();
                    final_error = Some(error(DriverErrorKind::InvalidParameter).with_context(
                        alloc::format!(
                            "virtio-blk read at offset {offset} requested {len} bytes without a sufficiently large buffer"
                        ),
                    ));
                    break;
                }
            }

            let mut lease = match qs.read_ops.alloc() {
                Some(lease) => lease,
                None if !pending.is_empty() => {
                    let result = submit_block_ops_to_queue(
                        &inner,
                        qs,
                        VIRTIO_BLK_T_IN,
                        &pending,
                        false,
                        "read",
                    )
                    .await;
                    pending.clear();

                    if let Err(err) = result {
                        final_error = Some(err);
                        break;
                    }

                    match qs.read_ops.alloc() {
                        Some(lease) => lease,
                        None => wait_for_pending_op_slot(qs, &qs.read_ops).await,
                    }
                }
                None => wait_for_pending_op_slot(qs, &qs.read_ops).await,
            };

            let buffer = match read.buffer.take() {
                Some(buffer) => buffer,
                None => {
                    cold_path();
                    final_error = Some(error(DriverErrorKind::InvalidParameter).with_context(
                        alloc::format!(
                            "virtio-blk read buffer disappeared at offset {offset} with length {len}"
                        ),
                    ));
                    break;
                }
            };

            let mapped_buffer = match map_request_buffer(&parent, buffer) {
                Ok(buffer) => buffer,
                Err(error_kind) => {
                    cold_path();
                    final_error = Some(error(error_kind).with_context(alloc::format!(
                        "DMA-mapping virtio-blk read at offset {offset} with length {len}"
                    )));
                    break;
                }
            };

            lease.write(PendingBlockOp {
                sector: offset >> 9,
                len,
                mapped_buffer,
            });

            pending.push(lease);
        }
    }

    if final_error.is_none() && !pending.is_empty() {
        if let Err(err) =
            submit_block_ops_to_queue(&inner, qs, VIRTIO_BLK_T_IN, &pending, false, "read").await
        {
            final_error = Some(err);
        }
    }

    match final_error {
        Some(err) => Err(err).with_context(|| "processing a virtio-blk read request chain"),
        None => Ok(DriverStep::Complete),
    }
}
#[inline(always)]
pub(crate) async fn virtio_pdo_write_impl<'req, 'data, 'b>(
    pdo: &Arc<DeviceObject>,
    req: &'b mut Write<'data>,
) -> Result<DriverStep, kernel_api::error::KernelError> {
    let (parent, inner) = match get_parent_inner(pdo) {
        Ok(v) => v,
        Err(status) => {
            cold_path();
            return Err(error(status))
                .with_context(|| "locating the virtio block device for write");
        }
    };

    let queue_idx = inner.select_queue();
    let qs = inner.get_queue(queue_idx);

    let mut final_error = None;
    let mut pending = PendingOpBatch::new(&qs.write_ops);

    {
        let request = &mut *req;

        for write in request.iter_mut() {
            if pending.is_full() {
                let result = submit_block_ops_to_queue(
                    &inner,
                    qs,
                    VIRTIO_BLK_T_OUT,
                    &pending,
                    true,
                    "write",
                )
                .await;
                pending.clear();

                if let Err(err) = result {
                    final_error = Some(err);
                    break;
                }
            }

            let offset = write.offset;
            let len = write.len;

            if unlikely(len == 0) {
                continue;
            }

            match validate_common_block_io(offset, len) {
                Ok(()) => {}
                Err(error_kind) => {
                    final_error = Some(error(error_kind).with_context(alloc::format!(
                        "validating virtio-blk write at offset {offset} with length {len}: offset and length must be 512-byte aligned"
                    )));
                    break;
                }
            }

            match write.buffer.as_ref() {
                Some(buffer) if buffer.len() >= len => {}
                Some(_) | None => {
                    cold_path();
                    final_error = Some(error(DriverErrorKind::InvalidParameter).with_context(
                        alloc::format!(
                            "virtio-blk write at offset {offset} requested {len} bytes without a sufficiently large buffer"
                        ),
                    ));
                    break;
                }
            }

            let mut lease = match qs.write_ops.alloc() {
                Some(lease) => lease,
                None if !pending.is_empty() => {
                    let result = submit_block_ops_to_queue(
                        &inner,
                        qs,
                        VIRTIO_BLK_T_OUT,
                        &pending,
                        true,
                        "write",
                    )
                    .await;
                    pending.clear();

                    if let Err(err) = result {
                        final_error = Some(err);
                        break;
                    }

                    match qs.write_ops.alloc() {
                        Some(lease) => lease,
                        None => wait_for_pending_op_slot(qs, &qs.write_ops).await,
                    }
                }
                None => wait_for_pending_op_slot(qs, &qs.write_ops).await,
            };

            let buffer = match write.buffer.take() {
                Some(buffer) => buffer,
                None => {
                    cold_path();
                    final_error = Some(error(DriverErrorKind::InvalidParameter).with_context(
                        alloc::format!(
                            "virtio-blk write buffer disappeared at offset {offset} with length {len}"
                        ),
                    ));
                    break;
                }
            };

            let mapped_buffer = match map_request_buffer(&parent, buffer) {
                Ok(buffer) => buffer,
                Err(error_kind) => {
                    cold_path();
                    final_error = Some(error(error_kind).with_context(alloc::format!(
                        "DMA-mapping virtio-blk write at offset {offset} with length {len}"
                    )));
                    break;
                }
            };

            lease.write(PendingBlockOp {
                sector: offset >> 9,
                len,
                mapped_buffer,
            });

            pending.push(lease);
        }
    }

    if final_error.is_none() && !pending.is_empty() {
        if let Err(err) =
            submit_block_ops_to_queue(&inner, qs, VIRTIO_BLK_T_OUT, &pending, true, "write").await
        {
            final_error = Some(err);
        }
    }

    match final_error {
        Some(err) => Err(err).with_context(|| "processing a virtio-blk write request chain"),
        None => Ok(DriverStep::Complete),
    }
}
#[inline(always)]
pub(crate) async fn virtio_pdo_flush_impl<'req, 'b>(
    _pdo: &Arc<DeviceObject>,
    req: &'b mut Flush,
) -> Result<DriverStep, kernel_api::error::KernelError> {
    Ok(DriverStep::Complete)
}
