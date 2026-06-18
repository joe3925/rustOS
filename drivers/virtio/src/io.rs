use alloc::sync::Arc;
use core::hint::{cold_path, unlikely};
use kernel_api::benchmark::{
    BENCH_FLAG_IRQ, BENCH_FLAG_POLL, BENCH_FLAG_REQUEST, BenchSweepBothResult, BenchSweepParams,
    BenchSweepResult,
};
use kernel_api::device::DeviceObject;
use kernel_api::kernel_types::dma::{FromDevice, IoBufferDmaSegment, ToDevice};
use kernel_api::kernel_types::io::{DeviceControlHandler, DeviceFlush, DeviceRead, DeviceWrite};
use kernel_api::pnp::DriverStep;
use kernel_api::request::{DeviceControl, Flush, Read, RequestHandle, Write};
use kernel_api::request_handler;
use kernel_api::status::DriverStatus;

use crate::blk::{VIRTIO_BLK_T_FLUSH, VIRTIO_BLK_T_IN, VIRTIO_BLK_T_OUT};
use crate::dev_ext::{ChildExt, DevExt, DevExtInner, QueueState};
use crate::temp_benchmark::{
    IOCTL_BLOCK_BENCH_SWEEP, IOCTL_BLOCK_BENCH_SWEEP_BOTH, IOCTL_BLOCK_BENCH_SWEEP_POLLING,
    bench_sweep, bench_sweep_params, bench_sweep_params_request, sanitize_bench_params,
};
use crate::{
    COMPLETION_POLL_TIME, IOCTL_BLOCK_FLUSH, SubmitTasksGuard, blk_status_to_driver_status,
    complete_req, drain_queue_completions, map_request_buffer, virtio_device_error,
    wait_completion_hybrid,
};

pub(crate) struct VirtioPdoIo;

impl DeviceRead for VirtioPdoIo {
    #[request_handler]
    async fn handler<'req, 'data, 'b>(
        pdo: &Arc<DeviceObject>,
        req: &'b mut RequestHandle<'req, Read<'data>>,
        buf_len: usize,
    ) -> kernel_api::pnp::DriverStep {
        virtio_pdo_read_impl(pdo, req, buf_len).await
    }
}

impl DeviceWrite for VirtioPdoIo {
    #[request_handler]
    async fn handler<'req, 'data, 'b>(
        pdo: &Arc<DeviceObject>,
        req: &'b mut RequestHandle<'req, Write<'data>>,
        buf_len: usize,
    ) -> kernel_api::pnp::DriverStep {
        virtio_pdo_write_impl(pdo, req, buf_len).await
    }
}

impl DeviceFlush for VirtioPdoIo {
    #[request_handler]
    async fn handler<'req, 'b>(
        pdo: &Arc<DeviceObject>,
        req: &'b mut RequestHandle<'req, Flush>,
    ) -> kernel_api::pnp::DriverStep {
        virtio_pdo_flush_impl(pdo, req).await
    }
}

impl DeviceControlHandler for VirtioPdoIo {
    #[request_handler]
    async fn handler<'req, 'data, 'b>(
        pdo: &Arc<DeviceObject>,
        req: &'b mut RequestHandle<'req, DeviceControl<'data>>,
    ) -> kernel_api::pnp::DriverStep {
        virtio_pdo_ioctl_impl(pdo, req).await
    }
}

async fn submit_virtio_no_data_request(
    inner: &DevExtInner,
    qs: &QueueState,
    req_type: u32,
    operation: &str,
) -> DriverStatus {
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
                Some(h) => {
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
                None => {
                    cold_path();
                    vq.notify(inner.notify_base, inner.notify_off_multiplier);
                    false
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

    match wait_completion_hybrid(qs, completion, COMPLETION_POLL_TIME).await {
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
#[inline(always)]
pub(crate) async fn virtio_pdo_read_impl<'req, 'data, 'b>(
    pdo: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'req, Read<'data>>,
    _buf_len: usize,
) -> DriverStep {
    let (parent, inner) = match get_parent_inner(pdo) {
        Ok(v) => v,
        Err(s) => {
            cold_path();
            return complete_req(req, s);
        }
    };
    let (offset, len) = {
        let r = req.read();
        (r.body.offset, r.body.len)
    };

    if unlikely(len == 0) {
        cold_path();
        return complete_req(req, DriverStatus::Success);
    }
    if unlikely((offset & 0x1FF) != 0 || (len & 0x1FF) != 0) {
        cold_path();
        return complete_req(req, DriverStatus::InvalidParameter);
    }

    let sector = offset >> 9;
    let queue_idx = inner.select_queue();
    let qs = inner.get_queue(queue_idx);

    let status = 'transfer: {
        let buffer = &req.read().body.buffer;
        if unlikely(buffer.len() < len) {
            cold_path();
            break 'transfer DriverStatus::InvalidParameter;
        }
        let mapped_buffer = match map_request_buffer::<FromDevice>(&parent, buffer) {
            Ok(b) => b,
            Err(status) => {
                cold_path();
                break 'transfer status;
            }
        };

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
                let segments = mapped_buffer.dma_segments();
                match qs
                    .arena
                    .submit_request(&mut vq, VIRTIO_BLK_T_IN, sector, segments, false)
                {
                    Some(h) => {
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
                    None => {
                        cold_path();
                        vq.notify(inner.notify_base, inner.notify_off_multiplier);
                        false
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

        match wait_completion_hybrid(qs, completion, COMPLETION_POLL_TIME).await {
            Ok(device_status) => blk_status_to_driver_status("read", device_status),
            Err(_) => {
                cold_path();
                virtio_device_error(
                    "virtio-blk: read failed: completion canceled before device status",
                )
            }
        }
    };

    complete_req(req, status)
}
#[inline(always)]
pub(crate) async fn virtio_pdo_write_impl<'req, 'data, 'b>(
    pdo: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'req, Write<'data>>,
    _buf_len: usize,
) -> DriverStep {
    let (parent, inner) = match get_parent_inner(pdo) {
        Ok(v) => v,
        Err(s) => {
            cold_path();
            return complete_req(req, s);
        }
    };

    let (offset, len) = {
        let r = req.read();
        (r.body.offset, r.body.len)
    };

    if unlikely(len == 0) {
        cold_path();
        return complete_req(req, DriverStatus::Success);
    }
    if unlikely((offset & 0x1FF) != 0 || (len & 0x1FF) != 0) {
        cold_path();
        return complete_req(req, DriverStatus::InvalidParameter);
    }

    let sector = offset >> 9;
    let queue_idx = inner.select_queue();
    let qs = inner.get_queue(queue_idx);

    let status = 'transfer: {
        let buffer = &req.read().body.buffer;
        if unlikely(buffer.len() < len) {
            cold_path();
            break 'transfer DriverStatus::InvalidParameter;
        }
        let mapped_buffer = match map_request_buffer::<ToDevice>(&parent, buffer) {
            Ok(b) => b,
            Err(status) => {
                cold_path();
                break 'transfer status;
            }
        };

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
                let segments = mapped_buffer.dma_segments();
                match qs
                    .arena
                    .submit_request(&mut vq, VIRTIO_BLK_T_OUT, sector, segments, true)
                {
                    Some(h) => {
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
                    None => {
                        cold_path();
                        vq.notify(inner.notify_base, inner.notify_off_multiplier);
                        false
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

        match wait_completion_hybrid(qs, completion, COMPLETION_POLL_TIME).await {
            Ok(device_status) => blk_status_to_driver_status("write", device_status),
            Err(_) => {
                cold_path();
                virtio_device_error(
                    "virtio-blk: write failed: completion canceled before device status",
                )
            }
        }
    };

    complete_req(req, status)
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
