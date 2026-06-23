#![no_std]
#![no_main]
#![feature(const_option_ops)]
#![feature(const_trait_impl)]
#![feature(likely_unlikely)]
extern crate alloc;

mod blk;
mod completion;
mod dev_ext;
mod dma_region;
mod io;
mod outstanding;
mod pci;
mod temp_benchmark;
mod virtqueue;

use alloc::{sync::Arc, vec, vec::Vec};
use blk::{BlkIoSlots, VIRTIO_BLK_S_IOERR, VIRTIO_BLK_S_OK, VIRTIO_BLK_S_UNSUPP};
use core::cell::UnsafeCell;
use core::future::poll_fn;
use core::hint::{cold_path, likely, unlikely};
use core::panic::PanicInfo;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::{AtomicU16, AtomicU32, AtomicUsize, Ordering};
use core::task::Poll;
use core::time::Duration;
use dev_ext::{ChildExt, DevExt, DevExtInner, QueueSelectionStrategy, QueueState};
use io::VirtioPdoIo;
use kernel_api::device::{DeviceInit, DeviceObject, DriverObject};
use kernel_api::disk_profile as dp;
use kernel_api::dma::dma::DmaMapped;
use kernel_api::dma::dma::IoBufferAccess;
use kernel_api::dma::dma::PhysFramed;
use kernel_api::dma::dma::ToDevice;
use kernel_api::irq::IrqBorrowedHandleExt;
use kernel_api::irq::{
    IrqBorrowedHandle, IrqHandle, IrqHandleExt, irq_alloc_vector, irq_free_vector,
    irq_register_isr, irq_register_isr_gsi, irq_wait_closed,
};
use kernel_api::kernel_types::disk_profile::{
    B_INTERRUPT_COMPLETION_HANDLING, B_VIRTIO_QUEUE_NOTIFY, B_WAITING_FOR_COMPLETION,
    C_LOCK_ACQUISITIONS, C_VIRTIO_COMPLETIONS, C_VIRTIO_QUEUE_KICKS,
};
use kernel_api::kernel_types::dma::{Described, DmaMappingStrategy, IoBuffer, IoBufferState};
use kernel_api::kernel_types::io::DiskInfo;
use kernel_api::kernel_types::irq::{IRQ_RESCUE_WAKEUP, IrqFrame, IrqMeta};
use kernel_api::kernel_types::irq::{MsiRequest, MsiTarget};
use kernel_api::kernel_types::pnp::DeviceIds;
use kernel_api::kernel_types::request::RequestData;
use kernel_api::memory::{PhysAddr, VirtAddr, unmap_mmio_region};
use kernel_api::pnp::{
    DeviceRelationType, DriverStep, PnpMinorFunction, PnpRequest, PnpVtable, QueryIdType,
    driver_set_evt_device_add, pnp_create_child_devnode_and_pdo_with_init,
    pnp_forward_request_to_next_lower,
};
use kernel_api::request::{DeviceControl, Pnp, RequestHandle, RequestKind};
use kernel_api::runtime::{KernelStopwatch, cycle_counter, spawn_detached};
use kernel_api::status::DriverStatus;
use kernel_api::util::panic_common;
use kernel_api::{IOCTL_PCI_SETUP_MSIX, println, request_handler};
use spin::{Mutex, RwLock};
use virtqueue::Virtqueue;

static MOD_NAME: &str = option_env!("CARGO_PKG_NAME").unwrap_or(module_path!());

const PIC_BASE_VECTOR: u8 = 0x20;

const COMPLETION_POLL_MIN_NS: u64 = 2_000;
const COMPLETION_POLL_MAX_NS: u64 = 500_000;
const COMPLETION_FIT_MIN_SAMPLES: u64 = 32;
const COMPLETION_FIT_FALLBACK_BASE_NS: u64 = 5_000;
const COMPLETION_FIT_FALLBACK_NS_PER_KIB: u64 = 1_250;
const COMPLETION_FIT_MAX_SAMPLE_NS: u64 = 2_000_000;
const COMPLETION_FIT_MAX_X_KIB: u64 = 1024 * 1024;

static COMPLETION_FIT_COUNT: AtomicU64 = AtomicU64::new(0);
static COMPLETION_FIT_SUM_X: AtomicU64 = AtomicU64::new(0);
static COMPLETION_FIT_SUM_Y: AtomicU64 = AtomicU64::new(0);
static COMPLETION_FIT_SUM_XY: AtomicU64 = AtomicU64::new(0);
static COMPLETION_FIT_SUM_X2: AtomicU64 = AtomicU64::new(0);
#[inline]
fn completion_fit_x(byte_len: usize) -> u64 {
    if byte_len == 0 {
        return 0;
    }

    let kib = ((byte_len as u64).saturating_add(1023)) >> 10;
    kib.max(1).min(COMPLETION_FIT_MAX_X_KIB)
}

#[inline]
fn completion_fallback_poll_ns(byte_len: usize) -> Option<usize> {
    let x = completion_fit_x(byte_len);

    if x == 0 {
        return None;
    }

    let ns = COMPLETION_FIT_FALLBACK_BASE_NS
        .saturating_add(x.saturating_mul(COMPLETION_FIT_FALLBACK_NS_PER_KIB));

    if ns > COMPLETION_POLL_MAX_NS {
        None
    } else {
        Some(ns.max(COMPLETION_POLL_MIN_NS) as usize)
    }
}

#[inline]
fn record_completion_fit_sample(byte_len: usize, elapsed_ns: u64) {
    let x = completion_fit_x(byte_len);

    if x == 0 {
        return;
    }

    let y = elapsed_ns.min(COMPLETION_FIT_MAX_SAMPLE_NS);
    let xy = x.saturating_mul(y);
    let x2 = x.saturating_mul(x);

    COMPLETION_FIT_SUM_X.fetch_add(x, Ordering::Relaxed);
    COMPLETION_FIT_SUM_Y.fetch_add(y, Ordering::Relaxed);
    COMPLETION_FIT_SUM_XY.fetch_add(xy, Ordering::Relaxed);
    COMPLETION_FIT_SUM_X2.fetch_add(x2, Ordering::Relaxed);
    COMPLETION_FIT_COUNT.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub(crate) fn virtio_completion_should_poll(byte_len: usize) -> Option<usize> {
    let x = completion_fit_x(byte_len);

    if x == 0 {
        return None;
    }

    let n = COMPLETION_FIT_COUNT.load(Ordering::Relaxed);

    if n < COMPLETION_FIT_MIN_SAMPLES {
        return completion_fallback_poll_ns(byte_len);
    }

    let n = n as i128;
    let x = x as i128;
    let sum_x = COMPLETION_FIT_SUM_X.load(Ordering::Relaxed) as i128;
    let sum_y = COMPLETION_FIT_SUM_Y.load(Ordering::Relaxed) as i128;
    let sum_xy = COMPLETION_FIT_SUM_XY.load(Ordering::Relaxed) as i128;
    let sum_x2 = COMPLETION_FIT_SUM_X2.load(Ordering::Relaxed) as i128;

    let denom = n * sum_x2 - sum_x * sum_x;

    if denom <= 0 {
        return completion_fallback_poll_ns(byte_len);
    }

    let slope_num = n * sum_xy - sum_x * sum_y;
    let pred_num = sum_y * denom - slope_num * sum_x + slope_num * x * n;
    let pred_den = n * denom;

    if pred_num <= 0 || pred_den <= 0 {
        return completion_fallback_poll_ns(byte_len);
    }

    let ns = ((pred_num + (pred_den / 2)) / pred_den) as u64;
    // if (byte_len == 1024) {
    //     println!("1024 bytes: ns {}", ns)
    // }
    if ns > COMPLETION_POLL_MAX_NS {
        None
    } else {
        Some(ns.max(COMPLETION_POLL_MIN_NS) as usize)
    }
}
#[inline]
fn duration_to_cycle_counter_ticks(duration: Duration, frequency_hz: u64) -> u64 {
    if unlikely(frequency_hz == 0) {
        cold_path();
        return 0;
    }

    let nanos = duration.as_nanos();
    if unlikely(nanos == 0) {
        cold_path();
        return 0;
    }

    let cycles = nanos
        .saturating_mul(frequency_hz as u128)
        .saturating_add(999_999_999)
        / 1_000_000_000;
    cycles.min(u64::MAX as u128) as u64
}

pub(crate) async fn wait_completion_hybrid<F>(
    qs: &QueueState,
    completion: F,
    byte_len: usize,
) -> F::Output
where
    F: Future,
{
    let profile_start = dp::timestamp_ns();
    let mut completion = core::pin::pin!(completion);

    let Some(poll_ns) = virtio_completion_should_poll(byte_len) else {
        let result = completion.await;
        let elapsed_ns = dp::timestamp_ns().saturating_sub(profile_start);
        record_completion_fit_sample(byte_len, elapsed_ns);
        dp::add_elapsed(B_WAITING_FOR_COMPLETION, profile_start);
        return result;
    };

    let timer = KernelStopwatch::start();
    let spin_cycles = duration_to_cycle_counter_ticks(
        Duration::from_nanos(poll_ns as u64),
        timer.cycle_counter_frequency_hz(),
    );
    let start_cycles = timer.start_cycles();

    loop {
        drain_queue_completions(qs);

        if let Some(result) = poll_fn(|cx| match completion.as_mut().poll(cx) {
            Poll::Ready(result) => Poll::Ready(Some(result)),
            Poll::Pending => Poll::Ready(None),
        })
        .await
        {
            let elapsed_ns = dp::timestamp_ns().saturating_sub(profile_start);
            record_completion_fit_sample(byte_len, elapsed_ns);
            dp::add_elapsed(B_WAITING_FOR_COMPLETION, profile_start);
            return result;
        }

        if spin_cycles == 0 || cycle_counter().wrapping_sub(start_cycles) >= spin_cycles {
            break;
        }

        core::hint::spin_loop();
    }

    let result = completion.await;
    let elapsed_ns = dp::timestamp_ns().saturating_sub(profile_start);
    record_completion_fit_sample(byte_len, elapsed_ns);
    dp::add_elapsed(B_WAITING_FOR_COMPLETION, profile_start);
    result
}
// Request helpers
#[inline(always)]
pub(crate) fn complete_req<K: RequestKind>(
    _req: &mut RequestHandle<'_, K>,
    status: DriverStatus,
) -> DriverStep {
    DriverStep::complete(status)
}
#[inline(always)]
fn continue_req<K: RequestKind>(_req: &mut RequestHandle<'_, K>) -> DriverStep {
    DriverStep::Continue
}

pub(crate) fn virtio_device_error(message: impl Into<alloc::string::String>) -> DriverStatus {
    DriverStatus::DeviceError {
        message: message.into(),
    }
}

pub(crate) fn blk_status_to_driver_status(operation: &str, status: u8) -> DriverStatus {
    match status {
        VIRTIO_BLK_S_OK => DriverStatus::Success,
        VIRTIO_BLK_S_IOERR => virtio_device_error(alloc::format!(
            "virtio-blk: {operation} failed: device reported I/O error"
        )),
        VIRTIO_BLK_S_UNSUPP => virtio_device_error(alloc::format!(
            "virtio-blk: {operation} failed: request unsupported by device"
        )),
        other => virtio_device_error(alloc::format!(
            "virtio-blk: {operation} failed: unknown device status {other:#x}"
        )),
    }
}

pub(crate) fn map_request_buffer<'buffer, D>(
    device: &Arc<DeviceObject>,
    buffer: IoBuffer<'buffer, 'buffer, Described, D>,
) -> Result<IoBuffer<'buffer, 'buffer, DmaMapped<PhysFramed>, D>, DriverStatus>
where
    D: IoBufferAccess,
{
    let phys_framed = buffer
        .into_phys_framed()
        .map_err(|_| DriverStatus::InvalidParameter)?;

    kernel_api::dma::map_buffer(device, phys_framed, DmaMappingStrategy::SingleContiguous)
        .map_err(|_| DriverStatus::InsufficientResources)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    panic_common(MOD_NAME, info)
}

#[unsafe(no_mangle)]
pub extern "C" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    driver_set_evt_device_add(driver, virtio_device_add);
    DriverStatus::Success
}

pub extern "C" fn virtio_device_add(
    _driver: &Arc<DriverObject>,
    dev_init: &mut DeviceInit,
) -> DriverStep {
    let mut pnp_vt = PnpVtable::new();
    pnp_vt.set(PnpMinorFunction::StartDevice, virtio_pnp_start);
    pnp_vt.set(PnpMinorFunction::RemoveDevice, virtio_pnp_remove);
    pnp_vt.set(
        PnpMinorFunction::QueryDeviceRelations,
        virtio_pnp_query_devrels,
    );

    let init = DeviceInit::with_pnp(Some(pnp_vt));
    *dev_init = init;
    dev_init.set_dev_ext_from(DevExt::new());

    DriverStep::complete(DriverStatus::Success)
}

extern "C" fn virtio_isr(
    _vector: u8,
    _cpu: u32,
    _frame: &mut IrqFrame,
    handle: IrqBorrowedHandle,
    ctx: usize,
) -> bool {
    let isr_va = ctx as *const u8;
    let isr_status = unsafe { core::ptr::read_volatile(isr_va) };

    if likely(isr_status & 1 != 0) {
        handle.signal_one(IrqMeta {
            tag: 0,
            data: [0; 3],
        });
        true
    } else {
        cold_path();
        false
    }
}

extern "C" fn virtio_msix_isr(
    _vector: u8,
    _cpu: u32,
    _frame: &mut IrqFrame,
    handle: IrqBorrowedHandle,
    _ctx: usize,
) -> bool {
    handle.signal_one(IrqMeta {
        tag: 0,
        data: [0; 3],
    });

    true
}

async fn setup_msix_via_pci(
    dev: &Arc<DeviceObject>,
    vector: u8,
    platform_cpu_id: u8,
    table_index: u16,
) -> Result<(), DriverStatus> {
    let setup = MsiRequest::pci_msix(
        vector,
        MsiTarget::platform_cpu(platform_cpu_id as u32),
        table_index,
    );

    let mut req = RequestHandle::new(DeviceControl::new_t(IOCTL_PCI_SETUP_MSIX, setup));
    let status = pnp_forward_request_to_next_lower(dev.clone(), &mut req).await;

    if status == DriverStatus::Success {
        Ok(())
    } else {
        Err(status)
    }
}
#[request_handler]
async fn virtio_pnp_start<'req, 'data, 'b>(
    dev: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'req, Pnp<'data>>,
) -> DriverStep {
    let mut query_req = RequestHandle::new(Pnp {
        request: PnpRequest {
            minor_function: PnpMinorFunction::QueryResources,
            relation: DeviceRelationType::TargetDeviceRelation,
            id_type: QueryIdType::CompatibleIds,
            ids_out: Vec::new(),
            data_out: RequestData::empty(),
        },
    });
    let qr_status = pnp_forward_request_to_next_lower(dev.clone(), &mut query_req).await;
    if qr_status != DriverStatus::Success {
        println!("virtio-blk: QueryResources failed: {:?}", qr_status);
        return complete_req(req, qr_status);
    }

    let resources = {
        let r = query_req.read();
        let blob = r
            .body
            .request
            .data_out_ref()
            .view::<Vec<u8>>()
            .map(|v| v.as_slice())
            .unwrap_or(&[]);
        pci::parse_resources(blob)
    };
    let msix_cap = pci::find_msix_capability(&resources);

    let mapped_bars = pci::map_memory_bars(&resources);
    if mapped_bars.is_empty() {
        println!("virtio-blk: no memory BARs found");
        return complete_req(req, virtio_device_error("virtio-blk: no memory BARs found"));
    }

    let (cfg_phys, cfg_len) = match pci::find_config_space(&resources) {
        Some(v) => v,
        None => {
            println!("virtio-blk: no PCI config space resource");
            for &(_idx, va, sz) in &mapped_bars {
                let _ = unmap_mmio_region(va, sz);
            }
            return complete_req(
                req,
                virtio_device_error("virtio-blk: no PCI config space resource"),
            );
        }
    };

    let cfg_base = match kernel_api::memory::map_mmio_region(PhysAddr::new(cfg_phys), cfg_len) {
        Ok(va) => va,
        Err(_) => {
            println!("virtio-blk: failed to map PCI config space");
            for &(_idx, va, sz) in &mapped_bars {
                let _ = unmap_mmio_region(va, sz);
            }
            return complete_req(
                req,
                virtio_device_error("virtio-blk: failed to map PCI config space"),
            );
        }
    };

    let caps = match pci::parse_virtio_caps(cfg_base, &mapped_bars) {
        Some(c) => c,
        None => {
            println!("virtio-blk: failed to parse virtio PCI capabilities");
            let _ = unmap_mmio_region(cfg_base, cfg_len);
            for &(_idx, va, sz) in &mapped_bars {
                let _ = unmap_mmio_region(va, sz);
            }
            return complete_req(
                req,
                virtio_device_error("virtio-blk: failed to parse virtio PCI capabilities"),
            );
        }
    };

    let _ = unmap_mmio_region(cfg_base, cfg_len);

    let init_result = match blk::init_device(caps.common_cfg, caps.device_cfg) {
        Ok(r) => r,
        Err(message) => {
            println!(
                "virtio-blk: device init / feature negotiation failed: {}",
                message
            );
            for &(_idx, va, sz) in &mapped_bars {
                let _ = unmap_mmio_region(va, sz);
            }
            return complete_req(
                req,
                virtio_device_error(alloc::format!(
                    "virtio-blk: device init / feature negotiation failed: {message}"
                )),
            );
        }
    };

    let cpu_ids = kernel_api::irq::platform_cpu_ids();
    let cpu_count = cpu_ids.len().max(1);
    let target_queue_count = (init_result.num_queues as usize).min(cpu_count).max(1);

    let mut virtqueues: Vec<Virtqueue> = Vec::with_capacity(target_queue_count);
    for queue_idx in 0..target_queue_count {
        match Virtqueue::new(queue_idx as u16, caps.common_cfg, &dev) {
            Some(vq) => virtqueues.push(vq),
            None => {
                println!("virtio-blk: failed to create queue {}", queue_idx);
                break;
            }
        }
    }

    if virtqueues.is_empty() {
        println!("virtio-blk: no queues created");
        blk::reset_device(caps.common_cfg);
        for &(_idx, va, sz) in &mapped_bars {
            let _ = unmap_mmio_region(va, sz);
        }
        return complete_req(
            req,
            virtio_device_error(alloc::format!(
                "virtio-blk: no queues created; requested {target_queue_count}"
            )),
        );
    }

    let actual_queue_count = virtqueues.len();
    let mut msix_allocations: Vec<Option<(u8, IrqHandle, u16)>> = Vec::new();

    if msix_cap.is_some() {
        for queue_idx in 0..actual_queue_count {
            let vector = match irq_alloc_vector() {
                Some(v) => v,
                None => {
                    println!(
                        "virtio-blk: failed to allocate vector for queue {}",
                        queue_idx
                    );
                    break;
                }
            };

            let handle = match irq_register_isr(vector, virtio_msix_isr, 0) {
                Some(h) => h,
                None => {
                    let _ = irq_free_vector(vector);
                    println!("virtio-blk: failed to register ISR for queue {}", queue_idx);
                    break;
                }
            };

            let target_cpu = cpu_ids[queue_idx % cpu_count];
            let table_index = queue_idx as u16;

            match setup_msix_via_pci(&dev, vector, target_cpu, table_index).await {
                Ok(()) => {
                    unsafe {
                        pci::common_write_u16(
                            caps.common_cfg,
                            pci::COMMON_QUEUE_SELECT,
                            queue_idx as u16,
                        );
                        pci::common_write_u16(
                            caps.common_cfg,
                            pci::COMMON_QUEUE_MSIX_VECTOR,
                            table_index,
                        );
                    }

                    let readback = unsafe {
                        pci::common_read_u16(caps.common_cfg, pci::COMMON_QUEUE_MSIX_VECTOR)
                    };
                    if readback == 0xFFFF {
                        println!("virtio-blk: device rejected MSI-X for queue {}", queue_idx);
                        handle.unregister();
                        let _ = irq_free_vector(vector);
                        break;
                    }

                    msix_allocations.push(Some((vector, handle, table_index)));
                }
                Err(e) => {
                    println!(
                        "virtio-blk: MSI-X setup failed for queue {}: {:?}",
                        queue_idx, e
                    );
                    handle.unregister();
                    let _ = irq_free_vector(vector);
                    break;
                }
            }
        }

        if !msix_allocations.is_empty() {
            unsafe {
                pci::common_write_u16(caps.common_cfg, pci::COMMON_MSIX_CONFIG, 0);
            }
        }
    }

    let (final_queue_count, use_msix) =
        if msix_allocations.len() == actual_queue_count && !msix_allocations.is_empty() {
            (actual_queue_count, true)
        } else if msix_allocations.is_empty() {
            (1, false)
        } else {
            for vq in virtqueues.iter_mut().skip(msix_allocations.len()) {
                vq.destroy();
            }
            (msix_allocations.len().max(1), true)
        };

    virtqueues.truncate(final_queue_count);

    let line_irq_handle: Option<IrqHandle> = if !use_msix {
        if let Some(gsi) = pci::find_gsi(&resources) {
            if gsi < 64 {
                irq_register_isr_gsi(gsi as u8, virtio_isr, caps.isr_cfg.as_u64() as usize)
            } else {
                None
            }
        } else if let Some(line) = pci::find_interrupt_line(&resources) {
            if line < 16 {
                let vector = PIC_BASE_VECTOR + line;
                irq_register_isr(vector, virtio_isr, caps.isr_cfg.as_u64() as usize)
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    let mut queue_states: Vec<QueueState> = Vec::with_capacity(final_queue_count);
    let mut virtqueue_iter = virtqueues.into_iter();

    for i in 0..final_queue_count {
        let mut vq = virtqueue_iter
            .next()
            .expect("virtio-blk: virtqueue missing during init");

        let arena = match BlkIoSlots::new(vq.size as usize, &dev) {
            Some(a) => a,
            None => {
                println!(
                    "virtio-blk: failed to create slots for queue {} with size {}",
                    i, vq.size
                );

                for qs in queue_states.iter() {
                    if let Some(h) = unsafe { &*qs.irq_handle.get() } {
                        h.unregister();
                    }
                    if let Some(vec) = qs.msix_vector {
                        let _ = irq_free_vector(vec);
                    }
                    qs.queue
                        .try_write()
                        .expect("queue not locked during cleanup")
                        .destroy();
                }

                for alloc in msix_allocations.iter().skip(i) {
                    if let Some((vec, handle, _)) = alloc {
                        handle.unregister();
                        let _ = irq_free_vector(*vec);
                    }
                }

                vq.destroy();
                for mut remaining_vq in virtqueue_iter.by_ref() {
                    remaining_vq.destroy();
                }

                blk::reset_device(caps.common_cfg);
                for &(_idx, va, sz) in &mapped_bars {
                    let _ = unmap_mmio_region(va, sz);
                }
                return complete_req(req, DriverStatus::InsufficientResources);
            }
        };

        let (irq_handle, msix_vector, msix_table_index) = if use_msix && i < msix_allocations.len()
        {
            match msix_allocations[i].take() {
                Some((vec, handle, table_idx)) => (Some(handle), Some(vec), Some(table_idx)),
                None => (None, None, None),
            }
        } else if i == 0 && !use_msix {
            (line_irq_handle.clone(), None, None)
        } else {
            (None, None, None)
        };

        let vq_capacity = vq.size as usize;

        let completion_slots = match completion::CompletionTable::new(vq_capacity) {
            Some(slots) => slots,
            None => {
                println!(
                    "virtio-blk: failed to create completion slots for queue {} with size {}",
                    i, vq.size
                );

                for qs in queue_states.iter() {
                    if let Some(h) = unsafe { &*qs.irq_handle.get() } {
                        h.unregister();
                    }
                    if let Some(vec) = qs.msix_vector {
                        let _ = irq_free_vector(vec);
                    }
                    qs.queue
                        .try_write()
                        .expect("queue not locked during cleanup")
                        .destroy();
                }
                vq.destroy();
                for mut remaining_vq in virtqueue_iter.by_ref() {
                    remaining_vq.destroy();
                }
                for &(_idx, va, sz) in &mapped_bars {
                    let _ = unmap_mmio_region(va, sz);
                }
                return complete_req(
                    req,
                    virtio_device_error(alloc::format!(
                        "virtio-blk: failed to create completion slots for queue {i}"
                    )),
                );
            }
        };

        let read_ops = match outstanding::PendingOpPool::new(vq_capacity) {
            Some(pool) => pool,
            None => {
                println!(
                    "virtio-blk: failed to create read outstanding pool for queue {} with size {}",
                    i, vq.size
                );

                for qs in queue_states.iter() {
                    if let Some(h) = unsafe { &*qs.irq_handle.get() } {
                        h.unregister();
                    }
                    if let Some(vec) = qs.msix_vector {
                        let _ = irq_free_vector(vec);
                    }
                    qs.queue
                        .try_write()
                        .expect("queue not locked during cleanup")
                        .destroy();
                }
                vq.destroy();
                for mut remaining_vq in virtqueue_iter.by_ref() {
                    remaining_vq.destroy();
                }
                for &(_idx, va, sz) in &mapped_bars {
                    let _ = unmap_mmio_region(va, sz);
                }
                return complete_req(req, DriverStatus::InsufficientResources);
            }
        };

        let write_ops = match outstanding::PendingOpPool::new(vq_capacity) {
            Some(pool) => pool,
            None => {
                println!(
                    "virtio-blk: failed to create write outstanding pool for queue {} with size {}",
                    i, vq.size
                );

                for qs in queue_states.iter() {
                    if let Some(h) = unsafe { &*qs.irq_handle.get() } {
                        h.unregister();
                    }
                    if let Some(vec) = qs.msix_vector {
                        let _ = irq_free_vector(vec);
                    }
                    qs.queue
                        .try_write()
                        .expect("queue not locked during cleanup")
                        .destroy();
                }
                vq.destroy();
                for mut remaining_vq in virtqueue_iter.by_ref() {
                    remaining_vq.destroy();
                }
                for &(_idx, va, sz) in &mapped_bars {
                    let _ = unmap_mmio_region(va, sz);
                }
                return complete_req(req, DriverStatus::InsufficientResources);
            }
        };

        let submitted_completions = match outstanding::SubmittedCompletionPool::new(vq_capacity) {
            Some(pool) => pool,
            None => {
                println!(
                    "virtio-blk: failed to create submitted completion pool for queue {} with size {}",
                    i, vq.size
                );

                for qs in queue_states.iter() {
                    if let Some(h) = unsafe { &*qs.irq_handle.get() } {
                        h.unregister();
                    }
                    if let Some(vec) = qs.msix_vector {
                        let _ = irq_free_vector(vec);
                    }
                    qs.queue
                        .try_write()
                        .expect("queue not locked during cleanup")
                        .destroy();
                }
                vq.destroy();
                for mut remaining_vq in virtqueue_iter.by_ref() {
                    remaining_vq.destroy();
                }
                for &(_idx, va, sz) in &mapped_bars {
                    let _ = unmap_mmio_region(va, sz);
                }
                return complete_req(req, DriverStatus::InsufficientResources);
            }
        };

        let used_idx = vq.used_idx_ptr();

        queue_states.push(QueueState {
            queue: RwLock::new(vq),
            arena,
            irq_handle: UnsafeCell::new(irq_handle),
            msix_vector,
            msix_table_index,
            submitting_tasks: AtomicU32::new(0),
            use_indirect: init_result.indirect_desc_supported,
            completion_slots,
            read_ops,
            write_ops,
            submitted_completions,
            used_idx,
            last_drained_used_idx: AtomicU16::new(0),
        });
    }

    for (idx, qs) in queue_states.iter().enumerate() {
        unsafe {
            pci::common_write_u16(caps.common_cfg, pci::COMMON_QUEUE_SELECT, idx as u16);
        }
        let vq = qs.queue.try_write().expect("queue not locked during init");
        vq.enable(caps.common_cfg);
    }

    blk::set_driver_ok(caps.common_cfg);

    let status = unsafe { pci::common_read_u8(caps.common_cfg, pci::COMMON_DEVICE_STATUS) };
    if status & blk::VIRTIO_STATUS_FAILED != 0 || status & blk::VIRTIO_STATUS_DRIVER_OK == 0 {
        println!(
            "virtio-blk: device status bad after DRIVER_OK: status={:#x}",
            status
        );
        blk::reset_device(caps.common_cfg);
        for qs in queue_states.iter() {
            if let Some(h) = unsafe { &*qs.irq_handle.get() } {
                h.unregister();
            }
            if let Some(vec) = qs.msix_vector {
                let _ = irq_free_vector(vec);
            }
            qs.queue
                .try_write()
                .expect("queue not locked during cleanup")
                .destroy();
        }
        for &(_idx, va, sz) in &mapped_bars {
            let _ = unmap_mmio_region(va, sz);
        }
        return complete_req(
            req,
            virtio_device_error(alloc::format!(
                "virtio-blk: device status bad after DRIVER_OK: status={status:#x}"
            )),
        );
    }

    let msix_pba = match msix_cap {
        Some(cap) if use_msix => mapped_bars
            .iter()
            .find(|(idx, _, _)| *idx == cap.pba_bar as u32)
            .map(|(_, va, _)| VirtAddr::new(va.as_u64() + cap.pba_offset as u64)),
        _ => None,
    };

    let dx = dev.try_devext::<DevExt>().expect("virtio: DevExt missing");
    let bar_list: Vec<(u32, VirtAddr, u64)> = mapped_bars.iter().copied().collect();

    dx.inner.call_once(|| {
        Arc::new(DevExtInner {
            common_cfg: caps.common_cfg,
            notify_base: caps.notify_base,
            notify_off_multiplier: caps.notify_off_multiplier,
            isr_cfg: caps.isr_cfg,
            device_cfg: caps.device_cfg,
            queues: queue_states,
            queue_count: final_queue_count,
            queue_strategy: QueueSelectionStrategy::RoundRobin,
            rr_counter: AtomicUsize::new(0),
            capacity: init_result.capacity,
            mapped_bars: Mutex::new(bar_list),
            msix_pba,
            indirect_desc_enabled: init_result.indirect_desc_supported,
            flush_supported: init_result.flush_supported,
        })
    });

    // Spawn one drain task per queue. Each task owns a clone of its IrqHandle;
    // when pnp_remove unregisters the handle the wait returns IRQ_WAIT_CLOSED
    // and the task exits cleanly.
    if let Some(inner) = dx.inner.get().cloned() {
        for queue_idx in 0..inner.queue_count {
            let irq = unsafe { (*inner.queues[queue_idx].irq_handle.get()).clone() };
            if let Some(handle) = irq {
                let inner_clone = inner.clone();
                spawn_detached(async move {
                    queue_drain_loop(inner_clone, queue_idx, handle).await;
                });
            }
        }
    }

    complete_req(req, DriverStatus::Success)
}

#[request_handler]
async fn virtio_pnp_remove<'req, 'data, 'b>(
    dev: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'req, Pnp<'data>>,
) -> DriverStep {
    if let Ok(dx) = dev.try_devext::<DevExt>() {
        if let Some(inner) = dx.inner.get().cloned() {
            blk::reset_device(inner.common_cfg);

            for qs in inner.queues.iter() {
                // Unregistering closes the handle, causing the drain task's
                // irq_handle.wait() to return IRQ_WAIT_CLOSED so it exits.
                if let Some(h) = unsafe { &*qs.irq_handle.get() } {
                    h.unregister();
                }

                if let Some(vec) = qs.msix_vector {
                    let _ = irq_free_vector(vec);
                }

                // Acquire write lock to wait for any in-progress drain to finish
                // before unmapping the queue's DMA memory.
                qs.queue.write().destroy();

                // Cancel pending completions so in-flight submitters do not hang.
                qs.completion_slots.cancel_all();
            }

            {
                let bars = inner.mapped_bars.lock();
                for &(_, va, sz) in bars.iter() {
                    let _ = unmap_mmio_region(va, sz);
                }
            }
        }
    }

    complete_req(req, DriverStatus::Success)
}

#[request_handler]
async fn virtio_pnp_query_devrels<'req, 'data, 'b>(
    dev: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'req, Pnp<'data>>,
) -> DriverStep {
    let relation = { req.read().body.request.relation };
    if relation == DeviceRelationType::BusRelations {
        create_child_pdo(&dev);
        return complete_req(req, DriverStatus::Success);
    }
    continue_req(req)
}

fn create_child_pdo(parent: &Arc<DeviceObject>) {
    let dx = match parent.try_devext::<DevExt>() {
        Ok(x) => x,
        Err(_) => return,
    };

    if dx.enumerated.swap(true, Ordering::AcqRel) {
        return;
    }

    let ids = DeviceIds {
        hardware: vec!["VirtIO\\Disk".into(), "GenDisk".into()],
        compatible: vec!["VirtIO\\Disk".into(), "GenDisk".into()],
    };

    let mut pnp_vt = PnpVtable::new();
    pnp_vt.set(PnpMinorFunction::QueryId, virtio_pdo_query_id);
    pnp_vt.set(PnpMinorFunction::QueryResources, virtio_pdo_query_resources);
    pnp_vt.set(PnpMinorFunction::StartDevice, virtio_pdo_start);

    let capacity = dx.inner.get().map(|i| i.capacity).unwrap_or(0);
    let total_bytes = capacity * 512;

    let disk_info = DiskInfo {
        logical_block_size: 512,
        physical_block_size: 512,
        total_logical_blocks: capacity,
        total_bytes_low: total_bytes,
        total_bytes_high: 0,
    };

    let mut child_init = DeviceInit::with_pnp(Some(pnp_vt));
    child_init.ops.read.register::<VirtioPdoIo>();
    child_init.ops.write.register::<VirtioPdoIo>();
    child_init.ops.device_control.register::<VirtioPdoIo>();
    child_init.ops.flush.register::<VirtioPdoIo>();
    child_init.set_dev_ext_from(ChildExt {
        parent_device: Arc::downgrade(parent),
        disk_info,
    });

    let parent_dn = parent.dev_node.get().unwrap().upgrade().unwrap();
    let _ = pnp_create_child_devnode_and_pdo_with_init(
        &parent_dn,
        "VirtIO_Disk_0".into(),
        "VirtIO\\Disk_0".into(),
        ids,
        Some("disk".into()),
        child_init,
    );
}

/// Tracks concurrent submitters on a queue so only the last one kicks.
/// Notify happens automatically in Drop — no manual finish call required.
pub(crate) struct SubmitTasksGuard<'a> {
    counter: &'a AtomicU32,
    vq: &'a Virtqueue,
    notify_base: VirtAddr,
    notify_off_multiplier: u32,
    force_notify: bool,
}
impl<'a> SubmitTasksGuard<'a> {
    #[inline]
    fn new(
        counter: &'a AtomicU32,
        vq: &'a Virtqueue,
        notify_base: VirtAddr,
        notify_off_multiplier: u32,
        force_notify: bool,
    ) -> Self {
        counter.fetch_add(1, Ordering::AcqRel);
        Self {
            counter,
            vq,
            notify_base,
            notify_off_multiplier,
            force_notify,
        }
    }
}
impl<'a> Drop for SubmitTasksGuard<'a> {
    fn drop(&mut self) {
        let prev = self.counter.fetch_sub(1, Ordering::AcqRel);
        if likely(self.force_notify || prev == 1) {
            dp::add_counter(C_VIRTIO_QUEUE_KICKS, 1);
            let profile_start = dp::timestamp_ns();
            self.vq.notify(self.notify_base, self.notify_off_multiplier);
            dp::add_elapsed(B_VIRTIO_QUEUE_NOTIFY, profile_start);
        }
    }
}

pub(crate) fn drain_queue_completions(qs: &QueueState) -> usize {
    if likely(!qs.has_pending_used()) {
        return 0;
    }

    let mut drained = 0usize;
    dp::add_counter(C_LOCK_ACQUISITIONS, 1);
    let profile_start = dp::timestamp_ns();
    let mut vq = qs.queue.write();
    while let Some((head, _len)) = vq.pop_used() {
        if unlikely(head as usize >= qs.completion_slots.len()) {
            cold_path();
            panic!(
                "virtio: device returned out-of-bounds descriptor index {}",
                head
            );
        }
        core::sync::atomic::fence(Ordering::Acquire);
        let status = qs.arena.get_status(head);
        vq.free_chain(head);
        if unlikely(!qs.completion_slots.complete_head(head, status)) {
            cold_path();
            panic!("virtio: completed descriptor had no waiter");
        }
        drained += 1;
    }
    qs.last_drained_used_idx
        .store(vq.last_used_idx(), Ordering::Release);
    if drained != 0 {
        dp::add_counter(C_VIRTIO_COMPLETIONS, drained as u64);
        dp::add_elapsed(B_INTERRUPT_COMPLETION_HANDLING, profile_start);
    }
    drained
}

/// Drain loop run as one background task per queue.
/// Waits for an IRQ, drains the entire used ring under the write lock,
/// frees descriptor chains, and delivers completion results via the per-head
/// completion slots. Exits when the IRQ handle is closed (device removal).
async fn queue_drain_loop(inner: Arc<DevExtInner>, queue_idx: usize, irq_handle: IrqHandle) {
    let meta = IrqMeta {
        tag: 0,
        data: [0; 3],
    };
    let qs = &inner.queues[queue_idx];

    loop {
        let result = irq_handle.wait(meta).await;

        if unlikely(irq_wait_closed(result)) {
            cold_path();
            break;
        }
        if unlikely(result.code == IRQ_RESCUE_WAKEUP) {
            cold_path();
            panic!("WHYYYYYYY");
        }

        drain_queue_completions(qs);
    }
}

pub(crate) const IOCTL_BLOCK_FLUSH: u32 = 0xB000_0003;

#[request_handler]
pub async fn virtio_pdo_start<'req, 'data, 'b>(
    _dev: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'req, Pnp<'data>>,
) -> DriverStep {
    complete_req(req, DriverStatus::Success)
}

#[request_handler]
pub async fn virtio_pdo_query_id<'req, 'data, 'b>(
    pdo: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'req, Pnp<'data>>,
) -> DriverStep {
    let ty = { req.read().body.request.id_type };
    let status = {
        let w = req.write();
        let p = &mut w.body.request;
        match ty {
            QueryIdType::HardwareIds | QueryIdType::CompatibleIds => {
                p.ids_out.push("VirtIO\\Disk".into());
                p.ids_out.push("GenDisk".into());
            }
            QueryIdType::DeviceId => {
                p.ids_out.push("VirtIO\\Disk".into());
            }
            QueryIdType::InstanceId => {
                p.ids_out.push(
                    pdo.dev_node
                        .get()
                        .unwrap()
                        .upgrade()
                        .unwrap()
                        .instance_path
                        .clone(),
                );
            }
        }
        DriverStatus::Success
    };
    complete_req(req, status)
}

#[request_handler]
pub async fn virtio_pdo_query_resources<'req, 'data, 'b>(
    pdo: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'req, Pnp<'data>>,
) -> DriverStep {
    let cdx = match pdo.try_devext::<ChildExt>() {
        Ok(x) => x,
        Err(_) => return complete_req(req, DriverStatus::NoSuchDevice),
    };

    let status = {
        let w = req.write();
        let p = &mut w.body.request;
        let di = &cdx.disk_info;
        p.data_out = RequestData::from_t::<DiskInfo>(*di);
        DriverStatus::Success
    };

    complete_req(req, status)
}
