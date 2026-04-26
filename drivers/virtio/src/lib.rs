#![no_std]
#![no_main]
#![feature(const_option_ops)]
#![feature(const_trait_impl)]
extern crate alloc;

mod blk;
mod dev_ext;
mod dma_region;
mod pci;
mod temp_benchmark;
mod virtqueue;

use alloc::{sync::Arc, vec, vec::Vec};
use core::arch::asm;
use core::cell::UnsafeCell;
use core::mem;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use kernel_api::benchmark::{
    BENCH_FLAG_IRQ, BENCH_FLAG_POLL, BenchSweepBothResult, BenchSweepParams, BenchSweepResult,
};
use kernel_api::device::{DeviceInit, DeviceObject, DriverObject};
use kernel_api::irq::{
    IrqHandle, IrqHandleExt, irq_alloc_vector, irq_free_vector, irq_register_isr,
    irq_register_isr_gsi, irq_wait_closed,
};
use kernel_api::kernel_types::dma::{Described, FromDevice, IoBuffer, ToDevice};
use kernel_api::kernel_types::io::{DiskInfo, IoType, IoVtable};
use kernel_api::kernel_types::irq::{IRQ_RESCUE_WAKEUP, IrqMeta};
use kernel_api::kernel_types::pnp::DeviceIds;
use kernel_api::kernel_types::request::RequestData;
use kernel_api::memory::unmap_mmio_region;
use kernel_api::pnp::{
    DeviceRelationType, DriverStep, PnpMinorFunction, PnpRequest, PnpVtable, QueryIdType,
    driver_set_evt_device_add, pnp_create_child_devnode_and_pdo_with_init,
    pnp_forward_request_to_next_lower,
};
use kernel_api::request::{RequestDataView, RequestHandle, RequestType};
use kernel_api::runtime::spawn_detached;
use kernel_api::status::DriverStatus;
use kernel_api::util::panic_common;
use kernel_api::x86_64::VirtAddr;
use kernel_api::{IOCTL_PCI_SETUP_MSIX, println, request_handler};
use spin::{Mutex, RwLock};
use temp_benchmark::{
    IOCTL_BLOCK_BENCH_SWEEP, IOCTL_BLOCK_BENCH_SWEEP_BOTH, IOCTL_BLOCK_BENCH_SWEEP_POLLING,
    bench_sweep, bench_sweep_params, sanitize_bench_params,
};

use blk::{BlkIoSlots, VIRTIO_BLK_S_OK, VIRTIO_BLK_T_IN, VIRTIO_BLK_T_OUT};
use dev_ext::{ChildExt, DevExt, DevExtInner, QueueSelectionStrategy, QueueState};
use virtqueue::Virtqueue;

static MOD_NAME: &str = option_env!("CARGO_PKG_NAME").unwrap_or(module_path!());

const PIC_BASE_VECTOR: u8 = 0x20;

// legacy helpers
#[inline(always)]
fn complete_req(req: &mut RequestHandle, status: DriverStatus) -> DriverStep {
    DriverStep::complete(status)
}
#[inline(always)]
fn continue_req(req: &mut RequestHandle) -> DriverStep {
    DriverStep::Continue
}

fn take_from_device_buffer<'a>(
    req: &mut RequestHandle<'a>,
    len: usize,
) -> Result<IoBuffer<'a, Described, FromDevice>, DriverStatus> {
    let mut data = match req.data() {
        RequestDataView::FromDevice(data) => data,
        _ => return Err(DriverStatus::InvalidParameter),
    };

    let buffer = data
        .view_mut::<IoBuffer<'a, Described, FromDevice>>()
        .ok_or(DriverStatus::InsufficientResources)?;
    if buffer.len() < len {
        return Err(DriverStatus::InsufficientResources);
    }

    let empty = IoBuffer::<Described, FromDevice>::new(unsafe {
        core::slice::from_raw_parts_mut(buffer.as_mut_ptr(), 0)
    });
    Ok(mem::replace(buffer, empty))
}

fn restore_from_device_buffer<'a>(
    req: &mut RequestHandle<'a>,
    buffer: IoBuffer<'a, Described, FromDevice>,
) {
    let mut data = match req.data() {
        RequestDataView::FromDevice(data) => data,
        _ => panic!("virtio: read request buffer vanished before restore"),
    };

    let slot = data
        .view_mut::<IoBuffer<'a, Described, FromDevice>>()
        .expect("virtio: read request buffer type changed before restore");
    *slot = buffer;
}

fn describe_to_device_buffer<'a>(
    req: &mut RequestHandle<'a>,
    len: usize,
) -> Result<IoBuffer<'a, Described, ToDevice>, DriverStatus> {
    let data = req.data().read_only();
    let buffer = data
        .view::<IoBuffer<'_, Described, ToDevice>>()
        .ok_or(DriverStatus::InsufficientResources)?;
    if buffer.len() < len {
        return Err(DriverStatus::InsufficientResources);
    }

    let slice = unsafe { core::slice::from_raw_parts(buffer.as_ptr(), len) };
    Ok(IoBuffer::<Described, ToDevice>::new(slice))
}

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    panic_common(MOD_NAME, info)
}

#[unsafe(no_mangle)]
pub extern "win64" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    driver_set_evt_device_add(driver, virtio_device_add);
    DriverStatus::Success
}

pub extern "win64" fn virtio_device_add(
    _driver: &Arc<DriverObject>,
    dev_init: &mut DeviceInit,
) -> DriverStep {
    let io_vt = IoVtable::new();

    let mut pnp_vt = PnpVtable::new();
    pnp_vt.set(PnpMinorFunction::StartDevice, virtio_pnp_start);
    pnp_vt.set(PnpMinorFunction::RemoveDevice, virtio_pnp_remove);
    pnp_vt.set(
        PnpMinorFunction::QueryDeviceRelations,
        virtio_pnp_query_devrels,
    );

    let init = DeviceInit::new(io_vt, Some(pnp_vt));
    *dev_init = init;
    dev_init.set_dev_ext_from(DevExt::new());

    DriverStep::complete(DriverStatus::Success)
}

extern "win64" fn virtio_isr(
    _vector: u8,
    _cpu: u32,
    _frame: &mut kernel_api::x86_64::structures::idt::InterruptStackFrame,
    handle: IrqHandle,
    ctx: usize,
) -> bool {
    let isr_va = ctx as *const u8;
    let isr_status = unsafe { core::ptr::read_volatile(isr_va) };

    if isr_status & 1 != 0 {
        handle.signal_one(IrqMeta {
            tag: 0,
            data: [0; 3],
        });
        true
    } else {
        false
    }
}

extern "win64" fn virtio_msix_isr(
    _vector: u8,
    _cpu: u32,
    _frame: &mut kernel_api::x86_64::structures::idt::InterruptStackFrame,
    handle: IrqHandle,
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
    cpu: u8,
    table_index: u16,
) -> Result<(), DriverStatus> {
    let mut buf = vec![0u8; 6];
    buf[0..2].copy_from_slice(&1u16.to_le_bytes());
    buf[2..4].copy_from_slice(&table_index.to_le_bytes());
    buf[4] = vector;
    buf[5] = cpu;

    let mut req = RequestHandle::new(
        RequestType::DeviceControl(IOCTL_PCI_SETUP_MSIX),
        RequestData::from_t::<Vec<u8>>(buf),
    );
    let status = pnp_forward_request_to_next_lower(dev.clone(), &mut req).await;

    if status == DriverStatus::Success {
        Ok(())
    } else {
        Err(status)
    }
}
#[request_handler]
async fn virtio_pnp_start<'a, 'b>(
    dev: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
) -> DriverStep {
    let mut query_req = RequestHandle::new_pnp(
        PnpRequest {
            minor_function: PnpMinorFunction::QueryResources,
            relation: DeviceRelationType::TargetDeviceRelation,
            id_type: QueryIdType::CompatibleIds,
            ids_out: Vec::new(),
            data_out: RequestData::empty(),
        },
        RequestData::empty(),
    );
    let qr_status = pnp_forward_request_to_next_lower(dev.clone(), &mut query_req).await;
    if qr_status != DriverStatus::Success {
        println!("virtio-blk: QueryResources failed: {:?}", qr_status);
        return complete_req(req, qr_status);
    }

    let resources = {
        let r = query_req.read();
        let blob = r
            .pnp
            .as_ref()
            .and_then(|p| p.data_out_ref().view::<Vec<u8>>())
            .map(|v| v.as_slice())
            .unwrap_or(&[]);
        pci::parse_resources(blob)
    };
    let msix_cap = pci::find_msix_capability(&resources);

    let mapped_bars = pci::map_memory_bars(&resources);
    if mapped_bars.is_empty() {
        println!("virtio-blk: no memory BARs found");
        return complete_req(req, DriverStatus::DeviceError);
    }

    let (cfg_phys, cfg_len) = match pci::find_config_space(&resources) {
        Some(v) => v,
        None => {
            println!("virtio-blk: no PCI config space resource");
            for &(_idx, va, sz) in &mapped_bars {
                let _ = unmap_mmio_region(va, sz);
            }
            return complete_req(req, DriverStatus::DeviceError);
        }
    };

    let cfg_base = match kernel_api::memory::map_mmio_region(
        kernel_api::x86_64::PhysAddr::new(cfg_phys),
        cfg_len,
    ) {
        Ok(va) => va,
        Err(_) => {
            println!("virtio-blk: failed to map PCI config space");
            for &(_idx, va, sz) in &mapped_bars {
                let _ = unmap_mmio_region(va, sz);
            }
            return complete_req(req, DriverStatus::DeviceError);
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
            return complete_req(req, DriverStatus::DeviceError);
        }
    };

    let _ = unmap_mmio_region(cfg_base, cfg_len);

    let init_result = match blk::init_device(caps.common_cfg, caps.device_cfg) {
        Some(r) => r,
        None => {
            println!("virtio-blk: device init / feature negotiation failed");
            for &(_idx, va, sz) in &mapped_bars {
                let _ = unmap_mmio_region(va, sz);
            }
            return complete_req(req, DriverStatus::DeviceError);
        }
    };

    let cpu_ids = kernel_api::irq::apic_cpu_ids();
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
        return complete_req(req, DriverStatus::DeviceError);
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

    let legacy_irq_handle: Option<IrqHandle> = if !use_msix {
        if let Some(gsi) = pci::find_gsi(&resources) {
            if gsi < 64 {
                irq_register_isr_gsi(gsi as u8, virtio_isr, caps.isr_cfg.as_u64() as usize)
            } else {
                None
            }
        } else if let Some(line) = pci::find_legacy_irq_line(&resources) {
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
            (legacy_irq_handle.clone(), None, None)
        } else {
            (None, None, None)
        };

        let vq_capacity = vq.size as usize;
        let max_data_segments = core::cmp::min(
            blk::MAX_INDIRECT_DESCRIPTORS.saturating_sub(2),
            vq_capacity.saturating_sub(2),
        );

        let max_request_bytes = ((max_data_segments * 4096) & !511).max(512) as u32;

        let completion_slots = (0..vq_capacity)
            .map(|_| spin::Mutex::new(None))
            .collect::<Vec<_>>()
            .into_boxed_slice();

        queue_states.push(QueueState {
            queue: RwLock::new(vq),
            arena,
            max_request_bytes,
            max_data_segments: max_data_segments as u16,
            irq_handle: UnsafeCell::new(irq_handle),
            msix_vector,
            msix_table_index,
            submitting_tasks: AtomicU32::new(0),
            use_indirect: init_result.indirect_desc_supported,
            completion_slots,
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
        return complete_req(req, DriverStatus::DeviceError);
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
async fn virtio_pnp_remove<'a, 'b>(
    dev: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
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

                // Drop all pending completion senders so that in-flight submitters
                // blocked on rx.await get Err(Canceled) instead of hanging forever.
                for slot in qs.completion_slots.iter() {
                    slot.lock().take();
                }
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
async fn virtio_pnp_query_devrels<'a, 'b>(
    dev: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
) -> DriverStep {
    let relation = { req.read().pnp.as_ref().unwrap().relation };
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

    let mut io_vt = IoVtable::new();
    io_vt.set(IoType::Read(virtio_pdo_read), 0);
    io_vt.set(IoType::Write(virtio_pdo_write), 0);
    io_vt.set(IoType::DeviceControl(virtio_pdo_ioctl), 0);

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

    let mut child_init = DeviceInit::new(io_vt, Some(pnp_vt));
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
        if self.force_notify || prev == 1 {
            self.vq.notify(self.notify_base, self.notify_off_multiplier);
        }
    }
}

/// Drain loop run as one background task per queue.
/// Waits for an IRQ, drains the entire used ring under the write lock,
/// frees descriptor chains, and delivers completion results via the per-head
/// oneshot slots. Exits when the IRQ handle is closed (device removal).
async fn queue_drain_loop(inner: Arc<DevExtInner>, queue_idx: usize, irq_handle: IrqHandle) {
    let meta = IrqMeta {
        tag: 0,
        data: [0; 3],
    };
    let qs = &inner.queues[queue_idx];

    loop {
        let result = irq_handle.wait(meta).await;

        if irq_wait_closed(result) {
            break;
        }
        if result.code == IRQ_RESCUE_WAKEUP {
            panic!("WHYYYYYYY");
        }

        let mut vq = qs.queue.write();
        while let Some((head, len)) = vq.pop_used() {
            if head as usize >= qs.completion_slots.len() {
                panic!(
                    "virtio: device returned out-of-bounds descriptor index {}",
                    head
                );
            }
            vq.free_chain(head);
            if let Some(tx) = qs.completion_slots[head as usize].lock().take() {
                let _ = tx.send(len);
            } else {
                panic!("oops");
            }
        }
    }
}

const IOCTL_BLOCK_FLUSH: u32 = 0xB000_0003;
#[inline]
fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags)
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

#[request_handler]
pub async fn virtio_pdo_start<'a, 'b>(
    _dev: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
) -> DriverStep {
    complete_req(req, DriverStatus::Success)
}

#[request_handler]
pub async fn virtio_pdo_query_id<'a, 'b>(
    pdo: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
) -> DriverStep {
    let ty = { req.read().pnp.as_ref().unwrap().id_type };
    let status = {
        let mut w = req.write();
        let p = w.pnp.as_mut().unwrap();
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
pub async fn virtio_pdo_query_resources<'a, 'b>(
    pdo: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
) -> DriverStep {
    let cdx = match pdo.try_devext::<ChildExt>() {
        Ok(x) => x,
        Err(_) => return complete_req(req, DriverStatus::NoSuchDevice),
    };

    let status = {
        let mut w = req.write();
        match w.pnp.as_mut() {
            Some(p) => {
                let di = &cdx.disk_info;
                p.data_out = RequestData::from_t::<DiskInfo>(*di);
                DriverStatus::Success
            }
            None => DriverStatus::InvalidParameter,
        }
    };

    complete_req(req, status)
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

#[request_handler]
pub async fn virtio_pdo_read<'a, 'b>(
    pdo: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
    _buf_len: usize,
) -> DriverStep {
    let (parent, inner) = match get_parent_inner(pdo) {
        Ok(v) => v,
        Err(s) => return complete_req(req, s),
    };
    let (offset, len) = match {
        let r = req.read();
        match r.kind {
            RequestType::Read { offset, len } => Some((offset, len)),
            _ => None,
        }
    } {
        Some(v) => v,
        None => return complete_req(req, DriverStatus::InvalidParameter),
    };

    if len == 0 {
        return complete_req(req, DriverStatus::Success);
    }
    if (offset & 0x1FF) != 0 || (len & 0x1FF) != 0 {
        return complete_req(req, DriverStatus::InvalidParameter);
    }

    let sector = offset >> 9;
    let queue_idx = inner.select_queue();
    let qs = inner.get_queue(queue_idx);

    let buffer = match take_from_device_buffer(req, len) {
        Ok(buffer) => buffer,
        Err(status) => return complete_req(req, status),
    };
    let mapped_buffer = match kernel_api::dma::map_buffer(
        &parent,
        buffer,
        kernel_api::kernel_types::dma::DmaMappingStrategy::SingleContiguous,
    ) {
        Ok(b) => b,
        Err((buffer, _)) => {
            restore_from_device_buffer(req, buffer);
            return complete_req(req, DriverStatus::InsufficientResources);
        }
    };

    let mut submitted_head = None;
    loop {
        let (tx, rx) = futures_channel::oneshot::channel::<u32>();
        let head_opt = {
            let mut vq = qs.queue.write();
            let segments = mapped_buffer.dma_segments();
            match qs
                .arena
                .submit_request(&mut vq, VIRTIO_BLK_T_IN, sector, segments, false)
            {
                Some(h) => {
                    *qs.completion_slots[h as usize].lock() = Some(tx);
                    let queue_full = vq.num_free == 0;
                    let _submit_guard = SubmitTasksGuard::new(
                        &qs.submitting_tasks,
                        &vq,
                        inner.notify_base,
                        inner.notify_off_multiplier,
                        queue_full,
                    );
                    Some(h)
                }
                None => {
                    vq.notify(inner.notify_base, inner.notify_off_multiplier);
                    None
                }
            }
        };

        if let Some(h) = head_opt {
            submitted_head = Some((h, rx));
            break;
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
    }

    let (head, rx) = submitted_head.unwrap();
    let status = match rx.await {
        Ok(_) => {
            if qs.arena.get_status(head) == VIRTIO_BLK_S_OK {
                DriverStatus::Success
            } else {
                DriverStatus::DeviceError
            }
        }
        Err(_) => DriverStatus::DeviceError,
    };

    restore_from_device_buffer(req, kernel_api::dma::unmap_buffer(mapped_buffer));
    complete_req(req, status)
}

#[request_handler]
pub async fn virtio_pdo_write<'a, 'b>(
    pdo: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
    _buf_len: usize,
) -> DriverStep {
    let (parent, inner) = match get_parent_inner(pdo) {
        Ok(v) => v,
        Err(s) => return complete_req(req, s),
    };

    let (offset, len) = match {
        let r = req.read();
        match r.kind {
            RequestType::Write { offset, len, .. } => Some((offset, len)),
            _ => None,
        }
    } {
        Some(v) => v,
        None => return complete_req(req, DriverStatus::InvalidParameter),
    };

    if len == 0 {
        return complete_req(req, DriverStatus::Success);
    }
    if (offset & 0x1FF) != 0 || (len & 0x1FF) != 0 {
        return complete_req(req, DriverStatus::InvalidParameter);
    }

    let sector = offset >> 9;
    let queue_idx = inner.select_queue();
    let qs = inner.get_queue(queue_idx);

    let buffer = match describe_to_device_buffer(req, len) {
        Ok(buffer) => buffer,
        Err(status) => return complete_req(req, status),
    };

    let mapped_buffer = match kernel_api::dma::map_buffer(
        &parent,
        buffer,
        kernel_api::kernel_types::dma::DmaMappingStrategy::SingleContiguous,
    ) {
        Ok(b) => b,
        Err(_) => return complete_req(req, DriverStatus::InsufficientResources),
    };

    let mut submitted_head = None;
    loop {
        let (tx, rx) = futures_channel::oneshot::channel::<u32>();
        let head_opt = {
            let mut vq = qs.queue.write();
            let segments = mapped_buffer.dma_segments();
            match qs
                .arena
                .submit_request(&mut vq, VIRTIO_BLK_T_OUT, sector, segments, true)
            {
                Some(h) => {
                    *qs.completion_slots[h as usize].lock() = Some(tx);
                    let queue_full = vq.num_free == 0;
                    let _submit_guard = SubmitTasksGuard::new(
                        &qs.submitting_tasks,
                        &vq,
                        inner.notify_base,
                        inner.notify_off_multiplier,
                        queue_full,
                    );
                    Some(h)
                }
                None => {
                    vq.notify(inner.notify_base, inner.notify_off_multiplier);
                    None
                }
            }
        };

        if let Some(h) = head_opt {
            submitted_head = Some((h, rx));
            break;
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
    }

    let (head, rx) = submitted_head.unwrap();
    let status = match rx.await {
        Ok(_) => {
            if qs.arena.get_status(head) == VIRTIO_BLK_S_OK {
                DriverStatus::Success
            } else {
                DriverStatus::DeviceError
            }
        }
        Err(_) => DriverStatus::DeviceError,
    };

    let _ = kernel_api::dma::unmap_buffer(mapped_buffer);
    complete_req(req, status)
}

#[request_handler]
pub async fn virtio_pdo_ioctl<'a, 'b>(
    pdo: &Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
) -> DriverStep {
    let code = match {
        let r = req.read();
        match r.kind {
            RequestType::DeviceControl(c) => Some(c),
            _ => None,
        }
    } {
        Some(c) => c,
        None => return complete_req(req, DriverStatus::InvalidParameter),
    };

    match code {
        IOCTL_BLOCK_FLUSH => complete_req(req, DriverStatus::Success),

        IOCTL_BLOCK_BENCH_SWEEP => {
            let (_parent, inner) = match get_parent_inner(pdo) {
                Ok(v) => v,
                Err(s) => return complete_req(req, s),
            };

            match bench_sweep(&inner, true).await {
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
            let (_parent, inner) = match get_parent_inner(pdo) {
                Ok(v) => v,
                Err(s) => return complete_req(req, s),
            };

            match bench_sweep(&inner, false).await {
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
            let (_parent, inner) = match get_parent_inner(pdo) {
                Ok(v) => v,
                Err(s) => return complete_req(req, s),
            };

            let params_in = {
                let r = req.write();
                r.data()
                    .read_only()
                    .view::<BenchSweepParams>()
                    .copied()
                    .unwrap_or_default()
            };
            let params_used = sanitize_bench_params(&inner, params_in);

            let irq = if (params_used.flags & BENCH_FLAG_IRQ) != 0 {
                match bench_sweep_params(&inner, &params_used, true).await {
                    Ok(r) => r,
                    Err(e) => return complete_req(req, e),
                }
            } else {
                BenchSweepResult::default()
            };

            let poll = if (params_used.flags & BENCH_FLAG_POLL) != 0 {
                match bench_sweep_params(&inner, &params_used, false).await {
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
