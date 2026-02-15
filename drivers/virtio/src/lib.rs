#![no_std]
#![no_main]
#![feature(const_option_ops)]
#![feature(const_trait_impl)]
extern crate alloc;

mod blk;
mod dev_ext;
mod pci;
mod virtqueue;

use alloc::{sync::Arc, vec, vec::Vec};
use core::cell::UnsafeCell;
use core::hint::spin_loop;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use kernel_api::benchmark::{
    BENCH_FLAG_IRQ, BENCH_FLAG_POLL, BENCH_PARAMS_VERSION_1, BenchLevelResult,
    BenchSweepBothResult, BenchSweepParams, BenchSweepResult,
};
use kernel_api::device::{DeviceInit, DeviceObject, DriverObject};
use kernel_api::irq::{
    IrqHandle, irq_alloc_vector, irq_free_vector, irq_register_isr, irq_register_isr_gsi,
    irq_wait_ok,
};
use kernel_api::kernel_types::async_types::AsyncMutex;
use kernel_api::kernel_types::io::{DiskInfo, IoType, IoVtable, Synchronization};
use kernel_api::kernel_types::irq::{IrqHandlePtr, IrqMeta};
use kernel_api::kernel_types::pnp::DeviceIds;
use kernel_api::kernel_types::request::RequestData;
use kernel_api::memory::{unmap_mmio_region, unmap_range};
use kernel_api::pnp::{
    DeviceRelationType, DriverStep, PnpMinorFunction, PnpRequest, PnpVtable, QueryIdType,
    driver_set_evt_device_add, pnp_create_child_devnode_and_pdo_with_init,
    pnp_forward_request_to_next_lower,
};
use kernel_api::request::{RequestHandle, RequestType};
use kernel_api::status::DriverStatus;
use kernel_api::util::panic_common;
use kernel_api::x86_64::VirtAddr;
use kernel_api::{IOCTL_PCI_SETUP_MSIX, println, request_handler};
use spin::Mutex;

use blk::{
    BlkIoArena, VIRTIO_BLK_S_OK, VIRTIO_BLK_T_IN, VIRTIO_BLK_T_OUT, calculate_per_queue_arena_sizes,
};
use dev_ext::{ChildExt, DevExt, DevExtInner, QueueSelectionStrategy, QueueState};
use virtqueue::Virtqueue;

use crate::blk::PREALLOCATED_DATA_SIZE;

static MOD_NAME: &str = option_env!("CARGO_PKG_NAME").unwrap_or(module_path!());

const PIC_BASE_VECTOR: u8 = 0x20;
const INVALID_HEAD: u16 = 0xFFFF;

fn complete_req(req: &mut RequestHandle, status: DriverStatus) -> DriverStep {
    {
        let mut w = req.write();
        w.status = status;
    }
    DriverStep::complete(status)
}

fn continue_req(req: &mut RequestHandle) -> DriverStep {
    {
        let mut w = req.write();
        w.status = DriverStatus::ContinueStep;
    }
    DriverStep::Continue
}

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    unsafe { panic_common(MOD_NAME, info) }
}

#[unsafe(no_mangle)]
pub extern "win64" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    driver_set_evt_device_add(driver, virtio_device_add);
    DriverStatus::Success
}

pub extern "win64" fn virtio_device_add(
    _driver: Arc<DriverObject>,
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
    _frame: *mut kernel_api::x86_64::structures::idt::InterruptStackFrame,
    handle: IrqHandlePtr,
    ctx: usize,
) -> bool {
    let isr_va = ctx as *const u8;
    let isr_status = unsafe { core::ptr::read_volatile(isr_va) };

    if isr_status & 1 != 0 {
        if let Some(h) = unsafe { IrqHandle::from_raw(handle) } {
            h.signal_one(IrqMeta {
                tag: 0,
                data: [0; 3],
            });
            core::mem::forget(h);
        }
        true
    } else {
        false
    }
}

extern "win64" fn virtio_msix_isr(
    _vector: u8,
    _cpu: u32,
    _frame: *mut kernel_api::x86_64::structures::idt::InterruptStackFrame,
    handle: IrqHandlePtr,
    _ctx: usize,
) -> bool {
    if let Some(h) = unsafe { IrqHandle::from_raw(handle) } {
        h.signal_one(IrqMeta {
            tag: 0,
            data: [0; 3],
        });
        core::mem::forget(h);
    }
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
        RequestData::from_boxed_bytes(buf.into_boxed_slice()),
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
    dev: Arc<DeviceObject>,
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
        let blob = r.pnp.as_ref().map(|p| p.data_out.as_slice()).unwrap_or(&[]);
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
        match Virtqueue::new(queue_idx as u16, caps.common_cfg) {
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

            let target_cpu = (queue_idx % cpu_count) as u8;
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
            for vq in virtqueues.iter().skip(msix_allocations.len()) {
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

    let (prealloc_per_queue, dynamic_per_queue) =
        calculate_per_queue_arena_sizes(final_queue_count);

    let mut queue_states: Vec<QueueState> = Vec::with_capacity(final_queue_count);
    let mut virtqueue_iter = virtqueues.into_iter();

    for i in 0..final_queue_count {
        let arena = match BlkIoArena::init_with_capacity(prealloc_per_queue, dynamic_per_queue) {
            Some(a) => a,
            None => {
                println!(
                    "virtio-blk: failed to create arena for queue {} with prealloc {} and dynamic {}",
                    i, prealloc_per_queue, dynamic_per_queue
                );

                for qs in queue_states.iter() {
                    if let Some(h) = unsafe { &*qs.irq_handle.get() } {
                        h.unregister();
                    }
                    if let Some(vec) = qs.msix_vector {
                        let _ = irq_free_vector(vec);
                    }
                    qs.queue
                        .try_lock()
                        .expect("queue not locked during cleanup")
                        .destroy();
                }

                for alloc in msix_allocations.iter().skip(i) {
                    if let Some((vec, handle, _)) = alloc {
                        handle.unregister();
                        let _ = irq_free_vector(*vec);
                    }
                }

                for vq in virtqueue_iter.by_ref() {
                    vq.destroy();
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

        let vq = virtqueue_iter
            .next()
            .expect("virtio-blk: virtqueue missing during init");

        let vq_capacity = vq.size as usize;
        let max_data_segments = core::cmp::min(
            blk::MAX_DESCRIPTORS_PER_REQUEST.saturating_sub(2),
            vq_capacity.saturating_sub(2),
        )
        .max(1);

        let max_request_bytes = ((max_data_segments * 4096) & !511).max(512) as u32;

        queue_states.push(QueueState {
            queue: AsyncMutex::new(vq),
            arena,
            max_request_bytes,
            max_data_segments: max_data_segments as u16,
            irq_handle: UnsafeCell::new(irq_handle),
            msix_vector,
            msix_table_index,
            waiting_tasks: AtomicU32::new(0),
            use_indirect: init_result.indirect_desc_supported,
        });
    }

    for (idx, qs) in queue_states.iter().enumerate() {
        unsafe {
            pci::common_write_u16(caps.common_cfg, pci::COMMON_QUEUE_SELECT, idx as u16);
        }
        let vq = qs.queue.try_lock().expect("queue not locked during init");
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
                .try_lock()
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

    let irq_ready = dev_ext::InitGate::new();

    dx.inner.call_once(|| DevExtInner {
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
        irq_ready,
        indirect_desc_enabled: init_result.indirect_desc_supported,
    });

    if let Some(inner) = dx.inner.get() {
        for qs in inner.queues.iter() {
            if let Some(h) = unsafe { &*qs.irq_handle.get() } {
                h.set_user_ctx(&qs.waiting_tasks as *const AtomicU32 as usize);
            }
        }
        inner.irq_ready.set_ready();
    }

    complete_req(req, DriverStatus::Success)
}

#[request_handler]
async fn virtio_pnp_remove<'a, 'b>(
    dev: Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
) -> DriverStep {
    if let Ok(dx) = dev.try_devext::<DevExt>() {
        if let Some(inner) = dx.inner.get() {
            blk::reset_device(inner.common_cfg);

            for qs in inner.queues.iter() {
                if let Some(h) = unsafe { &*qs.irq_handle.get() } {
                    h.unregister();
                }

                if let Some(vec) = qs.msix_vector {
                    let _ = irq_free_vector(vec);
                }

                {
                    let vq = qs
                        .queue
                        .try_lock()
                        .expect("queue not locked during cleanup");
                    vq.destroy();
                }

                if let Some(va) = qs.arena.indirect_pages_va {
                    unsafe {
                        unmap_range(va, (qs.arena.indirect_pages_count * 4096) as u64);
                    }
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
    dev: Arc<DeviceObject>,
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
    io_vt.set(IoType::Read(virtio_pdo_read), Synchronization::Async, 0);
    io_vt.set(IoType::Write(virtio_pdo_write), Synchronization::Async, 0);
    io_vt.set(
        IoType::DeviceControl(virtio_pdo_ioctl),
        Synchronization::Async,
        0,
    );

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

struct WaitTasksGuard<'a> {
    counter: &'a AtomicU32,
}
impl<'a> WaitTasksGuard<'a> {
    #[inline]
    fn new(counter: &'a AtomicU32) -> Self {
        counter.fetch_add(1, Ordering::AcqRel);
        Self { counter }
    }
}
impl<'a> Drop for WaitTasksGuard<'a> {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

async fn wait_for_completion(qs: &QueueState, head: u16) -> Result<u32, DriverStatus> {
    let meta = IrqMeta {
        tag: 0,
        data: [0; 3],
    };

    let _guard = WaitTasksGuard::new(&qs.waiting_tasks);

    let mut spins: u32 = 0;
    const SPIN_BEFORE_WAIT: u32 = 0;

    loop {
        let epoch_before = qs.drain_epoch();

        if let Some(len) = qs.take_completion(head) {
            qs.defer_free_chain(head);
            return Ok(len);
        }

        let we_are_drainer = qs.try_acquire_drainer();
        let mut made_progress = false;

        if we_are_drainer {
            let drained = qs.drain_used_to_completions_lockfree();
            if drained > 0 {
                made_progress = true;
                spins = 0;

                if let Some(irq_handle) = unsafe { &*qs.irq_handle.get() } {
                    let waiters = qs.waiting_tasks.load(Ordering::Acquire);
                    let to_wake = waiters.saturating_sub(1);
                    if to_wake > 0 {
                        irq_handle.signal_n(meta, to_wake);
                    }
                }
            }

            if let Some(len) = qs.take_completion(head) {
                qs.release_drainer();
                qs.defer_free_chain(head);
                return Ok(len);
            }

            qs.release_drainer();
        } else {
            if let Some(len) = qs.take_completion(head) {
                qs.defer_free_chain(head);
                return Ok(len);
            }
        }

        if made_progress {
            continue;
        }

        let epoch_after = qs.drain_epoch();
        if epoch_after != epoch_before {
            spins = 0;
            continue;
        }

        if spins < SPIN_BEFORE_WAIT {
            spins += 1;
            spin_loop();
            continue;
        }

        spins = 0;

        if let Some(irq_handle) = unsafe { &*qs.irq_handle.get() } {
            let wait_result = irq_handle.wait(meta).await;
            if !irq_wait_ok(wait_result) {
                return Err(DriverStatus::DeviceError);
            }
        } else {
            spin_loop();
        }
    }
}

const IOCTL_BLOCK_FLUSH: u32 = 0xB000_0003;
const IOCTL_BLOCK_BENCH_SWEEP: u32 = 0xB000_8002;
const IOCTL_BLOCK_BENCH_SWEEP_POLLING: u32 = 0xB000_8003;

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

const BENCH_TOTAL_BYTES: u64 = 4 * 1024 * 1024 * 1024;

struct BenchConfig {
    request_size: u32,
    requests_per_run: u32,
    max_queue_inflight: u16,
}
impl BenchConfig {
    fn from_inner_params(inner: &DevExtInner, params: &BenchSweepParams) -> Self {
        let request_size = params.request_size;

        let requests_per_run =
            ((params.total_bytes + request_size as u64 - 1) / request_size as u64).max(1) as u32;

        let max_queue_inflight =
            bench_max_inflight_queue0(inner, request_size, inner.indirect_desc_enabled) as u16;

        Self {
            request_size,
            requests_per_run,
            max_queue_inflight,
        }
    }
}
#[inline]
fn percentile_index_permille(len: usize, permille: u32) -> usize {
    if len <= 1 {
        return 0;
    }
    let n = (len - 1) as u64;
    let num = n * permille as u64 + 500;
    let idx = (num / 1000) as usize;
    if idx >= len { len - 1 } else { idx }
}

#[inline]
fn bench_descs_per_request(use_indirect: bool, request_size: u32) -> usize {
    if use_indirect {
        return 1;
    }
    let pages = ((request_size as usize) + 4095) / 4096;
    1 + pages + 1
}

#[inline]
fn bench_max_inflight_queue0(inner: &DevExtInner, request_size: u32, use_indirect: bool) -> usize {
    let qs = inner.get_queue(0);
    let vq = unsafe { &*qs.queue.as_ptr() };
    let qsz = vq.size as usize;
    let dpr = bench_descs_per_request(use_indirect, request_size);
    if dpr == 0 {
        return 1;
    }
    if !use_indirect && dpr > qsz {
        return 0;
    }
    let max = qsz / dpr;
    max.max(1)
}

impl BenchConfig {
    fn from_inner(inner: &DevExtInner) -> Self {
        let request_size = PREALLOCATED_DATA_SIZE as u32;

        let requests_per_run =
            ((BENCH_TOTAL_BYTES + request_size as u64 - 1) / request_size as u64).max(1) as u32;

        let max_queue_inflight =
            bench_max_inflight_queue0(inner, request_size, inner.indirect_desc_enabled) as u16;

        Self {
            request_size,
            requests_per_run,
            max_queue_inflight,
        }
    }
}

struct BenchInflightSlot<'a> {
    io_req: blk::BlkIoRequestHandle<'a>,
    head: u16,
    start_tsc: u64,
}

async fn bench_reads_direct(
    inner: &DevExtInner,
    start_sector: u64,
    inflight: usize,
    bench_cfg: &BenchConfig,
    use_interrupts: bool,
) -> Result<BenchLevelResult, DriverStatus> {
    inner.irq_ready.wait().await;

    let qs = inner.get_queue(0);
    let use_indirect = inner.indirect_desc_enabled;

    let max_inflight = bench_max_inflight_queue0(inner, bench_cfg.request_size, use_indirect);
    if max_inflight == 0 {
        return Err(DriverStatus::InvalidParameter);
    }

    let effective_inflight = inflight.min(max_inflight).max(1);
    let total_requests = bench_cfg.requests_per_run;

    let mut result = BenchLevelResult {
        inflight: effective_inflight as u32,
        request_count: 0,
        total_time_cycles: 0,
        total_cycles: 0,
        avg_cycles: 0,
        max_cycles: 0,
        min_cycles: u64::MAX,
        p50_cycles: 0,
        p99_cycles: 0,
        p999_cycles: 0,
        idle_pct: 0.0,
    };

    let sectors_per_request = (bench_cfg.request_size as u64) >> 9;
    let mut lat_samples: Vec<u64> = Vec::with_capacity(total_requests as usize);

    let meta = IrqMeta {
        tag: 0,
        data: [0; 3],
    };

    let mut slots: Vec<Option<BenchInflightSlot<'_>>> = Vec::with_capacity(effective_inflight);
    for _ in 0..effective_inflight {
        slots.push(None);
    }

    let run_start_tsc = rdtsc();

    let mut irq_wait_wall_cycles: u64 = 0;

    let mut submitted: u32 = 0;
    let mut completed: u32 = 0;
    let mut current_sector = start_sector;

    while completed < total_requests {
        let mut submitted_this_round: u32 = 0;

        {
            let mut vq = qs.queue.lock().await;

            for slot in slots.iter_mut() {
                if submitted >= total_requests {
                    break;
                }
                if slot.is_some() {
                    continue;
                }

                let io_req = match qs.arena.new_request_read(
                    VIRTIO_BLK_T_IN,
                    current_sector,
                    bench_cfg.request_size,
                ) {
                    Some(r) => r,
                    None => break,
                };

                let head = match io_req.submit(&mut vq, false, use_indirect) {
                    Some(h) => h,
                    None => break,
                };

                let start_tsc = rdtsc();

                *slot = Some(BenchInflightSlot {
                    io_req,
                    head,
                    start_tsc,
                });

                submitted += 1;
                submitted_this_round += 1;
                current_sector = current_sector.saturating_add(sectors_per_request);
            }

            if submitted_this_round != 0 {
                vq.notify(inner.notify_base, inner.notify_off_multiplier);
            }
        }

        let mut made_progress = false;

        if qs.try_acquire_drainer() {
            let drained = qs.drain_used_to_completions_lockfree();
            qs.release_drainer();
            if drained != 0 {
                made_progress = true;
            }
        }

        for slot in slots.iter_mut() {
            let Some(s) = slot.take() else { continue };

            let len_opt = qs.take_completion(s.head);
            if len_opt.is_none() {
                *slot = Some(s);
                continue;
            }

            let end_tsc = rdtsc();

            if s.io_req.status() != VIRTIO_BLK_S_OK {
                return Err(DriverStatus::DeviceError);
            }

            qs.defer_free_chain(s.head);

            lat_samples.push(end_tsc.saturating_sub(s.start_tsc));

            completed += 1;
            made_progress = true;
        }

        if completed >= total_requests {
            break;
        }
        if made_progress {
            continue;
        }

        let have_inflight = slots.iter().any(|s| s.is_some());
        if !have_inflight {
            spin_loop();
            continue;
        }

        if use_interrupts {
            if let Some(irq_handle) = unsafe { &*qs.irq_handle.get() } {
                let _guard = WaitTasksGuard::new(&qs.waiting_tasks);

                let t0 = rdtsc();
                let wait_result = irq_handle.wait(meta).await;
                let t1 = rdtsc();

                irq_wait_wall_cycles = irq_wait_wall_cycles.saturating_add(t1.saturating_sub(t0));

                if !irq_wait_ok(wait_result) {
                    return Err(DriverStatus::DeviceError);
                }
            } else {
                spin_loop();
            }
        } else {
            spin_loop();
        }
    }

    let run_end_tsc = rdtsc();

    result.request_count = lat_samples.len() as u32;
    result.total_time_cycles = run_end_tsc.saturating_sub(run_start_tsc);
    result.total_cycles = result.total_time_cycles;

    if result.total_time_cycles != 0 {
        let pct = (irq_wait_wall_cycles as f64) * 100.0 / (result.total_time_cycles as f64);
        result.idle_pct = if pct < 0.0 {
            0.0
        } else if pct > 100.0 {
            100.0
        } else {
            pct
        };
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
async fn bench_sweep_params(
    inner: &DevExtInner,
    params: &BenchSweepParams,
    use_interrupts: bool,
) -> Result<BenchSweepResult, DriverStatus> {
    let bench_cfg = BenchConfig::from_inner_params(inner, params);

    let max_inflight = (params.max_inflight as usize).max(1);
    let max_inflight = max_inflight
        .min(bench_cfg.max_queue_inflight as usize)
        .max(1);

    let sectors_per_run =
        ((bench_cfg.request_size as u64) >> 9).saturating_mul(bench_cfg.requests_per_run as u64);

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
    let mut current_sector: u64 = params.start_sector;
    println!(
        "Starting benchmark sweep with request size {} bytes, total bytes {} ({} sectors), max inflight {}, levels: {:?}",
        bench_cfg.request_size,
        params.total_bytes,
        params.total_bytes >> 9,
        max_inflight,
        levels
    );
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
fn sanitize_bench_params(inner: &DevExtInner, mut p: BenchSweepParams) -> BenchSweepParams {
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
async fn bench_sweep(
    inner: &DevExtInner,
    use_interrupts: bool,
) -> Result<BenchSweepResult, DriverStatus> {
    let p = sanitize_bench_params(inner, BenchSweepParams::default());
    bench_sweep_params(inner, &p, use_interrupts).await
}
const BENCH_SPIN_CHUNK: u32 = 256;

#[inline]
fn bench_spin_chunk_and_count(busy_cycles: &mut u64) {
    let t0 = rdtsc();
    let mut i = 0u32;
    while i < BENCH_SPIN_CHUNK {
        spin_loop();
        i += 1;
    }
    let t1 = rdtsc();
    *busy_cycles = busy_cycles.saturating_add(t1.saturating_sub(t0));
}
#[request_handler]
pub async fn virtio_pdo_start<'a, 'b>(
    _dev: Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
) -> DriverStep {
    complete_req(req, DriverStatus::Success)
}

#[request_handler]
pub async fn virtio_pdo_query_id<'a, 'b>(
    pdo: Arc<DeviceObject>,
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
    pdo: Arc<DeviceObject>,
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
) -> Result<(Arc<DeviceObject>, &'static DevExtInner), DriverStatus> {
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
    let inner = dx.inner.get().ok_or(DriverStatus::DeviceNotReady)?;
    let inner: &'static DevExtInner = unsafe { &*(inner as *const DevExtInner) };
    Ok((parent, inner))
}

#[request_handler]
pub async fn virtio_pdo_read<'a, 'b>(
    pdo: Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
    _buf_len: usize,
) -> DriverStep {
    let (_parent, inner) = match get_parent_inner(&pdo) {
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

    let mut queue_idx = inner.select_queue();
    let queue_count = inner.queue_count.max(1);
    let max_chunk = inner
        .queues
        .iter()
        .map(|q| q.max_request_bytes.max(512) as u64)
        .min()
        .unwrap_or(512);

    let mut remaining = len as u64;
    let mut buf_offset = 0usize;
    let mut next_sector = sector;

    inner.irq_ready.wait().await;

    let meta = IrqMeta {
        tag: 0,
        data: [0; 3],
    };

    while remaining > 0 {
        let chunk_len = core::cmp::min(max_chunk, remaining) as u32;

        let mut submitted = false;
        let start_idx = queue_idx;

        for attempt in 0..queue_count {
            let qi = (start_idx + attempt) % queue_count;
            let qs = inner.get_queue(qi);

            let io_req = match qs
                .arena
                .new_request(VIRTIO_BLK_T_IN, next_sector, chunk_len)
            {
                Some(r) => r,
                None => continue,
            };

            let head = {
                let mut vq = qs.queue.lock().await;
                let use_indirect = inner.indirect_desc_enabled;
                match io_req.submit(&mut vq, false, use_indirect) {
                    Some(h) => {
                        vq.notify(inner.notify_base, inner.notify_off_multiplier);
                        h
                    }
                    None => continue,
                }
            };

            let _ = match wait_for_completion(qs, head).await {
                Ok(l) => l,
                Err(e) => return complete_req(req, e),
            };

            if io_req.status() != VIRTIO_BLK_S_OK {
                return complete_req(req, DriverStatus::DeviceError);
            }

            {
                let mut w = req.write();
                let dst = &mut w.data_slice_mut()[buf_offset..buf_offset + chunk_len as usize];
                dst.copy_from_slice(io_req.data_slice());
            }

            remaining = remaining.saturating_sub(chunk_len as u64);
            buf_offset += chunk_len as usize;
            next_sector = next_sector.saturating_add((chunk_len as u64) >> 9);
            queue_idx = (qi + 1) % queue_count;
            submitted = true;
            break;
        }

        if submitted {
            continue;
        }

        let mut waited = false;
        for qs in inner.queues.iter() {
            if let Some(irq_handle) = unsafe { &*qs.irq_handle.get() } {
                let wait_result = irq_handle.wait(meta).await;
                if !irq_wait_ok(wait_result) {
                    return complete_req(req, DriverStatus::DeviceError);
                }
                waited = true;
                break;
            }
        }
        if !waited {
            spin_loop();
        }
    }

    complete_req(req, DriverStatus::Success)
}

#[request_handler]
pub async fn virtio_pdo_write<'a, 'b>(
    pdo: Arc<DeviceObject>,
    req: &'b mut RequestHandle<'a>,
    _buf_len: usize,
) -> DriverStep {
    let (_parent, inner) = match get_parent_inner(&pdo) {
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

    let mut queue_idx = inner.select_queue();
    let queue_count = inner.queue_count.max(1);
    let max_chunk = inner
        .queues
        .iter()
        .map(|q| q.max_request_bytes.max(512) as u64)
        .min()
        .unwrap_or(512);

    let mut remaining = len as u64;
    let mut buf_offset = 0usize;
    let mut next_sector = sector;

    inner.irq_ready.wait().await;

    let meta = IrqMeta {
        tag: 0,
        data: [0; 3],
    };

    while remaining > 0 {
        let chunk_len = core::cmp::min(max_chunk, remaining) as u32;

        let mut submitted = false;
        let start_idx = queue_idx;

        for attempt in 0..queue_count {
            let qi = (start_idx + attempt) % queue_count;
            let qs = inner.get_queue(qi);

            let mut io_req = match qs
                .arena
                .new_request(VIRTIO_BLK_T_OUT, next_sector, chunk_len)
            {
                Some(r) => r,
                None => continue,
            };

            {
                let r = req.read();
                let src = &r.data_slice()[buf_offset..buf_offset + chunk_len as usize];
                io_req.data_slice_mut().copy_from_slice(src);
            }

            let head = {
                let mut vq = qs.queue.lock().await;
                let use_indirect = inner.indirect_desc_enabled;
                match io_req.submit(&mut vq, true, use_indirect) {
                    Some(h) => {
                        vq.notify(inner.notify_base, inner.notify_off_multiplier);
                        h
                    }
                    None => continue,
                }
            };

            let _ = match wait_for_completion(qs, head).await {
                Ok(l) => l,
                Err(e) => return complete_req(req, e),
            };

            if io_req.status() != VIRTIO_BLK_S_OK {
                return complete_req(req, DriverStatus::DeviceError);
            }

            remaining = remaining.saturating_sub(chunk_len as u64);
            buf_offset += chunk_len as usize;
            next_sector = next_sector.saturating_add((chunk_len as u64) >> 9);
            queue_idx = (qi + 1) % queue_count;
            submitted = true;
            break;
        }

        if submitted {
            continue;
        }

        let mut waited = false;
        for qs in inner.queues.iter() {
            if let Some(irq_handle) = unsafe { &*qs.irq_handle.get() } {
                let wait_result = irq_handle.wait(meta).await;
                if !irq_wait_ok(wait_result) {
                    return complete_req(req, DriverStatus::DeviceError);
                }
                waited = true;
                break;
            }
        }
        if !waited {
            spin_loop();
        }
    }

    complete_req(req, DriverStatus::Success)
}

#[request_handler]
pub async fn virtio_pdo_ioctl<'a, 'b>(
    pdo: Arc<DeviceObject>,
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
            let (_parent, inner) = match get_parent_inner(&pdo) {
                Ok(v) => v,
                Err(s) => return complete_req(req, s),
            };

            match bench_sweep(inner, true).await {
                Ok(r) => {
                    {
                        req.write().data = RequestData::from_t(r);
                    }
                    complete_req(req, DriverStatus::Success)
                }
                Err(e) => complete_req(req, e),
            }
        }

        IOCTL_BLOCK_BENCH_SWEEP_POLLING => {
            let (_parent, inner) = match get_parent_inner(&pdo) {
                Ok(v) => v,
                Err(s) => return complete_req(req, s),
            };

            match bench_sweep(inner, false).await {
                Ok(r) => {
                    {
                        req.write().data = RequestData::from_t(r);
                    }
                    complete_req(req, DriverStatus::Success)
                }
                Err(e) => complete_req(req, e),
            }
        }

        IOCTL_BLOCK_BENCH_SWEEP_BOTH => {
            let (_parent, inner) = match get_parent_inner(&pdo) {
                Ok(v) => v,
                Err(s) => return complete_req(req, s),
            };

            let params_in = {
                let r = req.read();
                r.data
                    .view::<BenchSweepParams>()
                    .copied()
                    .unwrap_or_default()
            };
            let params_used = sanitize_bench_params(inner, params_in);

            let irq = if (params_used.flags & BENCH_FLAG_IRQ) != 0 {
                match bench_sweep_params(inner, &params_used, true).await {
                    Ok(r) => r,
                    Err(e) => return complete_req(req, e),
                }
            } else {
                BenchSweepResult::default()
            };

            let poll = if (params_used.flags & BENCH_FLAG_POLL) != 0 {
                match bench_sweep_params(inner, &params_used, false).await {
                    Ok(r) => r,
                    Err(e) => return complete_req(req, e),
                }
            } else {
                BenchSweepResult::default()
            };

            let qs0 = inner.get_queue(0);
            let qsz = unsafe { (&*qs0.queue.as_ptr()).size };

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
                req.write().data = RequestData::from_t(out);
            }
            complete_req(req, DriverStatus::Success)
        }

        _ => complete_req(req, DriverStatus::NotImplemented),
    }
}
