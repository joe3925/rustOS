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
use core::hint::spin_loop;
use core::panic::PanicInfo;
use core::ptr::read_volatile;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use kernel_api::benchmark::{BENCH_MAX_LEVELS, BenchLevelResult, BenchSweepResult};
use kernel_api::kernel_types::pnp::DeviceIds;

use core::f64;
use kernel_api::device::{DeviceInit, DeviceObject, DriverObject};
use kernel_api::irq::{
    IrqHandle, irq_alloc_vector, irq_free_vector, irq_register_isr, irq_register_isr_gsi,
    irq_wait_ok,
};
use kernel_api::kernel_types::io::{DiskInfo, IoType, IoVtable, Synchronization};
use kernel_api::kernel_types::irq::{IrqHandlePtr, IrqMeta};
use kernel_api::kernel_types::request::RequestData;
use kernel_api::memory::unmap_mmio_region;
use kernel_api::pnp::{
    DeviceRelationType, DriverStep, PnpMinorFunction, PnpRequest, PnpVtable, QueryIdType,
    driver_set_evt_device_add, pnp_create_child_devnode_and_pdo_with_init,
    pnp_forward_request_to_next_lower,
};
use kernel_api::request::{Request, RequestHandle, RequestType};
use kernel_api::status::DriverStatus;
use kernel_api::x86_64::VirtAddr;
use kernel_api::{IOCTL_PCI_SETUP_MSIX, println, request_handler};
use spin::Mutex;
use spin::rwlock::RwLock;

use blk::{
    BlkIoArena, VIRTIO_BLK_S_OK, VIRTIO_BLK_T_IN, VIRTIO_BLK_T_OUT, calculate_per_queue_arena_sizes,
};
use dev_ext::{ChildExt, DevExt, DevExtInner, QueueSelectionStrategy, QueueState};
use virtqueue::Virtqueue;

static MOD_NAME: &str = option_env!("CARGO_PKG_NAME").unwrap_or(module_path!());

const PIC_BASE_VECTOR: u8 = 0x20;

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

fn signal_waiters(handle: &IrqHandle) {
    // Single-drainer pattern: always signal exactly ONE token.
    // This wakes one drainer task which will drain all completions and then
    // wake other waiters if their requests completed. This prevents the
    // thundering herd problem where N completions cause N wakeups that all
    // contend on the same virtqueue lock.
    handle.signal_n(
        IrqMeta {
            tag: 0,
            data: [0; 3],
        },
        1,
    );
}

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    use kernel_api::util::panic_common;
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
    // FDO handles only PnP/start; I/O is exposed on the child disk PDO.
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
            signal_waiters(&h);
            core::mem::forget(h);
        }
        true
    } else {
        false
    }
}

/// MSI-X ISR - simpler than legacy ISR since MSI-X is edge-triggered and dedicated.
/// No need to poll the ISR register.
extern "win64" fn virtio_msix_isr(
    _vector: u8,
    _cpu: u32,
    _frame: *mut kernel_api::x86_64::structures::idt::InterruptStackFrame,
    handle: IrqHandlePtr,
    _ctx: usize,
) -> bool {
    if let Some(h) = unsafe { IrqHandle::from_raw(handle) } {
        signal_waiters(&h);
        core::mem::forget(h);
    }
    true
}

/// Send IOCTL to PCI driver to program MSI-X table entry.
/// The child driver (us) has already allocated the vector from the kernel.
async fn setup_msix_via_pci(
    dev: &Arc<DeviceObject>,
    vector: u8,
    cpu: u8,
    table_index: u16,
) -> Result<(), DriverStatus> {
    // Encode request: num_entries(2) + [table_index(2) + vector(1) + cpu(1)] per entry
    let mut buf = vec![0u8; 6];
    buf[0..2].copy_from_slice(&1u16.to_le_bytes()); // num_entries = 1
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
        let req = query_req.read();
        let blob = req
            .pnp
            .as_ref()
            .map(|p| p.data_out.as_slice())
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

    // Determine target queue count: min(device_queues, cpu_count)
    let cpu_ids = kernel_api::irq::apic_cpu_ids();
    let cpu_count = cpu_ids.len().max(1);
    let target_queue_count = (init_result.num_queues as usize).min(cpu_count);

    // Create virtqueues
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

    // Allocate MSI-X vectors per queue (if MSI-X is available)
    // Each queue gets its own vector with CPU affinity
    let mut msix_allocations: Vec<Option<(u8, IrqHandle, u16)>> = Vec::new(); // (vector, handle, table_index)

    if msix_cap.is_some() {
        for queue_idx in 0..actual_queue_count {
            // Allocate vector
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

            // Register ISR
            let handle = match irq_register_isr(vector, virtio_msix_isr, 0) {
                Some(h) => h,
                None => {
                    let _ = irq_free_vector(vector);
                    println!("virtio-blk: failed to register ISR for queue {}", queue_idx);
                    break;
                }
            };

            // Target CPU for this queue's interrupts (round-robin across CPUs)
            let target_cpu = (queue_idx % cpu_count) as u8;
            let table_index = queue_idx as u16;

            // Program MSI-X table via PCI driver
            match setup_msix_via_pci(&dev, vector, target_cpu, table_index).await {
                Ok(()) => {
                    // Program device to use this MSI-X entry for this queue
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

                    // Verify device accepted the vector
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

        // Also set up config change vector (using first entry)
        if !msix_allocations.is_empty() {
            unsafe {
                pci::common_write_u16(caps.common_cfg, pci::COMMON_MSIX_CONFIG, 0);
            }
        }
    }

    // Determine final queue count based on MSI-X success
    let (final_queue_count, use_msix) =
        if msix_allocations.len() == actual_queue_count && !msix_allocations.is_empty() {
            // All queues got MSI-X vectors
            (actual_queue_count, true)
        } else if msix_allocations.is_empty() {
            // Fall back to legacy IRQ with single queue
            (1, false)
        } else {
            // Partial success - reduce queue count to match available vectors
            // Clean up extra virtqueues
            for vq in virtqueues.iter().skip(msix_allocations.len()) {
                vq.destroy();
            }
            (msix_allocations.len(), true)
        };

    // Truncate virtqueues to final count
    virtqueues.truncate(final_queue_count);

    // Set up legacy IRQ fallback for single queue if MSI-X failed
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

    // Calculate per-queue arena sizes
    let (prealloc_per_queue, dynamic_per_queue) =
        calculate_per_queue_arena_sizes(final_queue_count);

    // Build QueueState for each queue
    let mut queue_states: Vec<QueueState> = Vec::with_capacity(final_queue_count);
    let mut virtqueue_iter = virtqueues.into_iter();
    for i in 0..final_queue_count {
        // Create arena for this queue
        let arena = match BlkIoArena::init_with_capacity(prealloc_per_queue, dynamic_per_queue) {
            Some(a) => a,
            None => {
                println!("virtio-blk: failed to create arena for queue {}", i);
                // Clean up already created queue states
                for qs in queue_states.iter() {
                    if let Some(ref h) = qs.irq_handle {
                        h.unregister();
                    }
                    if let Some(vec) = qs.msix_vector {
                        let _ = irq_free_vector(vec);
                    }
                    qs.queue.lock().destroy();
                }
                // Clean up remaining MSI-X allocations
                for alloc in msix_allocations.iter().skip(i) {
                    if let Some((vec, handle, _)) = alloc {
                        handle.unregister();
                        let _ = irq_free_vector(*vec);
                    }
                }
                // Clean up remaining virtqueues
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
            // Legacy IRQ for queue 0
            (legacy_irq_handle.clone(), None, None)
        } else {
            (None, None, None)
        };

        // Take ownership of the virtqueue
        let vq = virtqueue_iter
            .next()
            .expect("virtio-blk: virtqueue missing during init");

        queue_states.push(QueueState {
            queue: Mutex::new(vq),
            arena,
            irq_handle,
            msix_vector,
            msix_table_index,
            waiting_tasks: AtomicU32::new(0),
        });
    }

    // Enable all queues
    for (idx, qs) in queue_states.iter().enumerate() {
        unsafe {
            pci::common_write_u16(caps.common_cfg, pci::COMMON_QUEUE_SELECT, idx as u16);
        }
        let vq = qs.queue.lock();
        vq.enable(caps.common_cfg);
    }

    blk::set_driver_ok(caps.common_cfg);

    // Check device status to catch any latent failure before exposing the queue.
    let status = unsafe { pci::common_read_u8(caps.common_cfg, pci::COMMON_DEVICE_STATUS) };
    if status & blk::VIRTIO_STATUS_FAILED != 0 || status & blk::VIRTIO_STATUS_DRIVER_OK == 0 {
        println!(
            "virtio-blk: device status bad after DRIVER_OK: status={:#x}",
            status
        );
        blk::reset_device(caps.common_cfg);
        for qs in queue_states.iter() {
            if let Some(ref h) = qs.irq_handle {
                h.unregister();
            }
            if let Some(vec) = qs.msix_vector {
                let _ = irq_free_vector(vec);
            }
            qs.queue.lock().destroy();
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
    });

    if let Some(inner) = dx.inner.get() {
        // Set user context for each queue's IRQ handle
        for qs in inner.queues.iter() {
            if let Some(ref h) = qs.irq_handle {
                h.set_user_ctx(&qs.waiting_tasks as *const AtomicU32 as usize);
            }
        }
        // Interrupt path is configured; either IRQ handle is present or we will poll.
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
            // Reset device first
            blk::reset_device(inner.common_cfg);

            // Clean up all queues
            for qs in inner.queues.iter() {
                // Unregister IRQ
                if let Some(ref h) = qs.irq_handle {
                    h.unregister();
                }

                // Free MSI-X vector
                if let Some(vec) = qs.msix_vector {
                    let _ = irq_free_vector(vec);
                }

                // Destroy virtqueue
                {
                    let vq = qs.queue.lock();
                    vq.destroy();
                }

                // Arena cleanup is automatic via Drop
            }

            // Unmap BARs
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
    let disk_info = kernel_api::kernel_types::io::DiskInfo {
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
    let _result = pnp_create_child_devnode_and_pdo_with_init(
        &parent_dn,
        "VirtIO_Disk_0".into(),
        "VirtIO\\Disk_0".into(),
        ids,
        Some("disk".into()),
        child_init,
    );
}

async fn wait_for_completion(qs: &QueueState, head: u16) -> Result<u32, DriverStatus> {
    let meta = IrqMeta {
        tag: 0,
        data: [0; 3],
    };

    struct WaiterGuard<'a> {
        counter: &'a AtomicU32,
    }
    impl<'a> Drop for WaiterGuard<'a> {
        fn drop(&mut self) {
            self.counter.fetch_sub(1, Ordering::AcqRel);
        }
    }

    qs.waiting_tasks.fetch_add(1, Ordering::AcqRel);
    let _waiter_guard = WaiterGuard {
        counter: &qs.waiting_tasks,
    };

    loop {
        // Fast path: check if already completed (lock-free peek via atomic)
        {
            let mut vq = qs.queue.lock();
            if let Some(len) = vq.take_completion(head) {
                vq.free_chain(head);
                return Ok(len);
            }
        }

        // Single-drainer pattern: try to become the drainer
        let epoch_before = {
            let vq = qs.queue.lock();
            vq.drain_epoch()
        };

        let we_are_drainer = {
            let vq = qs.queue.lock();
            vq.try_acquire_drainer()
        };

        if we_are_drainer {
            // We are the single drainer - drain all pending completions
            {
                let mut vq = qs.queue.lock();
                if vq.has_pending_used() {
                    vq.drain_used_to_completions();
                }
                vq.release_drainer();

                // Check our completion after draining
                if let Some(len) = vq.take_completion(head) {
                    vq.free_chain(head);
                    return Ok(len);
                }
            }

            // Re-signal one waiter if there are still pending used entries
            // This ensures forward progress when multiple completions arrive
            {
                let vq = qs.queue.lock();
                if vq.has_pending_used() {
                    if let Some(ref irq_handle) = qs.irq_handle {
                        irq_handle.signal_n(meta, 1);
                    }
                }
            }
        } else {
            // Another task is draining. Check if our completion is ready.
            {
                let mut vq = qs.queue.lock();
                if let Some(len) = vq.take_completion(head) {
                    vq.free_chain(head);
                    return Ok(len);
                }
            }
        }

        if let Some(ref irq_handle) = qs.irq_handle {
            let result = irq_handle.wait(meta).await;
            if !irq_wait_ok(result) {
                let mut vq = qs.queue.lock();
                vq.free_chain(head);
                return Err(DriverStatus::DeviceError);
            }
        } else {
            spin_loop();
        }

        // After waking, check if epoch changed (meaning drainer processed completions)
        // If so, immediately check our completion before trying to become drainer
        let epoch_after = {
            let vq = qs.queue.lock();
            vq.drain_epoch()
        };
        if epoch_after != epoch_before {
            // New completions were processed, check ours immediately
            let mut vq = qs.queue.lock();
            if let Some(len) = vq.take_completion(head) {
                vq.free_chain(head);
                return Ok(len);
            }
        }
    }
}

const IOCTL_BLOCK_FLUSH: u32 = 0xB000_0003;
const IOCTL_BLOCK_BENCH_SWEEP: u32 = 0xB000_8002;

// =============================================================================
// rdtsc helper
// =============================================================================

/// Read the CPU's Time Stamp Counter (TSC) using the RDTSC instruction.
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

// =============================================================================
// Benchmark Implementation
// =============================================================================

/// Size of each benchmark request in bytes (64 KiB).
const BENCH_REQUEST_SIZE: u32 = 100 * 1024 * 1024;

/// Total data to transfer per benchmark run.
const BENCH_TOTAL_BYTES: u64 = 100 * 1024 * 1024;

/// Number of requests per benchmark run.
const BENCH_REQUEST_COUNT: usize = (BENCH_TOTAL_BYTES / BENCH_REQUEST_SIZE as u64) as usize;

/// Approximate descriptor count per benchmark request for inflight sizing.
const DESCS_PER_REQUEST: usize = 2 + ((BENCH_REQUEST_SIZE as usize + 4095) / 4096);

/// Pending request tracking for benchmark.
struct PendingBenchRequest<'a> {
    head: u16,
    queue_idx: usize,
    start_tsc: u64,
    _request: blk::BlkIoRequestHandle<'a>,
}

/// Run a benchmark with a specific inflight request count.
/// Uses 64 KiB reads, total 100 MiB of data.
/// Uses round-robin queue selection across all available queues.
async fn bench_reads_with_inflight(
    inner: &DevExtInner,
    start_sector: u64,
    inflight: usize,
) -> Result<BenchLevelResult, DriverStatus> {
    // Wait for IRQ subsystem to be ready
    inner.irq_ready.wait().await;

    let mut result = BenchLevelResult {
        inflight: inflight as u32,
        request_count: 0,
        total_time_cycles: 0,
        total_cycles: 0,
        avg_cycles: 0,
        max_cycles: 0,
        min_cycles: u64::MAX,
        p50_cycles: 0,
        p99_cycles: 0,
        p999_cycles: 0,
    };

    let mut lat_samples: Vec<u64> = Vec::with_capacity(BENCH_REQUEST_COUNT);
    let run_start_tsc = rdtsc();

    let mut pending: Vec<PendingBenchRequest<'_>> = Vec::with_capacity(inflight);
    let mut submitted_count: usize = 0;
    let mut completed_count: usize = 0;

    // Sectors per request (64 KiB / 512 bytes = 128 sectors)
    let sectors_per_request = BENCH_REQUEST_SIZE / 512;

    let meta = kernel_api::kernel_types::irq::IrqMeta {
        tag: 0,
        data: [0; 3],
    };

    // Waiter guard for proper cleanup - register on all queues
    struct WaiterGuard<'a> {
        queues: &'a [QueueState],
    }
    impl<'a> Drop for WaiterGuard<'a> {
        fn drop(&mut self) {
            for qs in self.queues.iter() {
                qs.waiting_tasks.fetch_sub(1, Ordering::AcqRel);
            }
        }
    }
    for qs in inner.queues.iter() {
        qs.waiting_tasks.fetch_add(1, Ordering::AcqRel);
    }
    let _waiter_guard = WaiterGuard {
        queues: &inner.queues,
    };

    // Round-robin counter for queue selection
    let mut rr_idx: usize = 0;
    let queue_count = inner.queue_count;

    // Main benchmark loop: submit requests up to inflight limit, drain completions
    while completed_count < BENCH_REQUEST_COUNT {
        // Submit new requests until we hit the inflight limit or total count
        // Batch submissions per queue and notify once per queue to reduce MMIO overhead
        let batch_start_tsc = rdtsc();

        // Track which queues need notification
        let mut queue_needs_notify: Vec<(usize, u16)> = Vec::with_capacity(queue_count);

        while pending.len() < inflight && submitted_count < BENCH_REQUEST_COUNT {
            let sector = start_sector + (submitted_count as u64 * sectors_per_request as u64);

            // Round-robin queue selection
            let queue_idx = rr_idx % queue_count;
            rr_idx = rr_idx.wrapping_add(1);

            let qs = inner.get_queue(queue_idx);

            // Allocate request from this queue's arena
            let io_req =
                match qs
                    .arena
                    .new_request(blk::VIRTIO_BLK_T_IN, sector, BENCH_REQUEST_SIZE)
                {
                    Some(r) => r,
                    None => {
                        // This queue's arena exhausted, try next queue
                        continue;
                    }
                };

            // Submit without notifying yet
            let head = {
                let mut vq = qs.queue.lock();
                let avail_idx_before = vq.avail_idx();

                match io_req.submit(&mut vq, false) {
                    Some(h) => {
                        // Track if this queue needs notification
                        if vq.needs_notify(avail_idx_before) {
                            // Update or add entry for this queue
                            if let Some(entry) = queue_needs_notify
                                .iter_mut()
                                .find(|(idx, _)| *idx == queue_idx)
                            {
                                entry.1 = avail_idx_before;
                            } else {
                                queue_needs_notify.push((queue_idx, avail_idx_before));
                            }
                        }
                        h
                    }
                    None => {
                        // Queue full, try next queue
                        continue;
                    }
                }
            };

            pending.push(PendingBenchRequest {
                head,
                queue_idx,
                start_tsc: batch_start_tsc,
                _request: io_req,
            });
            submitted_count += 1;
        }

        // Notify all queues that had submissions
        for (queue_idx, _) in queue_needs_notify.iter() {
            let qs = inner.get_queue(*queue_idx);
            let vq = qs.queue.lock();
            vq.notify(inner.notify_base, inner.notify_off_multiplier);
        }

        // Drain completions from all queues using single-drainer pattern
        let mut found_any = false;

        for queue_idx in 0..queue_count {
            let qs = inner.get_queue(queue_idx);

            // Try to become drainer for this queue
            let we_are_drainer = {
                let vq = qs.queue.lock();
                vq.try_acquire_drainer()
            };

            if we_are_drainer {
                let mut vq = qs.queue.lock();
                vq.drain_used_to_completions();
                vq.release_drainer();

                // Check pending requests for this queue
                let mut i = 0;
                while i < pending.len() {
                    if pending[i].queue_idx != queue_idx {
                        i += 1;
                        continue;
                    }

                    if let Some(_len) = vq.take_completion(pending[i].head) {
                        let end_tsc = rdtsc();
                        let cycles = end_tsc.saturating_sub(pending[i].start_tsc);

                        result.total_cycles += cycles;
                        result.max_cycles = result.max_cycles.max(cycles);
                        result.min_cycles = result.min_cycles.min(cycles);
                        lat_samples.push(cycles);
                        result.request_count += 1;

                        vq.free_chain(pending[i].head);
                        pending.swap_remove(i);
                        completed_count += 1;
                        found_any = true;
                    } else {
                        i += 1;
                    }
                }

                // Re-signal if there are still pending used entries
                if vq.has_pending_used() {
                    if let Some(ref irq_handle) = qs.irq_handle {
                        irq_handle.signal_n(meta, 1);
                    }
                }
            } else {
                // Another task is draining this queue, just check our completions
                let mut vq = qs.queue.lock();
                let mut i = 0;
                while i < pending.len() {
                    if pending[i].queue_idx != queue_idx {
                        i += 1;
                        continue;
                    }

                    if let Some(_len) = vq.take_completion(pending[i].head) {
                        let end_tsc = rdtsc();
                        let cycles = end_tsc.saturating_sub(pending[i].start_tsc);

                        result.total_cycles += cycles;
                        result.max_cycles = result.max_cycles.max(cycles);
                        result.min_cycles = result.min_cycles.min(cycles);
                        lat_samples.push(cycles);
                        result.request_count += 1;

                        vq.free_chain(pending[i].head);
                        pending.swap_remove(i);
                        completed_count += 1;
                        found_any = true;
                    } else {
                        i += 1;
                    }
                }
            }
        }

        // If no completions found and we have pending requests, wait for IRQ from any queue
        if !found_any && !pending.is_empty() {
            // Wait on the first queue that has an IRQ handle
            // In practice, any queue's IRQ waking us is enough to check all queues
            let mut waited = false;
            for qs in inner.queues.iter() {
                if let Some(ref irq_handle) = qs.irq_handle {
                    let wait_result = irq_handle.wait(meta).await;
                    if !irq_wait_ok(wait_result) {
                        // Clean up pending requests
                        for req in pending.drain(..) {
                            let qs = inner.get_queue(req.queue_idx);
                            let mut vq = qs.queue.lock();
                            vq.free_chain(req.head);
                        }
                        return Err(DriverStatus::DeviceError);
                    }
                    waited = true;
                    break;
                }
            }
            if !waited {
                // Polling mode - yield
                spin_loop();
            }
        }
    }

    if result.request_count > 0 {
        result.avg_cycles = result.total_cycles / result.request_count as u64;
    }

    if !lat_samples.is_empty() {
        lat_samples.sort_unstable();
        let percentile_idx = |pct: f64| -> usize {
            if lat_samples.is_empty() {
                return 0;
            }
            let len_minus_one = (lat_samples.len().saturating_sub(1)) as f64;
            let idx = (len_minus_one * pct) + 0.5;
            let idx = idx as usize;
            idx.min(lat_samples.len() - 1)
        };
        result.p50_cycles = lat_samples[percentile_idx(0.50)];
        result.p99_cycles = lat_samples[percentile_idx(0.99)];
        result.p999_cycles = lat_samples[percentile_idx(0.999)];
    }

    // Total wall time for the run (from first submit to last completion)
    let run_end_tsc = rdtsc();
    result.total_time_cycles = run_end_tsc.saturating_sub(run_start_tsc);

    // If no samples were collected, set min to 0
    if result.min_cycles == u64::MAX {
        result.min_cycles = 0;
    }

    Ok(result)
}

const BENCH_SECTORS_PER_RUN: u64 = BENCH_TOTAL_BYTES / 512;

/// Run a benchmark sweep across multiple inflight levels.
/// Tests power-of-two levels from 1 to 1024, clamped by hardware capacity.
/// Each level reads from a different disk region to avoid host/page cache hits.
/// Uses combined capacity of all queues for inflight calculation.
async fn bench_sweep(inner: &DevExtInner) -> Result<BenchSweepResult, DriverStatus> {
    const LEVELS: [usize; BENCH_MAX_LEVELS] = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024];

    // Determine maximum supported inflight based on combined ring capacity across all queues
    let combined_ring_size: usize = inner
        .queues
        .iter()
        .map(|qs| {
            let vq = qs.queue.lock();
            vq.size as usize
        })
        .sum();

    // Combined arena capacity across all queues
    let combined_arena_capacity: usize =
        inner.queues.iter().map(|qs| qs.arena.max_capacity()).sum();

    // max_supported = min(combined_ring_size / descs_per_req, combined_arena_capacity)
    let max_from_ring = combined_ring_size / DESCS_PER_REQUEST;
    let max_supported = max_from_ring.min(combined_arena_capacity);

    let mut result = BenchSweepResult::default();

    // Each level uses a different starting sector to avoid host/page cache hits.
    // This ensures we're measuring actual storage/virtio performance, not cached reads.
    let mut current_sector: u64 = 0;

    for &level in LEVELS.iter() {
        // Clamp level to max supported
        let clamped_level = level.min(max_supported);

        // Skip if we've already tested this clamped level
        if result.used > 0 {
            let prev_level = result.levels[result.used as usize - 1].inflight as usize;
            if clamped_level == prev_level {
                // Already tested this level, stop the sweep
                break;
            }
        }

        // Run benchmark for this level with unique disk region
        let level_result = bench_reads_with_inflight(inner, current_sector, clamped_level).await?;

        result.levels[result.used as usize] = level_result;
        result.used += 1;

        // Advance to next region for the next level to avoid cache hits
        current_sector += BENCH_SECTORS_PER_RUN;

        // Stop if we've hit the cap
        if clamped_level >= max_supported {
            break;
        }
    }

    Ok(result)
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
    // SAFETY: inner lives as long as the parent DevExt (which is kept alive by the Arc).
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

    // Select queue based on strategy (CPU affinity or round-robin)
    let queue_idx = inner.select_queue();
    let qs = inner.get_queue(queue_idx);

    // Use this queue's arena allocator for request (returns slot on drop)
    let io_req = match qs.arena.new_request(VIRTIO_BLK_T_IN, sector, len as u32) {
        Some(r) => r,
        None => return complete_req(req, DriverStatus::InsufficientResources),
    };

    // Wait for IRQ subsystem to be ready
    inner.irq_ready.wait().await;

    let head = {
        let mut vq = qs.queue.lock();
        match io_req.submit(&mut vq, false) {
            Some(h) => {
                vq.notify(inner.notify_base, inner.notify_off_multiplier);
                h
            }
            None => {
                // io_req dropped here, returning slot to arena automatically
                return complete_req(req, DriverStatus::InsufficientResources);
            }
        }
    };
    let _len = match wait_for_completion(qs, head).await {
        Ok(l) => l,
        Err(e) => return complete_req(req, e),
    };

    if io_req.status() != VIRTIO_BLK_S_OK {
        // io_req dropped here, returning slot to arena automatically
        return complete_req(req, DriverStatus::DeviceError);
    }

    {
        let mut w = req.write();
        let dst = &mut w.data_slice_mut()[..len];
        dst.copy_from_slice(io_req.data_slice());
    }

    // io_req dropped here, returning slot to arena automatically
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

    // Select queue based on strategy (CPU affinity or round-robin)
    let queue_idx = inner.select_queue();
    let qs = inner.get_queue(queue_idx);

    // Use this queue's arena allocator for request (returns slot on drop)
    let mut io_req = match qs.arena.new_request(VIRTIO_BLK_T_OUT, sector, len as u32) {
        Some(r) => r,
        None => return complete_req(req, DriverStatus::InsufficientResources),
    };

    {
        let r = req.read();
        let src = &r.data_slice()[..len];
        io_req.data_slice_mut().copy_from_slice(src);
    }

    // Wait for IRQ subsystem to be ready
    inner.irq_ready.wait().await;

    let head = {
        let mut vq = qs.queue.lock();
        match io_req.submit(&mut vq, true) {
            Some(h) => {
                vq.notify(inner.notify_base, inner.notify_off_multiplier);
                h
            }
            None => {
                // io_req dropped here, returning slot to arena automatically
                return complete_req(req, DriverStatus::InsufficientResources);
            }
        }
    };

    let _len = match wait_for_completion(qs, head).await {
        Ok(l) => l,
        Err(e) => return complete_req(req, e),
    };

    if io_req.status() != VIRTIO_BLK_S_OK {
        // io_req dropped here, returning slot to arena automatically
        return complete_req(req, DriverStatus::DeviceError);
    }

    // io_req dropped here, returning slot to arena automatically
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

            match bench_sweep(inner).await {
                Ok(result) => {
                    {
                        let mut w = req.write();
                        w.data = RequestData::from_t(result);
                    }
                    complete_req(req, DriverStatus::Success)
                }
                Err(e) => complete_req(req, e),
            }
        }
        _ => complete_req(req, DriverStatus::NotImplemented),
    }
}
