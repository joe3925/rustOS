#![no_std]
#![no_main]
#![feature(const_option_ops)]
#![feature(const_trait_impl)]
extern crate alloc;

mod blk;
mod dev_ext;
mod pci;
mod virtqueue;

use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use core::cell::UnsafeCell;
use core::hint::spin_loop;
use core::panic::PanicInfo;
use core::ptr::read_volatile;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use kernel_api::benchmark::{BenchLevelResult, BenchSweepResult};
use kernel_api::kernel_types::pnp::DeviceIds;

use kernel_api::device::{DeviceInit, DeviceObject, DriverObject};
use kernel_api::irq::{
    IrqHandle, irq_alloc_vector, irq_free_vector, irq_register_isr, irq_register_isr_gsi,
    irq_wait_ok,
};
use kernel_api::kernel_types::async_types::AsyncMutex;
use kernel_api::kernel_types::io::{DiskInfo, IoType, IoVtable, Synchronization};
use kernel_api::kernel_types::irq::{IrqHandlePtr, IrqMeta};
use kernel_api::kernel_types::request::RequestData;
use kernel_api::memory::{unmap_mmio_region, unmap_range};
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

use blk::{
    BlkIoArena, VIRTIO_BLK_S_OK, VIRTIO_BLK_T_IN, VIRTIO_BLK_T_OUT, calculate_per_queue_arena_sizes,
};
use dev_ext::{ChildExt, DevExt, DevExtInner, QueueSelectionStrategy, QueueState};
use virtqueue::Virtqueue;

use crate::blk::PREALLOCATED_DATA_SIZE;

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
                println!(
                    "virtio-blk: failed to create arena for queue {} with prealloc {} and dynamic {}",
                    i, prealloc_per_queue, dynamic_per_queue
                );
                // Clean up already created queue states
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

    // Enable all queues
    for (idx, qs) in queue_states.iter().enumerate() {
        unsafe {
            pci::common_write_u16(caps.common_cfg, pci::COMMON_QUEUE_SELECT, idx as u16);
        }
        let vq = qs.queue.try_lock().expect("queue not locked during init");
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
        // Set user context for each queue's IRQ handle
        for qs in inner.queues.iter() {
            if let Some(h) = unsafe { &*qs.irq_handle.get() } {
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
                if let Some(h) = unsafe { &*qs.irq_handle.get() } {
                    h.unregister();
                }

                // Free MSI-X vector
                if let Some(vec) = qs.msix_vector {
                    let _ = irq_free_vector(vec);
                }

                // Destroy virtqueue
                {
                    let vq = qs
                        .queue
                        .try_lock()
                        .expect("queue not locked during cleanup");
                    vq.destroy();
                }

                // Manually deallocate the packed indirect table allocation for the arena.
                if let Some(va) = qs.arena.indirect_pages_va {
                    unsafe {
                        unmap_range(va, (qs.arena.indirect_pages_count * 4096) as u64);
                    }
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
    let _guard = WaiterGuard {
        counter: &qs.waiting_tasks,
    };

    let mut spins: u32 = 0;
    const SPIN_BEFORE_WAIT: u32 = 10;

    loop {
        // All operations below are lock-free via QueueState delegation methods

        // Read drain epoch (lock-free)
        let epoch_before = qs.drain_epoch();

        // Try to take our completion (lock-free)
        if let Some(len) = qs.take_completion(head) {
            // Defer descriptor freeing (lock-free push to MPSC queue)
            qs.defer_free_chain(head);
            return Ok(len);
        }

        // Try to become the drainer (lock-free)
        let we_are_drainer = qs.try_acquire_drainer();

        let mut made_progress = false;

        if we_are_drainer {
            // Drain used ring to completions (lock-free CAS loop)
            let drained = qs.drain_used_to_completions_lockfree();

            if drained > 0 {
                made_progress = true;
                spins = 0;

                // Wake other waiters
                if let Some(irq_handle) = unsafe { &*qs.irq_handle.get() } {
                    let waiters = qs.waiting_tasks.load(Ordering::Acquire);
                    let to_wake = waiters.saturating_sub(1);
                    if to_wake > 0 {
                        irq_handle.signal_n(meta, to_wake);
                    }
                }
            }

            // Check for our completion again (lock-free)
            if let Some(len) = qs.take_completion(head) {
                qs.release_drainer();
                qs.defer_free_chain(head);
                return Ok(len);
            }

            qs.release_drainer();
        } else {
            // Non-drainer path - just check completion (lock-free)
            if let Some(len) = qs.take_completion(head) {
                qs.defer_free_chain(head);
                return Ok(len);
            }
        }

        if made_progress {
            continue;
        }

        // Check if epoch changed (lock-free)
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

/// Total data to transfer per benchmark run.
const BENCH_TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;

struct BenchConfig {
    /// Target payload size per request (512-byte aligned, fits any queue).
    request_size: u32,
    /// Number of fixed-size requests to cover BENCH_TOTAL_BYTES.
    requests_per_run: u32,
    /// Maximum inflight requests that can fit in the queue.
    max_queue_inflight: u16,
}

impl BenchConfig {
    fn from_inner(inner: &DevExtInner) -> Self {
        // Keep this aligned and predictable. If you actually want "small", set this to 4*1024.
        let request_size: u32 = PREALLOCATED_DATA_SIZE as u32;

        let requests_per_run =
            ((BENCH_TOTAL_BYTES + request_size as u64 - 1) / request_size as u64).max(1) as u32;

        let min_queue_size = inner
            .queues
            .iter()
            .map(|qs| {
                let vq = unsafe { &*qs.queue.as_ptr() };
                vq.size as usize
            })
            .min()
            .unwrap_or(64);

        // If indirect is enabled, each request consumes 1 main-ring descriptor (the INDIRECT head).
        // Otherwise, it consumes 1(header) + N(4KiB segments) + 1(status).
        let max_queue_inflight = if inner.indirect_desc_enabled {
            min_queue_size.max(1) as u16
        } else {
            let data_segments = ((request_size as usize + 4095) / 4096).max(1);
            let descriptors_per_request = 1 + data_segments + 1;
            (min_queue_size / descriptors_per_request).max(1) as u16
        };

        Self {
            request_size,
            requests_per_run,
            max_queue_inflight,
        }
    }
}

/// State for a single in-flight benchmark request.
struct BenchInflightSlot<'a> {
    /// Arena request handle (owns DMA buffers).
    io_req: blk::BlkIoRequestHandle<'a>,
    /// Descriptor chain head in the virtqueue.
    head: u16,
    /// TSC when request was submitted.
    start_tsc: u64,
}

/// Run a benchmark with a specific inflight request count by submitting directly to the virtqueue.
/// - `use_interrupts`: if true, await interrupts when queue is full or waiting for completions.
///   if false, always poll without waiting.
async fn bench_reads_direct(
    inner: &DevExtInner,
    start_sector: u64,
    inflight: usize,
    bench_cfg: &BenchConfig,
    use_interrupts: bool,
) -> Result<BenchLevelResult, DriverStatus> {
    // Wait for IRQ subsystem to be ready
    inner.irq_ready.wait().await;

    // Use queue 0 for benchmarking (simplifies logic, avoids cross-queue coordination)
    let qs = inner.get_queue(0);

    // Snap inflight to max queue capacity if requested is higher
    let effective_inflight = (inflight as u16).min(bench_cfg.max_queue_inflight) as usize;
    if effective_inflight == 0 {
        return Err(DriverStatus::InvalidParameter);
    }

    let sectors_per_request = (bench_cfg.request_size as u64) >> 9;
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

    // Track in-flight requests (circular buffer style)
    let mut inflight_slots: Vec<Option<BenchInflightSlot<'_>>> =
        (0..effective_inflight).map(|_| None).collect();
    let mut next_slot = 0usize;
    let mut submitted = 0u32;
    let mut completed_count = 0u32;
    let mut current_sector = start_sector;

    // Latency samples
    let mut lat_samples: Vec<u64> = Vec::with_capacity(total_requests as usize);

    let meta = kernel_api::kernel_types::irq::IrqMeta {
        tag: 0,
        data: [0; 3],
    };

    let run_start_tsc = rdtsc();

    // Main benchmark loop
    while completed_count < total_requests {
        // Phase 1: Submit as many requests as possible up to inflight limit
        while submitted < total_requests {
            // Check if we have a free slot
            if inflight_slots[next_slot].is_some() {
                // Slot occupied, need to wait for completion
                break;
            }

            // Allocate request from arena
            let io_req =
                match qs
                    .arena
                    .new_request(VIRTIO_BLK_T_IN, current_sector, bench_cfg.request_size)
                {
                    Some(r) => r,
                    None => {
                        // Arena exhausted, wait for completions
                        break;
                    }
                };

            // Try to submit to queue
            let head = {
                let mut vq = qs.queue.lock().await;
                let use_indirect = inner.indirect_desc_enabled;
                match io_req.submit(&mut vq, false, use_indirect) {
                    Some(h) => {
                        vq.notify(inner.notify_base, inner.notify_off_multiplier);
                        h
                    }
                    None => {
                        // Queue full, drop io_req (returns to arena) and wait
                        break;
                    }
                }
            };

            let start_tsc = rdtsc();

            inflight_slots[next_slot] = Some(BenchInflightSlot {
                io_req,
                head,
                start_tsc,
            });

            submitted += 1;
            current_sector = current_sector.saturating_add(sectors_per_request);
            next_slot = (next_slot + 1) % effective_inflight;
        }

        // Phase 2: Check for completions
        let mut made_progress = false;

        // Try to drain used ring
        if qs.try_acquire_drainer() {
            let drained = qs.drain_used_to_completions_lockfree();
            qs.release_drainer();
            if drained > 0 {
                made_progress = true;
            }
        }

        // Check all inflight slots for completions
        for slot in inflight_slots.iter_mut() {
            if let Some(inflight) = slot.as_ref() {
                if let Some(_len) = qs.take_completion(inflight.head) {
                    let end_tsc = rdtsc();
                    let latency = end_tsc.saturating_sub(inflight.start_tsc);
                    lat_samples.push(latency);

                    // Check status
                    if inflight.io_req.status() != VIRTIO_BLK_S_OK {
                        return Err(DriverStatus::DeviceError);
                    }

                    // Defer freeing the descriptor chain
                    qs.defer_free_chain(inflight.head);

                    completed_count += 1;
                    made_progress = true;

                    // Clear the slot (io_req dropped here, returns to arena)
                    *slot = None;
                }
            }
        }

        // Phase 3: If no progress and we need to wait
        if !made_progress && completed_count < total_requests {
            if use_interrupts {
                // Wait for interrupt if we have pending requests
                let any_inflight = inflight_slots.iter().any(|s| s.is_some());
                if any_inflight {
                    if let Some(irq_handle) = unsafe { &*qs.irq_handle.get() } {
                        qs.waiting_tasks.fetch_add(1, Ordering::AcqRel);
                        let wait_result = irq_handle.wait(meta).await;
                        qs.waiting_tasks.fetch_sub(1, Ordering::AcqRel);

                        if !irq_wait_ok(wait_result) {
                            return Err(DriverStatus::DeviceError);
                        }
                    } else {
                        // No IRQ handle, just spin
                        spin_loop();
                    }
                }
            } else {
                // Polling mode: just spin briefly and retry
                spin_loop();
            }
        }
    }

    let run_end_tsc = rdtsc();

    result.request_count = lat_samples.len() as u32;
    result.total_time_cycles = run_end_tsc.saturating_sub(run_start_tsc);

    if !lat_samples.is_empty() {
        let mut sorted = lat_samples.clone();
        let total_cycles: u64 = lat_samples.iter().copied().sum();
        sorted.sort_unstable();

        let percentile_idx = |pct: f64, len: usize| -> usize {
            let len_minus_one = (len.saturating_sub(1)) as f64;
            let idx = (len_minus_one * pct) + 0.5;
            idx as usize
        };

        result.total_cycles = total_cycles;
        result.max_cycles = *sorted.last().unwrap_or(&0);
        result.min_cycles = *sorted.first().unwrap_or(&0);
        result.avg_cycles = total_cycles / sorted.len() as u64;
        result.p50_cycles = sorted[percentile_idx(0.50, sorted.len()).min(sorted.len() - 1)];
        result.p99_cycles = sorted[percentile_idx(0.99, sorted.len()).min(sorted.len() - 1)];
        result.p999_cycles = sorted[percentile_idx(0.999, sorted.len()).min(sorted.len() - 1)];
    } else {
        result.min_cycles = 0;
    }

    Ok(result)
}

/// Run a benchmark sweep across multiple inflight levels.
/// Requests are submitted directly to the virtqueue, bypassing the PnP request path.
/// Inflight is snapped to max queue capacity if it exceeds what the queue can hold.
async fn bench_sweep(
    inner: &DevExtInner,
    use_interrupts: bool,
) -> Result<BenchSweepResult, DriverStatus> {
    let bench_cfg = BenchConfig::from_inner(inner);

    // Test levels from 1 up to max queue capacity
    // With 256-desc queue and 4KB requests (3 desc each), max ~85 inflight
    let max_inflight = bench_cfg.max_queue_inflight as usize;
    let levels: [usize; 8] = [1, 2, 4, 8, 16, 32, 64, 85];

    let sectors_per_run =
        ((bench_cfg.request_size as u64) >> 9).saturating_mul(bench_cfg.requests_per_run as u64);

    let mut result = BenchSweepResult::default();

    // Each level uses a different starting sector to avoid host/page cache hits.
    let mut current_sector: u64 = 0;

    for &level in levels.iter() {
        // Snap to max queue capacity
        let effective_level = level.min(max_inflight).max(1);

        // Skip if we've already tested this effective level
        if result.used > 0 {
            let prev_level = result.levels[result.used as usize - 1].inflight as usize;
            if effective_level == prev_level {
                // Already tested this level, stop the sweep
                break;
            }
        }

        // Start idle tracking right before the level begins
        kernel_api::benchmark::idle_tracking_start();

        // Run benchmark for this level with unique disk region
        let mut level_result = bench_reads_direct(
            inner,
            current_sector,
            effective_level,
            &bench_cfg,
            use_interrupts,
        )
        .await?;

        // Stop idle tracking and record the idle percentage for this level
        level_result.idle_pct = kernel_api::benchmark::idle_tracking_stop();

        result.levels[result.used as usize] = level_result;
        result.used += 1;

        // Advance to next region for the next level to avoid cache hits
        current_sector = current_sector.wrapping_add(sectors_per_run);

        // Stop if we've hit the max queue capacity
        if effective_level >= max_inflight {
            break;
        }
    }

    Ok(result)
}

// =============================================================================
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

    // Select starting queue, but allow falling back to others if full.
    let mut queue_idx = inner.select_queue();
    let queue_count = inner.queue_count.max(1);
    let max_chunk = inner
        .queues
        .iter()
        .map(|q| q.max_request_bytes.max(512) as u64)
        .min()
        .unwrap_or(512);

    // Use this queue's arena allocator for request (returns slot on drop)
    let mut remaining = len as u64;
    let mut buf_offset = 0usize;
    let mut next_sector = sector;

    // Wait for IRQ subsystem to be ready
    inner.irq_ready.wait().await;

    let meta = IrqMeta {
        tag: 0,
        data: [0; 3],
    };

    while remaining > 0 {
        let chunk_len = core::cmp::min(max_chunk, remaining) as u32;

        // Try all queues before waiting for space.
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
                    None => {
                        // io_req dropped here, returning slot to arena automatically
                        continue;
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
                let dst = &mut w.data_slice_mut()[buf_offset..buf_offset + chunk_len as usize];
                dst.copy_from_slice(io_req.data_slice());
            }

            remaining = remaining.saturating_sub(chunk_len as u64);
            buf_offset += chunk_len as usize;
            next_sector = next_sector.saturating_add((chunk_len as u64) >> 9);
            queue_idx = (qi + 1) % queue_count; // advance starting queue for fairness
            submitted = true;
            break;
        }

        if submitted {
            continue;
        }

        // All queues full/exhausted: wait for an IRQ, then retry.
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

    // All chunk requests completed successfully; their handles have been dropped and returned.
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

    // Select starting queue, but allow falling back to others if full.
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

    // Wait for IRQ subsystem to be ready
    inner.irq_ready.wait().await;

    let meta = IrqMeta {
        tag: 0,
        data: [0; 3],
    };

    while remaining > 0 {
        let chunk_len = core::cmp::min(max_chunk, remaining) as u32;

        // Try all queues before waiting for space.
        let mut submitted = false;
        let start_idx = queue_idx;
        for attempt in 0..queue_count {
            let qi = (start_idx + attempt) % queue_count;
            let qs = inner.get_queue(qi);

            // Use this queue's arena allocator for request (returns slot on drop)
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
                    None => {
                        // io_req dropped here, returning slot to arena automatically
                        continue;
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

            remaining = remaining.saturating_sub(chunk_len as u64);
            buf_offset += chunk_len as usize;
            next_sector = next_sector.saturating_add((chunk_len as u64) >> 9);
            queue_idx = (qi + 1) % queue_count; // advance starting queue for fairness
            submitted = true;
            break;
        }

        if submitted {
            continue;
        }

        // All queues full/exhausted: wait for an IRQ, then retry.
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

    // Chunk requests dropped here, returning slots to arena automatically
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

            // Run benchmark with interrupts enabled
            match bench_sweep(inner, true).await {
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
        IOCTL_BLOCK_BENCH_SWEEP_POLLING => {
            let (_parent, inner) = match get_parent_inner(&pdo) {
                Ok(v) => v,
                Err(s) => return complete_req(req, s),
            };

            // Run benchmark in polling mode (no interrupt waits)
            match bench_sweep(inner, false).await {
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
