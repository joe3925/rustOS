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
use core::sync::atomic::Ordering;
use kernel_api::kernel_types::pnp::DeviceIds;

use kernel_api::device::{DeviceInit, DeviceObject, DriverObject};
use kernel_api::irq::{
    IrqHandle, irq_alloc_vector, irq_free_vector, irq_register_isr, irq_register_isr_gsi,
    irq_wait_ok,
};
use kernel_api::kernel_types::io::{IoType, IoVtable, Synchronization};
use kernel_api::kernel_types::irq::{IrqHandlePtr, IrqMeta};
use kernel_api::kernel_types::request::RequestData;
use kernel_api::memory::unmap_mmio_region;
use kernel_api::pnp::{
    DeviceRelationType, DriverStep, PnpMinorFunction, PnpRequest, PnpVtable, QueryIdType,
    driver_set_evt_device_add, pnp_create_child_devnode_and_pdo_with_init,
    pnp_forward_request_to_next_lower,
};
use kernel_api::request::{Request, RequestType};
use kernel_api::status::DriverStatus;
use kernel_api::x86_64::VirtAddr;
use kernel_api::{IOCTL_PCI_SETUP_MSIX, RequestExt, println, request_handler};
use spin::Mutex;
use spin::rwlock::RwLock;

use blk::{BlkIoRequest, VIRTIO_BLK_S_OK, VIRTIO_BLK_T_IN, VIRTIO_BLK_T_OUT};
use dev_ext::{ChildExt, DevExt, DevExtInner};
use virtqueue::Virtqueue;

static MOD_NAME: &str = option_env!("CARGO_PKG_NAME").unwrap_or(module_path!());

const PIC_BASE_VECTOR: u8 = 0x20;

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

/// MSI-X ISR - simpler than legacy ISR since MSI-X is edge-triggered and dedicated.
/// No need to poll the ISR register.
extern "win64" fn virtio_msix_isr(
    _vector: u8,
    _cpu: u32,
    _frame: *mut kernel_api::x86_64::structures::idt::InterruptStackFrame,
    handle: IrqHandlePtr,
    _ctx: usize,
) -> bool {
    // MSI-X interrupts are dedicated - always signal
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

    let req = Request::new(
        RequestType::DeviceControl(IOCTL_PCI_SETUP_MSIX),
        RequestData::from_boxed_bytes(buf.into_boxed_slice()),
    );
    let req = Arc::new(RwLock::new(req));
    let status = pnp_forward_request_to_next_lower(dev.clone(), req.clone()).await;

    if status == DriverStatus::Success {
        Ok(())
    } else {
        Err(status)
    }
}

#[request_handler]
async fn virtio_pnp_start(dev: Arc<DeviceObject>, req: Arc<RwLock<Request>>) -> DriverStep {
    let res_req = Arc::new(RwLock::new(Request::new_pnp(
        PnpRequest {
            minor_function: PnpMinorFunction::QueryResources,
            relation: DeviceRelationType::TargetDeviceRelation,
            id_type: QueryIdType::CompatibleIds,
            ids_out: Vec::new(),
            blob_out: Vec::new(),
        },
        RequestData::empty(),
    )));
    let qr_status = pnp_forward_request_to_next_lower(dev.clone(), res_req.clone()).await;
    if qr_status != DriverStatus::Success {
        println!("virtio-blk: QueryResources failed: {:?}", qr_status);
        return DriverStep::complete(qr_status);
    }

    let blob = { res_req.read().pnp.as_ref().unwrap().blob_out.clone() };
    let resources = pci::parse_resources(&blob);
    let msix_cap = pci::find_msix_capability(&resources);

    let mapped_bars = pci::map_memory_bars(&resources);
    if mapped_bars.is_empty() {
        println!("virtio-blk: no memory BARs found");
        return DriverStep::complete(DriverStatus::DeviceError);
    }

    let (cfg_phys, cfg_len) = match pci::find_config_space(&resources) {
        Some(v) => v,
        None => {
            println!("virtio-blk: no PCI config space resource");
            for &(_idx, va, sz) in &mapped_bars {
                let _ = unmap_mmio_region(va, sz);
            }
            return DriverStep::complete(DriverStatus::DeviceError);
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
            return DriverStep::complete(DriverStatus::DeviceError);
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
            return DriverStep::complete(DriverStatus::DeviceError);
        }
    };

    let _ = unmap_mmio_region(cfg_base, cfg_len);

    let capacity = match blk::init_device(caps.common_cfg, caps.device_cfg) {
        Some(c) => c,
        None => {
            println!("virtio-blk: device init / feature negotiation failed");
            for &(_idx, va, sz) in &mapped_bars {
                let _ = unmap_mmio_region(va, sz);
            }
            return DriverStep::complete(DriverStatus::DeviceError);
        }
    };

    let vq = match Virtqueue::new(0, caps.common_cfg) {
        Some(vq) => vq,
        None => {
            println!("virtio-blk: failed to create requestq");
            blk::reset_device(caps.common_cfg);
            for &(_idx, va, sz) in &mapped_bars {
                let _ = unmap_mmio_region(va, sz);
            }
            return DriverStep::complete(DriverStatus::DeviceError);
        }
    };

    let (irq_handle, msix_vector): (Option<IrqHandle>, Option<u8>) = if msix_cap.is_some() {
        match irq_alloc_vector() {
            Some(vector) => {
                if let Some(handle) = irq_register_isr(vector, virtio_msix_isr, 0) {
                    match setup_msix_via_pci(&dev, vector, 0, 0).await {
                        Ok(()) => {
                            unsafe {
                                pci::common_write_u16(caps.common_cfg, pci::COMMON_MSIX_CONFIG, 0);
                                pci::common_write_u16(caps.common_cfg, pci::COMMON_QUEUE_SELECT, 0);
                                pci::common_write_u16(
                                    caps.common_cfg,
                                    pci::COMMON_QUEUE_MSIX_VECTOR,
                                    0,
                                );
                            }
                            // Verify the device accepted the MSI-X vector (0xFFFF = rejected)
                            let readback = unsafe {
                                pci::common_read_u16(caps.common_cfg, pci::COMMON_QUEUE_MSIX_VECTOR)
                            };
                            if readback == 0xFFFF {
                                println!("virtio-blk: Device rejected MSI-X vector, falling back");
                                handle.unregister();
                                let _ = irq_free_vector(vector);
                                (None, None)
                            } else {
                                (Some(handle), Some(vector))
                            }
                        }
                        Err(e) => {
                            println!(
                                "virtio-blk: MSI-X setup IOCTL failed: {:?}, falling back",
                                e
                            );
                            handle.unregister();
                            let _ = irq_free_vector(vector);
                            (None, None)
                        }
                    }
                } else {
                    let _ = irq_free_vector(vector);
                    (None, None)
                }
            }
            None => (None, None),
        }
    } else {
        (None, None)
    };

    let irq_handle: Option<IrqHandle> = if irq_handle.is_some() {
        irq_handle
    } else if let Some(gsi) = pci::find_gsi(&resources) {
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
    };

    let msix_table_index = if msix_vector.is_some() {
        Some(0u16)
    } else {
        None
    };
    let msix_pba = match (msix_vector, msix_cap) {
        (Some(_), Some(cap)) => mapped_bars
            .iter()
            .find(|(idx, _, _)| *idx == cap.pba_bar as u32)
            .map(|(_, va, _)| VirtAddr::new(va.as_u64() + cap.pba_offset as u64)),
        _ => None,
    };

    // Queue must remain disabled until after the MSI-X vector (if any) is programmed.
    vq.enable(caps.common_cfg);
    blk::set_driver_ok(caps.common_cfg);

    // Check device status to catch any latent failure before exposing the queue.
    let status = unsafe { pci::common_read_u8(caps.common_cfg, pci::COMMON_DEVICE_STATUS) };
    if status & blk::VIRTIO_STATUS_FAILED != 0 || status & blk::VIRTIO_STATUS_DRIVER_OK == 0 {
        println!(
            "virtio-blk: device status bad after DRIVER_OK: status={:#x}",
            status
        );
        blk::reset_device(caps.common_cfg);
        vq.destroy();
        if let Some(ref h) = irq_handle {
            h.unregister();
        }
        for &(_idx, va, sz) in &mapped_bars {
            let _ = unmap_mmio_region(va, sz);
        }
        return DriverStep::complete(DriverStatus::DeviceError);
    }

    let dx = dev.try_devext::<DevExt>().expect("virtio: DevExt missing");
    let bar_list: Vec<(u32, VirtAddr, u64)> = mapped_bars.iter().copied().collect();

    let irq_ready = dev_ext::InitGate::new();

    dx.inner.call_once(|| DevExtInner {
        common_cfg: caps.common_cfg,
        notify_base: caps.notify_base,
        notify_off_multiplier: caps.notify_off_multiplier,
        isr_cfg: caps.isr_cfg,
        device_cfg: caps.device_cfg,
        requestq: Mutex::new(vq),
        capacity,
        irq_handle,
        mapped_bars: Mutex::new(bar_list),
        msix_vector,
        msix_table_index,
        msix_pba,
        irq_ready,
    });

    if let Some(inner) = dx.inner.get() {
        // Interrupt path is configured; either IRQ handle is present or we will poll.
        inner.irq_ready.set_ready();
    }

    DriverStep::complete(DriverStatus::Success)
}

#[request_handler]
async fn virtio_pnp_remove(dev: Arc<DeviceObject>, _req: Arc<RwLock<Request>>) -> DriverStep {
    if let Ok(dx) = dev.try_devext::<DevExt>() {
        if let Some(inner) = dx.inner.get() {
            blk::reset_device(inner.common_cfg);

            if let Some(ref h) = inner.irq_handle {
                h.unregister();
            }

            {
                let vq = inner.requestq.lock();
                vq.destroy();
            }

            {
                let bars = inner.mapped_bars.lock();
                for &(_, va, sz) in bars.iter() {
                    let _ = unmap_mmio_region(va, sz);
                }
            }
        }
    }

    DriverStep::complete(DriverStatus::Success)
}

#[request_handler]
async fn virtio_pnp_query_devrels(dev: Arc<DeviceObject>, req: Arc<RwLock<Request>>) -> DriverStep {
    let relation = { req.read().pnp.as_ref().unwrap().relation };
    if relation == DeviceRelationType::BusRelations {
        create_child_pdo(&dev);
        return DriverStep::complete(DriverStatus::Success);
    }
    DriverStep::Continue
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

async fn wait_for_completion(inner: &DevExtInner, head: u16) -> Result<(), DriverStatus> {
    if let Some(ref irq_handle) = inner.irq_handle {
        let meta = IrqMeta {
            tag: 0,
            data: [0; 3],
        };
        let result = irq_handle.wait(meta).await;
        if !irq_wait_ok(result) {
            let mut vq = inner.requestq.lock();
            vq.free_chain(head);
            return Err(DriverStatus::DeviceError);
        }
    }

    loop {
        {
            let mut vq = inner.requestq.lock();
            if let Some((used_head, _)) = vq.pop_used() {
                vq.free_chain(used_head as u16);
                if used_head as u16 == head {
                    return Ok(());
                }
                // Free unrelated completions while we wait for our head.
                continue;
            }
        }

        // Poll for completion when no interrupt is configured, or wait for the
        // device to update the used ring after an interrupt.
        spin_loop();
    }
}

const IOCTL_BLOCK_FLUSH: u32 = 0xB000_0003;

#[request_handler]
pub async fn virtio_pdo_start(_dev: Arc<DeviceObject>, _req: Arc<RwLock<Request>>) -> DriverStep {
    DriverStep::complete(DriverStatus::Success)
}

#[request_handler]
pub async fn virtio_pdo_query_id(pdo: Arc<DeviceObject>, req: Arc<RwLock<Request>>) -> DriverStep {
    let ty = { req.read().pnp.as_ref().unwrap().id_type };
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
    DriverStep::complete(DriverStatus::Success)
}

#[request_handler]
pub async fn virtio_pdo_query_resources(
    pdo: Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
) -> DriverStep {
    let cdx = match pdo.try_devext::<ChildExt>() {
        Ok(x) => x,
        Err(_) => return DriverStep::complete(DriverStatus::NoSuchDevice),
    };

    let mut w = req.write();
    let Some(p) = w.pnp.as_mut() else {
        return DriverStep::complete(DriverStatus::InvalidParameter);
    };

    let di = &cdx.disk_info;
    let di_ptr = di as *const kernel_api::kernel_types::io::DiskInfo as *const u8;
    let n = core::mem::size_of::<kernel_api::kernel_types::io::DiskInfo>();
    let bytes = unsafe { core::slice::from_raw_parts(di_ptr, n) };
    p.blob_out = bytes.to_vec();

    DriverStep::complete(DriverStatus::Success)
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
pub async fn virtio_pdo_read(
    pdo: Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
    _buf_len: usize,
) -> DriverStep {
    let (_parent, inner) = match get_parent_inner(&pdo) {
        Ok(v) => v,
        Err(s) => return DriverStep::complete(s),
    };

    let (offset, len) = {
        let r = req.read();
        match r.kind {
            RequestType::Read { offset, len } => (offset, len),
            _ => return DriverStep::complete(DriverStatus::InvalidParameter),
        }
    };

    if len == 0 {
        return DriverStep::complete(DriverStatus::Success);
    }
    if (offset & 0x1FF) != 0 || (len & 0x1FF) != 0 {
        return DriverStep::complete(DriverStatus::InvalidParameter);
    }

    let sector = offset >> 9;

    let io_req = match BlkIoRequest::new(VIRTIO_BLK_T_IN, sector, len as u32) {
        Some(r) => r,
        None => return DriverStep::complete(DriverStatus::InsufficientResources),
    };

    // Wait for IRQ subsystem to be ready
    inner.irq_ready.wait().await;

    let head = {
        let mut vq = inner.requestq.lock();
        match io_req.submit(&mut vq, false) {
            Some(h) => {
                vq.notify(inner.notify_base, inner.notify_off_multiplier);
                h
            }
            None => {
                io_req.destroy();
                return DriverStep::complete(DriverStatus::InsufficientResources);
            }
        }
    };
    if let Err(e) = wait_for_completion(inner, head).await {
        io_req.destroy();
        return DriverStep::complete(e);
    }

    if io_req.status() != VIRTIO_BLK_S_OK {
        io_req.destroy();
        return DriverStep::complete(DriverStatus::DeviceError);
    }

    {
        let mut w = req.write();
        let dst = &mut w.data_slice_mut()[..len];
        dst.copy_from_slice(io_req.data_slice());
    }

    io_req.destroy();
    DriverStep::complete(DriverStatus::Success)
}

#[request_handler]
pub async fn virtio_pdo_write(
    pdo: Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
    _buf_len: usize,
) -> DriverStep {
    let (_parent, inner) = match get_parent_inner(&pdo) {
        Ok(v) => v,
        Err(s) => return DriverStep::complete(s),
    };

    let (offset, len) = {
        let r = req.read();
        match r.kind {
            RequestType::Write { offset, len } => (offset, len),
            _ => return DriverStep::complete(DriverStatus::InvalidParameter),
        }
    };

    if len == 0 {
        return DriverStep::complete(DriverStatus::Success);
    }
    if (offset & 0x1FF) != 0 || (len & 0x1FF) != 0 {
        return DriverStep::complete(DriverStatus::InvalidParameter);
    }

    let sector = offset >> 9;

    let mut io_req = match BlkIoRequest::new(VIRTIO_BLK_T_OUT, sector, len as u32) {
        Some(r) => r,
        None => return DriverStep::complete(DriverStatus::InsufficientResources),
    };

    {
        let r = req.read();
        let src = &r.data_slice()[..len];
        io_req.data_slice_mut().copy_from_slice(src);
    }

    // Wait for IRQ subsystem to be ready
    inner.irq_ready.wait().await;

    let head = {
        let mut vq = inner.requestq.lock();
        match io_req.submit(&mut vq, true) {
            Some(h) => {
                vq.notify(inner.notify_base, inner.notify_off_multiplier);
                h
            }
            None => {
                io_req.destroy();
                return DriverStep::complete(DriverStatus::InsufficientResources);
            }
        }
    };

    if let Err(e) = wait_for_completion(inner, head).await {
        io_req.destroy();
        return DriverStep::complete(e);
    }

    if io_req.status() != VIRTIO_BLK_S_OK {
        io_req.destroy();
        return DriverStep::complete(DriverStatus::DeviceError);
    }

    io_req.destroy();
    DriverStep::complete(DriverStatus::Success)
}

#[request_handler]
pub async fn virtio_pdo_ioctl(_pdo: Arc<DeviceObject>, req: Arc<RwLock<Request>>) -> DriverStep {
    let code = {
        let r = req.read();
        match r.kind {
            RequestType::DeviceControl(c) => c,
            _ => return DriverStep::complete(DriverStatus::InvalidParameter),
        }
    };

    match code {
        IOCTL_BLOCK_FLUSH => DriverStep::complete(DriverStatus::Success),
        _ => DriverStep::complete(DriverStatus::NotImplemented),
    }
}
