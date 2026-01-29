#![no_std]
#![no_main]
#![feature(const_option_ops)]
#![feature(const_trait_impl)]
extern crate alloc;

mod blk;
mod dev_ext;
mod pci;
mod virtqueue;

use alloc::{sync::Arc, vec::Vec};
use core::panic::PanicInfo;

use kernel_api::device::{DeviceInit, DeviceObject, DriverObject};
use kernel_api::irq::{IrqHandle, irq_register_isr, irq_wait_ok};
use kernel_api::kernel_types::io::{IoType, IoVtable, Synchronization};
use kernel_api::kernel_types::irq::{IrqHandlePtr, IrqMeta};
use kernel_api::kernel_types::request::RequestData;
use kernel_api::memory::unmap_mmio_region;
use kernel_api::pnp::{
    DeviceRelationType, DriverStep, PnpMinorFunction, PnpRequest, PnpVtable, QueryIdType,
    driver_set_evt_device_add, pnp_forward_request_to_next_lower,
};
use kernel_api::request::{Request, RequestType};
use kernel_api::status::DriverStatus;
use kernel_api::x86_64::VirtAddr;
use kernel_api::{RequestExt, println, request_handler};
use spin::Mutex;
use spin::rwlock::RwLock;

use blk::{BlkIoRequest, VIRTIO_BLK_S_OK, VIRTIO_BLK_T_IN, VIRTIO_BLK_T_OUT};
use dev_ext::{DevExt, DevExtInner};
use virtqueue::Virtqueue;

static MOD_NAME: &str = option_env!("CARGO_PKG_NAME").unwrap_or(module_path!());

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    use kernel_api::util::panic_common;
    unsafe { panic_common(MOD_NAME, info) }
}

// ===========================================================================
// Driver entry
// ===========================================================================

#[unsafe(no_mangle)]
pub extern "win64" fn DriverEntry(driver: &Arc<DriverObject>) -> DriverStatus {
    println!("virtio-blk: DriverEntry\n");
    driver_set_evt_device_add(driver, virtio_device_add);
    DriverStatus::Success
}

pub extern "win64" fn virtio_device_add(
    _driver: Arc<DriverObject>,
    dev_init: &mut DeviceInit,
) -> DriverStep {
    let mut io_vt = IoVtable::new();
    io_vt.set(IoType::Read(virtio_blk_read), Synchronization::Async, 0);
    io_vt.set(IoType::Write(virtio_blk_write), Synchronization::Async, 0);
    io_vt.set(
        IoType::DeviceControl(virtio_blk_ioctl),
        Synchronization::Async,
        0,
    );

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

// ===========================================================================
// ISR — signals the IRQ handle from interrupt context
// ===========================================================================

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
            core::mem::forget(h); // ISR doesn't own the handle
        }
        true
    } else {
        false
    }
}

// ===========================================================================
// PnP: StartDevice
// ===========================================================================

#[request_handler]
async fn virtio_pnp_start(dev: Arc<DeviceObject>, req: Arc<RwLock<Request>>) -> DriverStep {
    let status = pnp_forward_request_to_next_lower(dev.clone(), req.clone()).await;
    if status != DriverStatus::Success {
        println!("virtio-blk: lower driver start failed: {:?}\n", status);
        return DriverStep::complete(status);
    }

    // Query resources from PDO
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
        println!("virtio-blk: QueryResources failed: {:?}\n", qr_status);
        return DriverStep::complete(qr_status);
    }

    let blob = { res_req.read().pnp.as_ref().unwrap().blob_out.clone() };
    let resources = pci::parse_resources(&blob);

    // Map memory BARs
    let mapped_bars = pci::map_memory_bars(&resources);
    if mapped_bars.is_empty() {
        println!("virtio-blk: no memory BARs found\n");
        return DriverStep::complete(DriverStatus::DeviceError);
    }

    let irq_vector = pci::find_irq(&resources);
    let cfg_base = mapped_bars[0].1;

    let caps = match pci::parse_virtio_caps(cfg_base, &mapped_bars) {
        Some(c) => c,
        None => {
            println!("virtio-blk: failed to parse virtio PCI capabilities\n");
            for &(_idx, va, sz) in &mapped_bars {
                let _ = unmap_mmio_region(va, sz);
            }
            return DriverStep::complete(DriverStatus::DeviceError);
        }
    };

    let capacity = match blk::init_device(caps.common_cfg, caps.device_cfg) {
        Some(c) => c,
        None => {
            println!("virtio-blk: device init / feature negotiation failed\n");
            for &(_idx, va, sz) in &mapped_bars {
                let _ = unmap_mmio_region(va, sz);
            }
            return DriverStep::complete(DriverStatus::DeviceError);
        }
    };

    let vq = match Virtqueue::new(0, caps.common_cfg) {
        Some(vq) => vq,
        None => {
            println!("virtio-blk: failed to create requestq\n");
            blk::reset_device(caps.common_cfg);
            for &(_idx, va, sz) in &mapped_bars {
                let _ = unmap_mmio_region(va, sz);
            }
            return DriverStep::complete(DriverStatus::DeviceError);
        }
    };

    let irq_handle = if let Some(vector) = irq_vector {
        irq_register_isr(vector, virtio_isr, caps.isr_cfg.as_u64() as usize)
    } else {
        None
    };

    blk::set_driver_ok(caps.common_cfg);

    println!(
        "virtio-blk: started, capacity={} sectors ({}MiB), irq={:?}\n",
        capacity,
        capacity * 512 / (1024 * 1024),
        irq_vector,
    );

    // Populate the device extension (set via Once)
    let dx = dev.try_devext::<DevExt>().expect("virtio: DevExt missing");
    let bar_list: Vec<(VirtAddr, u64)> = mapped_bars.iter().map(|&(_, va, sz)| (va, sz)).collect();
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
    });

    DriverStep::complete(DriverStatus::Success)
}

// ===========================================================================
// PnP: RemoveDevice
// ===========================================================================

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
                for &(va, sz) in bars.iter() {
                    let _ = unmap_mmio_region(va, sz);
                }
            }
        }
    }

    DriverStep::complete(DriverStatus::Success)
}

// ===========================================================================
// PnP: QueryDeviceRelations — no children (leaf driver)
// ===========================================================================

#[request_handler]
async fn virtio_pnp_query_devrels(
    _dev: Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
) -> DriverStep {
    let relation = { req.read().pnp.as_ref().unwrap().relation };
    if relation == DeviceRelationType::BusRelations {
        return DriverStep::complete(DriverStatus::Success);
    }
    DriverStep::Continue
}

// ===========================================================================
// I/O: Read (fully async via IRQ)
// ===========================================================================

#[request_handler]
pub async fn virtio_blk_read(
    dev: Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
    _buf_len: usize,
) -> DriverStep {
    let dx = match dev.try_devext::<DevExt>() {
        Ok(x) => x,
        Err(_) => return DriverStep::complete(DriverStatus::NoSuchDevice),
    };
    let inner = match dx.inner.get() {
        Some(i) => i,
        None => return DriverStep::complete(DriverStatus::DeviceNotReady),
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

    // Await completion via IRQ — fully async, no blocking
    if let Some(ref irq_handle) = inner.irq_handle {
        let meta = IrqMeta {
            tag: 0,
            data: [0; 3],
        };
        let result = irq_handle.wait(meta).await;
        if !irq_wait_ok(result) {
            let mut vq = inner.requestq.lock();
            vq.free_chain(head);
            io_req.destroy();
            return DriverStep::complete(DriverStatus::DeviceError);
        }
    }

    {
        let mut vq = inner.requestq.lock();
        let _ = vq.pop_used();
        vq.free_chain(head);
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

// ===========================================================================
// I/O: Write (fully async via IRQ)
// ===========================================================================

#[request_handler]
pub async fn virtio_blk_write(
    dev: Arc<DeviceObject>,
    req: Arc<RwLock<Request>>,
    _buf_len: usize,
) -> DriverStep {
    let dx = match dev.try_devext::<DevExt>() {
        Ok(x) => x,
        Err(_) => return DriverStep::complete(DriverStatus::NoSuchDevice),
    };
    let inner = match dx.inner.get() {
        Some(i) => i,
        None => return DriverStep::complete(DriverStatus::DeviceNotReady),
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

    if let Some(ref irq_handle) = inner.irq_handle {
        let meta = IrqMeta {
            tag: 0,
            data: [0; 3],
        };
        let result = irq_handle.wait(meta).await;
        if !irq_wait_ok(result) {
            let mut vq = inner.requestq.lock();
            vq.free_chain(head);
            io_req.destroy();
            return DriverStep::complete(DriverStatus::DeviceError);
        }
    }

    {
        let mut vq = inner.requestq.lock();
        let _ = vq.pop_used();
        vq.free_chain(head);
    }

    if io_req.status() != VIRTIO_BLK_S_OK {
        io_req.destroy();
        return DriverStep::complete(DriverStatus::DeviceError);
    }

    io_req.destroy();
    DriverStep::complete(DriverStatus::Success)
}

// ===========================================================================
// I/O: DeviceControl
// ===========================================================================

const IOCTL_BLOCK_FLUSH: u32 = 0xB000_0003;

#[request_handler]
pub async fn virtio_blk_ioctl(_dev: Arc<DeviceObject>, req: Arc<RwLock<Request>>) -> DriverStep {
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
