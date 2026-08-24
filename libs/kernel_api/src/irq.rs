use kernel_sys::{
    irq_handle_get_user_ctx, irq_handle_is_closed, irq_handle_set_user_ctx, irq_handle_unregister,
    irq_handle_wait_abi, kernel_interrupt_bind_msi, kernel_interrupt_bind_wired,
    kernel_irq_borrowed_ensure_signal, kernel_irq_borrowed_signal, kernel_irq_borrowed_signal_all,
    kernel_irq_borrowed_signal_n, kernel_platform_cpu_ids,
};
use kernel_types::irq::IRQ_RESCUE_WAKEUP;
pub use kernel_types::irq::{
    HardwareInterruptId, IRQ_WAIT_CLOSED, IRQ_WAIT_NULL, IRQ_WAIT_OK, IrqBorrowedHandle, IrqHandle,
    IrqIsrFn, IrqMeta, IrqWaitResult, MsiBinding, MsiBindingRequest, MsiMessage, MsiRequester,
    MsiTarget,
};

use kernel_types::async_ffi::AbiFuture;

use crate::println;

pub trait IrqHandleExt {
    fn unregister(&self);
    fn is_closed(&self) -> bool;
    fn set_user_ctx(&self, v: usize);
    fn user_ctx(&self) -> usize;
    fn wait(&self, meta: IrqMeta) -> AbiFuture<IrqWaitResult>;
}

impl IrqHandleExt for IrqHandle {
    #[inline]
    fn unregister(&self) {
        unsafe { irq_handle_unregister(self) };
    }

    #[inline]
    fn is_closed(&self) -> bool {
        unsafe { irq_handle_is_closed(self) }
    }

    #[inline]
    fn set_user_ctx(&self, v: usize) {
        unsafe { irq_handle_set_user_ctx(self, v) };
    }

    #[inline]
    fn user_ctx(&self) -> usize {
        unsafe { irq_handle_get_user_ctx(self) }
    }

    #[inline]
    fn wait(&self, meta: IrqMeta) -> AbiFuture<IrqWaitResult> {
        unsafe { irq_handle_wait_abi(self, meta) }
    }
}

pub trait IrqBorrowedHandleExt {
    fn signal_one(self, meta: IrqMeta);
    fn signal_n(self, meta: IrqMeta, n: u32);
    fn signal_all(self, meta: IrqMeta);
    fn ensure_signal_exactly_one(self, meta: IrqMeta);
}

impl IrqBorrowedHandleExt for IrqBorrowedHandle {
    #[inline]
    fn signal_one(self, meta: IrqMeta) {
        unsafe {
            kernel_irq_borrowed_signal(self, meta);
        }
    }

    #[inline]
    fn signal_n(self, meta: IrqMeta, n: u32) {
        unsafe {
            kernel_irq_borrowed_signal_n(self, meta, n);
        }
    }

    #[inline]
    fn signal_all(self, meta: IrqMeta) {
        unsafe {
            kernel_irq_borrowed_signal_all(self, meta);
        }
    }

    #[inline]
    fn ensure_signal_exactly_one(self, meta: IrqMeta) {
        unsafe {
            kernel_irq_borrowed_ensure_signal(self, meta);
        }
    }
}

pub fn bind_wired_interrupt(
    source: HardwareInterruptId,
    isr: IrqIsrFn,
    ctx: usize,
) -> Option<IrqHandle> {
    let h = unsafe { kernel_interrupt_bind_wired(source, isr, ctx) };

    if h.is_closed() { None } else { Some(h) }
}

pub fn bind_msi_interrupt(
    request: &MsiBindingRequest,
    isr: IrqIsrFn,
    ctx: usize,
) -> Option<MsiBinding> {
    let mut binding = MsiBinding {
        handle: IrqHandle::null(),
        message: MsiMessage::default(),
    };
    if unsafe { kernel_interrupt_bind_msi(request, isr, ctx, &mut binding) } {
        Some(binding)
    } else {
        None
    }
}

pub fn platform_cpu_ids() -> alloc::vec::Vec<kernel_types::irq::PlatformCpuId> {
    unsafe { kernel_platform_cpu_ids() }
}

#[inline]
pub fn irq_wait_ok(r: IrqWaitResult) -> bool {
    if r.code == IRQ_RESCUE_WAKEUP {
        return irq_rescue_wakeup_ok();
    }

    r.code == IRQ_WAIT_OK
}

#[cold]
fn irq_rescue_wakeup_ok() -> bool {
    println!("saved by rescue wakeup");
    true
}

#[inline]
pub fn irq_wait_closed(r: IrqWaitResult) -> bool {
    r.code == IRQ_WAIT_CLOSED
}

#[inline]
pub fn irq_wait_null(r: IrqWaitResult) -> bool {
    r.code == IRQ_WAIT_NULL
}
