use kernel_sys::{
    irq_handle_get_user_ctx, irq_handle_is_closed, irq_handle_set_user_ctx, irq_handle_unregister,
    irq_handle_wait_ffi, kernel_apic_cpu_ids, kernel_irq_alloc_vector, kernel_irq_ensure_signal,
    kernel_irq_free_vector, kernel_irq_register, kernel_irq_register_gsi, kernel_irq_signal,
    kernel_irq_signal_all, kernel_irq_signal_n,
};
pub use kernel_types::irq::{
    IrqHandle, IrqIsrFn, IrqMeta, IrqWaitResult, IRQ_WAIT_CLOSED, IRQ_WAIT_NULL, IRQ_WAIT_OK,
};

use kernel_types::async_ffi::FfiFuture;

pub trait IrqHandleExt {
    fn unregister(&self);
    fn is_closed(&self) -> bool;
    fn set_user_ctx(&self, v: usize);
    fn user_ctx(&self) -> usize;
    fn signal_one(&self, meta: IrqMeta);
    fn signal_n(&self, meta: IrqMeta, n: u32);
    fn signal_all(&self, meta: IrqMeta);
    fn ensure_signal_exactly_one(&self, meta: IrqMeta);
    fn wait(&self, meta: IrqMeta) -> FfiFuture<IrqWaitResult>;
}

impl IrqHandleExt for IrqHandle {
    fn unregister(&self) {
        unsafe { irq_handle_unregister(self) };
    }

    fn is_closed(&self) -> bool {
        unsafe { irq_handle_is_closed(self) }
    }

    fn set_user_ctx(&self, v: usize) {
        unsafe { irq_handle_set_user_ctx(self, v) };
    }

    fn user_ctx(&self) -> usize {
        unsafe { irq_handle_get_user_ctx(self) }
    }

    fn signal_one(&self, meta: IrqMeta) {
        unsafe { kernel_irq_signal(self, meta) };
    }

    fn signal_n(&self, meta: IrqMeta, n: u32) {
        unsafe { kernel_irq_signal_n(self, meta, n) };
    }

    fn signal_all(&self, meta: IrqMeta) {
        unsafe { kernel_irq_signal_all(self, meta) };
    }

    fn ensure_signal_exactly_one(&self, meta: IrqMeta) {
        unsafe { kernel_irq_ensure_signal(self, meta) };
    }

    fn wait(&self, meta: IrqMeta) -> FfiFuture<IrqWaitResult> {
        unsafe { irq_handle_wait_ffi(self, meta) }
    }
}

pub fn irq_register_isr(vector: u8, isr: IrqIsrFn, ctx: usize) -> Option<IrqHandle> {
    let h = unsafe { kernel_irq_register(vector, isr, ctx) };
    if h.is_closed() {
        None
    } else {
        Some(h)
    }
}

pub fn irq_register_isr_gsi(gsi: u8, isr: IrqIsrFn, ctx: usize) -> Option<IrqHandle> {
    let h = unsafe { kernel_irq_register_gsi(gsi, isr, ctx) };
    if h.is_closed() {
        None
    } else {
        Some(h)
    }
}

pub fn irq_alloc_vector() -> Option<u8> {
    let v = unsafe { kernel_irq_alloc_vector() };
    if v < 0 {
        None
    } else {
        Some(v as u8)
    }
}

pub fn irq_free_vector(vector: u8) -> bool {
    unsafe { kernel_irq_free_vector(vector) }
}

pub fn apic_cpu_ids() -> alloc::vec::Vec<u8> {
    unsafe { kernel_apic_cpu_ids() }
}

pub fn irq_wait_ok(r: IrqWaitResult) -> bool {
    r.code == IRQ_WAIT_OK
}

pub fn irq_wait_closed(r: IrqWaitResult) -> bool {
    r.code == IRQ_WAIT_CLOSED
}

pub fn irq_wait_null(r: IrqWaitResult) -> bool {
    r.code == IRQ_WAIT_NULL
}
