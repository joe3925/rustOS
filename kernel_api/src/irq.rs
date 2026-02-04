use core::ptr::NonNull;

use kernel_sys::{
    irq_handle_clone, irq_handle_drop, irq_handle_get_user_ctx, irq_handle_is_closed,
    irq_handle_set_user_ctx, irq_handle_unregister, irq_handle_wait_ffi, kernel_irq_register,
    kernel_irq_register_gsi, kernel_irq_signal, kernel_irq_signal_n, kernel_irq_alloc_vector,
    kernel_irq_free_vector, kernel_apic_cpu_ids,
};

use kernel_types::async_ffi::FfiFuture;
use kernel_types::irq::{
    IrqHandleOpaque, IrqHandlePtr, IrqIsrFn, IrqMeta, IrqWaitResult, IRQ_WAIT_CLOSED,
    IRQ_WAIT_NULL, IRQ_WAIT_OK,
};
unsafe impl Send for IrqHandle {}
unsafe impl Sync for IrqHandle {}
pub struct IrqHandle {
    ptr: NonNull<IrqHandleOpaque>,
}

impl IrqHandle {
    pub unsafe fn from_raw(ptr: IrqHandlePtr) -> Option<Self> {
        NonNull::new(ptr).map(|p| Self { ptr: p })
    }

    pub fn as_raw(&self) -> IrqHandlePtr {
        self.ptr.as_ptr()
    }

    pub fn unregister(&self) {
        unsafe { irq_handle_unregister(self.as_raw()) };
    }

    pub fn is_closed(&self) -> bool {
        unsafe { irq_handle_is_closed(self.as_raw()) }
    }

    pub fn set_user_ctx(&self, v: usize) {
        unsafe { irq_handle_set_user_ctx(self.as_raw(), v) };
    }

    pub fn user_ctx(&self) -> usize {
        unsafe { irq_handle_get_user_ctx(self.as_raw()) }
    }

    pub fn signal_one(&self, meta: IrqMeta) {
        unsafe { kernel_irq_signal(self.as_raw(), meta) };
    }

    pub fn signal_n(&self, meta: IrqMeta, n: u32) {
        unsafe { kernel_irq_signal_n(self.as_raw(), meta, n) };
    }

    pub fn wait(&self, meta: IrqMeta) -> FfiFuture<IrqWaitResult> {
        unsafe { irq_handle_wait_ffi(self.as_raw(), meta) }
    }
}

impl Clone for IrqHandle {
    fn clone(&self) -> Self {
        let p = unsafe { irq_handle_clone(self.as_raw()) };
        let nn = NonNull::new(p).expect("irq_handle_clone returned null");
        Self { ptr: nn }
    }
}

impl Drop for IrqHandle {
    fn drop(&mut self) {
        unsafe { irq_handle_drop(self.as_raw()) };
    }
}

pub fn irq_register_isr(vector: u8, isr: IrqIsrFn, ctx: usize) -> Option<IrqHandle> {
    let p = unsafe { kernel_irq_register(vector, isr, ctx) };
    unsafe { IrqHandle::from_raw(p) }
}

pub fn irq_register_isr_gsi(gsi: u8, isr: IrqIsrFn, ctx: usize) -> Option<IrqHandle> {
    let p = unsafe { kernel_irq_register_gsi(gsi, isr, ctx) };
    unsafe { IrqHandle::from_raw(p) }
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
