// kernel/src/drivers/irq.rs
#![no_std]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use core::task::Waker;
use kernel_types::async_ffi::{FfiFuture, FutureExt};
use kernel_types::irq::{
    DropHook, IrqHandleOpaque, IrqHandlePtr, IrqIsrFn, IrqMeta, IrqWaitResult,
};
use spin::{Mutex, RwLock};
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame};
use x86_64::VirtAddr;

use crate::drivers;
use crate::drivers::interrupt_index::{current_cpu_id, get_current_logical_id, send_eoi, APIC};
use crate::drivers::timer_driver::timer_interrupt_entry;
use crate::exception_handlers::exception_handlers;
use crate::gdt::{DOUBLE_FAULT_IST_INDEX, TIMER_IST_INDEX};
use crate::scheduling::scheduler::yield_interrupt_entry;

// =============================================================================
// IRQ HANDLE IMPLEMENTATION
// =============================================================================

/// Internal representation of an IRQ handle
struct IrqHandleInner {
    /// Drop hook called when refcount reaches zero
    drop_hook: Option<DropHook>,
    /// Whether the handle has been closed/unregistered
    closed: AtomicBool,
    /// User-defined context value
    user_ctx: AtomicUsize,
    /// Pending signal count
    signal_count: AtomicUsize,
    /// Last signaled metadata
    last_meta: Mutex<IrqMeta>,
    /// Wakers waiting for signals
    waiters: Mutex<Vec<Waker>>,
}

impl IrqHandleInner {
    fn new(drop_hook: DropHook) -> Self {
        Self {
            drop_hook: Some(drop_hook),
            closed: AtomicBool::new(false),
            user_ctx: AtomicUsize::new(0),
            signal_count: AtomicUsize::new(0),
            last_meta: Mutex::new(IrqMeta::new()),
            waiters: Mutex::new(Vec::new()),
        }
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        // Wake all waiters so they see the closed state
        let mut waiters = self.waiters.lock();
        for waker in waiters.drain(..) {
            waker.wake();
        }
    }

    fn signal_one(&self, meta: IrqMeta) {
        {
            let mut m = self.last_meta.lock();
            *m = meta;
        }
        self.signal_count.fetch_add(1, Ordering::Release);

        // Wake one waiter
        let mut waiters = self.waiters.lock();
        if let Some(waker) = waiters.pop() {
            waker.wake();
        }
    }

    fn signal_n(&self, meta: IrqMeta, n: u32) {
        if n == 0 {
            return;
        }
        {
            let mut m = self.last_meta.lock();
            *m = meta;
        }
        self.signal_count.fetch_add(n as usize, Ordering::Release);

        // Wake up to n waiters
        let mut waiters = self.waiters.lock();
        for _ in 0..n {
            if let Some(waker) = waiters.pop() {
                waker.wake();
            } else {
                break;
            }
        }
    }

    fn try_consume(&self) -> Option<(IrqMeta, u32)> {
        let count = self.signal_count.load(Ordering::Acquire);
        if count == 0 {
            return None;
        }

        // Try to consume one signal
        loop {
            let current = self.signal_count.load(Ordering::Acquire);
            if current == 0 {
                return None;
            }
            match self.signal_count.compare_exchange_weak(
                current,
                current - 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    let meta = *self.last_meta.lock();
                    return Some((meta, 1));
                }
                Err(_) => continue,
            }
        }
    }

    fn register_waker(&self, waker: Waker) {
        let mut waiters = self.waiters.lock();
        waiters.push(waker);
    }
}

impl Drop for IrqHandleInner {
    fn drop(&mut self) {
        if let Some(hook) = self.drop_hook.take() {
            hook.invoke();
        }
    }
}

/// Arc-wrapped handle that can be safely cloned
struct IrqHandleArc(Arc<IrqHandleInner>);

impl IrqHandleArc {
    fn new(drop_hook: DropHook) -> Self {
        Self(Arc::new(IrqHandleInner::new(drop_hook)))
    }

    fn into_raw(self) -> IrqHandlePtr {
        Arc::into_raw(self.0) as *mut IrqHandleOpaque
    }

    unsafe fn from_raw(ptr: IrqHandlePtr) -> Self {
        Self(Arc::from_raw(ptr as *const IrqHandleInner))
    }

    unsafe fn clone_from_raw(ptr: IrqHandlePtr) -> Self {
        let arc = Arc::from_raw(ptr as *const IrqHandleInner);
        let cloned = arc.clone();
        let _ = Arc::into_raw(arc); // Don't drop the original
        Self(cloned)
    }

    fn as_inner(&self) -> &IrqHandleInner {
        &self.0
    }
}

/// Future for waiting on an IRQ signal
struct IrqWaitFuture {
    handle: IrqHandleArc,
    registered: bool,
}

impl IrqWaitFuture {
    fn new(handle: IrqHandleArc) -> Self {
        Self {
            handle,
            registered: false,
        }
    }
}

impl core::future::Future for IrqWaitFuture {
    type Output = IrqWaitResult;

    fn poll(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        if self.handle.as_inner().is_closed() {
            return core::task::Poll::Ready(IrqWaitResult::closed());
        }

        if let Some((meta, count)) = self.handle.as_inner().try_consume() {
            return core::task::Poll::Ready(IrqWaitResult::ok_n(meta, count));
        }

        if !self.registered {
            self.handle.as_inner().register_waker(cx.waker().clone());
            self.registered = true;
        }

        if self.handle.as_inner().is_closed() {
            return core::task::Poll::Ready(IrqWaitResult::closed());
        }

        if let Some((meta, count)) = self.handle.as_inner().try_consume() {
            return core::task::Poll::Ready(IrqWaitResult::ok_n(meta, count));
        }

        core::task::Poll::Pending
    }
}

/// Create a new IRQ handle with the given drop hook
#[unsafe(no_mangle)]
pub extern "win64" fn irq_handle_create(drop_hook: DropHook) -> IrqHandlePtr {
    let handle = IrqHandleArc::new(drop_hook);
    handle.into_raw()
}

/// Clone an IRQ handle (increment refcount)
#[unsafe(no_mangle)]
pub unsafe extern "win64" fn irq_handle_clone(h: IrqHandlePtr) -> IrqHandlePtr {
    if h.is_null() {
        return core::ptr::null_mut();
    }
    let cloned = IrqHandleArc::clone_from_raw(h);
    cloned.into_raw()
}

/// Drop an IRQ handle (decrement refcount)
#[unsafe(no_mangle)]
pub unsafe extern "win64" fn irq_handle_drop(h: IrqHandlePtr) {
    if h.is_null() {
        return;
    }
    let _ = IrqHandleArc::from_raw(h);
    // Arc drop will decrement refcount and call drop_hook if needed
}

/// Unregister the handle (closes it for future waits)
#[unsafe(no_mangle)]
pub unsafe extern "win64" fn irq_handle_unregister(h: IrqHandlePtr) {
    if h.is_null() {
        return;
    }
    let handle = IrqHandleArc::clone_from_raw(h);
    handle.as_inner().close();
}

/// Check if handle is closed
#[unsafe(no_mangle)]
pub unsafe extern "win64" fn irq_handle_is_closed(h: IrqHandlePtr) -> bool {
    if h.is_null() {
        return true;
    }
    let handle = IrqHandleArc::clone_from_raw(h);
    let result = handle.as_inner().is_closed();
    let _ = handle.into_raw(); // Don't drop the clone
    result
}

/// Set user context
#[unsafe(no_mangle)]
pub unsafe extern "win64" fn irq_handle_set_user_ctx(h: IrqHandlePtr, v: usize) {
    if h.is_null() {
        return;
    }
    let handle = IrqHandleArc::clone_from_raw(h);
    handle.as_inner().user_ctx.store(v, Ordering::Release);
    let _ = handle.into_raw();
}

/// Get user context
#[unsafe(no_mangle)]
pub unsafe extern "win64" fn irq_handle_get_user_ctx(h: IrqHandlePtr) -> usize {
    if h.is_null() {
        return 0;
    }
    let handle = IrqHandleArc::clone_from_raw(h);
    let result = handle.as_inner().user_ctx.load(Ordering::Acquire);
    let _ = handle.into_raw();
    result
}

/// Signal the handle once (internal use)
#[unsafe(no_mangle)]
pub unsafe extern "win64" fn irq_handle_signal_one(h: IrqHandlePtr, meta: IrqMeta) {
    if h.is_null() {
        return;
    }
    let handle = IrqHandleArc::clone_from_raw(h);
    handle.as_inner().signal_one(meta);
    let _ = handle.into_raw();
}

/// Signal the handle n times (internal use)
#[unsafe(no_mangle)]
pub unsafe extern "win64" fn irq_handle_signal_n(h: IrqHandlePtr, meta: IrqMeta, n: u32) {
    if h.is_null() || n == 0 {
        return;
    }
    let handle = IrqHandleArc::clone_from_raw(h);
    handle.as_inner().signal_n(meta, n);
    let _ = handle.into_raw();
}

/// Async wait for a signal on the handle
#[unsafe(no_mangle)]
pub unsafe extern "win64" fn irq_handle_wait_ffi(
    h: IrqHandlePtr,
    _meta: IrqMeta,
) -> FfiFuture<IrqWaitResult> {
    if h.is_null() {
        return async { IrqWaitResult::null() }.into_ffi();
    }

    let handle = IrqHandleArc::clone_from_raw(h);

    async move { IrqWaitFuture::new(handle).await }.into_ffi()
}

// =============================================================================
// IRQ REGISTRATION SYSTEM
// =============================================================================

#[repr(transparent)]
#[derive(Clone, Copy)]
struct IrqHandleRaw(IrqHandlePtr);

unsafe impl Send for IrqHandleRaw {}
unsafe impl Sync for IrqHandleRaw {}

impl IrqHandleRaw {
    #[inline(always)]
    fn as_ptr(self) -> IrqHandlePtr {
        self.0
    }
}

struct IrqReg {
    id: usize,
    isr: IrqIsrFn,
    ctx: usize,
    handle: IrqHandleRaw,
}

pub struct IrqManager {
    vectors: Vec<RwLock<Vec<IrqReg>>>,
    id_to_vec: Mutex<BTreeMap<usize, u8>>,
    next_id: AtomicUsize,
}

impl IrqManager {
    fn new() -> Self {
        let mut vectors = Vec::with_capacity(256);
        for _ in 0..256 {
            vectors.push(RwLock::new(Vec::new()));
        }
        Self {
            vectors,
            id_to_vec: Mutex::new(BTreeMap::new()),
            next_id: AtomicUsize::new(1),
        }
    }

    fn alloc_id(&self) -> usize {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    fn register(&self, vector: u8, isr: IrqIsrFn, ctx: usize, handle: IrqHandlePtr, id: usize) {
        {
            let mut m = self.id_to_vec.lock();
            m.insert(id, vector);
        }

        let mut slot = self.vectors[vector as usize].write();
        slot.push(IrqReg {
            id,
            isr,
            ctx,
            handle: IrqHandleRaw(handle),
        });
    }

    fn unregister_id(&self, id: usize) {
        let vector = {
            let mut m = self.id_to_vec.lock();
            m.remove(&id)
        };

        let Some(vector) = vector else {
            return;
        };

        let mut v = self.vectors[vector as usize].write();
        let mut i = 0usize;
        while i < v.len() {
            if v[i].id == id {
                v.swap_remove(i);
                break;
            }
            i += 1;
        }
    }

    fn dispatch(&self, vector: u8, frame: &mut InterruptStackFrame) {
        let cpu = current_cpu_id() as u32;

        {
            let v = self.vectors[vector as usize].read();
            for r in v.iter() {
                let frame_ptr: *mut InterruptStackFrame = frame as *mut InterruptStackFrame;
                let claimed = (r.isr)(vector, cpu, frame_ptr, r.handle.as_ptr(), r.ctx);
                if claimed {
                    break;
                }
            }
        }

        send_eoi(vector);
    }
}

use lazy_static::lazy_static;

lazy_static! {
    static ref IRQ_MANAGER: IrqManager = IrqManager::new();
}

pub fn irq_init() {
    let _ = &*IRQ_MANAGER;
}

#[unsafe(no_mangle)]
pub extern "win64" fn irq_unregister_thunk(id: usize) {
    IRQ_MANAGER.unregister_id(id);
}

pub fn irq_register(vector: u8, isr: IrqIsrFn, ctx: usize) -> IrqHandlePtr {
    let id = IRQ_MANAGER.alloc_id();
    let hook = DropHook::new(irq_unregister_thunk, id);

    let handle = irq_handle_create(hook);
    if handle.is_null() {
        return core::ptr::null_mut();
    }

    let first_for_vector = {
        let v = IRQ_MANAGER.vectors[vector as usize].read();
        v.is_empty()
    };

    IRQ_MANAGER.register(vector, isr, ctx, handle, id);

    if first_for_vector {
        if let Some(irq) = vector_to_irq(vector) {
            APIC.lock().as_ref().unwrap().ioapic.unmask_irq_any_cpu(
                irq,
                vector,
                get_current_logical_id(),
            );
        }
    }

    handle
}
fn vector_to_irq(vector: u8) -> Option<u8> {
    let base = drivers::interrupt_index::InterruptIndex::Timer.as_u8();
    let irq = vector.wrapping_sub(base);
    if irq < 16 {
        Some(irq)
    } else {
        None
    }
}
pub fn irq_dispatch(vector: u8, frame: &mut InterruptStackFrame) {
    IRQ_MANAGER.dispatch(vector, frame);
}

pub fn irq_signal(handle: IrqHandlePtr, meta: IrqMeta) {
    if handle.is_null() {
        return;
    }
    unsafe { irq_handle_signal_one(handle, meta) };
}

pub fn irq_signal_n(handle: IrqHandlePtr, meta: IrqMeta, n: u32) {
    if handle.is_null() || n == 0 {
        return;
    }
    unsafe { irq_handle_signal_n(handle, meta, n) };
}

// =============================================================================
// IRQ VECTOR STUBS
// =============================================================================

macro_rules! gen_irq_stub {
    ($name:ident, $vec:expr) => {
        extern "x86-interrupt" fn $name(mut frame: InterruptStackFrame) {
            irq_dispatch($vec, &mut frame);
        }
    };
}

gen_irq_stub!(irq_vec_33, 33);
gen_irq_stub!(irq_vec_34, 34);
gen_irq_stub!(irq_vec_35, 35);
gen_irq_stub!(irq_vec_36, 36);
gen_irq_stub!(irq_vec_37, 37);
gen_irq_stub!(irq_vec_38, 38);
gen_irq_stub!(irq_vec_39, 39);
gen_irq_stub!(irq_vec_40, 40);
gen_irq_stub!(irq_vec_41, 41);
gen_irq_stub!(irq_vec_42, 42);
gen_irq_stub!(irq_vec_43, 43);
gen_irq_stub!(irq_vec_44, 44);
gen_irq_stub!(irq_vec_45, 45);
gen_irq_stub!(irq_vec_46, 46);
gen_irq_stub!(irq_vec_47, 47);

// =============================================================================
// IDT SETUP
// =============================================================================

lazy_static! {
    pub static ref IDT: InterruptDescriptorTable = unsafe {
        let mut idt = InterruptDescriptorTable::new();

        idt.divide_error
            .set_handler_fn(exception_handlers::divide_by_zero_fault);
        idt.debug
            .set_handler_fn(exception_handlers::debug_exception);
        idt.non_maskable_interrupt
            .set_handler_fn(exception_handlers::non_maskable_interrupt);
        idt.breakpoint
            .set_handler_fn(exception_handlers::breakpoint_exception)
            .set_privilege_level(x86_64::PrivilegeLevel::Ring3);
        idt.overflow
            .set_handler_fn(exception_handlers::overflow_exception);
        idt.bound_range_exceeded
            .set_handler_fn(exception_handlers::bound_range_exceeded_exception);
        idt.invalid_opcode
            .set_handler_fn(exception_handlers::invalid_opcode_exception);
        idt.device_not_available
            .set_handler_fn(exception_handlers::device_not_available_exception);
        idt.double_fault
            .set_handler_fn(exception_handlers::double_fault)
            .set_stack_index(DOUBLE_FAULT_IST_INDEX);
        idt.invalid_tss
            .set_handler_fn(exception_handlers::invalid_tss_exception);
        idt.segment_not_present
            .set_handler_fn(exception_handlers::segment_not_present_exception);
        idt.stack_segment_fault
            .set_handler_fn(exception_handlers::stack_segment_fault);
        idt.general_protection_fault
            .set_handler_fn(exception_handlers::general_protection_fault);
        idt.page_fault
            .set_handler_fn(exception_handlers::page_fault);
        idt.x87_floating_point
            .set_handler_fn(exception_handlers::x87_floating_point_exception);
        idt.alignment_check
            .set_handler_fn(exception_handlers::alignment_check_exception);
        idt.machine_check
            .set_handler_fn(exception_handlers::machine_check_exception);
        idt.simd_floating_point
            .set_handler_fn(exception_handlers::simd_floating_point_exception);
        idt.virtualization
            .set_handler_fn(exception_handlers::virtualization_exception);

        let base = drivers::interrupt_index::InterruptIndex::Timer.as_u8();

        idt[drivers::interrupt_index::InterruptIndex::Timer.as_u8()]
            .set_handler_addr(VirtAddr::new(timer_interrupt_entry as u64))
            .set_stack_index(TIMER_IST_INDEX);
        idt[base + 1].set_handler_fn(irq_vec_33);
        idt[base + 2].set_handler_fn(irq_vec_34);
        idt[base + 3].set_handler_fn(irq_vec_35);
        idt[base + 4].set_handler_fn(irq_vec_36);
        idt[base + 5].set_handler_fn(irq_vec_37);
        idt[base + 6].set_handler_fn(irq_vec_38);
        idt[base + 7].set_handler_fn(irq_vec_39);
        idt[base + 8].set_handler_fn(irq_vec_40);
        idt[base + 9].set_handler_fn(irq_vec_41);
        idt[base + 10].set_handler_fn(irq_vec_42);
        idt[base + 11].set_handler_fn(irq_vec_43);
        idt[base + 12].set_handler_fn(irq_vec_44);
        idt[base + 13].set_handler_fn(irq_vec_45);
        idt[base + 14].set_handler_fn(irq_vec_46);
        idt[base + 15].set_handler_fn(irq_vec_47);

        idt[0x80].set_handler_addr(VirtAddr::new(yield_interrupt_entry as u64));

        idt
    };
}

pub fn load_idt() {
    irq_init();
    IDT.load();
    x86_64::instructions::interrupts::enable();
}
