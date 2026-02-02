use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
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
use crate::gdt::{DOUBLE_FAULT_IST_INDEX, PAGE_FAULT_IST_INDEX, TIMER_IST_INDEX, YIELD_IST_INDEX};
use crate::scheduling::scheduler::{ipi_entry, yield_interrupt_entry};

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

const MAX_HANDLERS_PER_VECTOR: usize = 4;
const MAX_TOTAL_REGISTRATIONS: usize = 64;

#[derive(Clone, Copy)]
struct IrqReg {
    id: usize,
    isr: IrqIsrFn,
    ctx: usize,
    handle: IrqHandleRaw,
}

impl IrqReg {
    const EMPTY: Self = Self {
        id: 0,
        isr: dummy_isr,
        ctx: 0,
        handle: IrqHandleRaw(core::ptr::null_mut()),
    };
}

extern "win64" fn dummy_isr(
    _: u8,
    _: u32,
    _: *mut InterruptStackFrame,
    _: IrqHandlePtr,
    _: usize,
) -> bool {
    false
}

struct VectorSlot {
    regs: [IrqReg; MAX_HANDLERS_PER_VECTOR],
    count: AtomicUsize,
    lock: spin::RwLock<()>,
}

impl VectorSlot {
    const fn new() -> Self {
        Self {
            regs: [IrqReg::EMPTY; MAX_HANDLERS_PER_VECTOR],
            count: AtomicUsize::new(0),
            lock: spin::RwLock::new(()),
        }
    }
}

struct IdMapEntry {
    id: AtomicUsize,
    vector: AtomicU8,
}

impl IdMapEntry {
    const fn new() -> Self {
        Self {
            id: AtomicUsize::new(0),
            vector: AtomicU8::new(0),
        }
    }
}

pub struct IrqManager {
    vectors: [VectorSlot; 256],
    id_map: [IdMapEntry; MAX_TOTAL_REGISTRATIONS],
    next_id: AtomicUsize,
}

impl IrqManager {
    const fn new() -> Self {
        const SLOT: VectorSlot = VectorSlot::new();
        const ENTRY: IdMapEntry = IdMapEntry::new();
        Self {
            vectors: [SLOT; 256],
            id_map: [ENTRY; MAX_TOTAL_REGISTRATIONS],
            next_id: AtomicUsize::new(1),
        }
    }

    fn alloc_id(&self) -> usize {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    fn register(&self, vector: u8, isr: IrqIsrFn, ctx: usize, handle: IrqHandlePtr, id: usize) {
        // Store id -> vector mapping
        for entry in &self.id_map {
            if entry
                .id
                .compare_exchange(0, id, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                entry.vector.store(vector, Ordering::Release);
                break;
            }
        }

        let slot = &self.vectors[vector as usize];
        let _guard = slot.lock.write();
        let count = slot.count.load(Ordering::Acquire);
        if count < MAX_HANDLERS_PER_VECTOR {
            // SAFETY: We hold the write lock and count < MAX
            unsafe {
                let regs = &slot.regs as *const _ as *mut [IrqReg; MAX_HANDLERS_PER_VECTOR];
                (*regs)[count] = IrqReg {
                    id,
                    isr,
                    ctx,
                    handle: IrqHandleRaw(handle),
                };
            }
            slot.count.store(count + 1, Ordering::Release);
        }
    }

    fn unregister_id(&self, id: usize) {
        // Find and clear id -> vector mapping
        let mut vector = None;
        for entry in &self.id_map {
            if entry.id.load(Ordering::Acquire) == id {
                vector = Some(entry.vector.load(Ordering::Acquire));
                entry.id.store(0, Ordering::Release);
                break;
            }
        }

        let Some(vec) = vector else { return };

        let slot = &self.vectors[vec as usize];
        let _guard = slot.lock.write();
        let count = slot.count.load(Ordering::Acquire);

        // SAFETY: We hold the write lock
        unsafe {
            let regs = &slot.regs as *const _ as *mut [IrqReg; MAX_HANDLERS_PER_VECTOR];
            for i in 0..count {
                if (*regs)[i].id == id {
                    // Swap remove
                    if i < count - 1 {
                        (*regs)[i] = (*regs)[count - 1];
                    }
                    (*regs)[count - 1] = IrqReg::EMPTY;
                    slot.count.store(count - 1, Ordering::Release);
                    break;
                }
            }
        }
    }

    fn dispatch(&self, vector: u8, frame: &mut InterruptStackFrame) {
        let cpu = current_cpu_id() as u32;

        let slot = &self.vectors[vector as usize];
        let _guard = slot.lock.read();
        let count = slot.count.load(Ordering::Acquire);

        for i in 0..count {
            let r = &slot.regs[i];
            if r.id != 0 {
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

static IRQ_MANAGER: IrqManager = IrqManager::new();

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
        let _lock = IRQ_MANAGER.vectors[vector as usize].lock.read();
        IRQ_MANAGER.vectors[vector as usize]
            .count
            .load(Ordering::Acquire)
            == 0
    };

    IRQ_MANAGER.register(vector, isr, ctx, handle, id);

    if first_for_vector {
        if let Some(gsi) = vector_to_gsi(vector) {
            APIC.lock().as_ref().unwrap().ioapic.unmask_irq_any_cpu(
                gsi,
                vector,
                get_current_logical_id(),
            );
        }
    }

    handle
}
fn vector_to_gsi(vector: u8) -> Option<u8> {
    let base = drivers::interrupt_index::InterruptIndex::Timer.as_u8();
    let gsi = vector.wrapping_sub(base);
    if gsi < 64 {
        Some(gsi)
    } else {
        None
    }
}

/// Register an ISR for a Global System Interrupt (GSI).
/// The kernel maps the GSI to an IDT vector and programs the IOAPIC.
pub fn irq_register_gsi(gsi: u8, isr: IrqIsrFn, ctx: usize) -> IrqHandlePtr {
    let base = drivers::interrupt_index::InterruptIndex::Timer.as_u8();
    if gsi >= 64 {
        return core::ptr::null_mut();
    }
    let vector = base + gsi;
    let id = IRQ_MANAGER.alloc_id();
    let hook = DropHook::new(irq_unregister_thunk, id);

    let handle = irq_handle_create(hook);
    if handle.is_null() {
        return core::ptr::null_mut();
    }

    let first_for_vector = {
        let _lock = IRQ_MANAGER.vectors[vector as usize].lock.read();
        IRQ_MANAGER.vectors[vector as usize]
            .count
            .load(Ordering::Acquire)
            == 0
    };

    IRQ_MANAGER.register(vector, isr, ctx, handle, id);

    if first_for_vector {
        APIC.lock().as_ref().unwrap().ioapic.unmask_irq_any_cpu(
            gsi,
            vector,
            get_current_logical_id(),
        );
    }

    handle
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
pub const SCHED_IPI_VECTOR: u8 = 0xF2;

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

// ISA IRQs 1-15 (vectors 33-47)
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

// IOAPIC GSIs 16-63 (vectors 48-95)
gen_irq_stub!(irq_vec_48, 48);
gen_irq_stub!(irq_vec_49, 49);
gen_irq_stub!(irq_vec_50, 50);
gen_irq_stub!(irq_vec_51, 51);
gen_irq_stub!(irq_vec_52, 52);
gen_irq_stub!(irq_vec_53, 53);
gen_irq_stub!(irq_vec_54, 54);
gen_irq_stub!(irq_vec_55, 55);
gen_irq_stub!(irq_vec_56, 56);
gen_irq_stub!(irq_vec_57, 57);
gen_irq_stub!(irq_vec_58, 58);
gen_irq_stub!(irq_vec_59, 59);
gen_irq_stub!(irq_vec_60, 60);
gen_irq_stub!(irq_vec_61, 61);
gen_irq_stub!(irq_vec_62, 62);
gen_irq_stub!(irq_vec_63, 63);
gen_irq_stub!(irq_vec_64, 64);
gen_irq_stub!(irq_vec_65, 65);
gen_irq_stub!(irq_vec_66, 66);
gen_irq_stub!(irq_vec_67, 67);
gen_irq_stub!(irq_vec_68, 68);
gen_irq_stub!(irq_vec_69, 69);
gen_irq_stub!(irq_vec_70, 70);
gen_irq_stub!(irq_vec_71, 71);
gen_irq_stub!(irq_vec_72, 72);
gen_irq_stub!(irq_vec_73, 73);
gen_irq_stub!(irq_vec_74, 74);
gen_irq_stub!(irq_vec_75, 75);
gen_irq_stub!(irq_vec_76, 76);
gen_irq_stub!(irq_vec_77, 77);
gen_irq_stub!(irq_vec_78, 78);
gen_irq_stub!(irq_vec_79, 79);
gen_irq_stub!(irq_vec_80, 80);
gen_irq_stub!(irq_vec_81, 81);
gen_irq_stub!(irq_vec_82, 82);
gen_irq_stub!(irq_vec_83, 83);
gen_irq_stub!(irq_vec_84, 84);
gen_irq_stub!(irq_vec_85, 85);
gen_irq_stub!(irq_vec_86, 86);
gen_irq_stub!(irq_vec_87, 87);
gen_irq_stub!(irq_vec_88, 88);
gen_irq_stub!(irq_vec_89, 89);
gen_irq_stub!(irq_vec_90, 90);
gen_irq_stub!(irq_vec_91, 91);
gen_irq_stub!(irq_vec_92, 92);
gen_irq_stub!(irq_vec_93, 93);
gen_irq_stub!(irq_vec_94, 94);
gen_irq_stub!(irq_vec_95, 95);

// =============================================================================
// IDT SETUP
// =============================================================================

static IDT: spin::Once<InterruptDescriptorTable> = spin::Once::new();

fn init_idt() -> InterruptDescriptorTable {
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
    unsafe {
        idt.double_fault
            .set_handler_fn(exception_handlers::double_fault)
            .set_stack_index(DOUBLE_FAULT_IST_INDEX);
    }
    idt.invalid_tss
        .set_handler_fn(exception_handlers::invalid_tss_exception);
    idt.segment_not_present
        .set_handler_fn(exception_handlers::segment_not_present_exception);
    idt.stack_segment_fault
        .set_handler_fn(exception_handlers::stack_segment_fault);
    idt.general_protection_fault
        .set_handler_fn(exception_handlers::general_protection_fault);
    unsafe {
        idt.page_fault
            .set_handler_fn(exception_handlers::page_fault)
            .set_stack_index(PAGE_FAULT_IST_INDEX);
    }
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

    unsafe {
        idt[drivers::interrupt_index::InterruptIndex::Timer.as_u8()]
            .set_handler_addr(VirtAddr::new(timer_interrupt_entry as u64))
            .set_stack_index(TIMER_IST_INDEX);
    }
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

    // IOAPIC GSIs 16-63 (vectors 48-95)
    idt[base + 16].set_handler_fn(irq_vec_48);
    idt[base + 17].set_handler_fn(irq_vec_49);
    idt[base + 18].set_handler_fn(irq_vec_50);
    idt[base + 19].set_handler_fn(irq_vec_51);
    idt[base + 20].set_handler_fn(irq_vec_52);
    idt[base + 21].set_handler_fn(irq_vec_53);
    idt[base + 22].set_handler_fn(irq_vec_54);
    idt[base + 23].set_handler_fn(irq_vec_55);
    idt[base + 24].set_handler_fn(irq_vec_56);
    idt[base + 25].set_handler_fn(irq_vec_57);
    idt[base + 26].set_handler_fn(irq_vec_58);
    idt[base + 27].set_handler_fn(irq_vec_59);
    idt[base + 28].set_handler_fn(irq_vec_60);
    idt[base + 29].set_handler_fn(irq_vec_61);
    idt[base + 30].set_handler_fn(irq_vec_62);
    idt[base + 31].set_handler_fn(irq_vec_63);
    idt[base + 32].set_handler_fn(irq_vec_64);
    idt[base + 33].set_handler_fn(irq_vec_65);
    idt[base + 34].set_handler_fn(irq_vec_66);
    idt[base + 35].set_handler_fn(irq_vec_67);
    idt[base + 36].set_handler_fn(irq_vec_68);
    idt[base + 37].set_handler_fn(irq_vec_69);
    idt[base + 38].set_handler_fn(irq_vec_70);
    idt[base + 39].set_handler_fn(irq_vec_71);
    idt[base + 40].set_handler_fn(irq_vec_72);
    idt[base + 41].set_handler_fn(irq_vec_73);
    idt[base + 42].set_handler_fn(irq_vec_74);
    idt[base + 43].set_handler_fn(irq_vec_75);
    idt[base + 44].set_handler_fn(irq_vec_76);
    idt[base + 45].set_handler_fn(irq_vec_77);
    idt[base + 46].set_handler_fn(irq_vec_78);
    idt[base + 47].set_handler_fn(irq_vec_79);
    idt[base + 48].set_handler_fn(irq_vec_80);
    idt[base + 49].set_handler_fn(irq_vec_81);
    idt[base + 50].set_handler_fn(irq_vec_82);
    idt[base + 51].set_handler_fn(irq_vec_83);
    idt[base + 52].set_handler_fn(irq_vec_84);
    idt[base + 53].set_handler_fn(irq_vec_85);
    idt[base + 54].set_handler_fn(irq_vec_86);
    idt[base + 55].set_handler_fn(irq_vec_87);
    idt[base + 56].set_handler_fn(irq_vec_88);
    idt[base + 57].set_handler_fn(irq_vec_89);
    idt[base + 58].set_handler_fn(irq_vec_90);
    idt[base + 59].set_handler_fn(irq_vec_91);
    idt[base + 60].set_handler_fn(irq_vec_92);
    idt[base + 61].set_handler_fn(irq_vec_93);
    idt[base + 62].set_handler_fn(irq_vec_94);
    idt[base + 63].set_handler_fn(irq_vec_95);

    unsafe {
        idt[SCHED_IPI_VECTOR as u8]
            .set_handler_addr(VirtAddr::new(ipi_entry as u64))
            .set_stack_index(YIELD_IST_INDEX);

        idt[0x80]
            .set_handler_addr(VirtAddr::new(yield_interrupt_entry as u64))
            .set_stack_index(YIELD_IST_INDEX);
    }

    idt
}

pub fn load_idt() {
    IDT.call_once(init_idt).load();
    x86_64::instructions::interrupts::enable();
}
