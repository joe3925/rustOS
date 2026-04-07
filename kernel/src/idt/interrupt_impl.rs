use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use kernel_routing::println;
use kernel_types::async_ffi::{FfiFuture, FutureExt};
use kernel_types::irq::{DropHook, IrqHandle, IrqHandleInner, IrqIsrFn, IrqMeta, IrqWaitResult};
use spin::{Once, RwLock};
use x86_64::structures::idt::InterruptStackFrame;

use crate::drivers;
use crate::drivers::interrupt_index::{current_cpu_id, get_current_logical_id, send_eoi, APIC};

// =============================================================================
// IRQ HANDLE FFI WRAPPERS (SAFE)
// =============================================================================

#[unsafe(no_mangle)]
pub extern "win64" fn irq_handle_create(drop_hook: DropHook) -> IrqHandle {
    IrqHandleInner::new(drop_hook)
}

#[unsafe(no_mangle)]
pub extern "win64" fn irq_handle_clone(h: &IrqHandle) -> IrqHandle {
    h.clone()
}

#[unsafe(no_mangle)]
pub extern "win64" fn irq_handle_drop(_h: IrqHandle) {
    // dropping the Arc is sufficient
}

#[unsafe(no_mangle)]
pub extern "win64" fn irq_handle_unregister(h: &IrqHandle) {
    h.close();
}

#[unsafe(no_mangle)]
pub extern "win64" fn irq_handle_is_closed(h: &IrqHandle) -> bool {
    h.is_closed()
}

#[unsafe(no_mangle)]
pub extern "win64" fn irq_handle_set_user_ctx(h: &IrqHandle, v: usize) {
    h.set_user_ctx(v);
}

#[unsafe(no_mangle)]
pub extern "win64" fn irq_handle_get_user_ctx(h: &IrqHandle) -> usize {
    h.user_ctx()
}

#[unsafe(no_mangle)]
pub extern "win64" fn irq_handle_signal_one(h: &IrqHandle, meta: IrqMeta) {
    h.signal_one(meta);
}

#[unsafe(no_mangle)]
pub extern "win64" fn irq_handle_signal_exactly_one(h: &IrqHandle, meta: IrqMeta) {
    h.ensure_signal_exactly_one(meta);
}

#[unsafe(no_mangle)]
pub extern "win64" fn irq_handle_signal_n(h: &IrqHandle, meta: IrqMeta, n: u32) {
    h.signal_n(meta, n as usize);
}

pub(crate) fn signal_all(handle: &IrqHandle, meta: IrqMeta) {
    handle.signal_all(meta);
}

#[unsafe(no_mangle)]
pub extern "win64" fn irq_handle_wait_ffi(
    h: &IrqHandle,
    _meta: IrqMeta,
) -> FfiFuture<IrqWaitResult> {
    let handle = h.clone();
    async move { handle.wait_future().await }.into_ffi()
}

// =============================================================================
// IRQ REGISTRATION SYSTEM
// =============================================================================

const MAX_HANDLERS_PER_VECTOR: usize = 4;
const MAX_TOTAL_REGISTRATIONS: usize = 64;

#[derive(Clone)]
struct IrqReg {
    id: usize,
    isr: IrqIsrFn,
    ctx: usize,
    handle: IrqHandle,
}

extern "win64" fn dummy_isr(
    _: u8,
    _: u32,
    _: &mut InterruptStackFrame,
    _: IrqHandle,
    _: usize,
) -> bool {
    false
}

struct VectorSlot {
    regs: RwLock<Vec<IrqReg>>,
}

impl VectorSlot {
    fn new() -> Self {
        Self {
            regs: RwLock::new(Vec::new()),
        }
    }

    fn count(&self) -> usize {
        self.regs.read().len()
    }
}

struct IdMapEntry {
    id: AtomicUsize,
    vector: AtomicU8,
}

impl IdMapEntry {
    fn new() -> Self {
        Self {
            id: AtomicUsize::new(0),
            vector: AtomicU8::new(0),
        }
    }
}

const DYNAMIC_VECTOR_START: u8 = 0x60;
const DYNAMIC_VECTOR_END: u8 = 0xEF;

struct VectorAllocEntry {
    allocated: AtomicBool,
    users: AtomicUsize,
}

impl VectorAllocEntry {
    fn new() -> Self {
        Self {
            allocated: AtomicBool::new(false),
            users: AtomicUsize::new(0),
        }
    }
}

static VECTOR_ALLOC: Once<[VectorAllocEntry; 256]> = Once::new();

fn vector_alloc_table() -> &'static [VectorAllocEntry; 256] {
    VECTOR_ALLOC.call_once(|| core::array::from_fn(|_| VectorAllocEntry::new()))
}

struct VectorAllocator;

impl VectorAllocator {
    fn is_dynamic(vector: u8) -> bool {
        vector >= DYNAMIC_VECTOR_START && vector <= DYNAMIC_VECTOR_END && vector != 0x80
    }

    fn alloc() -> Option<u8> {
        for vec in DYNAMIC_VECTOR_START..=DYNAMIC_VECTOR_END {
            if Self::reserve(vec) {
                return Some(vec);
            }
        }
        None
    }

    fn reserve(vector: u8) -> bool {
        if !Self::is_dynamic(vector) {
            return false;
        }
        let state = &vector_alloc_table()[vector as usize];
        state
            .allocated
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn reserve_for_registration(vector: u8) -> bool {
        if !Self::is_dynamic(vector) {
            return true;
        }

        let state = &vector_alloc_table()[vector as usize];
        if !state.allocated.load(Ordering::Acquire) {
            let _ =
                state
                    .allocated
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire);
        }

        state
            .users
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn release_after_unregister(vector: u8) {
        if !Self::is_dynamic(vector) {
            return;
        }
        let state = &vector_alloc_table()[vector as usize];
        let prev = state.users.fetch_sub(1, Ordering::AcqRel);
        if prev == 1 {
            state.allocated.store(false, Ordering::Release);
        }
    }

    fn free_explicit(vector: u8) -> bool {
        if !Self::is_dynamic(vector) {
            return false;
        }
        let state = &vector_alloc_table()[vector as usize];
        if state.users.load(Ordering::Acquire) != 0 {
            return false;
        }
        state
            .allocated
            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
}

pub struct IrqManager {
    vectors: [VectorSlot; 256],
    id_map: [IdMapEntry; MAX_TOTAL_REGISTRATIONS],
    next_id: AtomicUsize,
}

impl IrqManager {
    fn new() -> Self {
        Self {
            vectors: core::array::from_fn(|_| VectorSlot::new()),
            id_map: core::array::from_fn(|_| IdMapEntry::new()),
            next_id: AtomicUsize::new(1),
        }
    }

    fn alloc_id(&self) -> usize {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    fn register(
        &self,
        vector: u8,
        isr: IrqIsrFn,
        ctx: usize,
        handle: IrqHandle,
        id: usize,
        exclusive: bool,
    ) -> bool {
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
        let mut regs = slot.regs.write();
        if regs.len() >= MAX_HANDLERS_PER_VECTOR || (exclusive && !regs.is_empty()) {
            return false;
        }

        regs.push(IrqReg {
            id,
            isr,
            ctx,
            handle,
        });
        true
    }

    fn unregister_id(&self, id: usize) {
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
        let mut regs = slot.regs.write();
        if let Some(pos) = regs.iter().position(|r| r.id == id) {
            regs.swap_remove(pos);
        }

        if VectorAllocator::is_dynamic(vec) {
            VectorAllocator::release_after_unregister(vec);
        }
    }

    fn dispatch(&self, vector: u8, frame: &mut InterruptStackFrame) {
        let cpu = current_cpu_id() as u32;

        let slot = &self.vectors[vector as usize];
        let regs = slot.regs.read();

        for r in regs.iter() {
            let claimed = (r.isr)(vector, cpu, frame, r.handle.clone(), r.ctx);
            if claimed {
                break;
            }
        }
        send_eoi(vector);
    }
}

static IRQ_MANAGER: Once<IrqManager> = Once::new();

fn irq_manager() -> &'static IrqManager {
    IRQ_MANAGER.call_once(|| IrqManager::new())
}

fn null_handle() -> IrqHandle {
    static NULL_HANDLE: Once<IrqHandle> = Once::new();
    NULL_HANDLE
        .call_once(|| {
            let h = IrqHandleInner::new(DropHook::new(dummy_drop, 0));
            h.close();
            h
        })
        .clone()
}

extern "win64" fn dummy_drop(_: usize) {}

#[unsafe(no_mangle)]
pub extern "win64" fn irq_unregister_thunk(id: usize) {
    irq_manager().unregister_id(id);
}

pub fn irq_register(vector: u8, isr: IrqIsrFn, ctx: usize) -> IrqHandle {
    if vector == 0x80 {
        return null_handle();
    }

    let dynamic = VectorAllocator::is_dynamic(vector);
    if dynamic && !VectorAllocator::reserve_for_registration(vector) {
        return null_handle();
    }

    let id = irq_manager().alloc_id();
    let hook = DropHook::new(irq_unregister_thunk, id);

    let handle = IrqHandleInner::new(hook);

    let first_for_vector = {
        let regs = irq_manager().vectors[vector as usize].regs.read();
        regs.is_empty()
    };

    let registered = irq_manager().register(vector, isr, ctx, handle.clone(), id, dynamic);
    if !registered {
        if dynamic {
            VectorAllocator::release_after_unregister(vector);
        }
        return null_handle();
    }

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

pub fn irq_register_gsi(gsi: u8, isr: IrqIsrFn, ctx: usize) -> IrqHandle {
    let base = drivers::interrupt_index::InterruptIndex::Timer.as_u8();
    if gsi >= 64 {
        return null_handle();
    }
    let vector = base + gsi;
    let id = irq_manager().alloc_id();
    let hook = DropHook::new(irq_unregister_thunk, id);

    let handle = IrqHandleInner::new(hook);

    let first_for_vector = {
        let regs = irq_manager().vectors[vector as usize].regs.read();
        regs.is_empty()
    };

    if !irq_manager().register(vector, isr, ctx, handle.clone(), id, false) {
        return null_handle();
    }

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
    irq_manager().dispatch(vector, frame);
}

pub fn irq_signal(handle: &IrqHandle, meta: IrqMeta) {
    handle.signal_one(meta);
}

pub fn irq_signal_exactly(handle: &IrqHandle, meta: IrqMeta) {
    handle.ensure_signal_exactly_one(meta);
}

pub fn irq_signal_n(handle: &IrqHandle, meta: IrqMeta, n: u32) {
    if n == 0 {
        return;
    }
    handle.signal_n(meta, n as usize);
}

pub fn irq_signal_all(handle: &IrqHandle, meta: IrqMeta) {
    handle.signal_all(meta);
}

pub fn irq_alloc_vector() -> Option<u8> {
    VectorAllocator::alloc()
}

pub fn irq_free_vector(vector: u8) -> bool {
    VectorAllocator::free_explicit(vector)
}

pub const SCHED_IPI_VECTOR: u8 = 0xF2;
