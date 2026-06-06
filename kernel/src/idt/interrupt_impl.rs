use crate::drivers::interrupt_index::current_is_in_interrupt_atomic;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use core::task::{Context, Poll};
use kernel_types::async_ffi::{FfiFuture, FutureExt};
use kernel_types::irq::{
    AtomicIrqMeta, DropHook, IrqBorrowedHandle, IrqHandle, IrqHandleInner, IrqIsrFn, IrqMeta,
    IrqSafeRwLock, IrqWaitResult, WaiterSlot, WAITER_CLAIMED, WAITER_FREE, WAITER_MAX_TICKET,
    WAITER_PREPARING, WAITER_SIGNALED, WAITER_WAITING,
};
use spin::{Mutex, Once};
use x86_64::structures::idt::InterruptStackFrame;

use crate::drivers;
use crate::drivers::interrupt_index::{current_cpu_id, get_current_logical_id, send_eoi, APIC};

const MAX_HANDLERS_PER_VECTOR: usize = 4;
const MAX_TOTAL_REGISTRATIONS: usize = 64;
const DYNAMIC_VECTOR_START: u8 = 0x60;
const DYNAMIC_VECTOR_END: u8 = 0xEF;
const RESERVED_ID: usize = usize::MAX;
const NO_VECTOR: usize = usize::MAX;

#[unsafe(no_mangle)]
pub extern "win64" fn irq_handle_create(drop_hook: DropHook) -> IrqHandle {
    let ptr = create_irq_handle_inner(drop_hook);

    match irq_manager().install_handle(NO_VECTOR, ptr) {
        Some(handle) => handle,
        None => {
            unsafe {
                drop(Box::from_raw(ptr.as_ptr()));
            }

            null_handle()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "win64" fn irq_handle_clone(h: &IrqHandle) -> IrqHandle {
    *h
}

#[unsafe(no_mangle)]
pub extern "win64" fn irq_handle_drop(_h: IrqHandle) {}

#[unsafe(no_mangle)]
pub extern "win64" fn irq_handle_unregister(h: &IrqHandle) {
    irq_manager().unregister_handle(*h);
}

#[unsafe(no_mangle)]
pub extern "win64" fn irq_handle_is_closed(h: &IrqHandle) -> bool {
    if h.is_null() {
        return true;
    }

    irq_manager()
        .with_handle(*h, |inner| inner.is_closed())
        .unwrap_or(true)
}

#[unsafe(no_mangle)]
pub extern "win64" fn irq_handle_set_user_ctx(h: &IrqHandle, v: usize) {
    let _ = irq_manager().with_handle(*h, |inner| {
        inner.set_user_ctx(v);
    });
}

#[unsafe(no_mangle)]
pub extern "win64" fn irq_handle_get_user_ctx(h: &IrqHandle) -> usize {
    irq_manager()
        .with_handle(*h, |inner| inner.user_ctx())
        .unwrap_or(0)
}

#[unsafe(no_mangle)]
pub extern "win64" fn irq_handle_signal_one(h: &IrqHandle, meta: IrqMeta) {
    irq_signal(h, meta);
}

#[unsafe(no_mangle)]
pub extern "win64" fn irq_handle_signal_exactly_one(h: &IrqHandle, meta: IrqMeta) {
    irq_signal_exactly(h, meta);
}

#[unsafe(no_mangle)]
pub extern "win64" fn irq_handle_signal_n(h: &IrqHandle, meta: IrqMeta, n: u32) {
    irq_signal_n(h, meta, n);
}

#[unsafe(no_mangle)]
pub extern "win64" fn irq_handle_wait_ffi(
    h: &IrqHandle,
    _meta: IrqMeta,
) -> FfiFuture<IrqWaitResult> {
    irq_wait_future(h).into_ffi()
}

pub(crate) fn signal_all(handle: &IrqHandle, meta: IrqMeta) {
    irq_signal_all(handle, meta);
}

pub(crate) trait IrqHandleOps {
    fn is_closed(&self) -> bool;
    fn close(&self);
    fn signal_one(&self, meta: IrqMeta);
    fn ensure_signal_exactly_one(&self, meta: IrqMeta);
    fn signal_n(&self, meta: IrqMeta, n: usize) -> usize;
    fn signal_all(&self, meta: IrqMeta) -> usize;
    fn cancel_waiter(&self, slot: usize);
    fn set_user_ctx(&self, v: usize);
    fn user_ctx(&self) -> usize;
}

impl IrqHandleOps for IrqHandleInner {
    #[inline]
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }

        self.pending_signals.store(0, Ordering::Release);

        for slot in &self.waiters {
            let Some(ticket) = slot.try_claim_for_signal() else {
                continue;
            };

            if let Some(waker) = slot.complete_claimed(ticket, IrqWaitResult::closed()) {
                waker.wake_by_ref();
            }
        }
    }

    fn signal_one(&self, meta: IrqMeta) {
        let _ = self.signal_n(meta, 1);
    }

    fn ensure_signal_exactly_one(&self, meta: IrqMeta) {
        if self.is_closed() {
            return;
        }

        self.last_meta.store(meta, Ordering::Release);
        self.signal_active.fetch_add(1, Ordering::AcqRel);
        self.signal_phase.fetch_add(1, Ordering::AcqRel);

        for slot in &self.waiters {
            let Some(ticket) = slot.try_claim_for_signal() else {
                continue;
            };

            if let Some(waker) = slot.complete_claimed(ticket, IrqWaitResult::ok_n(meta, 1)) {
                waker.wake_by_ref();
            }

            self.signal_phase.fetch_add(1, Ordering::AcqRel);
            self.signal_active.fetch_sub(1, Ordering::AcqRel);
            return;
        }

        let _ = self
            .pending_signals
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |pending| {
                if pending == 0 {
                    Some(1)
                } else {
                    Some(pending)
                }
            });

        self.signal_phase.fetch_add(1, Ordering::AcqRel);
        self.signal_active.fetch_sub(1, Ordering::AcqRel);
    }

    fn signal_n(&self, meta: IrqMeta, n: usize) -> usize {
        if n == 0 || self.is_closed() {
            return 0;
        }

        self.last_meta.store(meta, Ordering::Release);
        self.signal_active.fetch_add(1, Ordering::AcqRel);
        self.signal_phase.fetch_add(1, Ordering::AcqRel);

        let mut signaled = 0;

        for slot in &self.waiters {
            if signaled == n {
                break;
            }

            let Some(ticket) = slot.try_claim_for_signal() else {
                continue;
            };

            if let Some(waker) = slot.complete_claimed(ticket, IrqWaitResult::ok_n(meta, 1)) {
                waker.wake_by_ref();
            }

            signaled += 1;
        }

        if signaled < n {
            self.pending_signals
                .fetch_add(n - signaled, Ordering::AcqRel);
        }

        self.signal_phase.fetch_add(1, Ordering::AcqRel);
        self.signal_active.fetch_sub(1, Ordering::AcqRel);
        signaled
    }

    fn signal_all(&self, meta: IrqMeta) -> usize {
        if self.is_closed() {
            return 0;
        }

        self.last_meta.store(meta, Ordering::Release);
        self.signal_active.fetch_add(1, Ordering::AcqRel);
        self.signal_phase.fetch_add(1, Ordering::AcqRel);

        let mut signaled = 0;

        for slot in &self.waiters {
            let Some(ticket) = slot.try_claim_for_signal() else {
                continue;
            };

            if let Some(waker) = slot.complete_claimed(ticket, IrqWaitResult::ok_n(meta, 1)) {
                waker.wake_by_ref();
            }

            signaled += 1;
        }

        if signaled == 0 {
            self.pending_signals.fetch_add(1, Ordering::AcqRel);
        }

        self.signal_phase.fetch_add(1, Ordering::AcqRel);
        self.signal_active.fetch_sub(1, Ordering::AcqRel);
        signaled
    }

    fn cancel_waiter(&self, slot: usize) {
        if let Some(waiter) = self.waiters.get(slot) {
            waiter.cancel();
        }
    }

    fn set_user_ctx(&self, v: usize) {
        self.user_ctx.store(v, Ordering::Release);
    }

    fn user_ctx(&self) -> usize {
        self.user_ctx.load(Ordering::Acquire)
    }
}

fn alloc_waiter_slot(handle: &IrqHandleInner) -> Option<usize> {
    for (i, slot) in handle.waiters.iter().enumerate() {
        if slot.try_alloc() {
            return Some(i);
        }
    }

    None
}

fn next_waiter_ticket(handle: &IrqHandleInner) -> usize {
    let ticket = handle
        .waiter_ticket
        .fetch_add(1, Ordering::AcqRel)
        .wrapping_add(1)
        & WAITER_MAX_TICKET;

    if ticket == 0 {
        1
    } else {
        ticket
    }
}

fn try_consume_pending(handle: &IrqHandleInner) -> Option<IrqWaitResult> {
    loop {
        let pending = handle.pending_signals.load(Ordering::Acquire);

        if pending == 0 {
            return None;
        }

        if handle
            .pending_signals
            .compare_exchange(pending, pending - 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            let meta = handle.last_meta.load(Ordering::Acquire);
            return Some(IrqWaitResult::ok_n(meta, 1));
        }
    }
}

fn poll_slot(handle: &IrqHandleInner, slot_index: usize, cx: &Context<'_>) -> Poll<IrqWaitResult> {
    let Some(slot) = handle.waiters.get(slot_index) else {
        return Poll::Ready(IrqWaitResult::closed());
    };

    if let Some(result) = slot.take_signaled() {
        return Poll::Ready(result);
    }

    match slot.state() {
        WAITER_WAITING => {
            if handle.is_closed() {
                slot.cancel();
                return Poll::Ready(IrqWaitResult::closed());
            }

            if handle.pending_signals.load(Ordering::Acquire) == 0 {
                return Poll::Pending;
            }

            if !slot.try_withdraw_waiting() {
                return Poll::Pending;
            }
        }

        WAITER_CLAIMED => return Poll::Pending,

        WAITER_SIGNALED => {
            if let Some(result) = slot.take_signaled() {
                return Poll::Ready(result);
            }

            return Poll::Pending;
        }

        WAITER_FREE => return Poll::Ready(IrqWaitResult::rescue()),

        WAITER_PREPARING => {}

        _ => return Poll::Ready(IrqWaitResult::rescue()),
    }

    slot.set_preparing();
    slot.set_waker_exclusive(cx.waker());

    if handle.is_closed() {
        slot.cancel();
        return Poll::Ready(IrqWaitResult::closed());
    }

    if let Some(result) = try_consume_pending(handle) {
        slot.cancel();
        return Poll::Ready(result);
    }

    let phase_before = handle.signal_phase.load(Ordering::Acquire);
    let ticket = next_waiter_ticket(handle);
    slot.publish(ticket);
    let phase_after = handle.signal_phase.load(Ordering::Acquire);

    if phase_before != phase_after
        || handle.signal_active.load(Ordering::Acquire) != 0
        || handle.pending_signals.load(Ordering::Acquire) != 0
    {
        cx.waker().wake_by_ref();
    }

    Poll::Pending
}

pub(crate) fn create_irq_handle_inner(drop_hook: DropHook) -> NonNull<IrqHandleInner> {
    let inner = Box::new(IrqHandleInner {
        drop_hook: Mutex::new(Some(drop_hook)),
        closed: AtomicBool::new(false),
        user_ctx: AtomicUsize::new(0),
        pending_signals: AtomicUsize::new(0),
        signal_phase: AtomicUsize::new(0),
        signal_active: AtomicUsize::new(0),
        waiter_ticket: AtomicUsize::new(0),
        last_meta: AtomicIrqMeta::new(),
        waiters: core::array::from_fn(|_| WaiterSlot::new()),
    });

    unsafe { NonNull::new_unchecked(Box::into_raw(inner)) }
}

pub(crate) fn irq_wait_future(handle: &IrqHandle) -> IrqWaitFuture {
    IrqWaitFuture {
        handle: *handle,
        slot: None,
    }
}

pub struct IrqWaitFuture {
    handle: IrqHandle,
    slot: Option<usize>,
}

impl Future for IrqWaitFuture {
    type Output = IrqWaitResult;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        let Some(poll) = irq_manager().with_handle(this.handle, |handle| {
            if handle.is_closed() {
                return Poll::Ready(IrqWaitResult::closed());
            }

            if let Some(slot) = this.slot {
                let poll = poll_slot(handle, slot, cx);

                if matches!(poll, Poll::Ready(_)) {
                    this.slot = None;
                }

                return poll;
            }

            if let Some(result) = try_consume_pending(handle) {
                return Poll::Ready(result);
            }

            let Some(slot) = alloc_waiter_slot(handle) else {
                return Poll::Ready(IrqWaitResult::rescue());
            };

            this.slot = Some(slot);

            let poll = poll_slot(handle, slot, cx);

            if matches!(poll, Poll::Ready(_)) {
                this.slot = None;
            }

            poll
        }) else {
            this.slot = None;
            return Poll::Ready(IrqWaitResult::closed());
        };

        poll
    }
}

impl Drop for IrqWaitFuture {
    fn drop(&mut self) {
        let Some(slot) = self.slot.take() else {
            return;
        };

        let _ = irq_manager().with_handle(self.handle, |handle| {
            handle.cancel_waiter(slot);
        });
    }
}

struct IrqReg {
    id: usize,
    generation: usize,
    isr: IrqIsrFn,
    ctx: usize,
    handle: NonNull<IrqHandleInner>,
}

unsafe impl Send for IrqReg {}
unsafe impl Sync for IrqReg {}

extern "win64" fn dummy_isr(
    _: u8,
    _: u32,
    _: &mut InterruptStackFrame,
    _: IrqBorrowedHandle,
    _: usize,
) -> bool {
    false
}

struct VectorSlot {
    regs: IrqSafeRwLock<Vec<IrqReg>>,
}

impl VectorSlot {
    fn new() -> Self {
        Self {
            regs: IrqSafeRwLock::new(Vec::new()),
        }
    }

    fn count(&self) -> usize {
        self.regs.read().len()
    }
}

struct IdMapEntry {
    id: AtomicUsize,
    generation: AtomicUsize,
    vector: AtomicUsize,
    ptr: AtomicUsize,
    lifetime: IrqSafeRwLock<()>,
}

impl IdMapEntry {
    fn new() -> Self {
        Self {
            id: AtomicUsize::new(0),
            generation: AtomicUsize::new(0),
            vector: AtomicUsize::new(NO_VECTOR),
            ptr: AtomicUsize::new(0),
            lifetime: IrqSafeRwLock::new(()),
        }
    }
}

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
    next_generation: AtomicUsize,
}

impl IrqManager {
    fn new() -> Self {
        Self {
            vectors: core::array::from_fn(|_| VectorSlot::new()),
            id_map: core::array::from_fn(|_| IdMapEntry::new()),
            next_id: AtomicUsize::new(1),
            next_generation: AtomicUsize::new(1),
        }
    }

    fn alloc_id(&self) -> usize {
        let mut id = self.next_id.fetch_add(1, Ordering::Relaxed);

        if id == 0 || id == RESERVED_ID {
            id = self.next_id.fetch_add(1, Ordering::Relaxed);
        }

        id
    }

    fn alloc_generation(&self) -> usize {
        let mut generation = self.next_generation.fetch_add(1, Ordering::Relaxed);

        if generation == 0 {
            generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        }

        generation
    }

    fn install_handle(&self, vector: usize, ptr: NonNull<IrqHandleInner>) -> Option<IrqHandle> {
        let id = self.alloc_id();
        let generation = self.alloc_generation();

        for entry in &self.id_map {
            if entry
                .id
                .compare_exchange(0, RESERVED_ID, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                continue;
            }

            let _lifetime = entry.lifetime.write();

            entry.ptr.store(ptr.as_ptr() as usize, Ordering::Release);
            entry.vector.store(vector, Ordering::Release);
            entry.generation.store(generation, Ordering::Release);
            entry.id.store(id, Ordering::Release);

            return Some(IrqHandle { id, generation });
        }

        None
    }

    fn with_handle<R>(&self, handle: IrqHandle, f: impl FnOnce(&IrqHandleInner) -> R) -> Option<R> {
        if handle.is_null() {
            return None;
        }

        for entry in &self.id_map {
            if entry.id.load(Ordering::Acquire) != handle.id {
                continue;
            }

            let _lifetime = entry.lifetime.read();

            if entry.id.load(Ordering::Acquire) != handle.id {
                return None;
            }

            if entry.generation.load(Ordering::Acquire) != handle.generation {
                return None;
            }

            let ptr = entry.ptr.load(Ordering::Acquire);

            if ptr == 0 {
                return None;
            }

            let inner = unsafe { &*(ptr as *const IrqHandleInner) };
            return Some(f(inner));
        }

        None
    }

    fn register(
        &self,
        vector: u8,
        isr: IrqIsrFn,
        ctx: usize,
        handle: NonNull<IrqHandleInner>,
        exclusive: bool,
    ) -> Option<IrqHandle> {
        let slot = &self.vectors[vector as usize];
        let mut regs = slot.regs.write();

        if regs.len() >= MAX_HANDLERS_PER_VECTOR || (exclusive && !regs.is_empty()) {
            return None;
        }

        let public_handle = self.install_handle(vector as usize, handle)?;

        regs.push(IrqReg {
            id: public_handle.id,
            generation: public_handle.generation,
            isr,
            ctx,
            handle,
        });

        Some(public_handle)
    }

    fn unregister_handle(&self, handle: IrqHandle) {
        if handle.is_null() {
            return;
        }

        for entry in &self.id_map {
            if entry.id.load(Ordering::Acquire) != handle.id {
                continue;
            }

            let vector = entry.vector.load(Ordering::Acquire);

            if vector != NO_VECTOR {
                if vector >= self.vectors.len() {
                    return;
                }

                let slot = &self.vectors[vector];
                let mut regs = slot.regs.write();
                let _lifetime = entry.lifetime.write();

                if entry.id.load(Ordering::Acquire) != handle.id {
                    return;
                }

                if entry.generation.load(Ordering::Acquire) != handle.generation {
                    return;
                }

                let ptr = entry.ptr.load(Ordering::Acquire);

                if ptr == 0 {
                    return;
                }

                let Some(pos) = regs
                    .iter()
                    .position(|r| r.id == handle.id && r.generation == handle.generation)
                else {
                    return;
                };

                let reg = regs.swap_remove(pos);
                let inner = unsafe { reg.handle.as_ref() };

                inner.close();

                if let Some(hook) = inner.drop_hook.lock().take() {
                    hook.invoke();
                }

                entry.ptr.store(0, Ordering::Release);
                entry.vector.store(NO_VECTOR, Ordering::Release);
                entry.generation.store(0, Ordering::Release);
                entry.id.store(0, Ordering::Release);

                drop(_lifetime);
                drop(regs);

                unsafe {
                    drop(Box::from_raw(reg.handle.as_ptr()));
                }

                if VectorAllocator::is_dynamic(vector as u8) {
                    VectorAllocator::release_after_unregister(vector as u8);
                }

                return;
            }

            let _lifetime = entry.lifetime.write();

            if entry.id.load(Ordering::Acquire) != handle.id {
                return;
            }

            if entry.generation.load(Ordering::Acquire) != handle.generation {
                return;
            }

            let ptr = entry.ptr.load(Ordering::Acquire);

            if ptr == 0 {
                return;
            }

            let inner = unsafe { &*(ptr as *const IrqHandleInner) };

            inner.close();

            if let Some(hook) = inner.drop_hook.lock().take() {
                hook.invoke();
            }

            entry.ptr.store(0, Ordering::Release);
            entry.vector.store(NO_VECTOR, Ordering::Release);
            entry.generation.store(0, Ordering::Release);
            entry.id.store(0, Ordering::Release);

            drop(_lifetime);

            unsafe {
                drop(Box::from_raw(ptr as *mut IrqHandleInner));
            }

            return;
        }
    }

    fn dispatch(&self, vector: u8, frame: &mut InterruptStackFrame) {
        let cpu = current_cpu_id() as u32;
        let slot = &self.vectors[vector as usize];
        let regs = slot.regs.read();

        for r in regs.iter() {
            let claimed = (r.isr)(vector, cpu, frame, r.handle.as_ptr(), r.ctx);

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
    IrqHandle::null()
}

extern "win64" fn dummy_drop(_: usize) {}

pub fn irq_register(vector: u8, isr: IrqIsrFn, ctx: usize) -> IrqHandle {
    if vector == 0x80 {
        return null_handle();
    }

    let dynamic = VectorAllocator::is_dynamic(vector);

    if dynamic && !VectorAllocator::reserve_for_registration(vector) {
        return null_handle();
    }

    let handle_ptr = create_irq_handle_inner(DropHook::new(dummy_drop, 0));

    let first_for_vector = {
        let regs = irq_manager().vectors[vector as usize].regs.read();
        regs.is_empty()
    };

    let Some(handle) = irq_manager().register(vector, isr, ctx, handle_ptr, dynamic) else {
        unsafe {
            drop(Box::from_raw(handle_ptr.as_ptr()));
        }

        if dynamic {
            VectorAllocator::release_after_unregister(vector);
        }

        return null_handle();
    };

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
    let handle_ptr = create_irq_handle_inner(DropHook::new(dummy_drop, 0));

    let first_for_vector = {
        let regs = irq_manager().vectors[vector as usize].regs.read();
        regs.is_empty()
    };

    let Some(handle) = irq_manager().register(vector, isr, ctx, handle_ptr, false) else {
        unsafe {
            drop(Box::from_raw(handle_ptr.as_ptr()));
        }

        return null_handle();
    };

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
    let _ = irq_manager().with_handle(*handle, |inner| {
        inner.signal_one(meta);
    });
}

pub fn irq_signal_exactly(handle: &IrqHandle, meta: IrqMeta) {
    let _ = irq_manager().with_handle(*handle, |inner| {
        inner.ensure_signal_exactly_one(meta);
    });
}

pub fn irq_signal_n(handle: &IrqHandle, meta: IrqMeta, n: u32) {
    let _ = irq_manager().with_handle(*handle, |inner| {
        inner.signal_n(meta, n as usize);
    });
}

pub fn irq_signal_all(handle: &IrqHandle, meta: IrqMeta) {
    let _ = irq_manager().with_handle(*handle, |inner| {
        inner.signal_all(meta);
    });
}

pub unsafe fn irq_borrowed_signal(handle: IrqBorrowedHandle, meta: IrqMeta) {
    let Some(inner) = (unsafe { handle.as_ref() }) else {
        return;
    };

    inner.signal_one(meta);
}

pub unsafe fn irq_borrowed_ensure_signal(handle: IrqBorrowedHandle, meta: IrqMeta) {
    let Some(inner) = (unsafe { handle.as_ref() }) else {
        return;
    };

    inner.ensure_signal_exactly_one(meta);
}

pub unsafe fn irq_borrowed_signal_n(handle: IrqBorrowedHandle, meta: IrqMeta, n: u32) {
    let Some(inner) = (unsafe { handle.as_ref() }) else {
        return;
    };

    inner.signal_n(meta, n as usize);
}

pub unsafe fn irq_borrowed_signal_all(handle: IrqBorrowedHandle, meta: IrqMeta) {
    let Some(inner) = (unsafe { handle.as_ref() }) else {
        return;
    };

    inner.signal_all(meta);
}

pub fn irq_alloc_vector() -> Option<u8> {
    VectorAllocator::alloc()
}

pub fn irq_free_vector(vector: u8) -> bool {
    VectorAllocator::free_explicit(vector)
}

pub const SCHED_IPI_VECTOR: u8 = 0xF2;
pub const TLB_FLUSH_VECTOR: u8 = 0xF3;

pub struct InterruptGuard {
    was_in_interrupt: bool,
}

impl InterruptGuard {
    pub fn new() -> Self {
        let was_in_interrupt = current_is_in_interrupt_atomic().swap(true, Ordering::AcqRel);
        InterruptGuard { was_in_interrupt }
    }

    #[inline(always)]
    pub fn is_outermost(&self) -> bool {
        !self.was_in_interrupt
    }
}

impl Drop for InterruptGuard {
    fn drop(&mut self) {
        if !self.was_in_interrupt {
            current_is_in_interrupt_atomic().store(false, Ordering::Release);
        }
    }
}

pub struct NestedInterruptEnableGuard {
    disable_on_drop: bool,
}

impl NestedInterruptEnableGuard {
    #[inline(always)]
    pub fn new() -> Self {
        let was_enabled = x86_64::instructions::interrupts::are_enabled();

        if !was_enabled {
            x86_64::instructions::interrupts::enable();
        }

        Self {
            disable_on_drop: !was_enabled,
        }
    }
}

impl Drop for NestedInterruptEnableGuard {
    #[inline(always)]
    fn drop(&mut self) {
        if self.disable_on_drop {
            x86_64::instructions::interrupts::disable();
        }
    }
}
