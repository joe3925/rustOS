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
    DropHook, IrqBorrowedHandle, IrqHandle, IrqHandleInner, IrqIsrFn, IrqMeta, IrqSafeMutex,
    IrqSafeRwLock, IrqWaitResult, WaitState, Waiter, WaiterPtr,
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
    fn cancel_waiter(&self, waiter: WaiterPtr);
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

        let mut st = self.state.lock();
        st.pending_signals = 0;

        while let Some(waiter_ptr) = st.pop_waiter() {
            let waiter = unsafe { waiter_ptr.as_ref() };
            waiter.enqueued.store(false, Ordering::Release);
            waiter.store_result(IrqWaitResult::closed());
            waiter.wake_by_ref();
        }
    }

    fn signal_one(&self, meta: IrqMeta) {
        if self.is_closed() {
            return;
        }

        let mut st = self.state.lock();
        st.last_meta = meta;

        let Some(waiter_ptr) = st.pop_waiter() else {
            st.pending_signals = st.pending_signals.saturating_add(1);
            return;
        };

        let waiter = unsafe { waiter_ptr.as_ref() };
        waiter.enqueued.store(false, Ordering::Release);
        waiter.store_result(IrqWaitResult::ok_n(meta, 1));
        waiter.wake_by_ref();
    }

    fn ensure_signal_exactly_one(&self, meta: IrqMeta) {
        if self.is_closed() {
            return;
        }

        let mut st = self.state.lock();
        st.last_meta = meta;

        let Some(waiter_ptr) = st.pop_waiter() else {
            st.pending_signals = 1;
            return;
        };

        let waiter = unsafe { waiter_ptr.as_ref() };
        waiter.enqueued.store(false, Ordering::Release);
        waiter.store_result(IrqWaitResult::ok_n(meta, 1));
        waiter.wake_by_ref();
    }

    fn signal_n(&self, meta: IrqMeta, n: usize) -> usize {
        if n == 0 || self.is_closed() {
            return 0;
        }

        let mut st = self.state.lock();
        st.last_meta = meta;

        let mut woken = 0;

        while woken < n {
            let Some(waiter_ptr) = st.pop_waiter() else {
                st.pending_signals = st.pending_signals.saturating_add(n - woken);
                break;
            };

            let waiter = unsafe { waiter_ptr.as_ref() };
            waiter.enqueued.store(false, Ordering::Release);
            waiter.store_result(IrqWaitResult::ok_n(meta, 1));
            waiter.wake_by_ref();

            woken += 1;
        }

        woken
    }

    fn signal_all(&self, meta: IrqMeta) -> usize {
        if self.is_closed() {
            return 0;
        }

        let mut st = self.state.lock();
        st.last_meta = meta;

        let mut woken = 0;

        while let Some(waiter_ptr) = st.pop_waiter() {
            let waiter = unsafe { waiter_ptr.as_ref() };
            waiter.enqueued.store(false, Ordering::Release);
            waiter.store_result(IrqWaitResult::ok_n(meta, 1));
            waiter.wake_by_ref();

            woken += 1;
        }

        if woken == 0 {
            st.pending_signals = st.pending_signals.saturating_add(1);
        }

        woken
    }

    fn cancel_waiter(&self, waiter_ptr: WaiterPtr) {
        let mut st = self.state.lock();
        let waiter = unsafe { waiter_ptr.as_ref() };

        if waiter.enqueued.swap(false, Ordering::AcqRel) {
            st.remove_waiter(waiter_ptr);
        }

        waiter.clear();
    }

    fn set_user_ctx(&self, v: usize) {
        self.user_ctx.store(v, Ordering::Release);
    }

    fn user_ctx(&self) -> usize {
        self.user_ctx.load(Ordering::Acquire)
    }
}

pub(crate) fn create_irq_handle_inner(drop_hook: DropHook) -> NonNull<IrqHandleInner> {
    let inner = Box::new(IrqHandleInner {
        drop_hook: Mutex::new(Some(drop_hook)),
        closed: AtomicBool::new(false),
        user_ctx: AtomicUsize::new(0),
        state: IrqSafeMutex::new(WaitState::new()),
    });

    unsafe { NonNull::new_unchecked(Box::into_raw(inner)) }
}

pub(crate) fn irq_wait_future(handle: &IrqHandle) -> IrqWaitFuture {
    let waiter = Box::new(Waiter::new());
    let waiter = unsafe { WaiterPtr::from_raw(Box::into_raw(waiter)) };

    IrqWaitFuture {
        handle: *handle,
        test_wakeup: AtomicUsize::new(0),
        waiter: Some(waiter),
    }
}

pub struct IrqWaitFuture {
    handle: IrqHandle,
    test_wakeup: AtomicUsize,
    waiter: Option<WaiterPtr>,
}

impl IrqWaitFuture {
    fn free_waiter(&mut self) {
        let Some(waiter) = self.waiter.take() else {
            return;
        };

        unsafe {
            drop(Box::from_raw(waiter.as_ptr()));
        }
    }
}

impl Future for IrqWaitFuture {
    type Output = IrqWaitResult;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        let Some(waiter_ptr) = this.waiter else {
            return Poll::Ready(IrqWaitResult::closed());
        };

        let Some(poll) = irq_manager().with_handle(this.handle, |handle| {
            let waiter = unsafe { waiter_ptr.as_ref() };
            let mut st = handle.state.lock();

            if let Some(r) = waiter.take_result() {
                this.free_waiter();
                return Poll::Ready(r);
            }

            if this.test_wakeup.load(Ordering::Relaxed) > 500_000_000 {
                if waiter.enqueued.swap(false, Ordering::AcqRel) {
                    st.remove_waiter(waiter_ptr);
                }

                waiter.clear();
                this.free_waiter();
                return Poll::Ready(IrqWaitResult::rescue());
            }

            if handle.is_closed() {
                if waiter.enqueued.swap(false, Ordering::AcqRel) {
                    st.remove_waiter(waiter_ptr);
                }

                waiter.clear();
                this.free_waiter();
                return Poll::Ready(IrqWaitResult::closed());
            }

            waiter.set_waker(cx.waker());

            if st.pending_signals > 0 {
                st.pending_signals -= 1;
                let meta = st.last_meta;

                if waiter.enqueued.swap(false, Ordering::AcqRel) {
                    st.remove_waiter(waiter_ptr);
                }

                waiter.clear();
                this.free_waiter();
                return Poll::Ready(IrqWaitResult::ok_n(meta, 1));
            }

            if !waiter.enqueued.swap(true, Ordering::AcqRel) {
                st.push_waiter(waiter_ptr);
            }

            this.test_wakeup.fetch_add(1, Ordering::Relaxed);
            Poll::Pending
        }) else {
            this.free_waiter();
            return Poll::Ready(IrqWaitResult::closed());
        };

        poll
    }
}

impl Drop for IrqWaitFuture {
    fn drop(&mut self) {
        let Some(waiter) = self.waiter else {
            return;
        };

        let _ = irq_manager().with_handle(self.handle, |handle| {
            handle.cancel_waiter(waiter);
        });

        self.free_waiter();
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
        let _guard = InterruptGuard::new();
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
    let Some(inner) = handle.as_ref() else {
        return;
    };

    inner.signal_one(meta);
}

pub unsafe fn irq_borrowed_ensure_signal(handle: IrqBorrowedHandle, meta: IrqMeta) {
    let Some(inner) = handle.as_ref() else {
        return;
    };

    inner.ensure_signal_exactly_one(meta);
}

pub unsafe fn irq_borrowed_signal_n(handle: IrqBorrowedHandle, meta: IrqMeta, n: u32) {
    let Some(inner) = handle.as_ref() else {
        return;
    };

    inner.signal_n(meta, n as usize);
}

pub unsafe fn irq_borrowed_signal_all(handle: IrqBorrowedHandle, meta: IrqMeta) {
    let Some(inner) = handle.as_ref() else {
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

pub struct InterruptGuard {}

impl InterruptGuard {
    pub fn new() -> Self {
        current_is_in_interrupt_atomic().store(true, Ordering::Relaxed);
        InterruptGuard {}
    }
}

impl Drop for InterruptGuard {
    fn drop(&mut self) {
        current_is_in_interrupt_atomic().store(false, Ordering::Relaxed);
    }
}
