use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::future::Future;
use core::ops::Deref;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};
use core::task::{Context, Poll};
use kernel_types::async_ffi::{AbiFuture, FutureExt};
use kernel_types::irq::{
    AtomicIrqMeta, DropHook, HardwareInterruptId, IrqBorrowedHandle, IrqFrame, IrqHandle,
    IrqHandleInner, IrqIsrFn, IrqMeta, IrqWaitResult, MsiBinding, MsiBindingRequest,
    WAITER_CLAIMED, WAITER_FREE, WAITER_MAX_TICKET, WAITER_PREPARING, WAITER_SIGNALED,
    WAITER_WAITING, WaiterSlot,
};
use spin::{Mutex, Once};

use crate::platform::{self, ActivePlatform, InterruptPlatform};

pub type InterruptFrame = <ActivePlatform as InterruptPlatform>::InterruptFrame;

const SLOT_CLOSED: usize = 1 << (usize::BITS - 1);
const SLOT_READERS: usize = SLOT_CLOSED - 1;
const NO_VECTOR: usize = usize::MAX;
const NO_SOURCE: usize = usize::MAX;
const MAX_INTERRUPT_IDS: usize = 1024;
static BINDING_LIFECYCLE: Mutex<()> = Mutex::new(());

#[unsafe(no_mangle)]
pub extern "C" fn irq_handle_create(drop_hook: DropHook) -> IrqHandle {
    let inner = create_irq_handle_inner(drop_hook);
    irq_manager()
        .install_handle(NO_VECTOR, NO_SOURCE, inner, dummy_isr, 0, false)
        .unwrap_or_else(null_handle)
}

#[unsafe(no_mangle)]
pub extern "C" fn irq_handle_clone(h: &IrqHandle) -> IrqHandle {
    *h
}

#[unsafe(no_mangle)]
pub extern "C" fn irq_handle_drop(_h: IrqHandle) {}

#[unsafe(no_mangle)]
pub extern "C" fn irq_handle_unregister(h: &IrqHandle) {
    irq_manager().unregister_handle(*h);
}

#[unsafe(no_mangle)]
pub extern "C" fn irq_handle_is_closed(h: &IrqHandle) -> bool {
    if h.is_null() {
        return true;
    }

    irq_manager()
        .with_handle(*h, |inner| inner.is_closed())
        .unwrap_or(true)
}

#[unsafe(no_mangle)]
pub extern "C" fn irq_handle_set_user_ctx(h: &IrqHandle, v: usize) {
    let _ = irq_manager().with_handle(*h, |inner| {
        inner.set_user_ctx(v);
    });
}

#[unsafe(no_mangle)]
pub extern "C" fn irq_handle_get_user_ctx(h: &IrqHandle) -> usize {
    irq_manager()
        .with_handle(*h, |inner| inner.user_ctx())
        .unwrap_or(0)
}

#[unsafe(no_mangle)]
pub extern "C" fn irq_handle_signal_one(h: &IrqHandle, meta: IrqMeta) {
    irq_signal(h, meta);
}

#[unsafe(no_mangle)]
pub extern "C" fn irq_handle_signal_exactly_one(h: &IrqHandle, meta: IrqMeta) {
    irq_signal_exactly(h, meta);
}

#[unsafe(no_mangle)]
pub extern "C" fn irq_handle_signal_n(h: &IrqHandle, meta: IrqMeta, n: u32) {
    irq_signal_n(h, meta, n);
}

#[unsafe(no_mangle)]
pub extern "C" fn irq_handle_wait_abi(h: &IrqHandle, _meta: IrqMeta) -> AbiFuture<IrqWaitResult> {
    irq_wait_future(h).into_abi()
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

            if let Some(waker) = unsafe { slot.complete_claimed(ticket, IrqWaitResult::closed()) } {
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

            if let Some(waker) =
                unsafe { slot.complete_claimed(ticket, IrqWaitResult::ok_n(meta, 1)) }
            {
                waker.wake_by_ref();
            }

            self.signal_phase.fetch_add(1, Ordering::AcqRel);
            self.signal_active.fetch_sub(1, Ordering::AcqRel);
            return;
        }

        let _ = self
            .pending_signals
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |pending| {
                if pending == 0 { Some(1) } else { Some(pending) }
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

            if let Some(waker) =
                unsafe { slot.complete_claimed(ticket, IrqWaitResult::ok_n(meta, 1)) }
            {
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

            if let Some(waker) =
                unsafe { slot.complete_claimed(ticket, IrqWaitResult::ok_n(meta, 1)) }
            {
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

    if ticket == 0 { 1 } else { ticket }
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

    unsafe {
        slot.set_preparing();
        slot.set_waker_exclusive(cx.waker());
    }

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
    unsafe { slot.publish(ticket) };
    let phase_after = handle.signal_phase.load(Ordering::Acquire);

    if phase_before != phase_after
        || handle.signal_active.load(Ordering::Acquire) != 0
        || handle.pending_signals.load(Ordering::Acquire) != 0
    {
        cx.waker().wake_by_ref();
    }

    Poll::Pending
}

pub(crate) fn create_irq_handle_inner(drop_hook: DropHook) -> IrqHandleInner {
    assert!(!platform::current_is_in_interrupt());
    IrqHandleInner {
        drop_hook: Mutex::new(Some(drop_hook)),
        closed: AtomicBool::new(false),
        user_ctx: AtomicUsize::new(0),
        pending_signals: AtomicUsize::new(0),
        signal_phase: AtomicUsize::new(0),
        signal_active: AtomicUsize::new(0),
        waiter_ticket: AtomicUsize::new(0),
        last_meta: AtomicIrqMeta::new(),
        waiters: core::array::from_fn(|_| WaiterSlot::new()),
    }
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
    source: usize,
    isr: IrqIsrFn,
    ctx: usize,
    inner: IrqHandleInner,
}

extern "C" fn dummy_isr(_: u32, _: u32, _: &mut IrqFrame, _: IrqBorrowedHandle, _: usize) -> bool {
    false
}

struct VectorSlot {
    head: AtomicPtr<IdMapEntry>,
    tail: AtomicPtr<IdMapEntry>,
    users: AtomicUsize,
}

impl VectorSlot {
    fn new() -> Self {
        Self {
            head: AtomicPtr::new(core::ptr::null_mut()),
            tail: AtomicPtr::new(core::ptr::null_mut()),
            users: AtomicUsize::new(0),
        }
    }
}

struct IdMapEntry {
    access: AtomicUsize,
    id: AtomicUsize,
    vector: usize,
    next: Option<&'static IdMapEntry>,
    vector_next: AtomicPtr<IdMapEntry>,
    registration: UnsafeCell<Option<IrqReg>>,
}

unsafe impl Sync for IdMapEntry {}

impl IdMapEntry {
    fn try_read(&self) -> Option<IrqReadGuard<'_>> {
        let previous = self.access.fetch_add(1, Ordering::Acquire);
        let guard = IrqReadGuard { entry: self };
        if previous & SLOT_CLOSED != 0 {
            return None;
        }
        Some(guard)
    }
}

struct IrqReadGuard<'a> {
    entry: &'a IdMapEntry,
}

impl Deref for IrqReadGuard<'_> {
    type Target = IrqReg;

    fn deref(&self) -> &IrqReg {
        unsafe { (&*self.entry.registration.get()).as_ref().unwrap() }
    }
}

impl Drop for IrqReadGuard<'_> {
    fn drop(&mut self) {
        self.entry.access.fetch_sub(1, Ordering::Release);
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
        platform::is_dynamic_vector(vector)
    }

    fn alloc() -> Option<u8> {
        for vec in platform::dynamic_vector_range() {
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
}

pub struct IrqManager {
    vectors: [VectorSlot; MAX_INTERRUPT_IDS],
    id_map: AtomicPtr<IdMapEntry>,
    entries: Mutex<Vec<&'static IdMapEntry>>,
    next_id: AtomicUsize,
}

impl IrqManager {
    fn new() -> Self {
        Self {
            vectors: core::array::from_fn(|_| VectorSlot::new()),
            id_map: AtomicPtr::new(core::ptr::null_mut()),
            entries: Mutex::new(Vec::new()),
            next_id: AtomicUsize::new(1),
        }
    }

    fn install_handle(
        &self,
        vector: usize,
        source: usize,
        inner: IrqHandleInner,
        isr: IrqIsrFn,
        ctx: usize,
        exclusive: bool,
    ) -> Option<IrqHandle> {
        assert!(!platform::current_is_in_interrupt());
        let mut entries = self.entries.lock();
        let slot = if vector == NO_VECTOR {
            None
        } else {
            let slot = self.vectors.get(vector)?;
            if exclusive && slot.users.load(Ordering::Relaxed) != 0 {
                return None;
            }
            Some(slot)
        };
        let id = self
            .next_id
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .ok()?;
        let handle = IrqHandle { id, generation: id };
        let entry = if let Some(entry) = entries
            .iter()
            .copied()
            .find(|entry| entry.vector == vector && entry.id.load(Ordering::Acquire) == 0)
        {
            entry
        } else {
            let entry: &'static IdMapEntry = Box::leak(Box::new(IdMapEntry {
                access: AtomicUsize::new(SLOT_CLOSED),
                id: AtomicUsize::new(0),
                vector,
                next: unsafe { self.id_map.load(Ordering::Acquire).as_ref() },
                vector_next: AtomicPtr::new(core::ptr::null_mut()),
                registration: UnsafeCell::new(None),
            }));
            entries.push(entry);
            let address = core::ptr::from_ref(entry).cast_mut();
            self.id_map.store(address, Ordering::Release);
            if let Some(slot) = slot {
                let tail = slot.tail.load(Ordering::Relaxed);
                if let Some(tail) = unsafe { tail.as_ref() } {
                    tail.vector_next.store(address, Ordering::Release);
                } else {
                    slot.head.store(address, Ordering::Release);
                }
                slot.tail.store(address, Ordering::Release);
            }
            entry
        };
        unsafe {
            *entry.registration.get() = Some(IrqReg {
                id,
                generation: id,
                source,
                isr,
                ctx,
                inner,
            });
        }
        entry.id.store(id, Ordering::Release);
        entry.access.fetch_and(SLOT_READERS, Ordering::Release);
        if let Some(slot) = slot {
            slot.users.fetch_add(1, Ordering::Release);
        }
        Some(handle)
    }

    fn with_handle<R>(&self, handle: IrqHandle, f: impl FnOnce(&IrqHandleInner) -> R) -> Option<R> {
        if handle.is_null() {
            return None;
        }
        let mut entry = unsafe { self.id_map.load(Ordering::Acquire).as_ref() };
        while let Some(current) = entry {
            if current.id.load(Ordering::Acquire) == handle.id {
                let registration = current.try_read()?;
                if registration.id != handle.id || registration.generation != handle.generation {
                    return None;
                }
                return Some(f(&registration.inner));
            }
            entry = current.next;
        }
        None
    }

    fn unregister_handle(&self, handle: IrqHandle) {
        assert!(!platform::current_is_in_interrupt());
        if handle.is_null() {
            return;
        }
        let lifecycle = BINDING_LIFECYCLE.lock();
        let entries = self.entries.lock();
        let Some(entry) = entries
            .iter()
            .copied()
            .find(|entry| entry.id.load(Ordering::Acquire) == handle.id)
        else {
            return;
        };
        {
            let Some(registration) = entry.try_read() else {
                drop(entries);
                drop(lifecycle);
                while entry.id.load(Ordering::Acquire) == handle.id {
                    if platform::interrupts_enabled() {
                        crate::scheduling::runtime::runtime::yield_now();
                    } else {
                        core::hint::spin_loop();
                    }
                }
                return;
            };
            if registration.id != handle.id || registration.generation != handle.generation {
                return;
            }
        }
        entry.access.fetch_or(SLOT_CLOSED, Ordering::AcqRel);
        drop(entries);
        drop(lifecycle);
        while entry.access.load(Ordering::Acquire) & SLOT_READERS != 0 {
            if platform::interrupts_enabled() {
                crate::scheduling::runtime::runtime::yield_now();
            } else {
                core::hint::spin_loop();
            }
        }
        let lifecycle = BINDING_LIFECYCLE.lock();
        let registration = unsafe { (&mut *entry.registration.get()).take().unwrap() };
        if entry.vector != NO_VECTOR {
            let slot = &self.vectors[entry.vector];
            if slot.users.fetch_sub(1, Ordering::AcqRel) == 1 && registration.source != NO_SOURCE {
                platform::unbind_wired_interrupt(HardwareInterruptId(registration.source as u32));
            }
        }
        registration.inner.close();
        let hook = registration.inner.drop_hook.lock().take();
        if let Some(hook) = hook {
            hook.invoke();
        }
        let owns_vector = registration.source == NO_SOURCE
            || platform::wired_interrupt_id(HardwareInterruptId(registration.source as u32))
                .is_none();
        if entry.vector <= u8::MAX as usize
            && owns_vector
            && VectorAllocator::is_dynamic(entry.vector as u8)
        {
            VectorAllocator::release_after_unregister(entry.vector as u8);
        }
        drop(registration);
        let _entries = self.entries.lock();
        entry.id.store(0, Ordering::Release);
        drop(lifecycle);
    }

    fn dispatch(&self, interrupt_id: u32, frame: &mut InterruptFrame) {
        let cpu = platform::current_cpu_id() as u32;
        let Some(slot) = self.vectors.get(interrupt_id as usize) else {
            return;
        };
        let tail = slot.tail.load(Ordering::Acquire);
        if tail.is_null() {
            return;
        }
        let mut entry = slot.head.load(Ordering::Acquire);
        while let Some(current) = unsafe { entry.as_ref() } {
            if let Some(registration) = current.try_read() {
                let frame = unsafe { &mut *(frame as *mut InterruptFrame as *mut IrqFrame) };
                let claimed = (registration.isr)(
                    interrupt_id,
                    cpu,
                    frame,
                    &registration.inner,
                    registration.ctx,
                );
                if claimed {
                    break;
                }
            }
            if entry == tail {
                break;
            }
            entry = current.vector_next.load(Ordering::Acquire);
        }
    }
}

static IRQ_MANAGER: Once<IrqManager> = Once::new();

fn irq_manager() -> &'static IrqManager {
    IRQ_MANAGER.call_once(|| IrqManager::new())
}

fn null_handle() -> IrqHandle {
    IrqHandle::null()
}

extern "C" fn dummy_drop(_: usize) {}

extern "C" fn msi_drop(vector: usize) {
    if let Ok(vector) = u8::try_from(vector) {
        platform::unbind_msi(vector);
    }
}

fn register_vector(
    vector: u8,
    isr: IrqIsrFn,
    ctx: usize,
    source: usize,
    drop_hook: DropHook,
) -> IrqHandle {
    if platform::is_reserved_vector(vector) {
        return null_handle();
    }

    let dynamic = VectorAllocator::is_dynamic(vector);

    if dynamic && !VectorAllocator::reserve_for_registration(vector) {
        return null_handle();
    }

    let inner = create_irq_handle_inner(drop_hook);

    let Some(handle) =
        irq_manager().install_handle(vector as usize, source, inner, isr, ctx, dynamic)
    else {
        if dynamic {
            VectorAllocator::release_after_unregister(vector);
        }

        return null_handle();
    };

    handle
}

pub fn bind_wired_interrupt(source: HardwareInterruptId, isr: IrqIsrFn, ctx: usize) -> IrqHandle {
    assert!(!platform::current_is_in_interrupt());
    let lifecycle = BINDING_LIFECYCLE.lock();
    let (interrupt_id, handle, activate) =
        if let Some(interrupt_id) = platform::wired_interrupt_id(source) {
            if interrupt_id as usize >= MAX_INTERRUPT_IDS {
                return null_handle();
            }
            let activate = irq_manager().vectors[interrupt_id as usize]
                .users
                .load(Ordering::Acquire)
                == 0;
            let inner = create_irq_handle_inner(DropHook::new(dummy_drop, 0));
            let Some(handle) = irq_manager().install_handle(
                interrupt_id as usize,
                source.0 as usize,
                inner,
                isr,
                ctx,
                false,
            ) else {
                return null_handle();
            };
            (interrupt_id, handle, activate)
        } else {
            let Some(vector) = VectorAllocator::alloc() else {
                return null_handle();
            };
            (
                vector as u32,
                register_vector(
                    vector,
                    isr,
                    ctx,
                    source.0 as usize,
                    DropHook::new(dummy_drop, 0),
                ),
                true,
            )
        };
    if handle.is_null() {
        return handle;
    }
    if activate && !platform::bind_wired_interrupt(source, interrupt_id) {
        drop(lifecycle);
        irq_manager().unregister_handle(handle);
        return null_handle();
    }
    handle
}

pub fn bind_msi_interrupt(
    request: &MsiBindingRequest,
    isr: IrqIsrFn,
    ctx: usize,
) -> Option<MsiBinding> {
    assert!(!platform::current_is_in_interrupt());
    let lifecycle = BINDING_LIFECYCLE.lock();
    let vector = VectorAllocator::alloc()?;
    let handle = register_vector(
        vector,
        isr,
        ctx,
        NO_SOURCE,
        DropHook::new(msi_drop, vector as usize),
    );
    if handle.is_null() {
        return None;
    }
    let Some(message) = platform::bind_msi(request, vector) else {
        drop(lifecycle);
        irq_manager().unregister_handle(handle);
        return None;
    };
    Some(MsiBinding { handle, message })
}

pub fn irq_dispatch(interrupt_id: u32, frame: &mut InterruptFrame) {
    irq_manager().dispatch(interrupt_id, frame);
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

pub struct InterruptGuard {
    was_in_interrupt: bool,
}

impl InterruptGuard {
    pub fn new() -> Self {
        let was_in_interrupt = platform::enter_interrupt();
        InterruptGuard { was_in_interrupt }
    }

    #[inline(always)]
    pub fn is_outermost(&self) -> bool {
        !self.was_in_interrupt
    }
}

impl Drop for InterruptGuard {
    fn drop(&mut self) {
        platform::leave_interrupt(self.was_in_interrupt);
    }
}
