use alloc::{sync::Arc, vec::Vec};
use core::marker::PhantomPinned;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use core::task::Waker;
use kernel_types::async_ffi::{FfiFuture, FutureExt};
use kernel_types::irq::{
    DropHook, IrqHandleOpaque, IrqHandlePtr, IrqIsrFn, IrqMeta, IrqSafeMutex, IrqWaitResult,
};
use spin::Once;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame};
use x86_64::VirtAddr;

use crate::drivers;
use crate::drivers::interrupt_index::{current_cpu_id, get_current_logical_id, send_eoi, APIC};
use crate::drivers::timer_driver::timer_interrupt_entry;
use crate::exception_handlers::exception_handlers;
use crate::gdt::{DOUBLE_FAULT_IST_INDEX, PAGE_FAULT_IST_INDEX, TIMER_IST_INDEX, YIELD_IST_INDEX};
use crate::scheduling::scheduler::{ipi_entry, yield_interrupt_entry};

struct WaiterNode {
    next: *mut WaiterNode,
    waker: Option<Waker>,
    enqueued: bool,
    result: Option<IrqWaitResult>,
}

unsafe impl Send for WaiterNode {}

impl WaiterNode {
    const fn new() -> Self {
        Self {
            next: ptr::null_mut(),
            waker: None,
            enqueued: false,
            result: None,
        }
    }
}

struct WaiterList {
    head: *mut WaiterNode,
    tail: *mut WaiterNode,
}

unsafe impl Send for WaiterList {}

impl WaiterList {
    const fn new() -> Self {
        Self {
            head: ptr::null_mut(),
            tail: ptr::null_mut(),
        }
    }

    fn push_back(&mut self, node: *mut WaiterNode) {
        unsafe {
            (*node).next = ptr::null_mut();
        }
        if self.head.is_null() {
            self.head = node;
            self.tail = node;
        } else {
            unsafe {
                (*self.tail).next = node;
            }
            self.tail = node;
        }
    }

    fn pop_front(&mut self) -> Option<*mut WaiterNode> {
        let head = self.head;
        if head.is_null() {
            return None;
        }

        let next = unsafe { (*head).next };
        self.head = next;
        if next.is_null() {
            self.tail = ptr::null_mut();
        }
        unsafe {
            (*head).next = ptr::null_mut();
        }
        Some(head)
    }

    fn remove(&mut self, target: *mut WaiterNode) -> bool {
        let mut prev: *mut WaiterNode = ptr::null_mut();
        let mut curr = self.head;
        while !curr.is_null() {
            if curr == target {
                let next = unsafe { (*curr).next };
                if prev.is_null() {
                    self.head = next;
                } else {
                    unsafe { (*prev).next = next };
                }
                if self.tail == curr {
                    self.tail = prev;
                }
                unsafe {
                    (*curr).next = ptr::null_mut();
                    (*curr).enqueued = false;
                }
                return true;
            }
            prev = curr;
            curr = unsafe { (*curr).next };
        }
        false
    }
}

struct WaitState {
    waiters: WaiterList,
    pending_signals: usize,
    last_meta: IrqMeta,
}

unsafe impl Send for WaitState {}

impl WaitState {
    const fn new() -> Self {
        Self {
            waiters: WaiterList::new(),
            pending_signals: 0,
            last_meta: IrqMeta::new(),
        }
    }
}

struct IrqHandleInner {
    drop_hook: Option<DropHook>,
    closed: AtomicBool,
    user_ctx: AtomicUsize,
    state: IrqSafeMutex<WaitState>,
}

impl IrqHandleInner {
    fn new(drop_hook: DropHook) -> Self {
        Self {
            drop_hook: Some(drop_hook),
            closed: AtomicBool::new(false),
            user_ctx: AtomicUsize::new(0),
            state: IrqSafeMutex::new(WaitState::new()),
        }
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }

        let mut wakers: Vec<Waker> = Vec::new();

        {
            let mut state = self.state.lock();
            state.pending_signals = 0;

            while let Some(node) = state.waiters.pop_front() {
                unsafe {
                    (*node).enqueued = false;
                    (*node).next = ptr::null_mut();
                    (*node).result = Some(IrqWaitResult::closed());
                    if let Some(w) = (*node).waker.take() {
                        wakers.push(w);
                    }
                }
            }
        }

        for w in wakers {
            w.wake();
        }
    }

    fn signal_one(&self, meta: IrqMeta) {
        if self.is_closed() {
            return;
        }

        let mut waker: Option<Waker> = None;
        {
            let mut state = self.state.lock();
            state.last_meta = meta;

            if let Some(node) = state.waiters.pop_front() {
                unsafe {
                    (*node).enqueued = false;
                    (*node).next = core::ptr::null_mut();
                    (*node).result = Some(IrqWaitResult::ok_n(meta, 1));
                    waker = (*node).waker.take();
                }
            } else {
                state.pending_signals = state.pending_signals.saturating_add(1);
            }
        }

        if let Some(w) = waker {
            w.wake();
        }
    }
    fn signal_n(&self, meta: IrqMeta, n: usize) -> usize {
        if n == 0 || self.is_closed() {
            return 0;
        }

        let mut wakers: Vec<Waker> = Vec::new();
        let mut woken = 0;

        {
            let mut state = self.state.lock();
            state.last_meta = meta;

            while woken < n {
                let Some(node) = state.waiters.pop_front() else {
                    break;
                };
                unsafe {
                    (*node).enqueued = false;
                    (*node).next = ptr::null_mut();
                    (*node).result = Some(IrqWaitResult::ok_n(meta, 1));
                    if let Some(w) = (*node).waker.take() {
                        wakers.push(w);
                    }
                }
                woken += 1;
            }

            if woken < n {
                state.pending_signals = state.pending_signals.saturating_add(n - woken);
            }
        }

        for w in wakers {
            w.wake();
        }
        woken
    }

    fn signal_all(&self, meta: IrqMeta) -> usize {
        if self.is_closed() {
            return 0;
        }

        let mut wakers: Vec<Waker> = Vec::new();
        let mut woken = 0;

        {
            let mut state = self.state.lock();
            state.last_meta = meta;

            while let Some(node) = state.waiters.pop_front() {
                unsafe {
                    (*node).enqueued = false;
                    (*node).next = ptr::null_mut();
                    (*node).result = Some(IrqWaitResult::ok_n(meta, 1));
                    if let Some(w) = (*node).waker.take() {
                        wakers.push(w);
                    }
                }
                woken += 1;
            }
        }

        for w in wakers {
            w.wake();
        }
        woken
    }

    fn cancel_waiter(&self, node: *mut WaiterNode) {
        let mut state = self.state.lock();
        unsafe {
            if !(*node).enqueued {
                return;
            }
        }
        let _ = state.waiters.remove(node);
    }
}

impl Drop for IrqHandleInner {
    fn drop(&mut self) {
        if let Some(hook) = self.drop_hook.take() {
            hook.invoke();
        }
    }
}

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
        let _ = Arc::into_raw(arc);
        Self(cloned)
    }

    fn as_inner(&self) -> &IrqHandleInner {
        &self.0
    }
}

struct IrqWaitFuture {
    handle: IrqHandleArc,
    waiter: WaiterNode,
    _pin: PhantomPinned,
}

unsafe impl Send for IrqWaitFuture {}

impl IrqWaitFuture {
    fn new(handle: IrqHandleArc) -> Self {
        Self {
            handle,
            waiter: WaiterNode::new(),
            _pin: PhantomPinned,
        }
    }
}

impl core::future::Future for IrqWaitFuture {
    type Output = IrqWaitResult;

    fn poll(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        let this = unsafe { self.as_mut().get_unchecked_mut() };

        if let Some(result) = this.waiter.result.take() {
            return core::task::Poll::Ready(result);
        }

        {
            let handle = this.handle.as_inner();
            let mut state = handle.state.lock();

            if handle.is_closed() {
                return core::task::Poll::Ready(IrqWaitResult::closed());
            }

            let node_ptr: *mut WaiterNode = &mut this.waiter;

            if state.pending_signals > 0 {
                state.pending_signals -= 1;
                if this.waiter.enqueued {
                    let _ = state.waiters.remove(node_ptr);
                    this.waiter.enqueued = false;
                }
                let meta = state.last_meta;
                return core::task::Poll::Ready(IrqWaitResult::ok_n(meta, 1));
            }

            if !this.waiter.enqueued {
                this.waiter.enqueued = true;
                this.waiter.next = ptr::null_mut();
                state.waiters.push_back(node_ptr);
            }

            this.waiter.waker = Some(cx.waker().clone());
        }

        core::task::Poll::Pending
    }
}

impl Drop for IrqWaitFuture {
    fn drop(&mut self) {
        if self.waiter.enqueued {
            let ptr: *mut WaiterNode = &mut self.waiter;
            self.handle.as_inner().cancel_waiter(ptr);
            self.waiter.enqueued = false;
        }
    }
}

#[unsafe(no_mangle)]
pub extern "win64" fn irq_handle_create(drop_hook: DropHook) -> IrqHandlePtr {
    let handle = IrqHandleArc::new(drop_hook);
    handle.into_raw()
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn irq_handle_clone(h: IrqHandlePtr) -> IrqHandlePtr {
    if h.is_null() {
        return core::ptr::null_mut();
    }
    let cloned = IrqHandleArc::clone_from_raw(h);
    cloned.into_raw()
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn irq_handle_drop(h: IrqHandlePtr) {
    if h.is_null() {
        return;
    }
    let _ = IrqHandleArc::from_raw(h);
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn irq_handle_unregister(h: IrqHandlePtr) {
    if h.is_null() {
        return;
    }
    let arc = Arc::from_raw(h as *const IrqHandleInner);
    arc.close();
    let _ = Arc::into_raw(arc);
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn irq_handle_is_closed(h: IrqHandlePtr) -> bool {
    if h.is_null() {
        return true;
    }
    let arc = Arc::from_raw(h as *const IrqHandleInner);
    let r = arc.is_closed();
    let _ = Arc::into_raw(arc);
    r
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn irq_handle_set_user_ctx(h: IrqHandlePtr, v: usize) {
    if h.is_null() {
        return;
    }
    let arc = Arc::from_raw(h as *const IrqHandleInner);
    arc.user_ctx.store(v, Ordering::Release);
    let _ = Arc::into_raw(arc);
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn irq_handle_get_user_ctx(h: IrqHandlePtr) -> usize {
    if h.is_null() {
        return 0;
    }
    let arc = Arc::from_raw(h as *const IrqHandleInner);
    let v = arc.user_ctx.load(Ordering::Acquire);
    let _ = Arc::into_raw(arc);
    v
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn irq_handle_signal_one(h: IrqHandlePtr, meta: IrqMeta) {
    if h.is_null() {
        return;
    }
    let arc = Arc::from_raw(h as *const IrqHandleInner);
    arc.signal_one(meta);
    let _ = Arc::into_raw(arc);
}

#[unsafe(no_mangle)]
pub unsafe extern "win64" fn irq_handle_signal_n(h: IrqHandlePtr, meta: IrqMeta, n: u32) {
    if h.is_null() || n == 0 {
        return;
    }
    let arc = Arc::from_raw(h as *const IrqHandleInner);
    let _ = arc.signal_n(meta, n as usize);
    let _ = Arc::into_raw(arc);
}

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

const DYNAMIC_VECTOR_START: u8 = 0x60;
const DYNAMIC_VECTOR_END: u8 = 0xEF;

struct VectorAllocEntry {
    allocated: AtomicBool,
    users: AtomicUsize,
}

impl VectorAllocEntry {
    const fn new() -> Self {
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
    const fn is_dynamic(vector: u8) -> bool {
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

    fn register(
        &self,
        vector: u8,
        isr: IrqIsrFn,
        ctx: usize,
        handle: IrqHandlePtr,
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
        let _guard = slot.lock.write();
        let count = slot.count.load(Ordering::Acquire);
        if count >= MAX_HANDLERS_PER_VECTOR || (exclusive && count > 0) {
            return false;
        }

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
        let _guard = slot.lock.write();
        let count = slot.count.load(Ordering::Acquire);

        unsafe {
            let regs = &slot.regs as *const _ as *mut [IrqReg; MAX_HANDLERS_PER_VECTOR];
            for i in 0..count {
                if (*regs)[i].id == id {
                    if i < count - 1 {
                        (*regs)[i] = (*regs)[count - 1];
                    }
                    (*regs)[count - 1] = IrqReg::EMPTY;
                    slot.count.store(count - 1, Ordering::Release);
                    break;
                }
            }
        }

        if VectorAllocator::is_dynamic(vec) {
            VectorAllocator::release_after_unregister(vec);
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
    if vector == 0x80 {
        return core::ptr::null_mut();
    }

    let dynamic = VectorAllocator::is_dynamic(vector);
    if dynamic && !VectorAllocator::reserve_for_registration(vector) {
        return core::ptr::null_mut();
    }

    let id = IRQ_MANAGER.alloc_id();
    let hook = DropHook::new(irq_unregister_thunk, id);

    let handle = irq_handle_create(hook);
    if handle.is_null() {
        if dynamic {
            VectorAllocator::release_after_unregister(vector);
        }
        return core::ptr::null_mut();
    }

    let first_for_vector = {
        let _lock = IRQ_MANAGER.vectors[vector as usize].lock.read();
        IRQ_MANAGER.vectors[vector as usize]
            .count
            .load(Ordering::Acquire)
            == 0
    };

    let registered = IRQ_MANAGER.register(vector, isr, ctx, handle, id, dynamic);
    if !registered {
        if dynamic {
            VectorAllocator::release_after_unregister(vector);
        }
        unsafe { irq_handle_drop(handle) };
        return core::ptr::null_mut();
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

    if !IRQ_MANAGER.register(vector, isr, ctx, handle, id, false) {
        unsafe { irq_handle_drop(handle) };
        return core::ptr::null_mut();
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

pub fn irq_signal_all(handle: IrqHandlePtr, meta: IrqMeta) {
    if handle.is_null() {
        return;
    }
    unsafe {
        let arc = Arc::from_raw(handle as *const IrqHandleInner);
        let _ = arc.signal_all(meta);
        let _ = Arc::into_raw(arc);
    }
}

pub fn irq_alloc_vector() -> Option<u8> {
    VectorAllocator::alloc()
}

pub fn irq_free_vector(vector: u8) -> bool {
    VectorAllocator::free_explicit(vector)
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

macro_rules! gen_irq_stubs {
    ($(($name:ident, $vec:expr)),+ $(,)?) => {
        $(gen_irq_stub!($name, $vec);)+
        type IrqStub = extern "x86-interrupt" fn(InterruptStackFrame);
        const IRQ_VECTOR_STUBS: &[(u8, IrqStub)] = &[ $(($vec, $name)),+ ];
    };
}

gen_irq_stubs!(
    (irq_vec_33, 33),
    (irq_vec_34, 34),
    (irq_vec_35, 35),
    (irq_vec_36, 36),
    (irq_vec_37, 37),
    (irq_vec_38, 38),
    (irq_vec_39, 39),
    (irq_vec_40, 40),
    (irq_vec_41, 41),
    (irq_vec_42, 42),
    (irq_vec_43, 43),
    (irq_vec_44, 44),
    (irq_vec_45, 45),
    (irq_vec_46, 46),
    (irq_vec_47, 47),
    (irq_vec_48, 48),
    (irq_vec_49, 49),
    (irq_vec_50, 50),
    (irq_vec_51, 51),
    (irq_vec_52, 52),
    (irq_vec_53, 53),
    (irq_vec_54, 54),
    (irq_vec_55, 55),
    (irq_vec_56, 56),
    (irq_vec_57, 57),
    (irq_vec_58, 58),
    (irq_vec_59, 59),
    (irq_vec_60, 60),
    (irq_vec_61, 61),
    (irq_vec_62, 62),
    (irq_vec_63, 63),
    (irq_vec_64, 64),
    (irq_vec_65, 65),
    (irq_vec_66, 66),
    (irq_vec_67, 67),
    (irq_vec_68, 68),
    (irq_vec_69, 69),
    (irq_vec_70, 70),
    (irq_vec_71, 71),
    (irq_vec_72, 72),
    (irq_vec_73, 73),
    (irq_vec_74, 74),
    (irq_vec_75, 75),
    (irq_vec_76, 76),
    (irq_vec_77, 77),
    (irq_vec_78, 78),
    (irq_vec_79, 79),
    (irq_vec_80, 80),
    (irq_vec_81, 81),
    (irq_vec_82, 82),
    (irq_vec_83, 83),
    (irq_vec_84, 84),
    (irq_vec_85, 85),
    (irq_vec_86, 86),
    (irq_vec_87, 87),
    (irq_vec_88, 88),
    (irq_vec_89, 89),
    (irq_vec_90, 90),
    (irq_vec_91, 91),
    (irq_vec_92, 92),
    (irq_vec_93, 93),
    (irq_vec_94, 94),
    (irq_vec_95, 95),
    (irq_vec_96, 96),
    (irq_vec_97, 97),
    (irq_vec_98, 98),
    (irq_vec_99, 99),
    (irq_vec_100, 100),
    (irq_vec_101, 101),
    (irq_vec_102, 102),
    (irq_vec_103, 103),
    (irq_vec_104, 104),
    (irq_vec_105, 105),
    (irq_vec_106, 106),
    (irq_vec_107, 107),
    (irq_vec_108, 108),
    (irq_vec_109, 109),
    (irq_vec_110, 110),
    (irq_vec_111, 111),
    (irq_vec_112, 112),
    (irq_vec_113, 113),
    (irq_vec_114, 114),
    (irq_vec_115, 115),
    (irq_vec_116, 116),
    (irq_vec_117, 117),
    (irq_vec_118, 118),
    (irq_vec_119, 119),
    (irq_vec_120, 120),
    (irq_vec_121, 121),
    (irq_vec_122, 122),
    (irq_vec_123, 123),
    (irq_vec_124, 124),
    (irq_vec_125, 125),
    (irq_vec_126, 126),
    (irq_vec_127, 127),
    (irq_vec_129, 129),
    (irq_vec_130, 130),
    (irq_vec_131, 131),
    (irq_vec_132, 132),
    (irq_vec_133, 133),
    (irq_vec_134, 134),
    (irq_vec_135, 135),
    (irq_vec_136, 136),
    (irq_vec_137, 137),
    (irq_vec_138, 138),
    (irq_vec_139, 139),
    (irq_vec_140, 140),
    (irq_vec_141, 141),
    (irq_vec_142, 142),
    (irq_vec_143, 143),
    (irq_vec_144, 144),
    (irq_vec_145, 145),
    (irq_vec_146, 146),
    (irq_vec_147, 147),
    (irq_vec_148, 148),
    (irq_vec_149, 149),
    (irq_vec_150, 150),
    (irq_vec_151, 151),
    (irq_vec_152, 152),
    (irq_vec_153, 153),
    (irq_vec_154, 154),
    (irq_vec_155, 155),
    (irq_vec_156, 156),
    (irq_vec_157, 157),
    (irq_vec_158, 158),
    (irq_vec_159, 159),
    (irq_vec_160, 160),
    (irq_vec_161, 161),
    (irq_vec_162, 162),
    (irq_vec_163, 163),
    (irq_vec_164, 164),
    (irq_vec_165, 165),
    (irq_vec_166, 166),
    (irq_vec_167, 167),
    (irq_vec_168, 168),
    (irq_vec_169, 169),
    (irq_vec_170, 170),
    (irq_vec_171, 171),
    (irq_vec_172, 172),
    (irq_vec_173, 173),
    (irq_vec_174, 174),
    (irq_vec_175, 175),
    (irq_vec_176, 176),
    (irq_vec_177, 177),
    (irq_vec_178, 178),
    (irq_vec_179, 179),
    (irq_vec_180, 180),
    (irq_vec_181, 181),
    (irq_vec_182, 182),
    (irq_vec_183, 183),
    (irq_vec_184, 184),
    (irq_vec_185, 185),
    (irq_vec_186, 186),
    (irq_vec_187, 187),
    (irq_vec_188, 188),
    (irq_vec_189, 189),
    (irq_vec_190, 190),
    (irq_vec_191, 191),
    (irq_vec_192, 192),
    (irq_vec_193, 193),
    (irq_vec_194, 194),
    (irq_vec_195, 195),
    (irq_vec_196, 196),
    (irq_vec_197, 197),
    (irq_vec_198, 198),
    (irq_vec_199, 199),
    (irq_vec_200, 200),
    (irq_vec_201, 201),
    (irq_vec_202, 202),
    (irq_vec_203, 203),
    (irq_vec_204, 204),
    (irq_vec_205, 205),
    (irq_vec_206, 206),
    (irq_vec_207, 207),
    (irq_vec_208, 208),
    (irq_vec_209, 209),
    (irq_vec_210, 210),
    (irq_vec_211, 211),
    (irq_vec_212, 212),
    (irq_vec_213, 213),
    (irq_vec_214, 214),
    (irq_vec_215, 215),
    (irq_vec_216, 216),
    (irq_vec_217, 217),
    (irq_vec_218, 218),
    (irq_vec_219, 219),
    (irq_vec_220, 220),
    (irq_vec_221, 221),
    (irq_vec_222, 222),
    (irq_vec_223, 223),
    (irq_vec_224, 224),
    (irq_vec_225, 225),
    (irq_vec_226, 226),
    (irq_vec_227, 227),
    (irq_vec_228, 228),
    (irq_vec_229, 229),
    (irq_vec_230, 230),
    (irq_vec_231, 231),
    (irq_vec_232, 232),
    (irq_vec_233, 233),
    (irq_vec_234, 234),
    (irq_vec_235, 235),
    (irq_vec_236, 236),
    (irq_vec_237, 237),
    (irq_vec_238, 238),
    (irq_vec_239, 239),
);

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

    unsafe {
        idt[drivers::interrupt_index::InterruptIndex::Timer.as_u8()]
            .set_handler_addr(VirtAddr::new(timer_interrupt_entry as u64))
            .set_stack_index(TIMER_IST_INDEX);
    }
    for (vec, stub) in IRQ_VECTOR_STUBS {
        unsafe {
            idt[*vec].set_handler_fn(*stub);
        }
    }

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
