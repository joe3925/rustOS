use alloc::collections::VecDeque;
use core::cell::UnsafeCell;
use core::mem::{ManuallyDrop, MaybeUninit};
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};

use spin::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

pub type IrqContextQuery = extern "C" fn() -> bool;
pub type IrqInterruptsEnabled = extern "C" fn() -> bool;
pub type IrqInterruptsSet = extern "C" fn();

pub const MSI_REQUESTER_NONE: u32 = 0;
pub const MSI_REQUESTER_PCI: u32 = 1;

pub const MSI_TARGET_ANY: u32 = 0;
pub const MSI_TARGET_PLATFORM_CPU: u32 = 1;

pub const MSI_KIND_MSI: u32 = 0;
pub const MSI_KIND_MSIX: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MsiRequester {
    pub kind: u32,
    pub segment: u16,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub reserved0: u8,
    pub requester_id: u16,
}

impl MsiRequester {
    pub const fn none() -> Self {
        Self {
            kind: MSI_REQUESTER_NONE,
            segment: 0,
            bus: 0,
            device: 0,
            function: 0,
            reserved0: 0,
            requester_id: 0,
        }
    }

    pub const fn pci(segment: u16, bus: u8, device: u8, function: u8) -> Self {
        Self {
            kind: MSI_REQUESTER_PCI,
            segment,
            bus,
            device,
            function,
            reserved0: 0,
            requester_id: ((bus as u16) << 8) | ((device as u16) << 3) | function as u16,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MsiTarget {
    pub mode: u32,
    pub platform_cpu_id: u32,
}

impl MsiTarget {
    pub const fn any() -> Self {
        Self {
            mode: MSI_TARGET_ANY,
            platform_cpu_id: 0,
        }
    }

    pub const fn platform_cpu(platform_cpu_id: u32) -> Self {
        Self {
            mode: MSI_TARGET_PLATFORM_CPU,
            platform_cpu_id,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MsiMessage {
    pub address: u64,
    pub data: u32,
    pub reserved0: u32,
}

impl MsiMessage {
    pub const fn new(address: u64, data: u32) -> Self {
        Self {
            address,
            data,
            reserved0: 0,
        }
    }

    pub const fn address_lo(self) -> u32 {
        self.address as u32
    }

    pub const fn address_hi(self) -> u32 {
        (self.address >> 32) as u32
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, kernel_macros::RequestPayload)]
pub struct MsiRequest {
    pub requester: MsiRequester,
    pub target: MsiTarget,
    pub vector: u8,
    pub reserved0: u8,
    pub table_index: u16,
    pub kind: u32,
    pub flags: u32,
}

impl MsiRequest {
    pub const fn new(
        requester: MsiRequester,
        target: MsiTarget,
        vector: u8,
        kind: u32,
        table_index: u16,
    ) -> Self {
        Self {
            requester,
            target,
            vector,
            reserved0: 0,
            table_index,
            kind,
            flags: 0,
        }
    }

    pub const fn pci_msix(vector: u8, target: MsiTarget, table_index: u16) -> Self {
        Self::new(
            MsiRequester::none(),
            target,
            vector,
            MSI_KIND_MSIX,
            table_index,
        )
    }

    pub const fn with_requester(mut self, requester: MsiRequester) -> Self {
        self.requester = requester;
        self
    }
}

static IRQ_CONTEXT_QUERY: AtomicUsize = AtomicUsize::new(0);
static IRQ_INTERRUPTS_ENABLED: AtomicUsize = AtomicUsize::new(0);
static IRQ_INTERRUPTS_DISABLE: AtomicUsize = AtomicUsize::new(0);
static IRQ_INTERRUPTS_ENABLE: AtomicUsize = AtomicUsize::new(0);
static IRQ_INTERRUPTS_ENABLE_AND_HLT: AtomicUsize = AtomicUsize::new(0);

pub fn set_irq_context_query(query: IrqContextQuery) {
    IRQ_CONTEXT_QUERY.store(query as usize, Ordering::Release);
}

pub fn set_irq_interrupt_control(
    enabled: IrqInterruptsEnabled,
    disable: IrqInterruptsSet,
    enable: IrqInterruptsSet,
    enable_and_hlt: IrqInterruptsSet,
) {
    IRQ_INTERRUPTS_ENABLED.store(enabled as usize, Ordering::Release);
    IRQ_INTERRUPTS_DISABLE.store(disable as usize, Ordering::Release);
    IRQ_INTERRUPTS_ENABLE.store(enable as usize, Ordering::Release);
    IRQ_INTERRUPTS_ENABLE_AND_HLT.store(enable_and_hlt as usize, Ordering::Release);
}

#[inline(always)]
fn in_interrupt_context() -> bool {
    let query = IRQ_CONTEXT_QUERY.load(Ordering::Acquire);

    if query == 0 {
        return false;
    }

    let query: IrqContextQuery = unsafe { core::mem::transmute(query) };
    query()
}

#[inline(always)]
fn interrupts_enabled() -> bool {
    let enabled = IRQ_INTERRUPTS_ENABLED.load(Ordering::Acquire);

    if enabled == 0 {
        return false;
    }

    let enabled: IrqInterruptsEnabled = unsafe { core::mem::transmute(enabled) };
    enabled()
}

#[inline(always)]
fn interrupts_disable() {
    let disable = IRQ_INTERRUPTS_DISABLE.load(Ordering::Acquire);

    if disable == 0 {
        return;
    }

    let disable: IrqInterruptsSet = unsafe { core::mem::transmute(disable) };
    disable();
}

#[inline(always)]
fn interrupts_enable() {
    let enable = IRQ_INTERRUPTS_ENABLE.load(Ordering::Acquire);

    if enable == 0 {
        return;
    }

    let enable: IrqInterruptsSet = unsafe { core::mem::transmute(enable) };
    enable();
}

#[inline(always)]
fn interrupts_enable_and_hlt() {
    let enable_and_hlt = IRQ_INTERRUPTS_ENABLE_AND_HLT.load(Ordering::Acquire);

    if enable_and_hlt == 0 {
        core::hint::spin_loop();
        return;
    }

    let enable_and_hlt: IrqInterruptsSet = unsafe { core::mem::transmute(enable_and_hlt) };
    enable_and_hlt();
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IrqHandle {
    pub id: usize,
    pub generation: usize,
}

impl IrqHandle {
    pub const fn null() -> Self {
        Self {
            id: 0,
            generation: 0,
        }
    }

    pub const fn is_null(self) -> bool {
        self.id == 0
    }
}

pub type IrqBorrowedHandle = *const IrqHandleInner;

#[repr(C)]
pub struct IrqFrame {
    _private: [usize; 0],
}

pub type IrqIsrFn = extern "C" fn(
    vector: u8,
    cpu: u32,
    frame: &mut IrqFrame,
    handle: IrqBorrowedHandle,
    ctx: usize,
) -> bool;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct IrqMeta {
    pub tag: u64,
    pub data: [u64; 3],
}

impl IrqMeta {
    pub const fn new() -> Self {
        Self {
            tag: 0,
            data: [0; 3],
        }
    }

    pub const fn with_tag(tag: u64) -> Self {
        Self { tag, data: [0; 3] }
    }

    pub const fn with_data(tag: u64, d0: u64) -> Self {
        Self {
            tag,
            data: [d0, 0, 0],
        }
    }

    pub const fn with_data3(tag: u64, d0: u64, d1: u64, d2: u64) -> Self {
        Self {
            tag,
            data: [d0, d1, d2],
        }
    }
}

pub const IRQ_WAIT_OK: u32 = 0;
pub const IRQ_WAIT_CLOSED: u32 = 1;
pub const IRQ_WAIT_NULL: u32 = 2;
pub const IRQ_WAIT_TIMEOUT: u32 = 3;
pub const IRQ_RESCUE_WAKEUP: u32 = 4;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct IrqWaitResult {
    pub code: u32,
    pub count: u32,
    pub meta: IrqMeta,
}

impl IrqWaitResult {
    pub const fn ok(meta: IrqMeta) -> Self {
        Self {
            code: IRQ_WAIT_OK,
            count: 1,
            meta,
        }
    }

    pub const fn ok_n(meta: IrqMeta, count: u32) -> Self {
        Self {
            code: IRQ_WAIT_OK,
            count,
            meta,
        }
    }

    pub const fn closed() -> Self {
        Self {
            code: IRQ_WAIT_CLOSED,
            count: 0,
            meta: IrqMeta::new(),
        }
    }

    pub const fn null() -> Self {
        Self {
            code: IRQ_WAIT_NULL,
            count: 0,
            meta: IrqMeta::new(),
        }
    }

    pub const fn timeout() -> Self {
        Self {
            code: IRQ_WAIT_TIMEOUT,
            count: 0,
            meta: IrqMeta::new(),
        }
    }

    pub const fn rescue() -> Self {
        Self {
            code: IRQ_RESCUE_WAKEUP,
            count: 0,
            meta: IrqMeta::new(),
        }
    }

    pub fn is_ok(&self) -> bool {
        self.code == IRQ_WAIT_OK
    }

    pub fn is_closed(&self) -> bool {
        self.code == IRQ_WAIT_CLOSED
    }

    pub fn is_null(&self) -> bool {
        self.code == IRQ_WAIT_NULL
    }

    pub fn is_timeout(&self) -> bool {
        self.code == IRQ_WAIT_TIMEOUT
    }
}

impl Default for IrqWaitResult {
    fn default() -> Self {
        Self::null()
    }
}

#[repr(C)]
pub struct AtomicIrqMeta {
    tag: AtomicU64,
    data0: AtomicU64,
    data1: AtomicU64,
    data2: AtomicU64,
}

impl AtomicIrqMeta {
    pub const fn new() -> Self {
        Self {
            tag: AtomicU64::new(0),
            data0: AtomicU64::new(0),
            data1: AtomicU64::new(0),
            data2: AtomicU64::new(0),
        }
    }

    #[inline]
    pub fn store(&self, meta: IrqMeta, order: Ordering) {
        self.data0.store(meta.data[0], Ordering::Relaxed);
        self.data1.store(meta.data[1], Ordering::Relaxed);
        self.data2.store(meta.data[2], Ordering::Relaxed);
        self.tag.store(meta.tag, order);
    }

    #[inline]
    pub fn load(&self, order: Ordering) -> IrqMeta {
        let tag = self.tag.load(order);

        IrqMeta {
            tag,
            data: [
                self.data0.load(Ordering::Relaxed),
                self.data1.load(Ordering::Relaxed),
                self.data2.load(Ordering::Relaxed),
            ],
        }
    }
}

pub const MAX_WAITERS_PER_HANDLE: usize = 128;

pub const WAITER_FREE: usize = 0;
pub const WAITER_PREPARING: usize = 1;
pub const WAITER_WAITING: usize = 2;
pub const WAITER_CLAIMED: usize = 3;
pub const WAITER_SIGNALED: usize = 4;

pub const WAITER_STATE_MASK: usize = 0b111;
pub const WAITER_TICKET_SHIFT: usize = 3;
pub const WAITER_MAX_TICKET: usize = usize::MAX >> WAITER_TICKET_SHIFT;

#[inline]
pub const fn waiter_word(state: usize, ticket: usize) -> usize {
    (ticket << WAITER_TICKET_SHIFT) | state
}

#[inline]
pub const fn waiter_state(word: usize) -> usize {
    word & WAITER_STATE_MASK
}

#[inline]
pub const fn waiter_ticket(word: usize) -> usize {
    word >> WAITER_TICKET_SHIFT
}

#[repr(C)]
pub struct WaiterSlot {
    word: AtomicUsize,
    abandoned: AtomicBool,
    result: UnsafeCell<MaybeUninit<IrqWaitResult>>,
    waker: UnsafeCell<Option<Waker>>,
}

unsafe impl Send for WaiterSlot {}
unsafe impl Sync for WaiterSlot {}

impl WaiterSlot {
    pub const fn new() -> Self {
        Self {
            word: AtomicUsize::new(waiter_word(WAITER_FREE, 0)),
            abandoned: AtomicBool::new(false),
            result: UnsafeCell::new(MaybeUninit::uninit()),
            waker: UnsafeCell::new(None),
        }
    }

    #[inline]
    pub fn state(&self) -> usize {
        waiter_state(self.word.load(Ordering::Acquire))
    }

    #[inline]
    pub fn try_alloc(&self) -> bool {
        self.word
            .compare_exchange(
                waiter_word(WAITER_FREE, 0),
                waiter_word(WAITER_PREPARING, 0),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    #[inline]
    /// # Safety
    /// The caller must exclusively own this slot and ensure no signaler is
    /// concurrently accessing its result or waker storage.
    pub unsafe fn set_preparing(&self) {
        self.word
            .store(waiter_word(WAITER_PREPARING, 0), Ordering::Release);
    }

    #[inline]
    /// # Safety
    /// The caller must have exclusively initialized this slot's waker and the
    /// nonzero ticket must identify the registered wait operation.
    pub unsafe fn publish(&self, ticket: usize) {
        self.word
            .store(waiter_word(WAITER_WAITING, ticket), Ordering::Release);
    }

    #[inline]
    pub fn try_withdraw_waiting(&self) -> bool {
        let word = self.word.load(Ordering::Acquire);

        if waiter_state(word) != WAITER_WAITING {
            return false;
        }

        self.word
            .compare_exchange(
                word,
                waiter_word(WAITER_PREPARING, 0),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    #[inline]
    pub fn try_claim_for_signal(&self) -> Option<usize> {
        let word = self.word.load(Ordering::Acquire);

        if waiter_state(word) != WAITER_WAITING {
            return None;
        }

        let ticket = waiter_ticket(word);

        if ticket == 0 {
            return None;
        }

        self.word
            .compare_exchange(
                word,
                waiter_word(WAITER_CLAIMED, ticket),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .ok()
            .map(waiter_ticket)
    }

    #[inline]
    /// # Safety
    /// The caller must have transitioned this exact ticket from WAITING to
    /// CLAIMED and must be the only signaler completing it.
    pub unsafe fn complete_claimed(&self, ticket: usize, result: IrqWaitResult) -> Option<Waker> {
        unsafe {
            (*self.result.get()).write(result);
        }

        let waker = unsafe { (*self.waker.get()).clone() };

        self.word
            .store(waiter_word(WAITER_SIGNALED, ticket), Ordering::Release);

        if self.abandoned.swap(false, Ordering::AcqRel) {
            unsafe { self.cleanup_signaled(ticket) };
            return None;
        }

        waker
    }

    #[inline]
    unsafe fn cleanup_signaled(&self, ticket: usize) {
        if self
            .word
            .compare_exchange(
                waiter_word(WAITER_SIGNALED, ticket),
                waiter_word(WAITER_PREPARING, 0),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return;
        }

        unsafe {
            let _ = (*self.result.get()).assume_init_read();
            let _ = (*self.waker.get()).take();
        }

        self.word
            .store(waiter_word(WAITER_FREE, 0), Ordering::Release);
    }

    #[inline]
    pub fn take_signaled(&self) -> Option<IrqWaitResult> {
        let word = self.word.load(Ordering::Acquire);

        if waiter_state(word) != WAITER_SIGNALED {
            return None;
        }

        let ticket = waiter_ticket(word);

        if self
            .word
            .compare_exchange(
                word,
                waiter_word(WAITER_PREPARING, 0),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return None;
        }

        let result = unsafe { (*self.result.get()).assume_init_read() };

        unsafe {
            let _ = (*self.waker.get()).take();
        }

        self.word
            .store(waiter_word(WAITER_FREE, 0), Ordering::Release);

        if ticket == 0 {
            return None;
        }

        Some(result)
    }

    #[inline]
    /// # Safety
    /// The caller must exclusively own a PREPARING slot.
    pub unsafe fn set_waker_exclusive(&self, waker: &Waker) {
        unsafe {
            *self.waker.get() = Some(waker.clone());
        }
    }

    #[inline]
    unsafe fn clear_waker_exclusive(&self) {
        unsafe {
            let _ = (*self.waker.get()).take();
        }
    }

    #[inline]
    pub fn cancel(&self) {
        loop {
            let word = self.word.load(Ordering::Acquire);

            match waiter_state(word) {
                WAITER_FREE => return,

                WAITER_PREPARING => {
                    unsafe { self.clear_waker_exclusive() };
                    self.word
                        .store(waiter_word(WAITER_FREE, 0), Ordering::Release);
                    return;
                }

                WAITER_WAITING => {
                    if self
                        .word
                        .compare_exchange(
                            word,
                            waiter_word(WAITER_PREPARING, 0),
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_err()
                    {
                        continue;
                    }

                    unsafe { self.clear_waker_exclusive() };
                    self.word
                        .store(waiter_word(WAITER_FREE, 0), Ordering::Release);
                    return;
                }

                WAITER_CLAIMED => {
                    self.abandoned.store(true, Ordering::Release);

                    let after = self.word.load(Ordering::Acquire);

                    if waiter_state(after) == WAITER_SIGNALED {
                        unsafe { self.cleanup_signaled(waiter_ticket(after)) };
                    }

                    return;
                }

                WAITER_SIGNALED => {
                    self.abandoned.store(true, Ordering::Release);
                    unsafe { self.cleanup_signaled(waiter_ticket(word)) };
                    return;
                }

                _ => return,
            }
        }
    }
}

#[derive(Clone, Copy)]
pub struct WaiterPtr {
    ptr: NonNull<Waiter>,
}

impl WaiterPtr {
    pub fn new(waiter: &Waiter) -> Self {
        Self {
            ptr: NonNull::from(waiter),
        }
    }

    pub unsafe fn from_raw(ptr: *mut Waiter) -> Self {
        Self {
            ptr: NonNull::new_unchecked(ptr),
        }
    }

    pub fn as_ptr(self) -> *mut Waiter {
        self.ptr.as_ptr()
    }

    pub unsafe fn as_ref<'a>(self) -> &'a Waiter {
        self.ptr.as_ref()
    }

    pub fn ptr_eq(self, other: WaiterPtr) -> bool {
        self.ptr == other.ptr
    }
}

unsafe impl Send for WaiterPtr {}
unsafe impl Sync for WaiterPtr {}

#[repr(C)]
pub struct Waiter {
    pub waker: IrqSafeMutex<Option<Waker>>,
    pub result: IrqSafeMutex<Option<IrqWaitResult>>,
    pub enqueued: AtomicBool,
}

unsafe impl Send for Waiter {}
unsafe impl Sync for Waiter {}

impl Waiter {
    pub const fn new() -> Self {
        Self {
            waker: IrqSafeMutex::new(None),
            result: IrqSafeMutex::new(None),
            enqueued: AtomicBool::new(false),
        }
    }

    pub fn set_waker(&self, w: &Waker) {
        let mut g = self.waker.lock();
        let update = match g.as_ref() {
            Some(existing) => !existing.will_wake(w),
            None => true,
        };

        if update {
            *g = Some(w.clone());
        }
    }

    pub fn take_result(&self) -> Option<IrqWaitResult> {
        self.result.lock().take()
    }

    pub fn store_result(&self, r: IrqWaitResult) {
        *self.result.lock() = Some(r);
    }

    pub fn wake_by_ref(&self) {
        let g = self.waker.lock();

        if let Some(w) = g.as_ref() {
            w.wake_by_ref();
        }
    }

    pub fn clear(&self) {
        self.enqueued.store(false, Ordering::Release);
        *self.waker.lock() = None;
        *self.result.lock() = None;
    }
}

pub struct WaitState {
    pub waiters: VecDeque<WaiterPtr>,
    pub pending_signals: usize,
    pub last_meta: IrqMeta,
}

impl WaitState {
    pub const fn new() -> Self {
        Self {
            waiters: VecDeque::new(),
            pending_signals: 0,
            last_meta: IrqMeta::new(),
        }
    }

    pub fn pop_waiter(&mut self) -> Option<WaiterPtr> {
        self.waiters.pop_front()
    }

    pub fn push_waiter(&mut self, waiter: WaiterPtr) {
        self.waiters.push_back(waiter);
    }

    pub fn remove_waiter(&mut self, target: WaiterPtr) -> bool {
        let before = self.waiters.len();
        self.waiters.retain(|w| !w.ptr_eq(target));
        before != self.waiters.len()
    }
}

#[repr(C)]
pub struct IrqHandleInner {
    pub drop_hook: Mutex<Option<DropHook>>,
    pub closed: AtomicBool,
    pub user_ctx: AtomicUsize,

    pub pending_signals: AtomicUsize,
    pub signal_phase: AtomicUsize,
    pub signal_active: AtomicUsize,
    pub waiter_ticket: AtomicUsize,
    pub last_meta: AtomicIrqMeta,
    pub waiters: [WaiterSlot; MAX_WAITERS_PER_HANDLE],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DropHook {
    pub func: extern "C" fn(usize),
    pub arg: usize,
}

impl DropHook {
    pub const fn new(func: extern "C" fn(usize), arg: usize) -> Self {
        Self { func, arg }
    }

    pub fn invoke(self) {
        (self.func)(self.arg);
    }
}

impl core::fmt::Debug for DropHook {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DropHook")
            .field("func", &(self.func as usize))
            .field("arg", &self.arg)
            .finish()
    }
}

pub struct IrqSafeMutex<T> {
    inner: Mutex<T>,
}

pub struct IrqSafeMutexGuard<'a, T> {
    guard: ManuallyDrop<MutexGuard<'a, T>>,
    restore_interrupts: bool,
}

impl<T> IrqSafeMutex<T> {
    pub const fn new(value: T) -> Self {
        Self {
            inner: Mutex::new(value),
        }
    }

    #[inline(always)]
    pub fn lock(&self) -> IrqSafeMutexGuard<'_, T> {
        let restore_interrupts = interrupts_enabled();

        loop {
            if restore_interrupts {
                interrupts_disable();
            }

            if let Some(guard) = self.inner.try_lock() {
                return IrqSafeMutexGuard {
                    guard: ManuallyDrop::new(guard),
                    restore_interrupts,
                };
            }

            core::hint::spin_loop();
        }
    }

    #[inline(always)]
    pub fn try_lock(&self) -> Option<IrqSafeMutexGuard<'_, T>> {
        let restore_interrupts = interrupts_enabled();

        if restore_interrupts {
            interrupts_disable();
        }

        match self.inner.try_lock() {
            Some(guard) => Some(IrqSafeMutexGuard {
                guard: ManuallyDrop::new(guard),
                restore_interrupts,
            }),
            None => {
                if restore_interrupts {
                    interrupts_enable();
                }

                None
            }
        }
    }
}

impl<'a, T> Deref for IrqSafeMutexGuard<'a, T> {
    type Target = T;

    #[inline(always)]
    fn deref(&self) -> &T {
        &self.guard
    }
}

impl<'a, T> DerefMut for IrqSafeMutexGuard<'a, T> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut T {
        &mut self.guard
    }
}

impl<'a, T> Drop for IrqSafeMutexGuard<'a, T> {
    #[inline(always)]
    fn drop(&mut self) {
        unsafe {
            ManuallyDrop::drop(&mut self.guard);
        }

        if self.restore_interrupts {
            interrupts_enable();
        }
    }
}

pub struct IrqSafeRwLock<T> {
    inner: RwLock<T>,
}

pub struct IrqSafeRwLockReadGuard<'a, T> {
    guard: ManuallyDrop<RwLockReadGuard<'a, T>>,
    restore_interrupts: bool,
}

pub struct IrqSafeRwLockWriteGuard<'a, T> {
    guard: ManuallyDrop<RwLockWriteGuard<'a, T>>,
    restore_interrupts: bool,
}

impl<T> IrqSafeRwLock<T> {
    #[inline(always)]
    pub const fn new(value: T) -> Self {
        Self {
            inner: RwLock::new(value),
        }
    }

    #[inline(always)]
    pub fn read(&self) -> IrqSafeRwLockReadGuard<'_, T> {
        let restore_interrupts = interrupts_enabled();

        loop {
            if restore_interrupts {
                interrupts_disable();
            }

            if let Some(guard) = self.inner.try_read() {
                return IrqSafeRwLockReadGuard {
                    guard: ManuallyDrop::new(guard),
                    restore_interrupts,
                };
            }

            core::hint::spin_loop();
        }
    }

    #[inline(always)]
    pub fn try_read(&self) -> Option<IrqSafeRwLockReadGuard<'_, T>> {
        let restore_interrupts = interrupts_enabled();

        if restore_interrupts {
            interrupts_disable();
        }

        match self.inner.try_read() {
            Some(guard) => Some(IrqSafeRwLockReadGuard {
                guard: ManuallyDrop::new(guard),
                restore_interrupts,
            }),
            None => {
                if restore_interrupts {
                    interrupts_enable();
                }

                None
            }
        }
    }

    #[inline(always)]
    pub fn write(&self) -> IrqSafeRwLockWriteGuard<'_, T> {
        let restore_interrupts = interrupts_enabled();

        loop {
            if restore_interrupts {
                interrupts_disable();
            }

            if let Some(guard) = self.inner.try_write() {
                return IrqSafeRwLockWriteGuard {
                    guard: ManuallyDrop::new(guard),
                    restore_interrupts,
                };
            }

            core::hint::spin_loop();
        }
    }

    #[inline(always)]
    pub fn try_write(&self) -> Option<IrqSafeRwLockWriteGuard<'_, T>> {
        let restore_interrupts = interrupts_enabled();

        if restore_interrupts {
            interrupts_disable();
        }

        match self.inner.try_write() {
            Some(guard) => Some(IrqSafeRwLockWriteGuard {
                guard: ManuallyDrop::new(guard),
                restore_interrupts,
            }),
            None => {
                if restore_interrupts {
                    interrupts_enable();
                }

                None
            }
        }
    }
}

impl<'a, T> Deref for IrqSafeRwLockReadGuard<'a, T> {
    type Target = T;

    #[inline(always)]
    fn deref(&self) -> &T {
        &self.guard
    }
}

impl<'a, T> Drop for IrqSafeRwLockReadGuard<'a, T> {
    #[inline(always)]
    fn drop(&mut self) {
        unsafe {
            ManuallyDrop::drop(&mut self.guard);
        }

        if self.restore_interrupts {
            interrupts_enable();
        }
    }
}

impl<'a, T> Deref for IrqSafeRwLockWriteGuard<'a, T> {
    type Target = T;

    #[inline(always)]
    fn deref(&self) -> &T {
        &self.guard
    }
}

impl<'a, T> DerefMut for IrqSafeRwLockWriteGuard<'a, T> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut T {
        &mut self.guard
    }
}

impl<'a, T> Drop for IrqSafeRwLockWriteGuard<'a, T> {
    #[inline(always)]
    fn drop(&mut self) {
        unsafe {
            ManuallyDrop::drop(&mut self.guard);
        }

        if self.restore_interrupts {
            interrupts_enable();
        }
    }
}
