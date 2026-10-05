use core::cell::UnsafeCell;
use core::hint::spin_loop;
use core::marker::PhantomPinned;
use core::ops::Deref;
use core::pin::Pin;
use core::ptr;
use core::sync::atomic::Ordering::SeqCst;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU8, AtomicU64, AtomicUsize};
use core::task::Waker;
use portable_atomic::AtomicU128;

const COUNT_MASK: u64 = (1 << 48) - 1;
const PHASE_MASK: u64 = 0xff << 48;
const EDIT: u64 = 1 << 56;
const LOCAL: u64 = 0;
const WAITING: u64 = 1 << 48;
const NOTIFIED: u64 = 2 << 48;
const REMOVING: u64 = 3 << 48;
const DETACHED: u64 = 4 << 48;
const END: u128 = 0;
const BOUND: u128 = 1 << 112;
const DRAIN_REBIND: u128 = 2 << 112;
const DRAIN_CLOSE: u128 = 3 << 112;
const CLOSED: u128 = 4 << 112;
const LINK_STATE_MASK: u128 = 0xffff << 112;
const LINK_REFS_MASK: u128 = (COUNT_MASK as u128) << 64;
const LINK_REF: u128 = 1 << 64;
const ACTIVE: u8 = 1;
const DIRTY: u8 = 2;

fn link_pointer(value: u128) -> *mut RawWaiterNode {
    ptr::with_exposed_provenance_mut(value as u64 as usize)
}

struct CountedLink(AtomicU128);

impl CountedLink {
    const fn new() -> Self {
        Self(AtomicU128::new(END))
    }

    fn acquire(&self) -> Result<Option<LinkRef<'_>>, ()> {
        let mut old = self.0.load(SeqCst);
        loop {
            match old & LINK_STATE_MASK {
                END => return Ok(None),
                BOUND => {}
                _ => return Err(()),
            }
            assert_ne!(
                old & LINK_REFS_MASK,
                LINK_REFS_MASK,
                "waiter link count overflow"
            );
            match self
                .0
                .compare_exchange_weak(old, old + LINK_REF, SeqCst, SeqCst)
            {
                Ok(_) => {
                    return Ok(Some(LinkRef {
                        source: self,
                        node: link_pointer(old),
                    }));
                }
                Err(actual) => old = actual,
            }
        }
    }

    fn matches(&self, node: *mut RawWaiterNode) -> bool {
        let value = self.0.load(SeqCst);
        if node.is_null() {
            value == END
        } else {
            value & LINK_STATE_MASK == BOUND && link_pointer(value) == node
        }
    }

    fn drain(&self, close: bool) {
        let mut old = self.0.load(SeqCst);
        loop {
            assert!(matches!(old & LINK_STATE_MASK, END | BOUND));
            let state = if close { DRAIN_CLOSE } else { DRAIN_REBIND };
            let new = (old & !LINK_STATE_MASK) | state;
            match self.0.compare_exchange_weak(old, new, SeqCst, SeqCst) {
                Ok(_) => return,
                Err(actual) => old = actual,
            }
        }
    }

    unsafe fn commit(&self, node: *mut RawWaiterNode, close: bool) {
        let old = loop {
            let value = self.0.load(SeqCst);
            if value & LINK_REFS_MASK == 0 {
                break value;
            }
            spin_loop();
        };
        assert_eq!(
            old & LINK_STATE_MASK,
            if close { DRAIN_CLOSE } else { DRAIN_REBIND }
        );
        let new = if close {
            assert!(node.is_null());
            CLOSED
        } else if node.is_null() {
            END
        } else {
            BOUND | node.expose_provenance() as u128
        };
        self.0.store(new, SeqCst);
        let previous = link_pointer(old);
        if !previous.is_null() {
            let meta = unsafe { (*previous).meta.fetch_sub(1, SeqCst) };
            assert_ne!(meta & COUNT_MASK, 0, "waiter incoming count underflow");
        }
    }
}

struct LinkRef<'a> {
    source: &'a CountedLink,
    node: *mut RawWaiterNode,
}

impl Drop for LinkRef<'_> {
    fn drop(&mut self) {
        let old = self.source.0.fetch_sub(LINK_REF, SeqCst);
        assert_ne!(old & LINK_REFS_MASK, 0, "waiter link count underflow");
    }
}

struct EditClaims<'a> {
    queue: &'a RawWaiterQueue,
    head: bool,
    tail: bool,
    nodes: [*mut RawWaiterNode; 3],
    count: usize,
}

impl<'a> EditClaims<'a> {
    unsafe fn acquire(
        queue: &'a RawWaiterQueue,
        mut nodes: [*mut RawWaiterNode; 3],
        head: bool,
        tail: bool,
    ) -> Option<Self> {
        let mut claims = Self {
            queue,
            head: false,
            tail: false,
            nodes: [ptr::null_mut(); 3],
            count: 0,
        };
        if head {
            queue
                .head_edit
                .compare_exchange(false, true, SeqCst, SeqCst)
                .ok()?;
            claims.head = true;
        }
        if tail {
            queue
                .tail_edit
                .compare_exchange(false, true, SeqCst, SeqCst)
                .ok()?;
            claims.tail = true;
        }
        nodes.sort_unstable_by_key(|node| node.addr());
        for node in nodes {
            if node.is_null() || claims.nodes[..claims.count].contains(&node) {
                continue;
            }
            let meta = unsafe { &(*node).meta };
            let mut old = meta.load(SeqCst);
            loop {
                if old & EDIT != 0 || old & PHASE_MASK >= REMOVING {
                    return None;
                }
                match meta.compare_exchange_weak(old, old | EDIT, SeqCst, SeqCst) {
                    Ok(_) => break,
                    Err(actual) => old = actual,
                }
            }
            claims.nodes[claims.count] = node;
            claims.count += 1;
        }
        Some(claims)
    }
}

impl Drop for EditClaims<'_> {
    fn drop(&mut self) {
        for &node in self.nodes[..self.count].iter().rev() {
            unsafe { (*node).meta.fetch_and(!EDIT, SeqCst) };
        }
        if self.tail {
            self.queue.tail_edit.store(false, SeqCst);
        }
        if self.head {
            self.queue.head_edit.store(false, SeqCst);
        }
    }
}

pub struct RawWaiterNode {
    prev: CountedLink,
    next: CountedLink,
    meta: AtomicU64,
    ticket: UnsafeCell<u64>,
    waker: UnsafeCell<Option<Waker>>,
    _pin: PhantomPinned,
}

unsafe impl Send for RawWaiterNode {}
unsafe impl Sync for RawWaiterNode {}

impl RawWaiterNode {
    pub const fn new() -> Self {
        Self {
            prev: CountedLink::new(),
            next: CountedLink::new(),
            meta: AtomicU64::new(LOCAL),
            ticket: UnsafeCell::new(0),
            waker: UnsafeCell::new(None),
            _pin: PhantomPinned,
        }
    }

    unsafe fn reserve(node: *mut Self) {
        if node.is_null() {
            return;
        }
        let meta = unsafe { &(*node).meta };
        let mut old = meta.load(SeqCst);
        loop {
            assert_ne!(old & EDIT, 0);
            assert!(old & PHASE_MASK < REMOVING);
            assert_ne!(
                old & COUNT_MASK,
                COUNT_MASK,
                "waiter incoming count overflow"
            );
            match meta.compare_exchange_weak(old, old + 1, SeqCst, SeqCst) {
                Ok(_) => return,
                Err(actual) => old = actual,
            }
        }
    }
}

impl Default for RawWaiterNode {
    fn default() -> Self {
        Self::new()
    }
}

pub struct RawWaiterQueue {
    head: CountedLink,
    tail: CountedLink,
    head_edit: AtomicBool,
    tail_edit: AtomicBool,
    notifier_hazard: AtomicPtr<RawWaiterNode>,
    notification_control: AtomicU8,
    pending_one: AtomicUsize,
    broadcast_until: AtomicU64,
    last_ticket: AtomicU64,
}

struct NotificationOwner<'a> {
    queue: &'a RawWaiterQueue,
    active: bool,
}

impl Drop for NotificationOwner<'_> {
    fn drop(&mut self) {
        if self.active {
            self.queue.notifier_hazard.store(ptr::null_mut(), SeqCst);
            self.queue.notification_control.fetch_and(!ACTIVE, SeqCst);
        }
    }
}

impl RawWaiterQueue {
    pub const fn new() -> Self {
        Self {
            head: CountedLink::new(),
            tail: CountedLink::new(),
            head_edit: AtomicBool::new(false),
            tail_edit: AtomicBool::new(false),
            notifier_hazard: AtomicPtr::new(ptr::null_mut()),
            notification_control: AtomicU8::new(0),
            pending_one: AtomicUsize::new(0),
            broadcast_until: AtomicU64::new(0),
            last_ticket: AtomicU64::new(0),
        }
    }

    pub unsafe fn register(&self, node: Pin<&mut RawWaiterNode>, waker: &Waker) {
        assert!(
            AtomicU128::is_lock_free(),
            "waiter queue requires native 128-bit atomics"
        );
        assert_eq!(usize::BITS, 64);
        let node = unsafe { node.get_unchecked_mut() };
        let phase = node.meta.load(SeqCst) & PHASE_MASK;
        if phase == WAITING && unsafe { (&*node.waker.get()).as_ref().unwrap().will_wake(waker) } {
            return;
        }
        let new_waker = waker.clone();
        if phase == WAITING || phase == NOTIFIED {
            unsafe { self.remove(Pin::new_unchecked(&mut *node)) };
        }
        assert!(matches!(node.meta.load(SeqCst), LOCAL | DETACHED));
        unsafe { *node.waker.get() = Some(new_waker) };
        node.prev.0.store(END, SeqCst);
        node.next.0.store(END, SeqCst);
        node.meta.store(LOCAL, SeqCst);
        let node_ptr = ptr::from_mut(node);

        loop {
            let tail_ref = match self.tail.acquire() {
                Ok(value) => value,
                Err(()) => {
                    spin_loop();
                    continue;
                }
            };
            let tail = tail_ref
                .as_ref()
                .map_or(ptr::null_mut(), |value| value.node);
            let Some(claims) = (unsafe {
                EditClaims::acquire(
                    self,
                    [node_ptr, tail, ptr::null_mut()],
                    tail.is_null(),
                    true,
                )
            }) else {
                drop(tail_ref);
                spin_loop();
                continue;
            };
            let valid = self.tail.matches(tail)
                && if tail.is_null() {
                    self.head.matches(ptr::null_mut())
                } else {
                    unsafe { (*tail).next.matches(ptr::null_mut()) }
                };
            if !valid {
                drop(claims);
                drop(tail_ref);
                continue;
            }
            let ticket = self
                .last_ticket
                .fetch_update(SeqCst, SeqCst, |value| value.checked_add(1))
                .expect("waiter ticket exhausted")
                + 1;
            unsafe {
                *node.ticket.get() = ticket;
                RawWaiterNode::reserve(node_ptr);
                RawWaiterNode::reserve(node_ptr);
                RawWaiterNode::reserve(tail);
            }
            drop(tail_ref);
            self.tail.drain(false);
            if tail.is_null() {
                self.head.drain(false);
            } else {
                node.prev.drain(false);
                unsafe { (*tail).next.drain(false) };
            }
            node.meta
                .fetch_update(SeqCst, SeqCst, |meta| Some((meta & !PHASE_MASK) | WAITING))
                .unwrap();
            unsafe {
                if tail.is_null() {
                    self.head.commit(node_ptr, false);
                } else {
                    node.prev.commit(tail, false);
                    (*tail).next.commit(node_ptr, false);
                }
                self.tail.commit(node_ptr, false);
            }
            drop(claims);
            self.drive_notifications();
            return;
        }
    }

    pub unsafe fn remove(&self, node: Pin<&mut RawWaiterNode>) -> bool {
        let node = unsafe { node.get_unchecked_mut() };
        let phase = node.meta.load(SeqCst) & PHASE_MASK;
        if phase == LOCAL || phase == DETACHED {
            return false;
        }
        let node_ptr = ptr::from_mut(node);
        loop {
            let prev_ref = match node.prev.acquire() {
                Ok(value) => value,
                Err(()) => {
                    spin_loop();
                    continue;
                }
            };
            let next_ref = match node.next.acquire() {
                Ok(value) => value,
                Err(()) => {
                    drop(prev_ref);
                    spin_loop();
                    continue;
                }
            };
            let prev = prev_ref
                .as_ref()
                .map_or(ptr::null_mut(), |value| value.node);
            let next = next_ref
                .as_ref()
                .map_or(ptr::null_mut(), |value| value.node);
            let Some(claims) = (unsafe {
                EditClaims::acquire(self, [node_ptr, prev, next], prev.is_null(), next.is_null())
            }) else {
                drop(next_ref);
                drop(prev_ref);
                spin_loop();
                continue;
            };
            let valid = node.prev.matches(prev)
                && node.next.matches(next)
                && if prev.is_null() {
                    self.head.matches(node_ptr)
                } else {
                    unsafe { (*prev).next.matches(node_ptr) }
                }
                && if next.is_null() {
                    self.tail.matches(node_ptr)
                } else {
                    unsafe { (*next).prev.matches(node_ptr) }
                };
            if !valid {
                drop(claims);
                drop(next_ref);
                drop(prev_ref);
                continue;
            }
            let previous = node
                .meta
                .fetch_update(SeqCst, SeqCst, |meta| {
                    assert!(matches!(meta & PHASE_MASK, WAITING | NOTIFIED));
                    Some((meta & !PHASE_MASK) | REMOVING)
                })
                .unwrap();
            unsafe {
                RawWaiterNode::reserve(prev);
                RawWaiterNode::reserve(next);
            }
            drop(next_ref);
            drop(prev_ref);
            let left = if prev.is_null() {
                &self.head
            } else {
                unsafe { &(*prev).next }
            };
            let right = if next.is_null() {
                &self.tail
            } else {
                unsafe { &(*next).prev }
            };
            left.drain(false);
            right.drain(false);
            node.prev.drain(true);
            node.next.drain(true);
            unsafe {
                left.commit(next, false);
                right.commit(prev, false);
                node.prev.commit(ptr::null_mut(), true);
                node.next.commit(ptr::null_mut(), true);
            }
            assert_eq!(node.meta.load(SeqCst) & COUNT_MASK, 0);
            node.meta.store(DETACHED | EDIT, SeqCst);
            drop(claims);
            while self.notifier_hazard.load(SeqCst) == node_ptr {
                spin_loop();
            }
            unsafe { *node.waker.get() = None };
            self.drive_notifications();
            return previous & PHASE_MASK == NOTIFIED;
        }
    }

    pub fn notify_one(&self) {
        self.pending_one
            .fetch_update(SeqCst, SeqCst, |value| value.checked_add(1))
            .expect("waiter notification count overflow");
        self.drive_notifications();
    }

    pub fn notify_all(&self) {
        self.broadcast_until
            .fetch_max(self.last_ticket.load(SeqCst), SeqCst);
        self.drive_notifications();
    }

    fn drive_notifications(&self) {
        assert!(
            AtomicU128::is_lock_free(),
            "waiter queue requires native 128-bit atomics"
        );
        let mut control = self.notification_control.fetch_or(DIRTY, SeqCst) | DIRTY;
        loop {
            if control & ACTIVE != 0 {
                return;
            }
            match self.notification_control.compare_exchange_weak(
                control,
                control | ACTIVE,
                SeqCst,
                SeqCst,
            ) {
                Ok(_) => break,
                Err(actual) => control = actual,
            }
        }
        let mut owner = NotificationOwner {
            queue: self,
            active: true,
        };
        loop {
            self.notification_control.fetch_and(!DIRTY, SeqCst);
            loop {
                let pending = self.pending_one.load(SeqCst);
                let broadcast = self.broadcast_until.load(SeqCst);
                if pending == 0 && broadcast == 0 {
                    break;
                }
                let head = self.head.0.load(SeqCst);
                if head == END {
                    self.pending_one
                        .compare_exchange(pending, 0, SeqCst, SeqCst)
                        .ok();
                    self.broadcast_until
                        .compare_exchange(broadcast, 0, SeqCst, SeqCst)
                        .ok();
                    break;
                }
                if head & LINK_STATE_MASK != BOUND {
                    spin_loop();
                    continue;
                }
                let node = link_pointer(head);
                self.notifier_hazard.store(node, SeqCst);
                if !self.head.matches(node) {
                    self.notifier_hazard.store(ptr::null_mut(), SeqCst);
                    continue;
                }
                let node = unsafe { &*node };
                let mut meta = node.meta.load(SeqCst);
                if meta & PHASE_MASK != WAITING {
                    self.notifier_hazard.store(ptr::null_mut(), SeqCst);
                    if meta & PHASE_MASK == NOTIFIED {
                        break;
                    }
                    spin_loop();
                    continue;
                }
                let ticket = unsafe { *node.ticket.get() };
                if broadcast != 0 && ticket > broadcast {
                    self.broadcast_until
                        .compare_exchange(broadcast, 0, SeqCst, SeqCst)
                        .ok();
                    if pending == 0 {
                        self.notifier_hazard.store(ptr::null_mut(), SeqCst);
                        break;
                    }
                }
                let waker = unsafe { (&*node.waker.get()).as_ref().unwrap().clone() };
                let notified = loop {
                    if meta & PHASE_MASK != WAITING {
                        break false;
                    }
                    match node.meta.compare_exchange_weak(
                        meta,
                        (meta & !PHASE_MASK) | NOTIFIED,
                        SeqCst,
                        SeqCst,
                    ) {
                        Ok(_) => break true,
                        Err(actual) => meta = actual,
                    }
                };
                self.notifier_hazard.store(ptr::null_mut(), SeqCst);
                if notified {
                    if pending != 0 {
                        self.pending_one.fetch_sub(1, SeqCst);
                    }
                    waker.wake();
                    break;
                }
                drop(waker);
            }
            if self
                .notification_control
                .compare_exchange(ACTIVE, 0, SeqCst, SeqCst)
                .is_ok()
            {
                owner.active = false;
                return;
            }
        }
    }
}

impl Default for RawWaiterQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for RawWaiterQueue {
    fn drop(&mut self) {
        assert_eq!(
            *self.head.0.get_mut(),
            END,
            "waiter queue dropped while registered"
        );
        assert_eq!(
            *self.tail.0.get_mut(),
            END,
            "waiter queue dropped while registered"
        );
    }
}

pub struct WaiterQueue {
    raw: RawWaiterQueue,
}

impl WaiterQueue {
    pub const fn new() -> Self {
        Self {
            raw: RawWaiterQueue::new(),
        }
    }

    pub const fn registration(&self) -> WaitRegistration<'_> {
        WaitRegistration {
            queue: &self.raw,
            node: RawWaiterNode::new(),
        }
    }
}

impl Default for WaiterQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for WaiterQueue {
    type Target = RawWaiterQueue;

    fn deref(&self) -> &Self::Target {
        &self.raw
    }
}

pub struct WaitRegistration<'a> {
    queue: &'a RawWaiterQueue,
    node: RawWaiterNode,
}

impl WaitRegistration<'_> {
    pub fn register(self: Pin<&mut Self>, waker: &Waker) {
        unsafe {
            let this = self.get_unchecked_mut();
            this.queue
                .register(Pin::new_unchecked(&mut this.node), waker);
        }
    }

    pub fn remove(self: Pin<&mut Self>) -> bool {
        unsafe {
            let this = self.get_unchecked_mut();
            this.queue.remove(Pin::new_unchecked(&mut this.node))
        }
    }
}

impl Drop for WaitRegistration<'_> {
    fn drop(&mut self) {
        unsafe { self.queue.remove(Pin::new_unchecked(&mut self.node)) };
    }
}
