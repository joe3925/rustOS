use crate::platform;
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicPtr, Ordering};
use spin::Mutex;

#[derive(Debug)]
#[repr(C)]
pub(super) struct ReclaimNode {
    next: AtomicPtr<ReclaimNode>,
    reclaim: unsafe fn(*mut ReclaimNode),
}

static PENDING: AtomicPtr<ReclaimNode> = AtomicPtr::new(ptr::null_mut());
static DRAIN_LOCK: Mutex<()> = Mutex::new(());

impl ReclaimNode {
    pub(super) const fn new(reclaim: unsafe fn(*mut ReclaimNode)) -> Self {
        Self {
            next: AtomicPtr::new(ptr::null_mut()),
            reclaim,
        }
    }
}

#[cfg_attr(irq_check, irq::context)]
pub(super) unsafe fn enqueue(node: NonNull<ReclaimNode>) {
    let mut head = PENDING.load(Ordering::Relaxed);
    loop {
        unsafe { node.as_ref().next.store(head, Ordering::Relaxed) };
        match PENDING.compare_exchange_weak(
            head,
            node.as_ptr(),
            Ordering::Release,
            Ordering::Relaxed,
        ) {
            Ok(_) => {
                if head.is_null() {
                    super::scheduler::wake_reaper();
                }
                return;
            }
            Err(actual) => head = actual,
        }
    }
}

pub(super) fn has_pending() -> bool {
    !PENDING.load(Ordering::Acquire).is_null()
}

#[cfg_attr(irq_check, irq::forbidden)]
pub(super) fn drain() {
    let Some(_guard) = DRAIN_LOCK.try_lock() else {
        return;
    };
    let mut node = PENDING.swap(ptr::null_mut(), Ordering::Acquire);
    while !node.is_null() {
        unsafe {
            let next = (*node).next.load(Ordering::Relaxed);
            let reclaim = (*node).reclaim;
            reclaim(node);
            node = next;
        }
    }
}
