use alloc::boxed::Box;
use core::ptr;
use core::sync::atomic::Ordering;
use portable_atomic::AtomicU128;

use crate::block_dev::BlockDev;

pub(crate) struct ReaderSlot {
    pub reader: BlockDev,
    pub next: usize,
}

pub(crate) struct ReaderPool {
    pub state: AtomicU128,
}

pub(crate) struct ReaderPoolState {
    pub head: usize,
    pub pending: u32,
    pub idle: u32,
}

impl ReaderPoolState {
    pub fn unpack(state: u128) -> Self {
        Self {
            head: state as u64 as usize,
            pending: (state >> 64) as u32,
            idle: (state >> 96) as u32,
        }
    }

    pub fn pack(self) -> u128 {
        self.head as u128 | ((self.pending as u128) << 64) | ((self.idle as u128) << 96)
    }
}

pub(crate) struct ReaderLease<'a> {
    pub pool: &'a ReaderPool,
    pub slot: Option<Box<ReaderSlot>>,
    pub pending: bool,
}

impl ReaderPool {
    pub fn take(&self, reserved: bool) -> Option<Box<ReaderSlot>> {
        let mut old = self.state.load(Ordering::Acquire);
        loop {
            let before = ReaderPoolState::unpack(old);
            let after = ReaderPoolState {
                head: 0,
                pending: before
                    .pending
                    .checked_sub(u32::from(reserved))
                    .expect("FAT32 reader reservation count is zero"),
                idle: 0,
            };
            match self.state.compare_exchange_weak(
                old,
                after.pack(),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return if before.head == 0 {
                        None
                    } else {
                        Some(unsafe {
                            Box::from_raw(ptr::with_exposed_provenance_mut(before.head))
                        })
                    };
                }
                Err(actual) => old = actual,
            }
        }
    }

    pub fn put(&self, slot: Box<ReaderSlot>) {
        let mut node = Box::into_raw(slot);
        while !node.is_null() {
            let address = node.expose_provenance();
            let next = unsafe { (*node).next };
            let mut old = self.state.load(Ordering::Acquire);
            loop {
                let before = ReaderPoolState::unpack(old);
                if before.idle >= before.pending.max(1) {
                    unsafe { drop(Box::from_raw(node)) };
                    break;
                }
                unsafe { (*node).next = before.head };
                let after = ReaderPoolState {
                    head: address,
                    pending: before.pending,
                    idle: before.idle + 1,
                };
                match self.state.compare_exchange_weak(
                    old,
                    after.pack(),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => break,
                    Err(actual) => old = actual,
                }
            }
            node = ptr::with_exposed_provenance_mut(next);
        }
    }
}

impl Drop for ReaderLease<'_> {
    fn drop(&mut self) {
        if self.pending {
            let slots = self.pool.take(true);
            self.pending = false;
            if let Some(slots) = slots {
                self.pool.put(slots);
            }
        }
        if let Some(slot) = self.slot.take() {
            self.pool.put(slot);
        }
    }
}

impl Drop for ReaderPool {
    fn drop(&mut self) {
        let mut head = ReaderPoolState::unpack(*self.state.get_mut()).head;
        while head != 0 {
            let slot: Box<ReaderSlot> =
                unsafe { Box::from_raw(ptr::with_exposed_provenance_mut(head)) };
            head = slot.next;
        }
    }
}
