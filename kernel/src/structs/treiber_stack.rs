use alloc::boxed::Box;
use core::cell::UnsafeCell;
use core::mem::ManuallyDrop;
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

use crossbeam_epoch::{Atomic, Collector, Guard, LocalHandle, Owned, Shared};
use spin::Once;

static EPOCH_COLLECTOR: Once<Collector> = Once::new();

#[repr(transparent)]
struct TlsEpochHandle {
    value: UnsafeCell<Option<&'static LocalHandle>>,
}

unsafe impl Sync for TlsEpochHandle {}

#[thread_local]
static EPOCH_HANDLE: TlsEpochHandle = TlsEpochHandle {
    value: UnsafeCell::new(None),
};

fn epoch_collector() -> &'static Collector {
    EPOCH_COLLECTOR.call_once(Collector::new)
}

fn epoch_handle() -> &'static LocalHandle {
    unsafe {
        let slot = &mut *EPOCH_HANDLE.value.get();

        if let Some(handle) = *slot {
            return handle;
        }

        let handle = Box::leak(Box::new(epoch_collector().register()));
        *slot = Some(handle);
        handle
    }
}

fn epoch_pin() -> Guard {
    epoch_handle().pin()
}

#[repr(C)]
struct Node<T> {
    data: ManuallyDrop<T>,
    next: Atomic<Node<T>>,
}

#[repr(C)]
pub struct TreiberStack<T> {
    head: Atomic<Node<T>>,
    len: AtomicUsize,
}

impl<T> TreiberStack<T> {
    pub const fn new() -> Self {
        Self {
            head: Atomic::null(),
            len: AtomicUsize::new(0),
        }
    }

    pub fn len(&self) -> usize {
        self.len.load(Ordering::Acquire)
    }

    pub fn is_empty(&self) -> bool {
        let guard = epoch_pin();
        self.head.load(Ordering::Acquire, &guard).is_null()
    }

    pub fn push(&self, data: T) {
        let guard = epoch_pin();

        let mut new_node = Owned::new(Node {
            data: ManuallyDrop::new(data),
            next: Atomic::null(),
        });

        let mut head = self.head.load(Ordering::Acquire, &guard);

        loop {
            new_node.next.store(head, Ordering::Relaxed);

            match self.head.compare_exchange_weak(
                head,
                new_node,
                Ordering::Release,
                Ordering::Acquire,
                &guard,
            ) {
                Ok(_) => {
                    self.len.fetch_add(1, Ordering::Release);
                    return;
                }
                Err(err) => {
                    head = err.current;
                    new_node = err.new;
                }
            }
        }
    }

    pub fn pop(&self) -> Option<T> {
        let guard = epoch_pin();
        let mut head = self.head.load(Ordering::Acquire, &guard);

        loop {
            let node = unsafe { head.as_ref()? };
            let next = node.next.load(Ordering::Acquire, &guard);

            match self.head.compare_exchange_weak(
                head,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
                &guard,
            ) {
                Ok(_) => {
                    self.len.fetch_sub(1, Ordering::AcqRel);

                    let data = unsafe {
                        let data_ptr = ptr::addr_of!((*head.as_raw()).data);
                        ManuallyDrop::into_inner(ptr::read(data_ptr))
                    };

                    unsafe {
                        guard.defer_destroy(head);
                    }

                    return Some(data);
                }
                Err(err) => {
                    head = err.current;
                }
            }
        }
    }

    pub fn drain_fifo<F>(&self, mut f: F)
    where
        F: FnMut(T),
    {
        let guard = epoch_pin();

        let mut head = self.head.swap(Shared::null(), Ordering::AcqRel, &guard);
        let mut reversed = Shared::null();
        let mut count = 0usize;

        while let Some(node) = unsafe { head.as_ref() } {
            let next = node.next.load(Ordering::Acquire, &guard);
            node.next.store(reversed, Ordering::Relaxed);

            reversed = head;
            head = next;
            count += 1;
        }

        if count != 0 {
            self.len.fetch_sub(count, Ordering::AcqRel);
        }

        let mut current = reversed;

        while let Some(node) = unsafe { current.as_ref() } {
            let next = node.next.load(Ordering::Acquire, &guard);

            let data = unsafe {
                let data_ptr = ptr::addr_of!((*current.as_raw()).data);
                ManuallyDrop::into_inner(ptr::read(data_ptr))
            };

            unsafe {
                guard.defer_destroy(current);
            }

            f(data);
            current = next;
        }
    }
}

impl<T> Drop for TreiberStack<T> {
    fn drop(&mut self) {
        let guard = epoch_pin();
        let mut head = self.head.swap(Shared::null(), Ordering::AcqRel, &guard);

        while let Some(node) = unsafe { head.as_ref() } {
            let next = node.next.load(Ordering::Relaxed, &guard);

            unsafe {
                let raw = head.as_raw() as *mut Node<T>;
                ManuallyDrop::drop(&mut (*raw).data);
                drop(Box::from_raw(raw));
            }

            head = next;
        }

        self.len.store(0, Ordering::Release);
    }
}

impl<T> Default for TreiberStack<T> {
    fn default() -> Self {
        Self::new()
    }
}
