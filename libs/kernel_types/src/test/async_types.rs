use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use crate::async_types::{AsyncMutex, AsyncRwLock};

fn noop_waker() -> Waker {
    unsafe fn clone(_: *const ()) -> RawWaker {
        RawWaker::new(core::ptr::null(), &VTABLE)
    }
    unsafe fn wake(_: *const ()) {}
    unsafe fn wake_by_ref(_: *const ()) {}
    unsafe fn drop(_: *const ()) {}

    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop);
    unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) }
}

fn poll_once<F: Future + Unpin>(future: &mut F) -> Poll<F::Output> {
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    Pin::new(future).poll(&mut cx)
}

fn poll_pinned<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    future.poll(&mut cx)
}

#[test]
fn async_mutex_try_lock_enforces_exclusive_access() {
    let lock = AsyncMutex::new(Vec::<u8>::new());

    {
        let mut guard = lock.try_lock().unwrap();
        guard.push(1);
        guard.push(2);
        assert!(lock.try_lock().is_none());
    }

    let guard = lock.try_lock().unwrap();
    assert_eq!(guard.as_slice(), &[1, 2]);
}

#[test]
fn async_mutex_future_pending_then_ready_after_unlock() {
    let lock = AsyncMutex::new(10usize);
    let guard = lock.try_lock().unwrap();
    let mut wait = lock.lock();

    assert!(matches!(poll_once(&mut wait), Poll::Pending));
    drop(guard);

    match poll_once(&mut wait) {
        Poll::Ready(mut guard) => {
            *guard += 5;
        }
        Poll::Pending => panic!("mutex future stayed pending after unlock"),
    }

    assert_eq!(*lock.try_lock().unwrap(), 15);
}

#[test]
fn async_mutex_owned_guard_releases_arc_lock_on_drop() {
    let lock = Arc::new(AsyncMutex::new(3usize));
    let mut fut = Box::pin(lock.clone().lock_owned());

    match poll_pinned(fut.as_mut()) {
        Poll::Ready(mut guard) => {
            *guard = 11;
            assert!(lock.try_lock().is_none());
        }
        Poll::Pending => panic!("owned mutex lock should be ready"),
    }

    assert_eq!(*lock.try_lock().unwrap(), 11);
}

#[test]
fn async_rwlock_allows_many_readers_or_one_writer() {
    let lock = AsyncRwLock::new(5usize);

    let reader_a = lock.try_read().unwrap();
    let reader_b = lock.try_read().unwrap();
    assert_eq!(*reader_a, 5);
    assert_eq!(*reader_b, 5);
    assert!(lock.try_write().is_none());

    drop(reader_a);
    assert!(lock.try_write().is_none());
    drop(reader_b);

    {
        let mut writer = lock.try_write().unwrap();
        *writer = 8;
        assert!(lock.try_read().is_none());
        assert!(lock.try_write().is_none());
    }

    assert_eq!(*lock.try_read().unwrap(), 8);
}

#[test]
fn async_rwlock_write_future_waits_for_readers() {
    let lock = AsyncRwLock::new(1usize);
    let reader = lock.try_read().unwrap();
    let mut write = lock.write();

    assert!(matches!(poll_once(&mut write), Poll::Pending));
    drop(reader);

    match poll_once(&mut write) {
        Poll::Ready(mut guard) => *guard = 42,
        Poll::Pending => panic!("write future stayed pending after readers dropped"),
    }

    assert_eq!(*lock.try_read().unwrap(), 42);
}

#[test]
fn async_rwlock_owned_guards_release_when_dropped() {
    let lock = Arc::new(AsyncRwLock::new(AtomicUsize::new(0)));

    let mut read_fut = Box::pin(lock.clone().read_owned());
    let read_guard = match poll_pinned(read_fut.as_mut()) {
        Poll::Ready(guard) => guard,
        Poll::Pending => panic!("owned read should be ready"),
    };
    assert_eq!(read_guard.load(Ordering::Relaxed), 0);
    assert!(lock.try_write().is_none());
    drop(read_guard);

    let mut write_fut = Box::pin(lock.clone().write_owned());
    let write_guard = match poll_pinned(write_fut.as_mut()) {
        Poll::Ready(guard) => guard,
        Poll::Pending => panic!("owned write should be ready"),
    };
    write_guard.store(99, Ordering::Relaxed);
    drop(write_guard);

    assert_eq!(lock.try_read().unwrap().load(Ordering::Relaxed), 99);
}
