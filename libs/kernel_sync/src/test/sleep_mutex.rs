use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use crate::test::{recv_timeout, wait_until, P};
use crate::{Condvar, SleepMutex};

#[test]
fn lock_try_lock_and_mutation() {
    let mutex = SleepMutex::<P, usize>::new(1);

    {
        let mut guard = mutex.lock();
        assert_eq!(*guard, 1);
        *guard = 2;
        assert!(mutex.try_lock().is_none());
    }

    let guard = mutex.try_lock().expect("mutex should be unlocked");
    assert_eq!(*guard, 2);
}

#[test]
fn contended_lock_serializes_mutation() {
    let mutex = Arc::new(SleepMutex::<P, usize>::new(0));
    let threads = 8usize;
    let per_thread = 250usize;
    let mut handles = Vec::new();

    for _ in 0..threads {
        let mutex = mutex.clone();
        handles.push(std::thread::spawn(move || {
            for _ in 0..per_thread {
                let mut guard = mutex.lock();
                *guard += 1;
            }
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }

    assert_eq!(*mutex.lock(), threads * per_thread);
}

#[test]
fn condvar_notify_one_wakes_waiter_after_predicate_changes() {
    let pair = Arc::new((SleepMutex::<P, bool>::new(false), Condvar::<P>::new()));
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();

    let worker_pair = pair.clone();
    let handle = std::thread::spawn(move || {
        let (mutex, condvar) = &*worker_pair;
        let mut guard = mutex.lock();
        ready_tx.send(()).unwrap();
        while !*guard {
            guard = condvar.wait(guard);
        }
        done_tx.send(()).unwrap();
    });

    recv_timeout(&ready_rx);
    {
        let (mutex, condvar) = &*pair;
        *mutex.lock() = true;
        condvar.notify_one();
    }

    recv_timeout(&done_rx);
    handle.join().unwrap();
}

#[test]
fn condvar_notify_all_wakes_all_waiters() {
    let pair = Arc::new((SleepMutex::<P, bool>::new(false), Condvar::<P>::new()));
    let waiters = 4usize;
    let ready = Arc::new(AtomicUsize::new(0));
    let done = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();

    for _ in 0..waiters {
        let pair = pair.clone();
        let ready = ready.clone();
        let done = done.clone();
        handles.push(std::thread::spawn(move || {
            let (mutex, condvar) = &*pair;
            let mut guard = mutex.lock();
            ready.fetch_add(1, Ordering::SeqCst);
            while !*guard {
                guard = condvar.wait(guard);
            }
            done.fetch_add(1, Ordering::SeqCst);
        }));
    }

    wait_until(|| ready.load(Ordering::SeqCst) == waiters);
    {
        let (mutex, condvar) = &*pair;
        *mutex.lock() = true;
        condvar.notify_all();
    }

    wait_until(|| done.load(Ordering::SeqCst) == waiters);
    for handle in handles {
        handle.join().unwrap();
    }
}
