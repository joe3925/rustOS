use std::sync::Arc;

use crate::bounded_wait_queue::BoundedWaitQueueError;
use crate::platform::{ParkReason, Platform};
use crate::test::{recv_timeout, P};
use crate::BoundedWaitQueue;

#[test]
fn enqueue_clear_and_already_queued() {
    let queue = BoundedWaitQueue::<P>::new(2);

    assert_eq!(queue.capacity(), 2);
    assert!(queue.is_empty());
    assert_eq!(queue.enqueue_current(), Ok(()));
    assert_eq!(
        queue.enqueue_current(),
        Err(BoundedWaitQueueError::AlreadyQueued)
    );
    assert!(queue.is_current_enqueued());
    assert_eq!(queue.len(), 1);

    assert!(queue.clear_current_if_queued());
    assert!(!queue.clear_current_if_queued());
    assert!(queue.is_empty());
}

#[test]
fn capacity_is_enforced_across_tasks() {
    let queue = Arc::new(BoundedWaitQueue::<P>::new(1));
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (result_tx, result_rx) = std::sync::mpsc::channel();

    let first_queue = queue.clone();
    let first = std::thread::spawn(move || {
        assert_eq!(first_queue.enqueue_current(), Ok(()));
        ready_tx.send(()).unwrap();
        <P as Platform>::park_current(ParkReason::None);
    });

    recv_timeout(&ready_rx);
    assert_eq!(queue.len(), 1);

    let second_queue = queue.clone();
    let second = std::thread::spawn(move || {
        result_tx.send(second_queue.enqueue_current()).unwrap();
    });

    assert_eq!(recv_timeout(&result_rx), Err(BoundedWaitQueueError::Full));
    assert_eq!(queue.wake_all(), 1);

    first.join().unwrap();
    second.join().unwrap();
    assert!(queue.is_empty());
}

#[test]
fn wake_one_then_wake_all_unparks_waiters() {
    let queue = Arc::new(BoundedWaitQueue::<P>::new(3));
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let mut handles = Vec::new();

    for _ in 0..3 {
        let worker_queue = queue.clone();
        let ready_tx = ready_tx.clone();
        let done_tx = done_tx.clone();
        handles.push(std::thread::spawn(move || {
            assert_eq!(worker_queue.enqueue_current(), Ok(()));
            ready_tx.send(()).unwrap();
            <P as Platform>::park_current(ParkReason::None);
            done_tx.send(()).unwrap();
        }));
    }

    for _ in 0..3 {
        recv_timeout(&ready_rx);
    }
    assert_eq!(queue.len(), 3);

    assert!(queue.wake_one());
    recv_timeout(&done_rx);
    assert_eq!(queue.len(), 2);

    assert_eq!(queue.wake_all(), 2);
    recv_timeout(&done_rx);
    recv_timeout(&done_rx);

    for handle in handles {
        handle.join().unwrap();
    }
    assert!(queue.is_empty());
}
