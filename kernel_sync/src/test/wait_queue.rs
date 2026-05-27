use std::sync::Arc;

use crate::platform::{ParkReason, Platform};
use crate::test::{recv_timeout, P};
use crate::WaitQueue;

#[test]
fn enqueue_dequeue_and_clear_current() {
    let queue = WaitQueue::<P>::new();

    assert!(queue.is_empty());
    assert!(queue.enqueue_current());
    assert!(queue.is_current_enqueued());
    assert_eq!(queue.len(), 1);
    assert!(!queue.enqueue_current());

    let task = queue.dequeue_one().expect("current task should be queued");
    assert!(!<P as Platform>::is_waiting(&task, queue.id()));
    assert!(queue.is_empty());
    assert!(!queue.is_current_enqueued());
    assert!(queue.dequeue_one().is_none());

    assert!(queue.enqueue_current());
    assert!(queue.clear_current_if_queued());
    assert!(!queue.clear_current_if_queued());
    assert!(queue.is_empty());
    assert!(queue.dequeue_one().is_none());
}

#[test]
fn wake_one_unparks_waiting_thread() {
    let queue = Arc::new(WaitQueue::<P>::new());
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();

    let worker_queue = queue.clone();
    let handle = std::thread::spawn(move || {
        assert!(worker_queue.enqueue_current());
        ready_tx.send(()).unwrap();
        <P as Platform>::park_current(ParkReason::None);
        assert!(!worker_queue.is_current_enqueued());
        done_tx.send(()).unwrap();
    });

    recv_timeout(&ready_rx);
    assert_eq!(queue.len(), 1);
    let task = queue.dequeue_one().expect("worker should be queued");
    <P as Platform>::unpark(&task);

    recv_timeout(&done_rx);
    handle.join().unwrap();
    assert!(queue.is_empty());
}

#[test]
fn dequeue_all_returns_every_waiter() {
    let queue = Arc::new(WaitQueue::<P>::new());
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let mut handles = Vec::new();

    for _ in 0..4 {
        let worker_queue = queue.clone();
        let ready_tx = ready_tx.clone();
        let done_tx = done_tx.clone();
        handles.push(std::thread::spawn(move || {
            assert!(worker_queue.enqueue_current());
            ready_tx.send(()).unwrap();
            <P as Platform>::park_current(ParkReason::None);
            done_tx.send(()).unwrap();
        }));
    }

    for _ in 0..4 {
        recv_timeout(&ready_rx);
    }

    let tasks = queue.dequeue_all();
    assert_eq!(tasks.len(), 4);
    assert!(queue.is_empty());

    for task in tasks {
        <P as Platform>::unpark(&task);
    }

    for _ in 0..4 {
        recv_timeout(&done_rx);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}
