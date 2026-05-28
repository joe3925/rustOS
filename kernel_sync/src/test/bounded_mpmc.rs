use crate::bounded_mpmc::BoundedSendError;
use crate::mpmc::{RecvError, TryRecvError};
use crate::test::{recv_timeout, P};

#[test]
fn capacity_len_and_fifo_progress() {
    let (sender, receiver) = crate::bounded_mpmc::bounded_mpmc_channel::<P, i32>(2, 1);

    assert_eq!(sender.capacity(), 2);
    assert!(sender.is_empty());
    assert_eq!(sender.try_send(1), Ok(()));
    assert_eq!(sender.try_send(2), Ok(()));
    assert!(sender.is_full());
    assert_eq!(sender.try_send(3), Err(BoundedSendError::Full(3)));
    assert_eq!(receiver.try_recv(), Ok(1));
    assert_eq!(sender.try_send(3), Ok(()));
    assert_eq!(receiver.recv(), Ok(2));
    assert_eq!(receiver.recv(), Ok(3));
    assert!(receiver.is_empty());
}

#[test]
fn disconnect_paths_match_unbounded_mpmc() {
    let (sender, receiver) = crate::bounded_mpmc::bounded_mpmc_channel::<P, i32>(2, 1);

    sender.try_send(10).unwrap();
    drop(sender);
    assert_eq!(receiver.recv(), Ok(10));
    assert_eq!(receiver.recv(), Err(RecvError));
    assert_eq!(receiver.try_recv(), Err(TryRecvError::Disconnected));

    let (sender, receiver) = crate::bounded_mpmc::bounded_mpmc_channel::<P, i32>(2, 1);
    drop(receiver);
    assert_eq!(sender.try_send(11), Err(BoundedSendError::Disconnected(11)));
    assert!(sender.is_disconnected());
}

#[test]
fn blocking_recv_is_woken_by_try_send() {
    let (sender, receiver) = crate::bounded_mpmc::bounded_mpmc_channel::<P, usize>(4, 1);
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();

    let handle = std::thread::spawn(move || {
        ready_tx.send(()).unwrap();
        done_tx.send(receiver.recv()).unwrap();
    });

    recv_timeout(&ready_rx);
    sender.try_send(99).unwrap();

    assert_eq!(recv_timeout(&done_rx), Ok(99));
    handle.join().unwrap();
}

#[test]
fn concurrent_producers_and_consumers_transfer_all_values() {
    let (sender, receiver) = crate::bounded_mpmc::bounded_mpmc_channel::<P, usize>(64, 4);
    let producers = 4usize;
    let consumers = 4usize;
    let per_producer = 96usize;
    let total = producers * per_producer;
    let (out_tx, out_rx) = std::sync::mpsc::channel();
    let mut producer_handles = Vec::new();
    let mut consumer_handles = Vec::new();

    for _ in 0..consumers {
        let receiver = receiver.clone();
        let out_tx = out_tx.clone();
        consumer_handles.push(std::thread::spawn(move || {
            while let Ok(value) = receiver.recv() {
                out_tx.send(value).unwrap();
            }
        }));
    }
    drop(receiver);

    for producer in 0..producers {
        let sender = sender.clone();
        producer_handles.push(std::thread::spawn(move || {
            for n in 0..per_producer {
                let mut value = producer * per_producer + n;
                loop {
                    match sender.try_send(value) {
                        Ok(()) => break,
                        Err(BoundedSendError::Full(v)) => {
                            value = v;
                            std::thread::yield_now();
                        }
                        Err(BoundedSendError::Disconnected(_)) => panic!("receiver dropped"),
                    }
                }
            }
        }));
    }
    drop(sender);

    for handle in producer_handles {
        handle.join().unwrap();
    }
    drop(out_tx);

    let mut values = Vec::new();
    for _ in 0..total {
        values.push(recv_timeout(&out_rx));
    }

    for handle in consumer_handles {
        handle.join().unwrap();
    }

    values.sort_unstable();
    assert_eq!(values.len(), total);
    for (idx, value) in values.into_iter().enumerate() {
        assert_eq!(value, idx);
    }
}
