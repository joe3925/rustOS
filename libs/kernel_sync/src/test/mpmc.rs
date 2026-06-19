use std::sync::Arc;

use crate::mpmc::{RecvError, SendError, TryRecvError};
use crate::test::{recv_timeout, P};

#[test]
fn try_recv_send_recv_and_disconnect() {
    let (sender, receiver) = crate::mpmc::mpmc_channel::<P, i32>();

    assert_eq!(receiver.try_recv(), Err(TryRecvError::Empty));
    sender.send(1).unwrap();
    sender.send(2).unwrap();
    sender.send(3).unwrap();
    assert_eq!(receiver.recv(), Ok(1));
    assert_eq!(receiver.recv(), Ok(2));
    assert_eq!(receiver.recv(), Ok(3));
    assert!(receiver.is_empty());

    drop(sender);
    assert_eq!(receiver.try_recv(), Err(TryRecvError::Disconnected));
    assert_eq!(receiver.recv(), Err(RecvError));
}

#[test]
fn dropping_receiver_disconnects_senders() {
    let (sender, receiver) = crate::mpmc::mpmc_channel::<P, i32>();

    drop(receiver);

    assert_eq!(sender.send(7), Err(SendError(7)));
    assert!(sender.is_disconnected());
}

#[test]
fn blocking_recv_is_woken_by_send() {
    let (sender, receiver) = crate::mpmc::mpmc_channel::<P, usize>();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();

    let handle = std::thread::spawn(move || {
        ready_tx.send(()).unwrap();
        done_tx.send(receiver.recv()).unwrap();
    });

    recv_timeout(&ready_rx);
    sender.send(42).unwrap();

    assert_eq!(recv_timeout(&done_rx), Ok(42));
    handle.join().unwrap();
}

#[test]
fn concurrent_producers_deliver_every_message() {
    let (sender, receiver) = crate::mpmc::mpmc_channel::<P, usize>();
    let producers = 4usize;
    let per_producer = 128usize;
    let mut handles = Vec::new();

    for producer in 0..producers {
        let sender = sender.clone();
        handles.push(std::thread::spawn(move || {
            for n in 0..per_producer {
                sender.send(producer * per_producer + n).unwrap();
            }
        }));
    }
    drop(sender);

    for handle in handles {
        handle.join().unwrap();
    }

    let mut values = Vec::new();
    while let Ok(value) = receiver.recv() {
        values.push(value);
    }

    values.sort_unstable();
    assert_eq!(values.len(), producers * per_producer);
    for (idx, value) in values.into_iter().enumerate() {
        assert_eq!(value, idx);
    }
}

#[test]
fn cloned_receivers_compete_without_duplicates() {
    let (sender, receiver) = crate::mpmc::mpmc_channel::<P, usize>();
    let receiver = Arc::new(receiver);
    let consumers = 4usize;
    let messages = 256usize;
    let (out_tx, out_rx) = std::sync::mpsc::channel();
    let mut handles = Vec::new();

    for _ in 0..consumers {
        let receiver = receiver.as_ref().clone();
        let out_tx = out_tx.clone();
        handles.push(std::thread::spawn(move || {
            while let Ok(value) = receiver.recv() {
                out_tx.send(value).unwrap();
            }
        }));
    }

    drop(receiver);
    for value in 0..messages {
        sender.send(value).unwrap();
    }
    drop(sender);
    drop(out_tx);

    let mut values: Vec<_> = out_rx.into_iter().collect();
    for handle in handles {
        handle.join().unwrap();
    }

    values.sort_unstable();
    assert_eq!(values.len(), messages);
    for (idx, value) in values.into_iter().enumerate() {
        assert_eq!(value, idx);
    }
}
