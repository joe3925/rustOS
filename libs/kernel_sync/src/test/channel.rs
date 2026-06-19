use crate::channel::{RecvError, SendError, TryRecvError};
use crate::test::{recv_timeout, P};

#[test]
fn send_recv_order_len_and_empty() {
    let (sender, receiver) = crate::channel::channel::<P, i32>();

    assert_eq!(receiver.try_recv(), Err(TryRecvError::Empty));
    sender.send(1).unwrap();
    sender.send(2).unwrap();
    sender.send(3).unwrap();
    assert_eq!(receiver.len(), 3);
    assert!(!receiver.is_empty());
    assert_eq!(receiver.recv(), Ok(1));
    assert_eq!(receiver.recv(), Ok(2));
    assert_eq!(receiver.recv(), Ok(3));
    assert!(receiver.is_empty());
}

#[test]
fn all_senders_dropped_disconnects_receiver_after_drain() {
    let (sender, receiver) = crate::channel::channel::<P, i32>();
    let sender2 = sender.clone();

    sender.send(10).unwrap();
    drop(sender);
    assert!(!receiver.is_disconnected());
    drop(sender2);

    assert_eq!(receiver.recv(), Ok(10));
    assert_eq!(receiver.try_recv(), Err(TryRecvError::Disconnected));
    assert_eq!(receiver.recv(), Err(RecvError));
}

#[test]
fn receiver_drop_disconnects_senders() {
    let (sender, receiver) = crate::channel::channel::<P, i32>();

    drop(receiver);

    assert_eq!(sender.send(5), Err(SendError(5)));
    assert!(sender.is_disconnected());
}

#[test]
fn blocking_recv_is_woken_by_send() {
    let (sender, receiver) = crate::channel::channel::<P, usize>();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();

    let handle = std::thread::spawn(move || {
        ready_tx.send(()).unwrap();
        done_tx.send(receiver.recv()).unwrap();
    });

    recv_timeout(&ready_rx);
    sender.send(123).unwrap();

    assert_eq!(recv_timeout(&done_rx), Ok(123));
    handle.join().unwrap();
}

#[test]
fn concurrent_senders_deliver_all_messages() {
    let (sender, receiver) = crate::channel::channel::<P, usize>();
    let producers = 4usize;
    let per_producer = 64usize;
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
