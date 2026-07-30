use kernel_types::completion::{CompletionPermit, TaskCompletion, TaskOutcome, TaskToken};

use crate::test::P;
use crate::CompletionPort;

#[test]
fn grows_publishes_and_reclaims_capacity() {
    let port = CompletionPort::<P, usize>::new(4, 1);
    let mut permits = Vec::new();
    for _ in 0..4 {
        permits.push(port.try_reserve().unwrap());
    }
    assert!(port.try_reserve().is_err());
    port.try_grow(2).unwrap();
    for _ in 0..2 {
        permits.push(port.try_reserve().unwrap());
    }
    assert!(port.capacity() >= 6);
    assert_eq!(port.outstanding(), 6);

    for (index, permit) in permits.into_iter().enumerate() {
        permit.complete(TaskCompletion {
            task: TaskToken::from_raw(index + 1).unwrap(),
            key: index as u64,
            outcome: TaskOutcome::Completed(index),
        });
    }

    for _ in 0..6 {
        assert!(port.try_recv().is_ok());
    }
    assert_eq!(port.outstanding(), 0);
    port.try_shrink_to(4).unwrap();
    assert_eq!(port.capacity(), 4);
}

#[test]
fn unused_permit_returns_capacity() {
    let port = CompletionPort::<P, usize>::new(1, 1);
    drop(port.try_reserve().unwrap());
    assert_eq!(port.outstanding(), 0);
    assert!(port.try_reserve().is_ok());
}

#[test]
fn failed_shrink_leaves_capacity_unchanged() {
    let port = CompletionPort::<P, usize>::new(2, 1);
    let _first = port.try_reserve().unwrap();
    let _second = port.try_reserve().unwrap();
    assert!(port.try_shrink_to(1).is_err());
    assert_eq!(port.capacity(), 2);
}
