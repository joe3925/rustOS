use crate::bounded_mpmc::{BoundedMpmcPushError, BoundedMpmcQueue};

#[test]
fn try_push_pop_reports_full_empty_and_preserves_fifo_order() {
    let queue = BoundedMpmcQueue::<usize>::new(2);

    assert_eq!(queue.try_pop(), None);
    assert_eq!(queue.try_push(10), Ok(()));
    assert_eq!(queue.try_push(20), Ok(()));
    assert_eq!(queue.len(), 2);

    assert_eq!(queue.try_push(30), Err(BoundedMpmcPushError::Full(30)));
    assert_eq!(queue.try_pop(), Some(10));
    assert_eq!(queue.try_pop(), Some(20));
    assert_eq!(queue.try_pop(), None);
}

#[test]
fn retrying_push_pop_match_queue_style_api() {
    let queue = BoundedMpmcQueue::<usize>::new(2);
    assert_eq!(queue.try_push(1), Ok(()));
    assert_eq!(queue.try_push(2), Ok(()));
    assert_eq!(queue.try_push(3), Err(BoundedMpmcPushError::Full(3)));
    assert_eq!(queue.try_pop(), Some(1));
    assert_eq!(queue.try_pop(), Some(2));
    assert_eq!(queue.try_pop(), None);
}

#[test]
fn capacity_one_does_not_overwrite_live_slot() {
    let queue = BoundedMpmcQueue::<usize>::new(1);

    assert_eq!(queue.try_push(1), Ok(()));
    assert_eq!(queue.len(), 1);
    assert_eq!(queue.try_push(2), Err(BoundedMpmcPushError::Full(2)));
    assert_eq!(queue.try_pop(), Some(1));
    assert_eq!(queue.try_pop(), None);

    assert_eq!(queue.try_push(3), Ok(()));
    assert_eq!(queue.try_push(4), Err(BoundedMpmcPushError::Full(4)));
    assert_eq!(queue.try_pop(), Some(3));
}
