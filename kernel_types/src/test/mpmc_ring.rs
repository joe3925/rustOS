use crate::bounded_mpmc::{BoundedMpmcPushError, BoundedMpmcQueue, TryPushError};

#[test]
fn try_push_pop_reports_full_empty_and_preserves_fifo_order() {
    let queue = BoundedMpmcQueue::<usize>::new(2);

    assert_eq!(queue.try_pop(), None);
    assert_eq!(queue.try_push(10), Ok(()));
    assert_eq!(queue.try_push(20), Ok(()));
    assert_eq!(queue.len_approx(), 2);

    assert_eq!(
        queue.try_push(30),
        Err(crate::bounded_mpmc_queue::BoundedMpmcPushError::Full(30))
    );
    assert_eq!(queue.try_pop(), Some(10));
    assert_eq!(queue.try_pop(), Some(20));
    assert_eq!(queue.try_pop(), None);
}

#[test]
fn retrying_push_pop_match_queue_style_api() {
    let queue = BoundedMpmcQueue::<usize>::new(2);
    assert_eq!(queue.push(1), Ok(()));
    assert_eq!(queue.push(2), Ok(()));
    assert_eq!(queue.push(3), Err(3));
    assert_eq!(queue.pop(), Some(1));
    assert_eq!(queue.pop(), Some(2));
    assert_eq!(queue.pop(), None);
}
