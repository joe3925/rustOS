use crate::mpmc_ring::{MpmcRing, RingError, TryPushError};

#[test]
fn try_push_pop_reports_full_empty_and_preserves_fifo_order() {
    let queue = MpmcRing::<usize, 2>::new();

    assert_eq!(queue.try_pop(), Err(RingError::Empty));
    assert_eq!(queue.try_push(10), Ok(()));
    assert_eq!(queue.try_push(20), Ok(()));
    assert_eq!(queue.len_approx(), 2);

    assert_eq!(queue.try_push(30), Err(TryPushError::Full(30)));
    assert_eq!(queue.try_pop(), Ok(10));
    assert_eq!(queue.try_pop(), Ok(20));
    assert_eq!(queue.try_pop(), Err(RingError::Empty));
}

#[test]
fn retrying_push_pop_match_queue_style_api() {
    let queue = MpmcRing::<usize, 2>::new();

    assert_eq!(queue.push(1), Ok(()));
    assert_eq!(queue.push(2), Ok(()));
    assert_eq!(queue.push(3), Err(3));
    assert_eq!(queue.pop(), Some(1));
    assert_eq!(queue.pop(), Some(2));
    assert_eq!(queue.pop(), None);
}
