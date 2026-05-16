use alloc::vec;

use crate::runtime::runtime::{block_on, spawn_blocking, spawn_blocking_many};

#[test]
fn spawn_blocking_runs_job_and_join_consumes_result() {
    super::init_inline_platform();

    let join = spawn_blocking(|| 21usize * 2);
    assert_eq!(block_on(join), 42);
}

#[test]
fn spawn_blocking_many_preserves_join_order() {
    super::init_inline_platform();

    let joins = spawn_blocking_many(vec![|| 1usize, || 2usize, || 3usize]);
    let results: alloc::vec::Vec<_> = joins.into_iter().map(block_on).collect();

    assert_eq!(results, vec![1, 2, 3]);
}
