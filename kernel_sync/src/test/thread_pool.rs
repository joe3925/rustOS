use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::test::{wait_until, P};
use crate::{BoundedThreadPool, Job, SubmitError, ThreadPool};

extern "win64" fn increment(context: usize) {
    let counter = unsafe { &*(context as *const AtomicUsize) };
    counter.fetch_add(1, Ordering::SeqCst);
}

struct BlockingJob {
    started: AtomicBool,
    release: AtomicBool,
}

extern "win64" fn block_until_released(context: usize) {
    let job = unsafe { &*(context as *const BlockingJob) };
    job.started.store(true, Ordering::SeqCst);
    while !job.release.load(Ordering::SeqCst) {
        std::thread::yield_now();
    }
}

#[test]
fn unbounded_pool_runs_submitted_jobs() {
    let pool = ThreadPool::<P>::new(4);
    let counter = AtomicUsize::new(0);

    for _ in 0..64 {
        pool.submit(increment, &counter as *const AtomicUsize as usize);
    }

    wait_until(|| counter.load(Ordering::SeqCst) == 64);
    wait_until(|| pool.work_amount_hint() == 0);
    assert_eq!(pool.total_workers(), 4);
    assert!(!pool.is_shutdown());
}

#[test]
fn submit_many_counts_all_unbounded_jobs() {
    let pool = ThreadPool::<P>::new(2);
    let counter = AtomicUsize::new(0);
    let jobs: Vec<_> = (0..8)
        .map(|_| Job {
            f: increment,
            a: &counter as *const AtomicUsize as usize,
        })
        .collect();

    assert_eq!(pool.submit_many(&jobs), jobs.len());
    wait_until(|| counter.load(Ordering::SeqCst) == jobs.len());
}

#[test]
fn bounded_pool_reports_full_queue() {
    let pool = BoundedThreadPool::<P>::new(1, 1);
    let blocker = BlockingJob {
        started: AtomicBool::new(false),
        release: AtomicBool::new(false),
    };
    let counter = AtomicUsize::new(0);

    assert_eq!(
        pool.try_submit(
            block_until_released,
            &blocker as *const BlockingJob as usize
        ),
        Ok(())
    );
    wait_until(|| blocker.started.load(Ordering::SeqCst));

    assert_eq!(
        pool.try_submit(increment, &counter as *const AtomicUsize as usize),
        Ok(())
    );
    assert_eq!(
        pool.try_submit(increment, &counter as *const AtomicUsize as usize),
        Err(SubmitError::Full)
    );

    blocker.release.store(true, Ordering::SeqCst);
    wait_until(|| counter.load(Ordering::SeqCst) == 1);
}

#[test]
fn shutdown_rejects_new_jobs_and_submit_if_runnable_falls_back() {
    let pool = ThreadPool::<P>::new(1);
    let counter = AtomicUsize::new(0);

    pool.shutdown();
    assert!(pool.is_shutdown());
    assert_eq!(
        pool.try_submit(increment, &counter as *const AtomicUsize as usize),
        Err(SubmitError::Shutdown)
    );

    pool.submit_if_runnable(increment, &counter as *const AtomicUsize as usize);
    assert_eq!(counter.load(Ordering::SeqCst), 1);
}
