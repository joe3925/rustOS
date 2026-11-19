use super::support::{self, TestExecutorPlatform as Host};
use crate::global_async::{ExecutorDomainConfig, GlobalAsyncExecutor};
use crate::runtime::runtime::{
    TaskOutcome, block_on, spawn_detached_in_executor_domain,
    spawn_join_owned_in_executor_domain as spawn,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

#[test]
fn older_spawn_progresses_while_parent_self_wakes() {
    let _lock = support::global_runtime_lock();
    support::init_threaded_runtime();
    let executor = GlobalAsyncExecutor::<Host>::global();
    let domain = executor.create_executor_domain(ExecutorDomainConfig::kernel_normal(1));
    fn link(domain: crate::global_async::ExecutorDomainId, count: Arc<AtomicUsize>) {
        spawn_detached_in_executor_domain::<Host, _>(domain, async move {
            if count.fetch_add(1, Ordering::Relaxed) < 64 {
                link(domain, count);
            }
        });
    }
    let parent = spawn::<Host, _, _>(domain, async move {
        let count = Arc::new(AtomicUsize::new(0));
        let observed = count.clone();
        let old = spawn::<Host, _, _>(domain, async move { observed.load(Ordering::Relaxed) });
        link(domain, count);
        let mut polls = 0;
        core::future::poll_fn(|cx| {
            polls += 1;
            if polls == 64 {
                core::task::Poll::Ready(())
            } else {
                cx.waker().wake_by_ref();
                core::task::Poll::Pending
            }
        })
        .await;
        old.await
    });
    let TaskOutcome::Completed(TaskOutcome::Completed(links)) = block_on::<Host, _>(parent) else {
        panic!("unexpected cancellation");
    };
    executor.destroy_executor_domain(domain).unwrap();
    assert!(links < 16, "older task waited for {links} newer spawns");
}

#[test]
fn older_spawn_is_not_starved_by_new_spawn_chain() {
    let _lock = support::global_runtime_lock();
    support::init_threaded_runtime();
    let executor = GlobalAsyncExecutor::<Host>::global();
    let domain = executor.create_executor_domain(ExecutorDomainConfig::kernel_normal(1));
    fn link(domain: crate::global_async::ExecutorDomainId, count: Arc<AtomicUsize>) {
        spawn_detached_in_executor_domain::<Host, _>(domain, async move {
            if count.fetch_add(1, Ordering::Relaxed) < 64 {
                link(domain, count);
            }
        });
    }
    let parent = spawn::<Host, _, _>(domain, async move {
        let count = Arc::new(AtomicUsize::new(0));
        let observed = count.clone();
        let old = spawn::<Host, _, _>(domain, async move { observed.load(Ordering::Relaxed) });
        link(domain, count);
        old.await
    });
    let TaskOutcome::Completed(TaskOutcome::Completed(links)) = block_on::<Host, _>(parent) else {
        panic!("unexpected cancellation");
    };
    assert!(links < 16, "older task waited for {links} newer spawns");
    executor.destroy_executor_domain(domain).unwrap();
}

#[test]
fn child_starts_before_parent_returns_from_poll() {
    let _lock = support::global_runtime_lock();
    support::init_threaded_runtime();
    let executor = GlobalAsyncExecutor::<Host>::global();
    if executor.worker_count() < 2 {
        return;
    }
    let domain = executor.create_executor_domain(ExecutorDomainConfig::kernel_normal(2));
    let parent = spawn::<Host, _, _>(domain, async move {
        let started = Arc::new(AtomicBool::new(false));
        let flag = started.clone();
        let child = spawn::<Host, _, _>(domain, async move {
            flag.store(true, Ordering::Release);
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        while !started.load(Ordering::Acquire) && Instant::now() < deadline {
            core::hint::spin_loop();
        }
        let concurrent = started.load(Ordering::Acquire);
        assert_eq!(child.await, TaskOutcome::Completed(()));
        concurrent
    });
    assert_eq!(block_on::<Host, _>(parent), TaskOutcome::Completed(true));
    executor.destroy_executor_domain(domain).unwrap();
}

#[test]
fn visible_children_obey_domain_limit_and_overflow_queue() {
    let _lock = support::global_runtime_lock();
    support::init_threaded_runtime();
    let executor = GlobalAsyncExecutor::<Host>::global();
    let domain = executor.create_executor_domain(ExecutorDomainConfig::kernel_normal(1));
    let parent = spawn::<Host, _, _>(domain, async move {
        let started = Arc::new(AtomicUsize::new(0));
        let mut children = std::vec::Vec::new();
        for i in 0..1024 {
            let flag = started.clone();
            children.push(spawn::<Host, _, _>(domain, async move {
                flag.fetch_add(1, Ordering::Relaxed);
                i
            }));
        }
        // A spare physical worker must not bypass max_active=1.
        std::thread::sleep(Duration::from_millis(10));
        assert_eq!(started.load(Ordering::Relaxed), 0);
        for (i, child) in children.into_iter().enumerate() {
            assert_eq!(child.await, TaskOutcome::Completed(i));
        }
        assert_eq!(started.load(Ordering::Relaxed), 1024);
    });
    assert_eq!(block_on::<Host, _>(parent), TaskOutcome::Completed(()));
    executor.destroy_executor_domain(domain).unwrap();
}

#[test]
fn destroying_domain_drops_unpolled_deque_and_overflow_children_once() {
    let _lock = support::global_runtime_lock();
    support::init_threaded_runtime();
    let executor = GlobalAsyncExecutor::<Host>::global();
    let domain = executor.create_executor_domain(ExecutorDomainConfig::kernel_normal(1));
    struct DropCount(Arc<AtomicUsize>);
    impl Drop for DropCount {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Release);
        }
    }
    let dropped = Arc::new(AtomicUsize::new(0));
    let ready = Arc::new(AtomicBool::new(false));
    let release = Arc::new(AtomicBool::new(false));
    let (d, r, g) = (dropped.clone(), ready.clone(), release.clone());
    let parent = spawn::<Host, _, _>(domain, async move {
        for _ in 0..1024 {
            let marker = DropCount(d.clone());
            spawn_detached_in_executor_domain::<Host, _>(domain, async move {
                let _marker = marker;
                core::future::pending::<()>().await;
            });
        }
        r.store(true, Ordering::Release);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !g.load(Ordering::Acquire) {
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
    });
    support::wait_until(Duration::from_secs(5), || ready.load(Ordering::Acquire));
    executor.destroy_executor_domain(domain).unwrap();
    release.store(true, Ordering::Release);
    let _ = block_on::<Host, _>(parent);
    support::wait_until(Duration::from_secs(5), || {
        dropped.load(Ordering::Acquire) == 1024
    });
    assert_eq!(dropped.load(Ordering::Acquire), 1024);
}
