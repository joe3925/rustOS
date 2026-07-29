use crate::{
    global_async::{
        DestroyExecutorDomainResult, ExecutorDomainClass, ExecutorDomainConfig, ExecutorDomainId,
        ExecutorDomainState, ExecutorDomainTable, ExecutorSubmitErrorKind,
        SimpleRoundRobinScheduler, WorkItem, KERNEL_NORMAL_EXECUTOR_DOMAIN,
    },
    round_robin::{ScheduledDomain, SchedulerPolicy, WeightedDeficitRoundRobinScheduler},
};
use kernel_types::capacity::{GeometricResizePolicy, ResizePolicyKind};

extern "C" fn noop(_ctx: usize) {}

fn item() -> WorkItem {
    WorkItem {
        trampoline: noop,
        ctx: 0,
    }
}

#[test]
fn domain_table_rejects_invalid_and_stale_domain_ids() {
    let table = ExecutorDomainTable::new(1, 8);
    let invalid = ExecutorDomainId::from_parts(999, 1);

    let err = table
        .submit_to_executor_domain(invalid, item())
        .expect_err("invalid domain unexpectedly accepted work");
    assert_eq!(err.kind, ExecutorSubmitErrorKind::InvalidDomain);

    let id = table.create_executor_domain(ExecutorDomainConfig::default());
    assert_eq!(
        table.destroy_executor_domain(id),
        Ok(DestroyExecutorDomainResult::Destroyed)
    );

    let err = table
        .submit_to_executor_domain(id, item())
        .expect_err("stale domain unexpectedly accepted work");
    assert_eq!(err.kind, ExecutorSubmitErrorKind::StaleDomain);
}

#[test]
fn full_domain_submission_fails_cleanly() {
    let table = ExecutorDomainTable::new(1, 8);
    let id = table.create_executor_domain(ExecutorDomainConfig {
        initial_queue_capacity: 1,
        resize_policy: ResizePolicyKind::Fixed,
        ..ExecutorDomainConfig::default()
    });

    assert!(table.submit_to_executor_domain(id, item()).is_ok());

    let err = table
        .submit_to_executor_domain(id, item())
        .expect_err("full domain unexpectedly accepted work");
    assert_eq!(err.kind, ExecutorSubmitErrorKind::DomainFull);
}

#[test]
fn draining_domain_rejects_new_work_but_keeps_queued_work() {
    let table = ExecutorDomainTable::new(1, 8);
    let id = table.create_executor_domain(ExecutorDomainConfig::default());

    assert!(table.submit_to_executor_domain(id, item()).is_ok());
    assert_eq!(
        table.destroy_executor_domain(id),
        Ok(DestroyExecutorDomainResult::Draining)
    );

    let domain = table
        .get_executor_domain(id)
        .expect("draining domain should remain registered");
    assert_eq!(domain.state(), ExecutorDomainState::Draining);
    assert_eq!(domain.queued_count(), 1);

    let err = table
        .submit_to_executor_domain(id, item())
        .expect_err("draining domain unexpectedly accepted work");
    assert_eq!(err.kind, ExecutorSubmitErrorKind::DomainDraining);
}

#[test]
fn scheduler_runnable_tracking_deduplicates_domains() {
    let mut scheduler = WeightedDeficitRoundRobinScheduler::new();

    scheduler.on_domain_runnable(KERNEL_NORMAL_EXECUTOR_DOMAIN);
    scheduler.on_domain_runnable(KERNEL_NORMAL_EXECUTOR_DOMAIN);

    assert_eq!(scheduler.runnable_len(), 1);
}

#[test]
fn scheduler_skips_empty_domains_and_requeues_remaining_work() {
    let table = ExecutorDomainTable::new(1, 8);
    let id = table.create_executor_domain(ExecutorDomainConfig {
        initial_queue_capacity: 4,
        quantum: 1,
        ..ExecutorDomainConfig::default()
    });
    let mut scheduler = SimpleRoundRobinScheduler::new();

    scheduler.on_domain_runnable(id);
    assert_eq!(scheduler.pick_next_domain(&table), None);
    assert_eq!(scheduler.runnable_len(), 0);

    let outcome = table
        .submit_to_executor_domain(id, item())
        .expect("domain submission failed");
    if outcome.became_runnable {
        scheduler.on_domain_runnable(outcome.domain_id);
    }

    assert_eq!(
        scheduler.pick_next_domain(&table),
        Some(ScheduledDomain {
            domain_id: id,
            budget: 1
        })
    );
    scheduler.on_domain_ran(&table, id, 1, true);
    assert_eq!(scheduler.runnable_len(), 1);
}

#[test]
fn weighted_scheduler_uses_weighted_budget_without_starving_low_weight_domain() {
    let table = ExecutorDomainTable::new(1, 16);
    let high = table.create_executor_domain(ExecutorDomainConfig {
        class: ExecutorDomainClass::KernelHigh,
        weight: 8,
        quantum: 8,
        initial_queue_capacity: 8,
        ..ExecutorDomainConfig::default()
    });
    let low = table.create_executor_domain(ExecutorDomainConfig {
        class: ExecutorDomainClass::KernelBackground,
        weight: 1,
        quantum: 8,
        initial_queue_capacity: 8,
        ..ExecutorDomainConfig::default()
    });
    let mut scheduler = WeightedDeficitRoundRobinScheduler::new();

    let high_outcome = table.submit_to_executor_domain(high, item()).unwrap();
    let low_outcome = table.submit_to_executor_domain(low, item()).unwrap();
    scheduler.on_domain_runnable(high_outcome.domain_id);
    scheduler.on_domain_runnable(low_outcome.domain_id);

    let first = scheduler
        .pick_next_domain(&table)
        .expect("high domain should be selected");
    let second = scheduler
        .pick_next_domain(&table)
        .expect("low domain should also be selected");

    assert_eq!(first.domain_id, high);
    assert_eq!(first.budget, 8);
    assert_eq!(second.domain_id, low);
    assert_eq!(second.budget, 1);
}

#[test]
fn zero_quantum_and_zero_limits_are_clamped() {
    let table = ExecutorDomainTable::new(1, 8);
    let id = table.create_executor_domain(ExecutorDomainConfig {
        max_active: 0,
        initial_queue_capacity: 0,
        quantum: 0,
        weight: 0,
        ..ExecutorDomainConfig::default()
    });

    let stats = table
        .get_executor_domain(id)
        .expect("domain missing")
        .stats();
    assert_eq!(stats.max_active, 1);
    assert_eq!(stats.initial_queue_capacity, 1);
    assert_eq!(stats.quantum, 1);
    assert_eq!(stats.weight, 1);
}

#[test]
fn geometric_policy_grows_and_best_effort_shrinks_to_initial_capacity() {
    let table = ExecutorDomainTable::new(1, 8);
    let id = table.create_executor_domain(ExecutorDomainConfig {
        initial_queue_capacity: 2,
        resize_policy: ResizePolicyKind::Geometric(GeometricResizePolicy::new(2, 2, 50, 75)),
        ..ExecutorDomainConfig::default()
    });

    table.submit_to_executor_domain(id, item()).unwrap();
    table.submit_to_executor_domain(id, item()).unwrap();
    table.submit_to_executor_domain(id, item()).unwrap();

    let domain = table.get_executor_domain(id).unwrap();
    assert!(domain.stats().queue_capacity >= 4);

    domain.pop_work(0).unwrap();
    domain.pop_work(0).unwrap();
    domain.pop_work(0).unwrap();

    let stats = domain.stats();
    assert_eq!(stats.queued_count, 0);
    assert_eq!(stats.queue_capacity, stats.queue_minimum_capacity);
}

#[test]
fn live_policy_can_be_replaced_with_fixed() {
    use crate::global_async::ReplaceResizePolicyResult;

    let table = ExecutorDomainTable::new(1, 8);
    let id = table.create_executor_domain(ExecutorDomainConfig {
        initial_queue_capacity: 1,
        ..ExecutorDomainConfig::default()
    });
    let domain = table.get_executor_domain(id).unwrap();

    assert_eq!(
        domain.replace_resize_policy(ResizePolicyKind::Fixed),
        ReplaceResizePolicyResult::Changed
    );
    table.submit_to_executor_domain(id, item()).unwrap();
    let error = table.submit_to_executor_domain(id, item()).unwrap_err();
    assert_eq!(error.kind, ExecutorSubmitErrorKind::DomainFull);
}
