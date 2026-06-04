use crate::{
    global_async::{
        DestroyDomainResult, DomainClass, DomainConfig, DomainId, DomainState, DomainTable,
        KERNEL_NORMAL_DOMAIN, SimpleRoundRobinScheduler, SubmitErrorKind, WorkItem,
    },
    round_robin::{
        ScheduledDomain, SchedulerPolicy, WeightedDeficitRoundRobinScheduler,
    },
};

extern "win64" fn noop(_ctx: usize) {}

fn item() -> WorkItem {
    WorkItem {
        trampoline: noop,
        ctx: 0,
    }
}

#[test]
fn domain_table_rejects_invalid_and_stale_domain_ids() {
    let table = DomainTable::new(1, 8);
    let invalid = DomainId::from_parts(999, 1);

    let err = table
        .submit_to_domain(invalid, item())
        .expect_err("invalid domain unexpectedly accepted work");
    assert_eq!(err.kind, SubmitErrorKind::InvalidDomain);

    let id = table.create_domain(DomainConfig::default());
    assert_eq!(table.destroy_domain(id), Ok(DestroyDomainResult::Destroyed));

    let err = table
        .submit_to_domain(id, item())
        .expect_err("stale domain unexpectedly accepted work");
    assert_eq!(err.kind, SubmitErrorKind::StaleDomain);
}

#[test]
fn full_domain_submission_fails_cleanly() {
    let table = DomainTable::new(1, 8);
    let id = table.create_domain(DomainConfig {
        max_queued: 1,
        ..DomainConfig::default()
    });

    assert!(table.submit_to_domain(id, item()).is_ok());

    let err = table
        .submit_to_domain(id, item())
        .expect_err("full domain unexpectedly accepted work");
    assert_eq!(err.kind, SubmitErrorKind::DomainFull);
}

#[test]
fn draining_domain_rejects_new_work_but_keeps_queued_work() {
    let table = DomainTable::new(1, 8);
    let id = table.create_domain(DomainConfig::default());

    assert!(table.submit_to_domain(id, item()).is_ok());
    assert_eq!(table.destroy_domain(id), Ok(DestroyDomainResult::Draining));

    let domain = table
        .get_domain(id)
        .expect("draining domain should remain registered");
    assert_eq!(domain.state(), DomainState::Draining);
    assert_eq!(domain.queued_count(), 1);

    let err = table
        .submit_to_domain(id, item())
        .expect_err("draining domain unexpectedly accepted work");
    assert_eq!(err.kind, SubmitErrorKind::DomainDraining);
}

#[test]
fn scheduler_runnable_tracking_deduplicates_domains() {
    let mut scheduler = WeightedDeficitRoundRobinScheduler::new();

    scheduler.on_domain_runnable(KERNEL_NORMAL_DOMAIN);
    scheduler.on_domain_runnable(KERNEL_NORMAL_DOMAIN);

    assert_eq!(scheduler.runnable_len(), 1);
}

#[test]
fn scheduler_skips_empty_domains_and_requeues_remaining_work() {
    let table = DomainTable::new(1, 8);
    let id = table.create_domain(DomainConfig {
        max_queued: 4,
        quantum: 1,
        ..DomainConfig::default()
    });
    let mut scheduler = SimpleRoundRobinScheduler::new();

    scheduler.on_domain_runnable(id);
    assert_eq!(scheduler.pick_next_domain(&table), None);
    assert_eq!(scheduler.runnable_len(), 0);

    let outcome = table
        .submit_to_domain(id, item())
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
    let table = DomainTable::new(1, 16);
    let high = table.create_domain(DomainConfig {
        class: DomainClass::KernelHigh,
        weight: 8,
        quantum: 8,
        max_queued: 8,
        ..DomainConfig::default()
    });
    let low = table.create_domain(DomainConfig {
        class: DomainClass::KernelBackground,
        weight: 1,
        quantum: 8,
        max_queued: 8,
        ..DomainConfig::default()
    });
    let mut scheduler = WeightedDeficitRoundRobinScheduler::new();

    let high_outcome = table.submit_to_domain(high, item()).unwrap();
    let low_outcome = table.submit_to_domain(low, item()).unwrap();
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
    let table = DomainTable::new(1, 8);
    let id = table.create_domain(DomainConfig {
        max_active: 0,
        max_queued: 0,
        quantum: 0,
        weight: 0,
        ..DomainConfig::default()
    });

    let stats = table.get_domain(id).expect("domain missing").stats();
    assert_eq!(stats.max_active, 1);
    assert_eq!(stats.max_queued, 1);
    assert_eq!(stats.quantum, 1);
    assert_eq!(stats.weight, 1);
}
