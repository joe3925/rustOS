use alloc::collections::VecDeque;

use crate::domain::{ExecutorDomainId, ExecutorDomainTable};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScheduledDomain {
    pub domain_id: ExecutorDomainId,
    pub budget: usize,
}

pub trait SchedulerPolicy: Send {
    fn on_domain_runnable(&mut self, domain_id: ExecutorDomainId);
    fn pick_next_domain(&mut self, domain_table: &ExecutorDomainTable) -> Option<ScheduledDomain>;
    fn on_domain_ran(
        &mut self,
        domain_table: &ExecutorDomainTable,
        domain_id: ExecutorDomainId,
        ran_count: usize,
        still_runnable: bool,
    );
    fn on_domain_empty(&mut self, domain_id: ExecutorDomainId);
    fn on_domain_rejected(&mut self, domain_id: ExecutorDomainId);
    fn runnable_len(&self) -> usize;
}

fn push_unique(queue: &mut VecDeque<ExecutorDomainId>, domain_id: ExecutorDomainId) {
    if !queue.iter().any(|queued| *queued == domain_id) {
        queue.push_back(domain_id);
    }
}

fn remove_all(queue: &mut VecDeque<ExecutorDomainId>, domain_id: ExecutorDomainId) {
    queue.retain(|queued| *queued != domain_id);
}

pub struct SimpleRoundRobinScheduler {
    runnable: VecDeque<ExecutorDomainId>,
}

impl SimpleRoundRobinScheduler {
    pub fn new() -> Self {
        Self {
            runnable: VecDeque::new(),
        }
    }
}

impl Default for SimpleRoundRobinScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl SchedulerPolicy for SimpleRoundRobinScheduler {
    fn on_domain_runnable(&mut self, domain_id: ExecutorDomainId) {
        push_unique(&mut self.runnable, domain_id);
    }

    fn pick_next_domain(&mut self, domain_table: &ExecutorDomainTable) -> Option<ScheduledDomain> {
        let attempts = self.runnable.len();
        let mut checked = 0usize;

        while checked < attempts {
            let Some(domain_id) = self.runnable.pop_front() else {
                break;
            };

            checked += 1;

            let Some(domain) = domain_table.get_executor_domain(domain_id) else {
                continue;
            };

            if !domain.is_runnable_for_policy() {
                domain.clear_runnable();
                continue;
            }

            if domain.is_at_active_limit() {
                push_unique(&mut self.runnable, domain_id);
                continue;
            }

            return Some(ScheduledDomain {
                domain_id,
                budget: domain.quantum(),
            });
        }

        None
    }

    fn on_domain_ran(
        &mut self,
        _domain_table: &ExecutorDomainTable,
        domain_id: ExecutorDomainId,
        _ran_count: usize,
        still_runnable: bool,
    ) {
        if still_runnable {
            push_unique(&mut self.runnable, domain_id);
        } else {
            remove_all(&mut self.runnable, domain_id);
        }
    }

    fn on_domain_empty(&mut self, domain_id: ExecutorDomainId) {
        remove_all(&mut self.runnable, domain_id);
    }

    fn on_domain_rejected(&mut self, _domain_id: ExecutorDomainId) {}

    fn runnable_len(&self) -> usize {
        self.runnable.len()
    }
}

pub struct WeightedDeficitRoundRobinScheduler {
    runnable: VecDeque<ExecutorDomainId>,
}

impl WeightedDeficitRoundRobinScheduler {
    pub fn new() -> Self {
        Self {
            runnable: VecDeque::new(),
        }
    }
}

impl Default for WeightedDeficitRoundRobinScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl SchedulerPolicy for WeightedDeficitRoundRobinScheduler {
    fn on_domain_runnable(&mut self, domain_id: ExecutorDomainId) {
        push_unique(&mut self.runnable, domain_id);
    }

    fn pick_next_domain(&mut self, domain_table: &ExecutorDomainTable) -> Option<ScheduledDomain> {
        let attempts = self.runnable.len();
        let mut checked = 0usize;

        while checked < attempts {
            let Some(domain_id) = self.runnable.pop_front() else {
                break;
            };

            checked += 1;

            let Some(domain) = domain_table.get_executor_domain(domain_id) else {
                continue;
            };

            if !domain.is_runnable_for_policy() {
                domain.clear_runnable();
                continue;
            }

            if domain.is_at_active_limit() {
                push_unique(&mut self.runnable, domain_id);
                continue;
            }

            let deficit = domain.add_deficit(domain.weight());
            let budget = deficit.min(domain.quantum()).max(1);

            return Some(ScheduledDomain { domain_id, budget });
        }

        None
    }

    fn on_domain_ran(
        &mut self,
        domain_table: &ExecutorDomainTable,
        domain_id: ExecutorDomainId,
        ran_count: usize,
        still_runnable: bool,
    ) {
        if still_runnable {
            push_unique(&mut self.runnable, domain_id);
        } else {
            remove_all(&mut self.runnable, domain_id);
        }

        if let Some(domain) = domain_table.get_executor_domain(domain_id) {
            domain.spend_deficit(ran_count.max(1));
        }
    }

    fn on_domain_empty(&mut self, domain_id: ExecutorDomainId) {
        remove_all(&mut self.runnable, domain_id);
    }

    fn on_domain_rejected(&mut self, _domain_id: ExecutorDomainId) {}

    fn runnable_len(&self) -> usize {
        self.runnable.len()
    }
}
