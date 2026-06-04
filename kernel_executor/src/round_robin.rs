use alloc::vec::Vec;

use crate::domain::{DomainId, DomainTable};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScheduledDomain {
    pub domain_id: DomainId,
    pub budget: usize,
}

pub trait SchedulerPolicy: Send {
    fn on_domain_runnable(&mut self, domain_id: DomainId);
    fn pick_next_domain(&mut self, domain_table: &DomainTable) -> Option<ScheduledDomain>;
    fn on_domain_ran(
        &mut self,
        domain_table: &DomainTable,
        domain_id: DomainId,
        ran_count: usize,
        still_runnable: bool,
    );
    fn on_domain_empty(&mut self, domain_id: DomainId);
    fn on_domain_rejected(&mut self, domain_id: DomainId);
    fn runnable_len(&self) -> usize;
}

fn push_unique(queue: &mut Vec<DomainId>, domain_id: DomainId) {
    if !queue.iter().any(|queued| *queued == domain_id) {
        queue.push(domain_id);
    }
}

fn remove_all(queue: &mut Vec<DomainId>, domain_id: DomainId) {
    queue.retain(|queued| *queued != domain_id);
}

pub struct SimpleRoundRobinScheduler {
    runnable: Vec<DomainId>,
}

impl SimpleRoundRobinScheduler {
    pub fn new() -> Self {
        Self {
            runnable: Vec::new(),
        }
    }
}

impl Default for SimpleRoundRobinScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl SchedulerPolicy for SimpleRoundRobinScheduler {
    fn on_domain_runnable(&mut self, domain_id: DomainId) {
        push_unique(&mut self.runnable, domain_id);
    }

    fn pick_next_domain(&mut self, domain_table: &DomainTable) -> Option<ScheduledDomain> {
        let attempts = self.runnable.len();
        let mut checked = 0usize;

        while checked < attempts {
            let domain_id = self.runnable.remove(0);
            checked += 1;

            let Some(domain) = domain_table.get_domain(domain_id) else {
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
        _domain_table: &DomainTable,
        domain_id: DomainId,
        _ran_count: usize,
        still_runnable: bool,
    ) {
        if still_runnable {
            push_unique(&mut self.runnable, domain_id);
        } else {
            remove_all(&mut self.runnable, domain_id);
        }
    }

    fn on_domain_empty(&mut self, domain_id: DomainId) {
        remove_all(&mut self.runnable, domain_id);
    }

    fn on_domain_rejected(&mut self, _domain_id: DomainId) {}

    fn runnable_len(&self) -> usize {
        self.runnable.len()
    }
}

pub struct WeightedDeficitRoundRobinScheduler {
    runnable: Vec<DomainId>,
}

impl WeightedDeficitRoundRobinScheduler {
    pub fn new() -> Self {
        Self {
            runnable: Vec::new(),
        }
    }
}

impl Default for WeightedDeficitRoundRobinScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl SchedulerPolicy for WeightedDeficitRoundRobinScheduler {
    fn on_domain_runnable(&mut self, domain_id: DomainId) {
        push_unique(&mut self.runnable, domain_id);
    }

    fn pick_next_domain(&mut self, domain_table: &DomainTable) -> Option<ScheduledDomain> {
        let attempts = self.runnable.len();
        let mut checked = 0usize;

        while checked < attempts {
            let domain_id = self.runnable.remove(0);
            checked += 1;

            let Some(domain) = domain_table.get_domain(domain_id) else {
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
        domain_table: &DomainTable,
        domain_id: DomainId,
        ran_count: usize,
        still_runnable: bool,
    ) {
        if still_runnable {
            push_unique(&mut self.runnable, domain_id);
        } else {
            remove_all(&mut self.runnable, domain_id);
        }

        if let Some(domain) = domain_table.get_domain(domain_id) {
            domain.spend_deficit(ran_count.max(1));
        }
    }

    fn on_domain_empty(&mut self, domain_id: DomainId) {
        remove_all(&mut self.runnable, domain_id);
    }

    fn on_domain_rejected(&mut self, _domain_id: DomainId) {}

    fn runnable_len(&self) -> usize {
        self.runnable.len()
    }
}
