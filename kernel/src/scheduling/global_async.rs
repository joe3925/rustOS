use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::{Mutex, Once};

use crate::scheduling::runtime::runtime::RUNTIME_POOL;

pub type Trampoline = extern "win64" fn(usize);

#[derive(Clone, Copy)]
struct WorkItem {
    trampoline: Trampoline,
    ctx: usize,
}

const MAX_SHARDS: usize = 8;

struct ShardedQueues {
    queues: Vec<Mutex<VecDeque<WorkItem>>>,
    active: AtomicUsize,
    enqueue_hint: AtomicUsize,
    pump_hint: AtomicUsize,
}

impl ShardedQueues {
    fn new(shards: usize) -> Self {
        let shard_count = if shards == 0 { 1 } else { shards };
        let mut queues = Vec::with_capacity(shard_count);
        for _ in 0..shard_count {
            queues.push(Mutex::new(VecDeque::new()));
        }

        Self {
            queues,
            active: AtomicUsize::new(shard_count),
            enqueue_hint: AtomicUsize::new(0),
            pump_hint: AtomicUsize::new(0),
        }
    }

    fn set_active(&self, shards: usize) {
        let capped = shards.clamp(1, self.queues.len());
        self.active.store(capped, Ordering::Release);
    }

    fn shard_count(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }

    fn push(&self, item: WorkItem) {
        let shards = self.shard_count();
        let idx = self.enqueue_hint.fetch_add(1, Ordering::Relaxed) % shards;
        let mut q = self.queues[idx].lock();
        q.push_back(item);
    }

    fn pop_round_robin(&self, start_idx: usize) -> Option<(WorkItem, usize)> {
        let shards = self.shard_count();
        for offset in 0..shards {
            let idx = (start_idx + offset) % shards;
            let mut q = self.queues[idx].lock();
            if let Some(item) = q.pop_front() {
                return Some((item, idx));
            }
        }
        None
    }

    fn is_empty(&self) -> bool {
        let shards = self.shard_count();
        for i in 0..shards {
            if !self.queues[i].lock().is_empty() {
                return false;
            }
        }
        true
    }

    fn next_pump_hint(&self) -> usize {
        let shards = self.shard_count();
        self.pump_hint.fetch_add(1, Ordering::Relaxed) % shards
    }
}

pub struct GlobalAsyncExecutor {
    queues: ShardedQueues,
    active_pumps: AtomicUsize,
    max_pumps: AtomicUsize,
}

impl GlobalAsyncExecutor {
    pub fn global() -> &'static GlobalAsyncExecutor {
        static EXEC: Once<GlobalAsyncExecutor> = Once::new();
        EXEC.call_once(|| GlobalAsyncExecutor {
            queues: ShardedQueues::new(MAX_SHARDS),
            active_pumps: AtomicUsize::new(0),
            max_pumps: AtomicUsize::new(1),
        })
    }

    pub fn set_parallelism(&self, n: usize) {
        let n = if n == 0 { 1 } else { n };
        self.max_pumps.store(n, Ordering::Release);
        self.queues.set_active(n);
        self.try_schedule();
    }

    pub fn submit(&self, trampoline: Trampoline, ctx: usize) {
        self.queues.push(WorkItem { trampoline, ctx });
        self.try_schedule();
    }

    fn try_schedule(&self) {
        let max = self.max_pumps.load(Ordering::Acquire);
        let active = self.active_pumps.load(Ordering::Acquire);
        if active >= max {
            return;
        }

        let hint = self.queues.next_pump_hint();
        RUNTIME_POOL.submit(pump_trampoline, hint);
    }

    fn try_enter_pump(&self) -> bool {
        let max = self.max_pumps.load(Ordering::Acquire);
        let prev = self.active_pumps.fetch_add(1, Ordering::AcqRel);
        if prev + 1 > max {
            self.active_pumps.fetch_sub(1, Ordering::AcqRel);
            return false;
        }
        true
    }

    fn exit_pump(&self) {
        self.active_pumps.fetch_sub(1, Ordering::AcqRel);
    }

    fn pump(&self, start_hint: usize) {
        if !self.try_enter_pump() {
            return;
        }

        let shard_count = self.queues.shard_count();
        let mut cursor = if shard_count == 0 {
            0
        } else {
            start_hint % shard_count
        };

        loop {
            let item = match self.queues.pop_round_robin(cursor) {
                Some((x, idx)) => {
                    cursor = (idx + 1) % shard_count;
                    x
                }
                None => break,
            };
            (item.trampoline)(item.ctx);
        }

        self.exit_pump();

        if !self.queues.is_empty() {
            self.try_schedule();
        }
    }
}

#[inline(never)]
pub extern "win64" fn pump_trampoline(ctx: usize) {
    GlobalAsyncExecutor::global().pump(ctx);
}
