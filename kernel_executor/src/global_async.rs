use crate::platform::{platform, Job};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use kernel_types::io::BoundedTreiberStack;
use spin::Once;

pub type Trampoline = extern "win64" fn(usize);

#[repr(align(64))]
struct CacheAligned(AtomicUsize);

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct WorkItem {
    pub trampoline: Trampoline,
    pub ctx: usize,
}

const MAX_SHARDS: usize = 32;

struct ShardedQueues {
    queues: Vec<BoundedTreiberStack<WorkItem>>,
    enqueue_hint: CacheAligned,
    pump_hint: CacheAligned,
    work_count: CacheAligned,
}

impl ShardedQueues {
    fn new(shards: usize, max_work_items: usize) -> Self {
        let base = max_work_items / shards;
        let rem = max_work_items % shards;

        let mut queues = Vec::with_capacity(shards);

        let mut i = 0usize;
        while i < shards {
            let cap = base + usize::from(i < rem);
            queues.push(BoundedTreiberStack::new(cap));
            i += 1;
        }

        Self {
            queues,
            enqueue_hint: CacheAligned(AtomicUsize::new(0)),
            pump_hint: CacheAligned(AtomicUsize::new(0)),
            work_count: CacheAligned(AtomicUsize::new(0)),
        }
    }

    fn shard_count(&self) -> usize {
        self.queues.len()
    }

    fn try_push(&self, mut item: WorkItem) -> Result<(), WorkItem> {
        let shards = self.shard_count();
        let start = self.enqueue_hint.0.fetch_add(1, Ordering::Relaxed) % shards;

        let mut offset = 0usize;
        while offset < shards {
            let idx = (start + offset) % shards;

            match self.queues[idx].try_push(item) {
                Ok(()) => {
                    self.work_count.0.fetch_add(1, Ordering::Release);
                    return Ok(());
                }
                Err(returned) => {
                    item = returned;
                }
            }

            offset += 1;
        }

        Err(item)
    }

    fn pop_round_robin(&self, start_idx: usize) -> Option<(WorkItem, usize)> {
        let shards = self.shard_count();

        let mut offset = 0usize;
        while offset < shards {
            let idx = (start_idx + offset) % shards;

            if let Some(item) = self.queues[idx].pop() {
                self.work_count.0.fetch_sub(1, Ordering::AcqRel);
                return Some((item, idx));
            }

            offset += 1;
        }

        None
    }

    fn has_pending_work(&self) -> bool {
        self.work_count.0.load(Ordering::Acquire) != 0
    }

    fn next_pump_hint(&self) -> usize {
        let shards = self.shard_count();
        self.pump_hint.0.fetch_add(1, Ordering::Relaxed) % shards
    }
}

pub struct GlobalAsyncExecutor {
    queues: Once<ShardedQueues>,
    active_pumps: CacheAligned,
    max_pumps: CacheAligned,
}

impl GlobalAsyncExecutor {
    pub fn global() -> &'static GlobalAsyncExecutor {
        static EXEC: Once<GlobalAsyncExecutor> = Once::new();

        EXEC.call_once(|| GlobalAsyncExecutor {
            queues: Once::new(),
            active_pumps: CacheAligned(AtomicUsize::new(0)),
            max_pumps: CacheAligned(AtomicUsize::new(1)),
        })
    }

    pub fn init(&self, shards: usize, max_work_items: usize) {
        let shards = shards.clamp(1, MAX_SHARDS);
        let max_work_items = max_work_items.max(shards);

        self.queues
            .call_once(|| ShardedQueues::new(shards, max_work_items));
        self.max_pumps.0.store(shards, Ordering::Release);

        platform().init_blocking(shards);
        platform().init_runtime(shards, shards);

        if self.queues().has_pending_work() {
            self.try_schedule();
        }
    }

    fn queues(&self) -> &ShardedQueues {
        self.queues
            .get()
            .expect("global async executor queues not initialized")
    }

    pub fn submit(&self, trampoline: Trampoline, ctx: usize) {
        self.try_submit(trampoline, ctx)
            .expect("failed to submit to executor pool")
    }

    pub fn try_submit(&self, trampoline: Trampoline, ctx: usize) -> Result<(), WorkItem> {
        self.queues().try_push(WorkItem { trampoline, ctx })?;
        self.try_schedule();
        Ok(())
    }

    fn try_schedule(&self) {
        let max = self.max_pumps.0.load(Ordering::Acquire);
        let reserved = self
            .active_pumps
            .0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < max).then_some(active + 1)
            })
            .is_ok();

        if !reserved {
            return;
        }

        let hint = self.queues().next_pump_hint();

        platform().submit_runtime(Job {
            f: pump_trampoline,
            a: hint,
        });
    }

    fn exit_pump(&self) {
        self.active_pumps.0.fetch_sub(1, Ordering::AcqRel);
    }

    fn pump(&self, start_hint: usize) {
        let queues = self.queues();
        let shard_count = queues.shard_count();
        let mut cursor = start_hint % shard_count;

        loop {
            let item = match queues.pop_round_robin(cursor) {
                Some((x, idx)) => {
                    cursor = (idx + 1) % shard_count;
                    x
                }
                None => break,
            };

            (item.trampoline)(item.ctx);
        }

        self.exit_pump();

        if queues.has_pending_work() {
            self.try_schedule();
        }
    }
}

#[inline(never)]
pub extern "win64" fn pump_trampoline(ctx: usize) {
    GlobalAsyncExecutor::global().pump(ctx);
}
