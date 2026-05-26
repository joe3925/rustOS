use crate::platform::{platform, Job};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use kernel_types::io::{BoundedTreiberStack, TreiberStack};
use spin::Once;
use x86_64::instructions::interrupts::without_interrupts;

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
const MAX_WORK_ITEMS: usize = 100_000;

struct ShardedQueues {
    queues: Vec<BoundedTreiberStack<WorkItem>>,
    active: CacheAligned,
    enqueue_hint: CacheAligned,
    pump_hint: CacheAligned,
    work_count: CacheAligned,
}

impl ShardedQueues {
    fn new(shards: usize) -> Self {
        let shard_count = shards.clamp(1, MAX_SHARDS);
        let base = MAX_WORK_ITEMS / shard_count;
        let rem = MAX_WORK_ITEMS % shard_count;

        let mut queues = Vec::with_capacity(shard_count);

        let mut i = 0usize;
        while i < shard_count {
            let cap = base + usize::from(i < rem);
            queues.push(BoundedTreiberStack::new(cap));
            i += 1;
        }

        Self {
            queues,
            active: CacheAligned(AtomicUsize::new(shard_count)),
            enqueue_hint: CacheAligned(AtomicUsize::new(0)),
            pump_hint: CacheAligned(AtomicUsize::new(0)),
            work_count: CacheAligned(AtomicUsize::new(0)),
        }
    }

    fn set_active(&self, shards: usize) {
        let capped = shards.clamp(1, self.queues.len());
        self.active.0.store(capped, Ordering::Release);
    }

    fn shard_count(&self) -> usize {
        self.active.0.load(Ordering::Acquire)
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
    queues: ShardedQueues,
    active_pumps: CacheAligned,
    max_pumps: CacheAligned,
}

impl GlobalAsyncExecutor {
    pub fn global() -> &'static GlobalAsyncExecutor {
        static EXEC: Once<GlobalAsyncExecutor> = Once::new();

        EXEC.call_once(|| GlobalAsyncExecutor {
            queues: ShardedQueues::new(MAX_SHARDS),
            active_pumps: CacheAligned(AtomicUsize::new(0)),
            max_pumps: CacheAligned(AtomicUsize::new(1)),
        })
    }

    pub fn init(&self, shards: usize) {
        let shards = shards.clamp(1, MAX_SHARDS);

        self.max_pumps.0.store(shards, Ordering::Release);
        self.queues.set_active(shards);

        platform().init_blocking(shards);
        platform().init_runtime(shards, MAX_SHARDS);

        if self.queues.has_pending_work() {
            self.try_schedule();
        }
    }

    pub fn submit(&self, trampoline: Trampoline, ctx: usize) {
        self.try_submit(trampoline, ctx)
            .expect("failed to submit to executor pool")
    }

    pub fn try_submit(&self, trampoline: Trampoline, ctx: usize) -> Result<(), WorkItem> {
        self.queues.try_push(WorkItem { trampoline, ctx })?;
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

        let hint = self.queues.next_pump_hint();

        platform().submit_runtime(Job {
            f: pump_trampoline,
            a: hint,
        });
    }

    fn exit_pump(&self) {
        self.active_pumps.0.fetch_sub(1, Ordering::AcqRel);
    }

    fn pump(&self, start_hint: usize) {
        let shard_count = self.queues.shard_count();
        let mut cursor = start_hint % shard_count;

        loop {
            let item = match self.queues.pop_round_robin(cursor) {
                Some((x, idx)) => {
                    if is_heap_addr(x.trampoline as usize) {
                        panic!("corrupted work item ctx: {:#X}", x.ctx);
                    }

                    cursor = (idx + 1) % shard_count;
                    x
                }
                None => break,
            };

            (item.trampoline)(item.ctx);
        }

        self.exit_pump();

        if self.queues.has_pending_work() {
            self.try_schedule();
        }
    }
}

#[inline]
fn addr_prefix_byte(addr: usize) -> u8 {
    ((addr >> 40) & 0xff) as u8
}

#[inline]
fn is_heap_addr(addr: usize) -> bool {
    addr_prefix_byte(addr) == 0x86
}

#[inline(never)]
pub extern "win64" fn pump_trampoline(ctx: usize) {
    GlobalAsyncExecutor::global().pump(ctx);
}
