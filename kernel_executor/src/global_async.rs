use crate::platform::{platform, Job};
use alloc::boxed::Box;
use core::array;
use core::sync::atomic::{AtomicUsize, Ordering};
use kernel_types::mpmc_ring::MpmcRing;
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
const QUEUE_CAP_PER_SHARD: usize = 12500;

struct ShardedQueues {
    queues: [&'static MpmcRing<WorkItem, QUEUE_CAP_PER_SHARD>; MAX_SHARDS],
    active: CacheAligned,
    enqueue_hint: CacheAligned,
    pump_hint: CacheAligned,
}

impl ShardedQueues {
    fn new(shards: usize) -> Self {
        let shard_count = shards.clamp(1, MAX_SHARDS);

        Self {
            queues: array::from_fn(|_| {
                let q: &'static MpmcRing<WorkItem, QUEUE_CAP_PER_SHARD> =
                    Box::leak(Box::new(MpmcRing::new()));
                q
            }),
            active: CacheAligned(AtomicUsize::new(shard_count)),
            enqueue_hint: CacheAligned(AtomicUsize::new(0)),
            pump_hint: CacheAligned(AtomicUsize::new(0)),
        }
    }

    fn set_active(&self, shards: usize) {
        let capped = shards.clamp(1, MAX_SHARDS);
        self.active.0.store(capped, Ordering::Release);
    }

    fn shard_count(&self) -> usize {
        self.active.0.load(Ordering::Acquire)
    }

    fn push(&self, item: WorkItem) -> Result<(), WorkItem> {
        let shards = self.shard_count();
        let start = self.enqueue_hint.0.fetch_add(1, Ordering::Relaxed);

        for offset in 0..shards {
            let idx = (start + offset) % shards;

            match self.queues[idx].try_push(item) {
                Ok(()) => return Ok(()),
                Err(x) => {
                    if offset + 1 == shards {
                        return Err(x);
                    }
                }
            }
        }

        unreachable!()
    }

    fn pop_round_robin(&self, start_idx: usize) -> Option<(WorkItem, usize)> {
        let shards = self.shard_count();

        for offset in 0..shards {
            let idx = (start_idx + offset) % shards;

            if let Some(item) = self.queues[idx].try_pop() {
                return Some((item, idx));
            }
        }

        None
    }

    fn is_empty(&self) -> bool {
        let shards = self.shard_count();

        for idx in 0..shards {
            if !self.queues[idx].is_empty_approx() {
                return false;
            }
        }

        true
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

        if !self.queues.is_empty() {
            self.try_schedule();
        }
    }

    pub fn submit(&self, trampoline: Trampoline, ctx: usize) {
        self.try_submit(trampoline, ctx)
            .expect("failed to submit to executor pool")
    }

    pub fn try_submit(&self, trampoline: Trampoline, ctx: usize) -> Result<(), WorkItem> {
        self.queues.push(WorkItem { trampoline, ctx })?;
        self.try_schedule();
        Ok(())
    }

    fn try_schedule(&self) {
        loop {
            let max = self.max_pumps.0.load(Ordering::Acquire);
            let active = self.active_pumps.0.load(Ordering::Acquire);

            if active >= max {
                return;
            }

            if self
                .active_pumps
                .0
                .compare_exchange_weak(active, active + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                break;
            }
        }

        let hint = self.queues.next_pump_hint();

        platform().submit_runtime(Job {
            f: pump_trampoline,
            a: hint,
        });
    }

    fn exit_pump(&self) {
        self.active_pumps.0.fetch_sub(1, Ordering::Release);
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

        if !self.queues.is_empty() {
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
