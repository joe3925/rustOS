use crate::alloc::format;
use crate::drivers::interrupt_index::{self, TSC_HZ};
use crate::drivers::pnp::manager::PNP_MANAGER;
use crate::drivers::timer_driver::{PER_CORE_SWITCHES, TIMER_TIME_SCHED};
use crate::executable::program::PROGRAM_MANAGER;
use crate::file_system::file::File;
use crate::memory::heap::ALLOCATOR;
use crate::memory::{
    heap::HEAP_SIZE,
    paging::frame_alloc::{total_usable_bytes, USED_MEMORY},
};
use crate::profiling::unwind::{
    capture_callchain_from_state_limited, CapturedCallchain, MAX_CALLCHAIN_DEPTH,
};
use crate::scheduling::runtime::runtime::{
    block_on, spawn_blocking, spawn_blocking_many, spawn_detached, JoinAll,
};
use crate::scheduling::scheduler::SCHEDULER;
use crate::scheduling::state::State;
use crate::static_handlers::{pnp_get_device_target, wait_duration};
use crate::structs::bench_archive::{bench_archive_for_path, BenchArchive, BenchArchiveRecord};
use crate::structs::stopwatch::Stopwatch;
use crate::util::{boot_info, TOTAL_TIME};
use crate::{cpu, println, vec};
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write;
use core::future::Future;
use core::hint::black_box;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use core::task::{Context, Poll};
use core::time::Duration;
use kernel_types::bench_archive::BENCH_ARCHIVE_EXTENSION;
use kernel_types::benchmark::{
    BenchDroppedSampleCounterProto, BenchLevelResult, BenchOverflowPolicy, BenchSampleChunkProto,
    BenchSampleProto, BenchSweepParams, BenchSweepResult, BenchWindowConfig, BENCH_FLAG_IRQ,
    BENCH_FLAG_REQUEST, BENCH_SAMPLE_PROTO_SCHEMA_VERSION,
};
use kernel_types::benchmark::{BenchSweepBothResult, BENCH_FLAG_POLL, BENCH_PARAMS_VERSION_1};
use kernel_types::fs::{FsSeekWhence, OpenFlags, Path};
use kernel_types::memory::{PePdbFormat, PePdbInfo};
use kernel_types::request::{RequestData, RequestHandle, RequestType, TraversalPolicy};
use kernel_types::status::{DriverStatus, FileStatus};
use kernel_types::ProstMessage;
use serde_json::{json, Value};
use spin::{Mutex, Once};
use x86_64::instructions::interrupts;
//const BENCH_ENABLED: bool = cfg!(debug_assertions);
const BENCH_ENABLED: bool = false;

const DEFAULT_SAMPLE_CAPACITY: usize = 8192;
const DEFAULT_SAMPLE_CHUNK_CAPACITY: usize = 1024;

#[derive(Clone, Copy, Debug)]
struct ResolvedBenchWindowConfig {
    overflow_policy: BenchOverflowPolicy,
    sample_capacity: usize,
    span_capacity: usize,
    event_capacity: usize,
    sample_chunk_capacity: usize,
    max_unwind_depth: usize,
}

impl ResolvedBenchWindowConfig {
    fn from_window_config(cfg: &BenchWindowConfig) -> Self {
        let fallback_capacity = if cfg.sample_reserve == 0 {
            DEFAULT_SAMPLE_CAPACITY
        } else {
            cfg.sample_reserve
        };

        let sample_capacity = cfg.sample_capacity.unwrap_or(fallback_capacity).max(1);
        let span_capacity = if cfg.log_spans { cfg.span_reserve } else { 0 };
        let event_capacity = sample_capacity.saturating_add(span_capacity).max(1);

        Self {
            overflow_policy: cfg.overflow_policy.unwrap_or_default(),
            sample_capacity,
            span_capacity,
            event_capacity,
            sample_chunk_capacity: cfg
                .sample_chunk_capacity
                .unwrap_or(DEFAULT_SAMPLE_CHUNK_CAPACITY)
                .max(1),
            max_unwind_depth: cfg
                .max_unwind_depth
                .unwrap_or(MAX_CALLCHAIN_DEPTH)
                .clamp(1, MAX_CALLCHAIN_DEPTH),
        }
    }
}

// ===== Global event stream =====

#[derive(Clone, Copy, Debug)]
struct BenchSampleEvent {
    rip: u64,
    task_id: u64,
    unwind_status: u32,
    depth: u8,
    stack_low: u64,
    stack_high: u64,
    frames: [u64; MAX_CALLCHAIN_DEPTH],
    frame_kinds: [u32; MAX_CALLCHAIN_DEPTH],
}

#[derive(Clone, Copy, Debug)]
struct BenchSpanEvent {
    span_id: u32,
    tag: &'static str,
    object_id: u64,
}

#[derive(Clone, Copy, Debug)]
struct BenchMetricsEvent {
    used_bytes: u64,
    total_bytes: u64,
    heap_used_bytes: u64,
    heap_total_bytes: u64,
    core_sched_ns: u64,
    core_switches: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BenchEventKind {
    None,
    Sample,
    SpanBegin,
    SpanEnd,
    Metrics,
}

#[derive(Clone, Copy, Debug, Default)]
enum BenchEventData {
    #[default]
    None,
    Sample(BenchSampleEvent),
    Span(BenchSpanEvent),
    Metrics(BenchMetricsEvent),
}

#[derive(Clone, Copy, Debug)]
struct BenchEvent {
    seq: u64,
    timestamp_ns: u64,
    core_id: u16,
    kind: BenchEventKind,
    data: BenchEventData,
}

impl Default for BenchEvent {
    fn default() -> Self {
        BenchEvent {
            seq: 0,
            timestamp_ns: 0,
            core_id: 0,
            kind: BenchEventKind::None,
            data: BenchEventData::None,
        }
    }
}

impl BenchEvent {
    fn is_empty(&self) -> bool {
        self.kind == BenchEventKind::None
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BenchPushOutcome {
    Stored,
    StoredNearFull,
    DroppedFull,
    OverwroteOldest,
}

struct BenchRing {
    next_seq: u64,
    buffer: Vec<BenchEvent>,
    write_idx: usize,
    wrapped: bool,
}

impl BenchRing {
    fn new(initial_capacity: usize) -> Self {
        BenchRing {
            next_seq: 1,
            buffer: Vec::with_capacity(initial_capacity),
            write_idx: 0,
            wrapped: false,
        }
    }

    fn reset_for_start(&mut self, capacity: usize) {
        self.next_seq = 1;
        self.write_idx = 0;
        self.wrapped = false;

        if self.buffer.capacity() != capacity {
            self.buffer = Vec::with_capacity(capacity);
        } else {
            self.buffer.clear();
        }
    }

    fn near_full(&self) -> bool {
        let capacity = self.buffer.capacity();
        capacity != 0 && self.buffer.len().saturating_mul(8) >= capacity.saturating_mul(7)
    }

    fn push_event(
        &mut self,
        mut event: BenchEvent,
        policy: BenchOverflowPolicy,
    ) -> BenchPushOutcome {
        let capacity = self.buffer.capacity();
        if capacity == 0 {
            return BenchPushOutcome::DroppedFull;
        }

        if self.buffer.len() < capacity {
            event.seq = self.next_seq;
            self.next_seq = self.next_seq.wrapping_add(1);
            self.buffer.push(event);
            return if self.near_full() {
                BenchPushOutcome::StoredNearFull
            } else {
                BenchPushOutcome::Stored
            };
        }

        match policy {
            BenchOverflowPolicy::OverwriteOldest => {
                event.seq = self.next_seq;
                self.next_seq = self.next_seq.wrapping_add(1);
                self.buffer[self.write_idx] = event;
                self.write_idx = (self.write_idx + 1) % capacity;
                self.wrapped = true;
                BenchPushOutcome::OverwroteOldest
            }
            BenchOverflowPolicy::Panic
            | BenchOverflowPolicy::DropAndCount
            | BenchOverflowPolicy::StopSampling
            | BenchOverflowPolicy::QueueDrainWorker
            | BenchOverflowPolicy::PauseFlushCompactTime
            | BenchOverflowPolicy::PauseFlushWallTime => BenchPushOutcome::DroppedFull,
        }
    }

    fn log(&mut self, event: BenchEvent) -> BenchPushOutcome {
        self.push_event(event, BenchOverflowPolicy::DropAndCount)
    }

    fn log_sample(
        &mut self,
        rip: u64,
        task_id: u64,
        mut callchain: CapturedCallchain,
        ts: u64,
        core_id: u16,
        max_unwind_depth: usize,
        overflow_policy: BenchOverflowPolicy,
    ) -> BenchPushOutcome {
        if callchain.depth as usize > max_unwind_depth {
            callchain.depth = max_unwind_depth as u8;
            callchain.status |= kernel_types::benchmark::BENCH_UNWIND_STATUS_TRUNCATED;
        }
        let event = BenchEvent {
            seq: 0,
            timestamp_ns: ts,
            core_id,
            kind: BenchEventKind::Sample,
            data: BenchEventData::Sample(BenchSampleEvent {
                rip,
                task_id,
                unwind_status: callchain.status,
                depth: callchain.depth,
                stack_low: callchain.stack_low,
                stack_high: callchain.stack_high,
                frames: callchain.frames,
                frame_kinds: callchain.frame_kinds,
            }),
        };
        self.push_event(event, overflow_policy)
    }

    fn drain_events(&mut self) -> Vec<BenchEvent> {
        let len = self.buffer.len();
        if len == 0 {
            return Vec::new();
        }

        let mut out = Vec::with_capacity(len);
        if self.wrapped && self.write_idx < len {
            out.extend_from_slice(&self.buffer[self.write_idx..]);
            out.extend_from_slice(&self.buffer[..self.write_idx]);
            self.buffer.clear();
        } else {
            out.append(&mut self.buffer);
        }
        self.write_idx = 0;
        self.wrapped = false;
        out
    }
}

struct BenchSampleDropCounters {
    ring_full: AtomicU64,
    ring_lock_busy: AtomicU64,
    bad_context: AtomicU64,
    unwind_failures: AtomicU64,
    samples_dropped: AtomicU64,
    samples_overwritten: AtomicU64,
    sampling_stopped: AtomicU64,
    flush_count: AtomicU64,
    pause_flush_ns: AtomicU64,
}

impl BenchSampleDropCounters {
    fn new() -> Self {
        Self {
            ring_full: AtomicU64::new(0),
            ring_lock_busy: AtomicU64::new(0),
            bad_context: AtomicU64::new(0),
            unwind_failures: AtomicU64::new(0),
            samples_dropped: AtomicU64::new(0),
            samples_overwritten: AtomicU64::new(0),
            sampling_stopped: AtomicU64::new(0),
            flush_count: AtomicU64::new(0),
            pause_flush_ns: AtomicU64::new(0),
        }
    }

    fn snapshot(&self, core_id: usize) -> BenchDroppedSampleCounterProto {
        BenchDroppedSampleCounterProto {
            core_id: core_id as u32,
            ring_full: self.ring_full.load(Ordering::Relaxed),
            ring_lock_busy: self.ring_lock_busy.load(Ordering::Relaxed),
            bad_context: self.bad_context.load(Ordering::Relaxed),
            unwind_failures: self.unwind_failures.load(Ordering::Relaxed),
            samples_dropped: self.samples_dropped.load(Ordering::Relaxed),
            samples_overwritten: self.samples_overwritten.load(Ordering::Relaxed),
            sampling_stopped: self.sampling_stopped.load(Ordering::Relaxed),
            flush_count: self.flush_count.load(Ordering::Relaxed),
            pause_flush_ns: self.pause_flush_ns.load(Ordering::Relaxed),
        }
    }

    fn reset(&self) {
        self.ring_full.store(0, Ordering::Relaxed);
        self.ring_lock_busy.store(0, Ordering::Relaxed);
        self.bad_context.store(0, Ordering::Relaxed);
        self.unwind_failures.store(0, Ordering::Relaxed);
        self.samples_dropped.store(0, Ordering::Relaxed);
        self.samples_overwritten.store(0, Ordering::Relaxed);
        self.sampling_stopped.store(0, Ordering::Relaxed);
        self.flush_count.store(0, Ordering::Relaxed);
        self.pause_flush_ns.store(0, Ordering::Relaxed);
    }
}

struct BenchState {
    rings: Vec<Mutex<BenchRing>>,
    drained_events: Vec<Mutex<Vec<BenchEvent>>>,
    sample_drops: Vec<BenchSampleDropCounters>,
    next_span_id: AtomicU32,
}

impl BenchState {
    fn new() -> Self {
        let cores = unsafe { TIMER_TIME_SCHED.iter() }.count().max(1);
        let mut rings = Vec::with_capacity(cores);
        let mut drained_events = Vec::with_capacity(cores);
        let mut sample_drops = Vec::with_capacity(cores);
        for _ in 0..cores {
            rings.push(Mutex::new(BenchRing::new(DEFAULT_SAMPLE_CAPACITY)));
            drained_events.push(Mutex::new(Vec::with_capacity(DEFAULT_SAMPLE_CAPACITY)));
            sample_drops.push(BenchSampleDropCounters::new());
        }
        BenchState {
            rings,
            drained_events,
            sample_drops,
            next_span_id: AtomicU32::new(1),
        }
    }

    fn ring_for_core(&self, core: usize) -> Option<&Mutex<BenchRing>> {
        self.rings.get(core)
    }

    fn drops_for_core(&self, core: usize) -> Option<&BenchSampleDropCounters> {
        self.sample_drops.get(core)
    }

    fn alloc_span_id(&self) -> u32 {
        self.next_span_id.fetch_add(1, Ordering::Relaxed)
    }

    fn ncores(&self) -> usize {
        self.rings.len().max(1)
    }

    fn reset_sample_drop_counters(&self) {
        for drops in &self.sample_drops {
            drops.reset();
        }
    }

    fn prepare_for_start(&self, capacity: usize) {
        for core in 0..self.rings.len() {
            if let Some(ring) = self.rings.get(core) {
                ring.lock().reset_for_start(capacity);
            }
            if let Some(drained) = self.drained_events.get(core) {
                let mut drained = drained.lock();
                if drained.capacity() < capacity {
                    *drained = Vec::with_capacity(capacity);
                } else {
                    drained.clear();
                }
            }
        }
        self.reset_sample_drop_counters();
        self.next_span_id.store(1, Ordering::Relaxed);
    }

    fn drain_core_to_spill(&self, core: usize) {
        let Some(ring) = self.rings.get(core) else {
            return;
        };
        let Some(spill) = self.drained_events.get(core) else {
            return;
        };

        let mut events = ring.lock().drain_events();
        if events.is_empty() {
            return;
        }

        let mut spill = spill.lock();
        spill.append(&mut events);
        if let Some(drops) = self.drops_for_core(core) {
            drops.flush_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn drain_all_to_spill(&self) {
        for core in 0..self.rings.len() {
            self.drain_core_to_spill(core);
        }
    }

    fn drain_core_events(&self, core: usize) -> Vec<BenchEvent> {
        let mut out = if let Some(spill) = self.drained_events.get(core) {
            let mut spill = spill.lock();
            let capacity = spill.capacity();
            core::mem::replace(&mut *spill, Vec::with_capacity(capacity))
        } else {
            Vec::new()
        };

        if let Some(ring) = self.rings.get(core) {
            let mut active = ring.lock().drain_events();
            if !active.is_empty() {
                out.append(&mut active);
            }
        }

        out
    }
}

static BENCH_STATE: Once<BenchState> = Once::new();
static BENCH_READY: AtomicBool = AtomicBool::new(false);

static SAMPLE_REFCOUNT: AtomicU32 = AtomicU32::new(0);
static SPAN_REFCOUNT: AtomicU32 = AtomicU32::new(0);
static METRICS_REFCOUNT: AtomicU32 = AtomicU32::new(0);
static ACTIVE_OVERFLOW_POLICY: AtomicU32 = AtomicU32::new(BenchOverflowPolicy::DropAndCount as u32);
static ACTIVE_MAX_UNWIND_DEPTH: AtomicUsize = AtomicUsize::new(MAX_CALLCHAIN_DEPTH);
static ACTIVE_DRAIN_PENDING: AtomicBool = AtomicBool::new(false);
static ACTIVE_PAUSE_PENDING: AtomicBool = AtomicBool::new(false);
static ACTIVE_PAUSE_POLICY: AtomicU32 =
    AtomicU32::new(BenchOverflowPolicy::PauseFlushWallTime as u32);
static ACTIVE_SAMPLING_STOPPED: AtomicBool = AtomicBool::new(false);
static ACTIVE_PERTURBED_BY_WORKER: AtomicBool = AtomicBool::new(false);
static ACTIVE_OVERFLOW_WORKER_RUNNING: AtomicBool = AtomicBool::new(false);

fn bench_policy_from_raw(raw: u32) -> BenchOverflowPolicy {
    match raw {
        0 => BenchOverflowPolicy::Panic,
        1 => BenchOverflowPolicy::DropAndCount,
        2 => BenchOverflowPolicy::StopSampling,
        3 => BenchOverflowPolicy::QueueDrainWorker,
        4 => BenchOverflowPolicy::PauseFlushCompactTime,
        5 => BenchOverflowPolicy::PauseFlushWallTime,
        6 => BenchOverflowPolicy::OverwriteOldest,
        _ => BenchOverflowPolicy::DropAndCount,
    }
}

fn bench_overflow_policy_name(policy: BenchOverflowPolicy) -> &'static str {
    match policy {
        BenchOverflowPolicy::Panic => "panic",
        BenchOverflowPolicy::DropAndCount => "drop_and_count",
        BenchOverflowPolicy::StopSampling => "stop_sampling",
        BenchOverflowPolicy::QueueDrainWorker => "queue_drain_worker",
        BenchOverflowPolicy::PauseFlushCompactTime => "pause_flush_compact_time",
        BenchOverflowPolicy::PauseFlushWallTime => "pause_flush_wall_time",
        BenchOverflowPolicy::OverwriteOldest => "overwrite_oldest",
    }
}

fn active_overflow_policy() -> BenchOverflowPolicy {
    bench_policy_from_raw(ACTIVE_OVERFLOW_POLICY.load(Ordering::Relaxed))
}

fn activate_bench_sampling_config(cfg: ResolvedBenchWindowConfig) {
    ACTIVE_OVERFLOW_POLICY.store(cfg.overflow_policy as u32, Ordering::Release);
    ACTIVE_MAX_UNWIND_DEPTH.store(cfg.max_unwind_depth, Ordering::Release);
    ACTIVE_DRAIN_PENDING.store(false, Ordering::Release);
    ACTIVE_PAUSE_PENDING.store(false, Ordering::Release);
    ACTIVE_SAMPLING_STOPPED.store(false, Ordering::Release);
    ACTIVE_PERTURBED_BY_WORKER.store(false, Ordering::Release);
}

fn bench_state() -> Option<&'static BenchState> {
    if !BENCH_ENABLED {
        return None;
    }
    let s = BENCH_STATE.call_once(BenchState::new);
    BENCH_READY.store(true, Ordering::Release);
    Some(s)
}

#[inline]
fn bench_state_get() -> Option<&'static BenchState> {
    if !BENCH_ENABLED {
        return None;
    }
    if !BENCH_READY.load(Ordering::Acquire) {
        return None;
    }
    BENCH_STATE.get()
}
fn bench_ncores() -> usize {
    bench_state().map(|s| s.ncores()).unwrap_or(1)
}

fn bench_now_ns() -> u64 {
    TOTAL_TIME.wait().elapsed_nanos()
}

fn bench_log_event_for_core(core_id: usize, event: BenchEvent) {
    if let Some(state) = bench_state() {
        if let Some(ring) = state.ring_for_core(core_id) {
            let mut r = ring.lock();
            r.log(event);
        }
    }
}

fn bench_metrics_enabled() -> bool {
    METRICS_REFCOUNT.load(Ordering::Relaxed) != 0
}

fn bench_samples_enabled() -> bool {
    SAMPLE_REFCOUNT.load(Ordering::Relaxed) != 0 && !ACTIVE_SAMPLING_STOPPED.load(Ordering::Acquire)
}

fn bench_spans_enabled() -> bool {
    SPAN_REFCOUNT.load(Ordering::Relaxed) != 0
}

fn bench_capture_metrics(core_id: usize, ts: u64) {
    if !BENCH_ENABLED || !bench_metrics_enabled() {
        return;
    }

    let heap_used = interrupts::without_interrupts(used_memory) as u64;

    let mut used_bytes = USED_MEMORY.load(Ordering::SeqCst) as u64;
    used_bytes = used_bytes.saturating_add(boot_info().kernel_len as u64);
    let total_bytes = total_usable_bytes();

    let heap_total_bytes = HEAP_SIZE;

    let core_sched_ns = unsafe { TIMER_TIME_SCHED.iter() }
        .nth(core_id)
        .map(|a| a.load(Ordering::SeqCst) as u64)
        .unwrap_or(0);

    let core_switches = unsafe { PER_CORE_SWITCHES.iter() }
        .nth(core_id)
        .map(|a| a.load(Ordering::SeqCst) as u64)
        .unwrap_or(0);

    let event = BenchEvent {
        seq: 0,
        timestamp_ns: ts,
        core_id: core_id as u16,
        kind: BenchEventKind::Metrics,
        data: BenchEventData::Metrics(BenchMetricsEvent {
            used_bytes,
            total_bytes,
            heap_used_bytes: heap_used,
            heap_total_bytes,
            core_sched_ns,
            core_switches,
        }),
    };

    bench_log_event_for_core(core_id, event);
}

// ===== Global submission API =====

pub fn bench_submit_rip_sample(core_id: usize, rip: u64, stack: &[u64]) {
    if !BENCH_ENABLED || !bench_samples_enabled() {
        return;
    }
    let ts = bench_now_ns();
    let callchain = callchain_from_external_stack(rip, stack);

    bench_log_sample_for_core(core_id, rip, 0, callchain, ts);
    bench_capture_metrics(core_id, ts);
}

fn callchain_from_external_stack(rip: u64, stack: &[u64]) -> CapturedCallchain {
    let mut out = CapturedCallchain::default();
    let max_depth = ACTIVE_MAX_UNWIND_DEPTH
        .load(Ordering::Relaxed)
        .clamp(1, MAX_CALLCHAIN_DEPTH);
    if stack.is_empty() {
        out.frames[0] = rip;
        out.depth = 1;
        return out;
    }

    let limit = core::cmp::min(stack.len(), max_depth);
    let mut i = 0usize;
    while i < limit {
        out.frames[i] = stack[i];
        i += 1;
    }
    out.depth = limit as u8;
    if stack.len() > max_depth {
        out.status |= kernel_types::benchmark::BENCH_UNWIND_STATUS_TRUNCATED;
    }
    out
}

#[inline]
fn bench_request_drain_worker() {
    ACTIVE_PERTURBED_BY_WORKER.store(true, Ordering::Release);
    let _ = ACTIVE_DRAIN_PENDING.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire);
}

#[inline]
fn bench_request_pause_flush(policy: BenchOverflowPolicy) {
    ACTIVE_PERTURBED_BY_WORKER.store(true, Ordering::Release);
    ACTIVE_PAUSE_POLICY.store(policy as u32, Ordering::Release);
    ACTIVE_SAMPLING_STOPPED.store(true, Ordering::Release);
    let _ = ACTIVE_PAUSE_PENDING.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire);
}

#[inline]
fn bench_note_sample_push_outcome(
    state: &BenchState,
    core_id: usize,
    outcome: BenchPushOutcome,
    policy: BenchOverflowPolicy,
) {
    let drops = state.drops_for_core(core_id);

    match outcome {
        BenchPushOutcome::Stored => {}
        BenchPushOutcome::StoredNearFull => match policy {
            BenchOverflowPolicy::QueueDrainWorker => bench_request_drain_worker(),
            BenchOverflowPolicy::Panic
            | BenchOverflowPolicy::DropAndCount
            | BenchOverflowPolicy::StopSampling
            | BenchOverflowPolicy::PauseFlushCompactTime
            | BenchOverflowPolicy::PauseFlushWallTime
            | BenchOverflowPolicy::OverwriteOldest => {}
        },
        BenchPushOutcome::OverwroteOldest => {
            if let Some(drops) = drops {
                drops.ring_full.fetch_add(1, Ordering::Relaxed);
                drops.samples_overwritten.fetch_add(1, Ordering::Relaxed);
            }
        }
        BenchPushOutcome::DroppedFull => match policy {
            BenchOverflowPolicy::Panic => {
                panic!("benchmark sample buffer full on core {}", core_id);
            }
            BenchOverflowPolicy::DropAndCount => {
                if let Some(drops) = drops {
                    drops.ring_full.fetch_add(1, Ordering::Relaxed);
                    drops.samples_dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
            BenchOverflowPolicy::StopSampling => {
                if let Some(drops) = drops {
                    drops.ring_full.fetch_add(1, Ordering::Relaxed);
                    drops.samples_dropped.fetch_add(1, Ordering::Relaxed);
                    drops.sampling_stopped.fetch_add(1, Ordering::Relaxed);
                }
                ACTIVE_SAMPLING_STOPPED.store(true, Ordering::Release);
            }
            BenchOverflowPolicy::QueueDrainWorker => {
                if let Some(drops) = drops {
                    drops.ring_full.fetch_add(1, Ordering::Relaxed);
                    drops.samples_dropped.fetch_add(1, Ordering::Relaxed);
                }
                bench_request_drain_worker();
            }
            BenchOverflowPolicy::PauseFlushCompactTime => {
                if let Some(drops) = drops {
                    drops.ring_full.fetch_add(1, Ordering::Relaxed);
                    drops.samples_dropped.fetch_add(1, Ordering::Relaxed);
                    drops.sampling_stopped.fetch_add(1, Ordering::Relaxed);
                }
                bench_request_pause_flush(BenchOverflowPolicy::PauseFlushCompactTime);
            }
            BenchOverflowPolicy::PauseFlushWallTime => {
                if let Some(drops) = drops {
                    drops.ring_full.fetch_add(1, Ordering::Relaxed);
                    drops.samples_dropped.fetch_add(1, Ordering::Relaxed);
                    drops.sampling_stopped.fetch_add(1, Ordering::Relaxed);
                }
                bench_request_pause_flush(BenchOverflowPolicy::PauseFlushWallTime);
            }
            BenchOverflowPolicy::OverwriteOldest => {
                if let Some(drops) = drops {
                    drops.ring_full.fetch_add(1, Ordering::Relaxed);
                    drops.samples_dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
        },
    }
}

#[inline]
fn bench_log_event_for_core_try(core_id: usize, event: BenchEvent) {
    let Some(state) = bench_state_get() else {
        return;
    };
    let Some(ring) = state.ring_for_core(core_id) else {
        return;
    };

    let Some(mut g) = ring.try_lock() else {
        return;
    };
    let _ = g.log(event);
}

#[inline]
fn bench_log_sample_for_core(
    core_id: usize,
    rip: u64,
    task_id: u64,
    callchain: CapturedCallchain,
    ts: u64,
) {
    let Some(state) = bench_state() else {
        return;
    };
    let Some(ring) = state.ring_for_core(core_id) else {
        return;
    };

    let policy = active_overflow_policy();
    let max_unwind_depth = ACTIVE_MAX_UNWIND_DEPTH.load(Ordering::Relaxed);
    let mut g = ring.lock();
    let outcome = g.log_sample(
        rip,
        task_id,
        callchain,
        ts,
        core_id as u16,
        max_unwind_depth,
        policy,
    );
    bench_note_sample_push_outcome(state, core_id, outcome, policy);
}

#[inline]
fn bench_log_sample_for_core_try(
    core_id: usize,
    rip: u64,
    task_id: u64,
    callchain: CapturedCallchain,
    ts: u64,
) {
    let Some(state) = bench_state_get() else {
        return;
    };
    let Some(ring) = state.ring_for_core(core_id) else {
        return;
    };

    let Some(mut g) = ring.try_lock() else {
        if let Some(drops) = state.drops_for_core(core_id) {
            drops.ring_lock_busy.fetch_add(1, Ordering::Relaxed);
            drops.samples_dropped.fetch_add(1, Ordering::Relaxed);
        }
        return;
    };
    let policy = active_overflow_policy();
    let max_unwind_depth = ACTIVE_MAX_UNWIND_DEPTH.load(Ordering::Relaxed);
    let outcome = g.log_sample(
        rip,
        task_id,
        callchain,
        ts,
        core_id as u16,
        max_unwind_depth,
        policy,
    );
    bench_note_sample_push_outcome(state, core_id, outcome, policy);
}

#[inline]
fn bench_capture_metrics_try(core_id: usize, ts: u64) {
    if !BENCH_ENABLED || !bench_metrics_enabled() {
        return;
    }

    let heap_used = interrupts::without_interrupts(used_memory) as u64;

    let mut used_bytes = USED_MEMORY.load(Ordering::SeqCst) as u64;
    used_bytes = used_bytes.saturating_add(boot_info().kernel_len as u64);
    let total_bytes = total_usable_bytes();

    let heap_total_bytes = HEAP_SIZE;

    let core_sched_ns = unsafe { TIMER_TIME_SCHED.iter() }
        .nth(core_id)
        .map(|a| a.load(Ordering::SeqCst) as u64)
        .unwrap_or(0);

    let core_switches = unsafe { PER_CORE_SWITCHES.iter() }
        .nth(core_id)
        .map(|a| a.load(Ordering::SeqCst) as u64)
        .unwrap_or(0);

    let event = BenchEvent {
        seq: 0,
        timestamp_ns: ts,
        core_id: core_id as u16,
        kind: BenchEventKind::Metrics,
        data: BenchEventData::Metrics(BenchMetricsEvent {
            used_bytes,
            total_bytes,
            heap_used_bytes: heap_used,
            heap_total_bytes,
            core_sched_ns,
            core_switches,
        }),
    };

    bench_log_event_for_core_try(core_id, event);
}

pub fn bench_submit_rip_sample_current_core(rip: u64) {
    if !BENCH_ENABLED || !bench_samples_enabled() {
        return;
    }
    if !BENCH_READY.load(Ordering::Acquire) {
        return;
    }

    let core_id = interrupt_index::current_cpu_id();
    let ts = bench_now_ns();
    let callchain = callchain_from_external_stack(rip, &[]);

    bench_log_sample_for_core_try(core_id, rip, 0, callchain, ts);
    bench_capture_metrics_try(core_id, ts);
}

pub fn bench_submit_interrupt_sample_current_core(state: &State) {
    if !BENCH_ENABLED || !bench_samples_enabled() {
        return;
    }
    if !BENCH_READY.load(Ordering::Acquire) {
        return;
    }

    let core_id = interrupt_index::current_cpu_id();
    let task = SCHEDULER.get_current_task(core_id);
    if task.is_none() {
        if let Some(state) = bench_state_get() {
            if let Some(drops) = state.drops_for_core(core_id) {
                drops.bad_context.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    let task_id = task.as_ref().map(|t| t.task_id()).unwrap_or(0);
    let max_unwind_depth = ACTIVE_MAX_UNWIND_DEPTH.load(Ordering::Relaxed);
    let callchain = capture_callchain_from_state_limited(state, task.as_deref(), max_unwind_depth);
    if callchain.status
        & (kernel_types::benchmark::BENCH_UNWIND_STATUS_BAD_STACK_READ
            | kernel_types::benchmark::BENCH_UNWIND_STATUS_BAD_UNWIND_INFO
            | kernel_types::benchmark::BENCH_UNWIND_STATUS_UNSUPPORTED_OPCODE)
        != 0
    {
        if let Some(state) = bench_state_get() {
            if let Some(drops) = state.drops_for_core(core_id) {
                drops.unwind_failures.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    let rip = state.rip;
    let ts = bench_now_ns();

    bench_log_sample_for_core_try(core_id, rip, task_id, callchain, ts);
    bench_capture_metrics_try(core_id, ts);
}

// ===== Spans =====

fn bench_alloc_span_id() -> Option<u32> {
    bench_state().map(|s| s.alloc_span_id())
}

fn bench_log_span_begin(span_id: u32, tag: &'static str, object_id: u64) {
    if !BENCH_ENABLED || !bench_spans_enabled() {
        return;
    }

    let core_id = interrupt_index::current_cpu_id();
    let ts = bench_now_ns();

    let event = BenchEvent {
        seq: 0,
        timestamp_ns: ts,
        core_id: core_id as u16,
        kind: BenchEventKind::SpanBegin,
        data: BenchEventData::Span(BenchSpanEvent {
            span_id,
            tag,
            object_id,
        }),
    };

    bench_log_event_for_core(core_id, event);
    bench_capture_metrics(core_id, ts);
}

pub fn bench_log_span_end(span_id: u32, tag: &'static str, object_id: u64) {
    if !BENCH_ENABLED || !bench_spans_enabled() {
        return;
    }

    let core_id = interrupt_index::current_cpu_id();
    let ts = bench_now_ns();

    let event = BenchEvent {
        seq: 0,
        timestamp_ns: ts,
        core_id: core_id as u16,
        kind: BenchEventKind::SpanEnd,
        data: BenchEventData::Span(BenchSpanEvent {
            span_id,
            tag,
            object_id,
        }),
    };

    bench_log_event_for_core(core_id, event);
    bench_capture_metrics(core_id, ts);
}
#[repr(C)]
#[derive(Debug)]
pub struct BenchSpanGuard {
    span_id: u32,
    tag: &'static str,
    object_id: u64,
    enabled: bool,
}

impl BenchSpanGuard {
    pub fn new(tag: &'static str, object_id: u64) -> Self {
        if !BENCH_ENABLED || !bench_spans_enabled() {
            return BenchSpanGuard {
                span_id: 0,
                tag,
                object_id,
                enabled: false,
            };
        }
        if let Some(span_id) = bench_alloc_span_id() {
            bench_log_span_begin(span_id, tag, object_id);
            BenchSpanGuard {
                span_id,
                tag,
                object_id,
                enabled: true,
            }
        } else {
            BenchSpanGuard {
                span_id: 0,
                tag,
                object_id,
                enabled: false,
            }
        }
    }
}

impl Drop for BenchSpanGuard {
    fn drop(&mut self) {
        if self.enabled {
            bench_log_span_end(self.span_id, self.tag, self.object_id);
        }
    }
}

pub fn bench_span_guard(tag: &'static str, object_id: u64) -> BenchSpanGuard {
    BenchSpanGuard::new(tag, object_id)
}

// ===== Sessions + window dirs =====

#[derive(Clone)]
struct BenchSessionInfo {
    archive_path: String,
    archive: Arc<BenchArchive>,
    ncores: usize,
}

static SESSION_REGISTRY: Once<Mutex<BTreeMap<String, BenchSessionInfo>>> = Once::new();
static WINDOW_DIR_REGISTRY: Once<Mutex<BTreeMap<String, u32>>> = Once::new();

fn session_registry() -> &'static Mutex<BTreeMap<String, BenchSessionInfo>> {
    SESSION_REGISTRY.call_once(|| Mutex::new(BTreeMap::new()))
}

fn window_dir_registry() -> &'static Mutex<BTreeMap<String, u32>> {
    WINDOW_DIR_REGISTRY.call_once(|| Mutex::new(BTreeMap::new()))
}

fn join_path2(a: &str, b: &str) -> String {
    if a.ends_with('\\') || a.ends_with('/') {
        format!("{a}{b}")
    } else {
        format!("{a}\\{b}")
    }
}

fn basename(mut s: &str) -> &str {
    loop {
        match s.rfind(['\\', '/']) {
            Some(i) => s = &s[i + 1..],
            None => break,
        }
    }
    while s.ends_with('\\') || s.ends_with('/') {
        s = &s[..s.len() - 1];
    }
    s
}

fn parse_session_suffix(entry: &str) -> Option<u32> {
    let name = basename(entry);
    if !name.starts_with("session_") {
        return None;
    }
    let suffix = name[8..]
        .strip_suffix(BENCH_ARCHIVE_EXTENSION)
        .unwrap_or(&name[8..]);
    suffix.parse::<u32>().ok()
}

async fn ensure_session_async(root: &str) -> BenchSessionInfo {
    {
        let reg = session_registry().lock();
        if let Some(info) = reg.get(root) {
            return info.clone();
        }
    }

    let root_path = Path::from_string(root);
    let _ = File::make_dir(&root_path).await;

    let entries = File::list_dir(&root_path)
        .await
        .unwrap_or_else(|_| Vec::new());
    let mut max_id: u32 = 0;
    for e in entries {
        if let Some(id) = parse_session_suffix(&e) {
            if id > max_id {
                max_id = id;
            }
        }
    }

    let new_id = max_id.saturating_add(1);
    let archive_path = join_path2(root, &format!("session_{new_id}{BENCH_ARCHIVE_EXTENSION}"));
    let archive = Arc::new(bench_archive_for_path(archive_path.clone()));

    let ncores = bench_ncores();

    let info = BenchSessionInfo {
        archive_path,
        archive,
        ncores,
    };

    let mut reg = session_registry().lock();
    reg.insert(root.to_string(), info.clone());
    info
}

async fn compute_next_window_suffix_async(session_dir: &str, name: &str) -> u32 {
    let _ = session_dir;
    let _ = name;
    0
}
async fn allocate_window_name_async(session_dir: &str, name: &str) -> String {
    let mut key = String::new();
    key.push_str(session_dir);
    key.push('|');
    key.push_str(name);

    let suffix_opt = {
        let reg = window_dir_registry().lock();
        reg.get(&key).copied()
    };

    let mut suffix = match suffix_opt {
        Some(v) => v,
        None => compute_next_window_suffix_async(session_dir, name).await,
    };

    {
        let mut reg = window_dir_registry().lock();
        if let Some(registered_suffix) = reg.get(&key).copied() {
            suffix = registered_suffix;
        }
        reg.insert(key, suffix.saturating_add(1));
    }

    let window_dir = if suffix == 0 {
        name.to_string()
    } else {
        format!("{name}-{suffix}")
    };

    window_dir
}
fn window_path_for_target(
    session_dir: &str,
    window_dir: &str,
    target: usize,
    ncores: usize,
) -> String {
    let window_root = join_path2(session_dir, window_dir);
    if target == ncores {
        join_path2(&window_root, "avg")
    } else {
        join_path2(&window_root, "core")
    }
}

fn window_file_name_for_target(run_id: u32, stream: &str, target: usize, ncores: usize) -> String {
    if target == ncores {
        format!("run_{run_id}_{stream}.csv")
    } else {
        format!("core-{target}_run_{run_id}_{stream}.csv")
    }
}

fn archive_component(s: &str) -> String {
    let mut out = String::new();
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push('_');
    }
    out
}

fn archive_target_component(target: usize, ncores: usize) -> String {
    if target == ncores {
        "avg".to_string()
    } else {
        format!("core/{target:03}")
    }
}

fn archive_stream_entry_path(
    window_dir: &str,
    run_id: u32,
    persist_id: u64,
    chunk_idx: usize,
    target: usize,
    ncores: usize,
    stream: &str,
) -> String {
    format!(
        "windows/{}/runs/run_{:06}/persists/persist_{:06}/chunks/chunk_{:06}/{}/{}.csv",
        archive_component(window_dir),
        run_id,
        persist_id,
        chunk_idx,
        archive_target_component(target, ncores),
        stream
    )
}

fn archive_stream_file_entry_path(
    window_dir: &str,
    run_id: u32,
    persist_id: u64,
    chunk_idx: usize,
    target: usize,
    ncores: usize,
    file_name: &str,
) -> String {
    format!(
        "windows/{}/runs/run_{:06}/persists/persist_{:06}/chunks/chunk_{:06}/{}/{}",
        archive_component(window_dir),
        run_id,
        persist_id,
        chunk_idx,
        archive_target_component(target, ncores),
        file_name
    )
}

fn archive_manifest_entry_path(
    window_dir: &str,
    run_id: u32,
    persist_id: u64,
    name: &str,
) -> String {
    format!(
        "windows/{}/runs/run_{:06}/persists/persist_{:06}/{}",
        archive_component(window_dir),
        run_id,
        persist_id,
        name
    )
}

fn push_csv_archive_record(
    records: &mut Vec<BenchArchiveRecord>,
    path: String,
    mut csv: String,
    rows: String,
    timestamp_ns: u64,
) {
    if rows.is_empty() {
        return;
    }

    csv.push_str(&rows);
    records.push(BenchArchiveRecord::data(
        path,
        csv.into_bytes(),
        timestamp_ns,
    ));
}

fn encode_sample_chunk_proto(
    run_id: u32,
    chunk_idx: usize,
    target: usize,
    ncores: usize,
    start_ns: u64,
    to_ns: u64,
    frame_limit: usize,
    max_seq_by_core: &[u64],
    sample_drops: &[BenchDroppedSampleCounterProto],
    samples: Vec<BenchSampleProto>,
) -> Option<Vec<u8>> {
    if samples.is_empty() {
        return None;
    }

    let chunk = BenchSampleChunkProto {
        schema_version: BENCH_SAMPLE_PROTO_SCHEMA_VERSION,
        run_id,
        chunk_index: chunk_idx as u32,
        target_core_id: if target == ncores {
            u32::MAX
        } else {
            target as u32
        },
        aggregate: target == ncores,
        start_ns,
        end_ns: to_ns,
        frame_limit: frame_limit as u32,
        samples,
        dropped: sample_drops.to_vec(),
        max_seq_by_core: max_seq_by_core.to_vec(),
    };

    let mut bytes = Vec::with_capacity(chunk.encoded_len());
    chunk.encode(&mut bytes).ok()?;
    Some(bytes)
}

// ===== Export build (cursor-based; persist "clears" by advancing last_export_seq) =====

struct ExportBundle {
    samples: Vec<Vec<BenchSampleProto>>,
    spans_rows: Vec<String>,
    mem_rows: Vec<String>,  // includes heap+mem+sched counters per event
    max_seq_seen: Vec<u64>, // per core
    sample_drops: Vec<BenchDroppedSampleCounterProto>,
}

#[derive(Clone, Copy)]
struct SpanRowRec {
    tag: &'static str,
    object_id: u64,
    start_core: u16,
    start_ts: u64,
    dur: u64,
}

#[derive(Clone, Copy, Debug)]
struct BenchPauseInterval {
    pause_start_ns: u64,
    pause_end_ns: u64,
    duration_ns: u64,
    policy: BenchOverflowPolicy,
    logical_time_shifted: bool,
    reason: &'static str,
}

fn make_empty_bundle(ncores: usize) -> ExportBundle {
    let mut samples = Vec::with_capacity(ncores + 1);
    let mut spans_rows = Vec::with_capacity(ncores + 1);
    let mut mem_rows = Vec::with_capacity(ncores + 1);

    for _ in 0..(ncores + 1) {
        samples.push(Vec::new());
        spans_rows.push(String::new());
        mem_rows.push(String::new());
    }

    ExportBundle {
        samples,
        spans_rows,
        mem_rows,
        max_seq_seen: vec![0u64; ncores],
        sample_drops: Vec::new(),
    }
}

fn heap_sift_down(heap: &mut [(u64, u16, u64, usize)], mut idx: usize) {
    let len = heap.len();
    loop {
        let left = 2 * idx + 1;
        let right = 2 * idx + 2;
        let mut smallest = idx;

        if left < len && heap[left] < heap[smallest] {
            smallest = left;
        }
        if right < len && heap[right] < heap[smallest] {
            smallest = right;
        }

        if smallest == idx {
            break;
        }

        heap.swap(idx, smallest);
        idx = smallest;
    }
}

fn heap_build(heap: &mut [(u64, u16, u64, usize)]) {
    for i in (0..(heap.len() / 2)).rev() {
        heap_sift_down(heap, i);
    }
}

fn sample_proto_from_event(ev: &BenchEvent, sample: BenchSampleEvent) -> BenchSampleProto {
    let depth = core::cmp::min(sample.depth as usize, MAX_CALLCHAIN_DEPTH);
    BenchSampleProto {
        seq: ev.seq,
        timestamp_ns: ev.timestamp_ns,
        core_id: ev.core_id as u32,
        task_id: sample.task_id,
        sampled_rip: sample.rip,
        unwind_status: sample.unwind_status,
        frames: sample.frames[..depth].to_vec(),
        frame_kinds: sample.frame_kinds[..depth].to_vec(),
        stack_low: sample.stack_low,
        stack_high: sample.stack_high,
        adjusted_timestamp_ns: None,
    }
}

fn write_metrics_row(row: &mut String, run_id: u32, ts: u64, core_id: u16, m: &BenchMetricsEvent) {
    let _ = writeln!(
        row,
        "{},{},{},{},{},{},{},{},{}",
        run_id,
        ts,
        core_id,
        m.used_bytes,
        m.total_bytes,
        m.heap_used_bytes,
        m.heap_total_bytes,
        m.core_sched_ns,
        m.core_switches
    );
}

fn write_span_row(
    row: &mut String,
    run_id: u32,
    tag: &'static str,
    object_id: u64,
    start_core: u16,
    start_ts: u64,
    dur: u64,
) {
    let _ = writeln!(
        row,
        "{},{},0x{:016x},{},{},{}",
        run_id, tag, object_id, start_core, start_ts, dur
    );
}

fn pdb_format_name(format: PePdbFormat) -> &'static str {
    match format {
        PePdbFormat::Pdb70 => "RSDS",
        PePdbFormat::Pdb20 => "NB10",
    }
}

fn pdb_guid_string(guid: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        guid[3],
        guid[2],
        guid[1],
        guid[0],
        guid[5],
        guid[4],
        guid[7],
        guid[6],
        guid[8],
        guid[9],
        guid[10],
        guid[11],
        guid[12],
        guid[13],
        guid[14],
        guid[15]
    )
}

fn pdb_info_json(pdb: Option<&PePdbInfo>) -> Value {
    match pdb {
        Some(pdb) => {
            let guid = pdb.guid.map(|guid| pdb_guid_string(&guid));
            let guid_bytes = pdb.guid.map(|guid| guid.to_vec());
            json!({
                "format": pdb_format_name(pdb.format),
                "path": pdb.path.as_str(),
                "age": pdb.age,
                "guid": guid,
                "guid_bytes": guid_bytes,
                "signature": pdb.signature,
                "codeview_offset": pdb.codeview_offset,
            })
        }
        None => Value::Null,
    }
}

fn build_krnl_debug_metadata_json(run_id: u32, start_ns: u64, to_ns: u64) -> Option<String> {
    let program = PROGRAM_MANAGER.get(0)?;
    let (program_title, program_path, modules) = {
        let program = program.read();
        let modules = program.modules.read().clone();
        (
            program.title.clone(),
            program.image_path.to_string(),
            modules,
        )
    };

    let mut modules_json = Vec::with_capacity(modules.len());
    for module in modules {
        let module = module.read();
        let pdb = module
            .pe_info
            .as_ref()
            .and_then(|pe_info| pe_info.pdb.as_ref());
        let pe = module.pe_info.as_ref();

        modules_json.push(json!({
            "name": module.title.as_str(),
            "image_path": module.image_path.to_string(),
            "image_base": format!("0x{:016x}", module.image_base.as_u64()),
            "debug": pdb_info_json(pdb),
            "pe": pe.map(|pe_info| json!({
                "is_64": pe_info.is_64,
                "is_dll": pe_info.is_dll,
                "preferred_image_base": format!("0x{:016x}", pe_info.preferred_image_base),
                "loaded_image_base": format!("0x{:016x}", pe_info.loaded_image_base.as_u64()),
                "entry_rva": format!("0x{:x}", pe_info.entry_rva),
                "size_of_image": pe_info.size_of_image,
                "aslr": pe_info.aslr,
                "relocated": pe_info.relocated,
            })),
        }));
    }

    let root = json!({
        "run_id": run_id,
        "start_ns": start_ns,
        "to_ns": to_ns,
        "program": {
            "pid": 0u64,
            "name": program_title,
            "image_path": program_path,
        },
        "modules": modules_json,
    });

    serde_json::to_string_pretty(&root).ok()
}

async fn build_exports_for_window(
    cfg: &BenchWindowConfig,
    resolved_cfg: ResolvedBenchWindowConfig,
    run_id: u32,
    start_ns: u64,
    to_ns: u64,
    last_export_seq: &[u64],
    ncores: usize,
    open_spans: &mut BTreeMap<u32, (BenchSpanEvent, u64, u16)>,
) -> Vec<ExportBundle> {
    if !BENCH_ENABLED {
        return vec![make_empty_bundle(ncores)];
    }

    let state = match bench_state() {
        Some(s) => s,
        None => return vec![make_empty_bundle(ncores)],
    };

    let log_samples = cfg.log_samples;
    let log_spans = cfg.log_spans;
    let want_mem_stream = cfg.log_mem_on_persist;
    let per_core_enabled = !cfg.disable_per_core;

    struct CoreIterator {
        events: Vec<BenchEvent>,
        index: usize,
        core: usize,
    }

    impl CoreIterator {
        fn peek(&self) -> Option<&BenchEvent> {
            self.events.get(self.index)
        }

        fn pop(&mut self) -> Option<BenchEvent> {
            if self.index < self.events.len() {
                let idx = self.index;
                self.index += 1;
                Some(core::mem::take(&mut self.events[idx]))
            } else {
                None
            }
        }

        fn shrink_consumed(&mut self) {
            if self.index > 1024 && self.index > self.events.len() / 2 {
                self.events.drain(0..self.index);
                self.index = 0;
                self.events.shrink_to_fit();
            }
        }
    }

    let mut gather_joins = Vec::with_capacity(ncores);
    for core in 0..ncores {
        let st = state;
        let last_seq = *last_export_seq.get(core).unwrap_or(&0);

        gather_joins.push(crate::scheduling::runtime::runtime::spawn_blocking(
            move || -> Vec<BenchEvent> {
                let events = st.drain_core_events(core);

                let mut out = Vec::new();
                for ev in events {
                    if ev.is_empty() {
                        continue;
                    }
                    if ev.seq <= last_seq {
                        continue;
                    }

                    let ts = ev.timestamp_ns;
                    if ts < start_ns || ts > to_ns {
                        continue;
                    }

                    out.push(ev);
                }

                out.sort_unstable_by(|a, b| {
                    a.timestamp_ns
                        .cmp(&b.timestamp_ns)
                        .then(a.core_id.cmp(&b.core_id))
                        .then(a.seq.cmp(&b.seq))
                });

                out
            },
        ));
    }

    let mut iterators: Vec<CoreIterator> = Vec::with_capacity(ncores);
    let mut total_events = 0usize;

    for (core, j) in gather_joins.into_iter().enumerate() {
        let events = j.await;
        total_events += events.len();
        if !events.is_empty() {
            iterators.push(CoreIterator {
                events,
                index: 0,
                core,
            });
        }
    }

    if total_events == 0 || iterators.is_empty() {
        return vec![make_empty_bundle(ncores)];
    }

    let avg = ncores;
    let sample_drops: Vec<BenchDroppedSampleCounterProto> = if log_samples {
        (0..ncores)
            .filter_map(|core| state.drops_for_core(core).map(|d| d.snapshot(core)))
            .collect()
    } else {
        Vec::new()
    };

    let chunk_size = resolved_cfg.sample_chunk_capacity.max(1);
    let chunks = total_events.div_ceil(chunk_size).max(1);

    let mut out = Vec::with_capacity(chunks);
    for _ in 0..chunks {
        let mut bundle = make_empty_bundle(ncores);
        bundle.sample_drops = sample_drops.clone();
        out.push(bundle);
    }

    let k = iterators.len();
    let mut heap: Vec<(u64, u16, u64, usize)> = Vec::with_capacity(k);

    for (iter_idx, iter) in iterators.iter().enumerate() {
        if let Some(ev) = iter.peek() {
            heap.push((ev.timestamp_ns, ev.core_id, ev.seq, iter_idx));
        }
    }
    heap_build(&mut heap);

    let mut global_idx = 0usize;
    let shrink_interval = 2048usize;

    while !heap.is_empty() {
        let (_, _, _, iter_idx) = heap[0];

        let iter = &mut iterators[iter_idx];
        let scan_core = iter.core;
        let ev = iter.pop().unwrap();

        if global_idx.is_multiple_of(shrink_interval) {
            iter.shrink_consumed();
        }

        let chunk_idx = core::cmp::min(global_idx / chunk_size, chunks - 1);
        let bundle = &mut out[chunk_idx];

        if scan_core < ncores && ev.seq > bundle.max_seq_seen[scan_core] {
            bundle.max_seq_seen[scan_core] = ev.seq;
        }

        match ev.kind {
            BenchEventKind::Sample if log_samples => {
                if let BenchEventData::Sample(s) = ev.data {
                    let sample = sample_proto_from_event(&ev, s);
                    if per_core_enabled && scan_core < ncores {
                        bundle.samples[scan_core].push(sample.clone());
                    }
                    bundle.samples[avg].push(sample);
                }
            }
            BenchEventKind::Metrics if want_mem_stream => {
                if let BenchEventData::Metrics(m) = ev.data {
                    if per_core_enabled && scan_core < ncores {
                        write_metrics_row(
                            &mut bundle.mem_rows[scan_core],
                            run_id,
                            ev.timestamp_ns,
                            ev.core_id,
                            &m,
                        );
                    }
                    write_metrics_row(
                        &mut bundle.mem_rows[avg],
                        run_id,
                        ev.timestamp_ns,
                        ev.core_id,
                        &m,
                    );
                }
            }
            BenchEventKind::SpanBegin if log_spans => {
                if let BenchEventData::Span(span) = ev.data {
                    open_spans.insert(span.span_id, (span, ev.timestamp_ns, ev.core_id));
                }
            }
            BenchEventKind::SpanEnd if log_spans => {
                if let BenchEventData::Span(span) = ev.data {
                    if let Some((start_span, start_ts, start_core)) =
                        open_spans.remove(&span.span_id)
                    {
                        let dur = ev.timestamp_ns.saturating_sub(start_ts);

                        write_span_row(
                            &mut bundle.spans_rows[avg],
                            run_id,
                            start_span.tag,
                            start_span.object_id,
                            start_core,
                            start_ts,
                            dur,
                        );

                        let start_idx = start_core as usize;
                        if per_core_enabled && start_idx < ncores {
                            write_span_row(
                                &mut bundle.spans_rows[start_idx],
                                run_id,
                                start_span.tag,
                                start_span.object_id,
                                start_core,
                                start_ts,
                                dur,
                            );
                        }
                    }
                }
            }
            _ => {}
        }

        global_idx += 1;

        if let Some(next_ev) = iterators[iter_idx].peek() {
            heap[0] = (next_ev.timestamp_ns, next_ev.core_id, next_ev.seq, iter_idx);
            heap_sift_down(&mut heap, 0);
        } else {
            let last = heap.len() - 1;
            heap.swap(0, last);
            heap.pop();
            if !heap.is_empty() {
                heap_sift_down(&mut heap, 0);
            }

            iterators[iter_idx].events = Vec::new();
        }
    }

    iterators.clear();

    out
}

// ===== BenchWindow =====

struct BenchWindowInner {
    cfg: BenchWindowConfig,
    resolved_cfg: ResolvedBenchWindowConfig,

    session_archive_path: String,
    session_archive: Option<Arc<BenchArchive>>,
    window_dir: String,
    ncores: usize,

    running: bool,
    start_ns: u64,
    stop_ns: Option<u64>,

    run_id_counter: u32,
    current_run_id: u32,

    last_export_seq: Vec<u64>,
    sampling_truncated: bool,
    pause_flush_ns: u64,
    logical_time_compacted: bool,
    perturbed_by_worker: bool,
    pause_intervals: Vec<BenchPauseInterval>,

    spans_header_written: Vec<bool>,
    mem_header_written: Vec<bool>,

    open_spans: BTreeMap<u32, (BenchSpanEvent, u64, u16)>,
}

impl BenchWindowInner {
    fn new(
        cfg: BenchWindowConfig,
        resolved_cfg: ResolvedBenchWindowConfig,
        session_archive_path: String,
        session_archive: Option<Arc<BenchArchive>>,
        window_dir: String,
        ncores: usize,
    ) -> Self {
        BenchWindowInner {
            cfg,
            resolved_cfg,
            session_archive_path,
            session_archive,
            window_dir,
            ncores,
            running: false,
            start_ns: 0,
            stop_ns: None,
            run_id_counter: 1,
            current_run_id: 0,
            last_export_seq: vec![0; ncores],
            sampling_truncated: false,
            pause_flush_ns: 0,
            logical_time_compacted: false,
            perturbed_by_worker: false,
            pause_intervals: Vec::new(),
            spans_header_written: vec![false; ncores + 1],
            mem_header_written: vec![false; ncores + 1],
            open_spans: BTreeMap::new(),
        }
    }

    fn reset_run_state(&mut self) {
        self.last_export_seq.fill(0);
        self.sampling_truncated = false;
        self.pause_flush_ns = 0;
        self.logical_time_compacted = false;
        self.perturbed_by_worker = false;
        self.pause_intervals.clear();
        for v in &mut self.spans_header_written {
            *v = false;
        }
        for v in &mut self.mem_header_written {
            *v = false;
        }
        self.open_spans.clear();
    }
}
const INIT_UNINIT: u32 = 0;
const INIT_IN_PROGRESS: u32 = 1;
const INIT_READY: u32 = 2;
#[derive(Clone)]
pub struct BenchWindow {
    inner: Arc<Mutex<BenchWindowInner>>,
    init_state: Arc<AtomicU32>,
}

impl BenchWindow {
    pub fn new(cfg: BenchWindowConfig) -> Self {
        let resolved_cfg = ResolvedBenchWindowConfig::from_window_config(&cfg);
        if !BENCH_ENABLED {
            let inner =
                BenchWindowInner::new(cfg, resolved_cfg, String::new(), None, String::new(), 1);
            return BenchWindow {
                inner: Arc::new(Mutex::new(inner)),
                init_state: Arc::new(AtomicU32::new(INIT_READY)),
            };
        }

        if cfg.log_mem_on_persist {
            METRICS_REFCOUNT.fetch_add(1, Ordering::Relaxed);
        }

        let ncores = bench_ncores();
        let inner = BenchWindowInner::new(
            cfg,
            resolved_cfg,
            String::new(),
            None,
            String::new(),
            ncores,
        );

        BenchWindow {
            inner: Arc::new(Mutex::new(inner)),
            init_state: Arc::new(AtomicU32::new(INIT_UNINIT)),
        }
    }
    async fn ensure_fs_ready(&self) -> bool {
        if self.init_state.load(Ordering::Acquire) == INIT_READY {
            return true;
        }

        if self
            .init_state
            .compare_exchange(
                INIT_UNINIT,
                INIT_IN_PROGRESS,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return false;
        }

        let (folder, name) = {
            let inner = self.inner.lock();
            (inner.cfg.folder, inner.cfg.name)
        };

        let session = ensure_session_async(folder).await;
        let window_dir = allocate_window_name_async(&session.archive_path, name).await;

        {
            let mut inner = self.inner.lock();
            if inner.session_archive_path.is_empty() {
                inner.session_archive_path = session.archive_path;
                inner.session_archive = Some(session.archive);
                inner.window_dir = window_dir;
                inner.ncores = session.ncores;
            }
        }

        self.init_state.store(INIT_READY, Ordering::Release);
        true
    }

    fn mark_worker_perturbed(&self) {
        let mut inner = self.inner.lock();
        inner.perturbed_by_worker = true;
    }

    fn handle_pause_flush(&self, policy: BenchOverflowPolicy) {
        let logical_time_shifted = match policy {
            BenchOverflowPolicy::PauseFlushCompactTime => true,
            BenchOverflowPolicy::PauseFlushWallTime => false,
            BenchOverflowPolicy::Panic
            | BenchOverflowPolicy::DropAndCount
            | BenchOverflowPolicy::StopSampling
            | BenchOverflowPolicy::QueueDrainWorker
            | BenchOverflowPolicy::OverwriteOldest => return,
        };

        let pause_start_ns = bench_now_ns();
        if let Some(state) = bench_state_get() {
            state.drain_all_to_spill();
        }
        let pause_end_ns = bench_now_ns();
        let duration_ns = pause_end_ns.saturating_sub(pause_start_ns);

        if let Some(state) = bench_state_get() {
            for core in 0..state.ncores() {
                if let Some(drops) = state.drops_for_core(core) {
                    drops
                        .pause_flush_ns
                        .fetch_add(duration_ns, Ordering::Relaxed);
                }
            }
        }

        {
            let mut inner = self.inner.lock();
            inner.pause_flush_ns = inner.pause_flush_ns.saturating_add(duration_ns);
            inner.logical_time_compacted |= logical_time_shifted;
            inner.perturbed_by_worker = true;
            inner.pause_intervals.push(BenchPauseInterval {
                pause_start_ns,
                pause_end_ns,
                duration_ns,
                policy,
                logical_time_shifted,
                reason: "buffer_full",
            });
        }

        ACTIVE_SAMPLING_STOPPED.store(false, Ordering::Release);
    }

    fn spawn_overflow_worker_if_needed(&self, policy: BenchOverflowPolicy) {
        match policy {
            BenchOverflowPolicy::QueueDrainWorker
            | BenchOverflowPolicy::PauseFlushCompactTime
            | BenchOverflowPolicy::PauseFlushWallTime => {}
            BenchOverflowPolicy::Panic
            | BenchOverflowPolicy::DropAndCount
            | BenchOverflowPolicy::StopSampling
            | BenchOverflowPolicy::OverwriteOldest => return,
        }

        if ACTIVE_OVERFLOW_WORKER_RUNNING
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }

        let this = self.clone();
        spawn_blocking(move || {
            loop {
                if ACTIVE_DRAIN_PENDING.swap(false, Ordering::AcqRel) {
                    if let Some(state) = bench_state_get() {
                        state.drain_all_to_spill();
                    }
                    this.mark_worker_perturbed();
                }

                if ACTIVE_PAUSE_PENDING.swap(false, Ordering::AcqRel) {
                    let policy = bench_policy_from_raw(ACTIVE_PAUSE_POLICY.load(Ordering::Acquire));
                    this.handle_pause_flush(policy);
                }

                let running = {
                    let inner = this.inner.lock();
                    inner.running
                };
                if !running {
                    break;
                }
            }
            ACTIVE_OVERFLOW_WORKER_RUNNING.store(false, Ordering::Release);
        });
    }

    pub fn start(&self) {
        if !BENCH_ENABLED {
            return;
        }

        let auto_persist_secs_opt;
        let timeout_ms_opt;
        let resolved_cfg;
        let log_samples_for_worker;

        {
            let mut inner = self.inner.lock();
            if inner.running {
                return;
            }

            resolved_cfg = inner.resolved_cfg;
            log_samples_for_worker = inner.cfg.log_samples;

            inner.running = true;
            inner.start_ns = bench_now_ns();
            inner.stop_ns = None;

            inner.current_run_id = inner.run_id_counter;
            inner.run_id_counter = inner.run_id_counter.wrapping_add(1);

            inner.reset_run_state();

            if let Some(state) = bench_state() {
                state.prepare_for_start(resolved_cfg.event_capacity);
            }

            if inner.cfg.log_samples {
                activate_bench_sampling_config(resolved_cfg);
                SAMPLE_REFCOUNT.fetch_add(1, Ordering::Relaxed);
            }
            if inner.cfg.log_spans {
                SPAN_REFCOUNT.fetch_add(1, Ordering::Relaxed);
            }
            auto_persist_secs_opt = inner.cfg.auto_persist_secs;
            timeout_ms_opt = inner.cfg.timeout_ms;
        }

        if log_samples_for_worker {
            self.spawn_overflow_worker_if_needed(resolved_cfg.overflow_policy);
        }

        if let Some(timeout_ms) = timeout_ms_opt {
            let this = self.clone();
            spawn_blocking(move || {
                interrupt_index::wait_duration(timeout_ms);
                this.stop();
                println!("starting timeout persist");
                block_on(this.persist());
                println!("timeout done");
            });
        }

        if let Some(secs) = auto_persist_secs_opt {
            if !secs.is_zero() {
                let interval = secs;
                let this = self.clone();
                let this_arc = Arc::new(self.clone());
                spawn_blocking(move || loop {
                    interrupt_index::wait_duration(interval);

                    if !BENCH_ENABLED {
                        return;
                    }

                    {
                        let inner = this_arc.inner.lock();
                        if !inner.running {
                            break;
                        }
                    }

                    let moved = Arc::clone(&this_arc);
                    block_on(moved.persist());
                });
            }
        }
    }
    pub async fn stop_and_persist(&self) {
        self.stop();
        let this = self.clone();
        this.persist().await
    }
    pub fn stop(&self) {
        if !BENCH_ENABLED {
            return;
        }

        let (log_samples, log_spans) = {
            let mut inner = self.inner.lock();
            if !inner.running {
                return;
            }
            inner.running = false;
            inner.stop_ns = Some(bench_now_ns());
            inner.sampling_truncated |= ACTIVE_SAMPLING_STOPPED.load(Ordering::Acquire);
            inner.perturbed_by_worker |= ACTIVE_PERTURBED_BY_WORKER.load(Ordering::Acquire);
            (inner.cfg.log_samples, inner.cfg.log_spans)
        };

        if log_samples {
            SAMPLE_REFCOUNT.fetch_sub(1, Ordering::Relaxed);
        }
        if log_spans {
            SPAN_REFCOUNT.fetch_sub(1, Ordering::Relaxed);
        }
    }

    pub fn span_guard(&self, tag: &'static str, object_id: u64) -> BenchSpanGuard {
        BenchSpanGuard::new(tag, object_id)
    }

    pub async fn persist(&self) {
        if !BENCH_ENABLED {
            return;
        }
        if !self.ensure_fs_ready().await {
            return;
        }

        let session_archive = {
            let inner = self.inner.lock();
            match inner.session_archive.clone() {
                Some(archive) => archive,
                None => return,
            }
        };

        let mut archive_persist = session_archive.begin_persist().await;
        let persist_id = archive_persist.persist_id();

        let cfg: BenchWindowConfig;
        let resolved_cfg: ResolvedBenchWindowConfig;
        let run_id: u32;
        let start_ns: u64;
        let to_ns: u64;

        let window_dir: String;
        let ncores: usize;

        let last_export_seq: Vec<u64>;

        let mut open_spans: BTreeMap<u32, (BenchSpanEvent, u64, u16)>;

        {
            let inner = self.inner.lock();
            if inner.start_ns == 0 {
                return;
            }

            cfg = inner.cfg.clone();
            resolved_cfg = inner.resolved_cfg;
            run_id = inner.current_run_id;

            start_ns = inner.start_ns;
            to_ns = match inner.stop_ns {
                Some(stop) => stop,
                None => bench_now_ns(),
            };

            window_dir = inner.window_dir.clone();
            ncores = inner.ncores;

            last_export_seq = inner.last_export_seq.clone();

            open_spans = inner.open_spans.clone();
        }

        if start_ns >= to_ns {
            return;
        }

        let exports_vec = build_exports_for_window(
            &cfg,
            resolved_cfg,
            run_id,
            start_ns,
            to_ns,
            &last_export_seq,
            ncores,
            &mut open_spans,
        )
        .await;

        if exports_vec.is_empty() {
            return;
        }

        let mut records: Vec<BenchArchiveRecord> = Vec::new();
        let mut merged_max_seq = vec![0u64; ncores];

        if cfg.export_debug_metadata {
            if let Some(json) = build_krnl_debug_metadata_json(run_id, start_ns, to_ns) {
                let path = archive_manifest_entry_path(
                    &window_dir,
                    run_id,
                    persist_id,
                    "debug_metadata.json",
                );
                records.push(BenchArchiveRecord::manifest(
                    path,
                    json.into_bytes(),
                    bench_now_ns(),
                ));
            }
        }

        for (chunk_idx, mut b) in exports_vec.into_iter().enumerate() {
            for i in 0..ncores {
                let s = b.max_seq_seen[i];
                if s > merged_max_seq[i] {
                    merged_max_seq[i] = s;
                }
            }

            for target in 0..(ncores + 1) {
                if cfg.disable_per_core && target != ncores {
                    continue;
                }

                if cfg.log_samples {
                    let samples = core::mem::take(&mut b.samples[target]);
                    if let Some(bytes) = encode_sample_chunk_proto(
                        run_id,
                        chunk_idx,
                        target,
                        ncores,
                        start_ns,
                        to_ns,
                        resolved_cfg.max_unwind_depth,
                        &b.max_seq_seen,
                        &b.sample_drops,
                        samples,
                    ) {
                        let path = archive_stream_file_entry_path(
                            &window_dir,
                            run_id,
                            persist_id,
                            chunk_idx,
                            target,
                            ncores,
                            "samples.pb",
                        );
                        records.push(BenchArchiveRecord::data(path, bytes, bench_now_ns()));
                    }
                }

                if cfg.log_spans {
                    let rows = core::mem::take(&mut b.spans_rows[target]);
                    if !rows.is_empty() {
                        let path = archive_stream_entry_path(
                            &window_dir,
                            run_id,
                            persist_id,
                            chunk_idx,
                            target,
                            ncores,
                            "spans",
                        );
                        let csv = "run_id,tag,object_id,core,start_ns,duration_ns\n".to_string();
                        push_csv_archive_record(&mut records, path, csv, rows, bench_now_ns());
                    }
                }

                if cfg.log_mem_on_persist {
                    let rows = core::mem::take(&mut b.mem_rows[target]);
                    if !rows.is_empty() {
                        let path = archive_stream_entry_path(
                            &window_dir,
                            run_id,
                            persist_id,
                            chunk_idx,
                            target,
                            ncores,
                            "memory",
                        );
                        let csv = "run_id,timestamp_ns,core,used_bytes,total_bytes,heap_used_bytes,heap_total_bytes,core_sched_ns,core_switches\n".to_string();
                        push_csv_archive_record(&mut records, path, csv, rows, bench_now_ns());
                    }
                }
            }
        }

        let data_record_count = records.len();
        let sample_counter_snapshot: Vec<BenchDroppedSampleCounterProto> = if cfg.log_samples {
            bench_state()
                .map(|state| {
                    (0..ncores)
                        .filter_map(|core| state.drops_for_core(core).map(|d| d.snapshot(core)))
                        .collect()
                })
                .unwrap_or_else(Vec::new)
        } else {
            Vec::new()
        };
        let samples_dropped: u64 = sample_counter_snapshot
            .iter()
            .map(|c| c.samples_dropped)
            .sum();
        let samples_overwritten: u64 = sample_counter_snapshot
            .iter()
            .map(|c| c.samples_overwritten)
            .sum();
        let sampling_stopped: u64 = sample_counter_snapshot
            .iter()
            .map(|c| c.sampling_stopped)
            .sum();

        let (
            inner_sampling_truncated,
            inner_pause_flush_ns,
            inner_logical_time_compacted,
            inner_perturbed_by_worker,
            pause_intervals,
        ) = {
            let inner = self.inner.lock();
            (
                inner.sampling_truncated,
                inner.pause_flush_ns,
                inner.logical_time_compacted,
                inner.perturbed_by_worker,
                inner.pause_intervals.clone(),
            )
        };
        let sampling_truncated = inner_sampling_truncated
            || sampling_stopped != 0
            || ACTIVE_SAMPLING_STOPPED.load(Ordering::Acquire);
        let perturbed_by_worker =
            inner_perturbed_by_worker || ACTIVE_PERTURBED_BY_WORKER.load(Ordering::Acquire);
        let pause_intervals_json: Vec<Value> = pause_intervals
            .iter()
            .map(|p| {
                json!({
                    "pause_start_ns": p.pause_start_ns,
                    "pause_end_ns": p.pause_end_ns,
                    "duration_ns": p.duration_ns,
                    "policy": bench_overflow_policy_name(p.policy),
                    "logical_time_shifted": p.logical_time_shifted,
                    "reason": p.reason,
                })
            })
            .collect();

        let commit = json!({
            "schema": "rustos.benchpack.persist.v2",
            "persist_id": persist_id,
            "window": window_dir.as_str(),
            "run_id": run_id,
            "start_ns": start_ns,
            "to_ns": to_ns,
            "ncores": ncores,
            "disable_per_core": cfg.disable_per_core,
            "log_samples": cfg.log_samples,
            "sample_format": if cfg.log_samples { "protobuf:BenchSampleChunkProto" } else { "" },
            "overflow_policy": bench_overflow_policy_name(resolved_cfg.overflow_policy),
            "overflow_policy_raw": resolved_cfg.overflow_policy as u32,
            "sample_capacity": resolved_cfg.sample_capacity,
            "span_capacity": resolved_cfg.span_capacity,
            "event_capacity": resolved_cfg.event_capacity,
            "sample_chunk_capacity": resolved_cfg.sample_chunk_capacity,
            "max_unwind_depth": resolved_cfg.max_unwind_depth,
            "sampling_truncated": sampling_truncated,
            "samples_dropped": samples_dropped,
            "samples_overwritten": samples_overwritten,
            "pause_count": pause_intervals_json.len(),
            "pause_flush_ns": inner_pause_flush_ns,
            "logical_time_compacted": inner_logical_time_compacted,
            "perturbed_by_worker": perturbed_by_worker,
            "pause_intervals": pause_intervals_json,
            "log_spans": cfg.log_spans,
            "log_mem_on_persist": cfg.log_mem_on_persist,
            "data_record_count": data_record_count,
        });
        records.push(BenchArchiveRecord::persist_commit(
            archive_manifest_entry_path(&window_dir, run_id, persist_id, "persist_commit.json"),
            commit.to_string().into_bytes(),
            bench_now_ns(),
        ));

        if archive_persist.append_records(&records).await.is_err() {
            return;
        }

        let mut inner = self.inner.lock();

        inner.open_spans = open_spans;
        inner.sampling_truncated = sampling_truncated;
        inner.perturbed_by_worker = perturbed_by_worker;

        for i in 0..ncores {
            let max_seq = merged_max_seq[i];
            if max_seq != 0 && max_seq > inner.last_export_seq[i] {
                inner.last_export_seq[i] = max_seq;
            }
        }
    }
}

impl Drop for BenchWindow {
    fn drop(&mut self) {
        if !BENCH_ENABLED {
            return;
        }

        let mut do_flush = false;
        let mut dec_samples = false;
        let mut dec_spans = false;
        let mut dec_metrics = false;

        {
            let mut inner = self.inner.lock();
            if inner.running {
                inner.running = false;
                inner.stop_ns = Some(bench_now_ns());
                inner.sampling_truncated |= ACTIVE_SAMPLING_STOPPED.load(Ordering::Acquire);
                inner.perturbed_by_worker |= ACTIVE_PERTURBED_BY_WORKER.load(Ordering::Acquire);
                dec_samples = inner.cfg.log_samples;
                dec_spans = inner.cfg.log_spans;
                do_flush = inner.cfg.end_on_drop;
            }
            if inner.cfg.log_mem_on_persist {
                dec_metrics = true;
            }
        }

        if do_flush {
            let this = self.clone();
            spawn_blocking(move || {
                block_on(this.persist());
            });
        }

        if dec_samples {
            SAMPLE_REFCOUNT.fetch_sub(1, Ordering::Relaxed);
        }

        if dec_spans {
            SPAN_REFCOUNT.fetch_sub(1, Ordering::Relaxed);
        }

        if dec_metrics {
            METRICS_REFCOUNT.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

// ===== File IO + heap =====

pub async fn append_named_file(path: &str, file_name: &str, data: &[u8]) -> Result<(), ()> {
    let dir_path = Path::from_string(path);
    let _ = File::make_dir(&dir_path).await;

    let file_path = Path::from_string(&format!("{path}\\{file_name}"));

    let mut file = match File::open(&file_path, &[OpenFlags::Create, OpenFlags::WriteThrough]).await
    {
        Ok(f) => f,
        Err(_) => File::open(&file_path, &[OpenFlags::Open, OpenFlags::WriteThrough])
            .await
            .map_err(|_| ())?,
    };

    if file.seek(0, FsSeekWhence::End).await.is_err() {
        return Err(());
    }

    file.append(data).await.map_err(|_| ())?;
    let _ = file.close().await;
    Ok(())
}

pub async fn write_named_file(path: &str, file_name: &str, data: &[u8]) -> Result<(), ()> {
    let dir_path = Path::from_string(path);
    let _ = File::make_dir(&dir_path).await;

    let file_path = Path::from_string(&format!("{path}\\{file_name}"));

    let mut file = match File::open(&file_path, &[OpenFlags::Create, OpenFlags::WriteThrough]).await
    {
        Ok(f) => f,
        Err(_) => File::open(&file_path, &[OpenFlags::Open, OpenFlags::WriteThrough])
            .await
            .map_err(|_| ())?,
    };

    file.set_len(0).await.map_err(|_| ())?;
    file.write(data).await.map_err(|_| ())?;
    let _ = file.close().await;
    Ok(())
}

pub fn used_memory() -> usize {
    #[cfg(feature = "allocator-mimalloc")]
    {
        let capacity = crate::memory::heap::BOOTSTRAP_HEAP_SIZE as usize
            + crate::memory::heap::MIMALLOC_META_HEAP_SIZE as usize;
        let used_meta = capacity - crate::memory::heap::ALLOCATOR.free_memory();
        let used_arena = crate::memory::heap::mimalloc::MIMALLOC_ARENA_COMMITTED
            .load(core::sync::atomic::Ordering::Relaxed);
        used_meta + used_arena
    }
    #[cfg(feature = "allocator-buddy")]
    {
        crate::memory::heap::HEAP_SIZE as usize - crate::memory::heap::ALLOCATOR.free_memory()
    }
}

const DEPTH: usize = 1_000;
const ITERS: usize = 500_000;

const BLOCK_TASKS: usize = 500_000;

pub fn bench_async_vs_sync_call_latency() {
    spawn_detached(async {
        bench_async_vs_sync_call_latency_async().await;
    });
}

#[inline(never)]
fn sync_leaf(x: u64) -> u64 {
    x.wrapping_add(1)
}

#[inline(never)]
fn sync_chain(mut x: u64) -> u64 {
    let mut i = 0usize;
    while i < DEPTH {
        x = sync_leaf(x);
        i += 1;
    }
    x
}

struct Ready;

impl Future for Ready {
    type Output = ();
    #[inline(always)]
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        Poll::Ready(())
    }
}

#[inline(always)]
fn ready() -> Ready {
    Ready
}

#[inline(never)]
async fn async_leaf(x: u64) -> u64 {
    ready().await;
    x.wrapping_add(1)
}

#[inline(never)]
async fn async_chain(mut x: u64) -> u64 {
    let mut i = 0usize;
    while i < DEPTH {
        x = async_leaf(x).await;
        i += 1;
    }
    x
}

#[inline(never)]
async fn blocking_chain(x: u64) -> u64 {
    spawn_blocking(move || {
        // if ret % 10_000 == 0 {
        //     println!("blocking done num: {}", ret);
        // }
        sync_chain(x)
    })
    .await
}

#[inline(never)]
async fn blocking_queue_stress(seed: u64) -> u64 {
    let mut funcs = Vec::with_capacity(BLOCK_TASKS);
    for i in 0..BLOCK_TASKS {
        let x = seed.wrapping_add(i as u64);
        funcs.push(move || {
            // if ret % 10_000 == 0 {
            //     println!("blocking done num: {}", ret);
            // }
            sync_chain(x)
        });
    }

    let joins = spawn_blocking_many(funcs);
    let _results = JoinAll::new(joins).await;
    BLOCK_TASKS as u64
}

#[inline(always)]
fn micros_to_ms(micros: u64) -> f64 {
    micros as f64 / 1000.0
}

#[inline(always)]
fn avg_micros_per(total_micros: u64, count: u64) -> f64 {
    if count == 0 {
        0.0
    } else {
        total_micros as f64 / count as f64
    }
}

#[inline(always)]
fn nanos_per_call(total_micros: u64, call_count: u64) -> f64 {
    if call_count == 0 {
        0.0
    } else {
        (total_micros as f64 * 1000.0) / call_count as f64
    }
}

#[inline(always)]
fn safe_ratio(num: u64, den: u64) -> f64 {
    if den == 0 {
        0.0
    } else {
        num as f64 / den as f64
    }
}

#[inline(always)]
fn ops_per_sec_from_micros(total_ops: u64, total_micros: u64) -> f64 {
    if total_micros == 0 {
        0.0
    } else {
        total_ops as f64 * 1_000_000.0 / total_micros as f64
    }
}

pub async fn bench_async_vs_sync_call_latency_async() {
    let mut warm = 0u64;
    for _ in 0..10_000 {
        warm = sync_chain(warm);
    }

    let mut warm_async = 0u64;
    for _ in 0..10_000 {
        warm_async = async_chain(warm_async).await;
    }
    black_box(warm_async);

    let mut warm_blk = 0u64;
    for _ in 0..200_000 {
        warm_blk = blocking_chain(warm_blk).await;
    }
    black_box(warm_blk);

    let mut s = 0u64;
    let sw_sync = Stopwatch::start();
    for _ in 0..ITERS {
        s = sync_chain(s);
    }
    let sync_us = sw_sync.elapsed_micros();
    black_box(s);

    let mut a = 0u64;
    let sw_async = Stopwatch::start();
    for _ in 0..ITERS {
        a = async_chain(a).await;
    }
    let async_us = sw_async.elapsed_micros();
    black_box(a);

    let mut b = 0u64;
    let sw_blk = Stopwatch::start();
    for _ in 0..ITERS {
        b = blocking_chain(b).await;
    }
    let blk_us = sw_blk.elapsed_micros();
    black_box(b);

    let mut q = 0u64;
    let sw_q = Stopwatch::start();
    for index in 1..2u64 {
        q = 0;
        q = blocking_queue_stress(q).await;
        println!("blocking num: {}", index * q);
    }
    let q_us = sw_q.elapsed_micros();
    black_box(q);

    let iters_u64 = ITERS as u64;
    let inner_calls_u64 = (ITERS as u64) * (DEPTH as u64);

    let sync_us_per_chain = avg_micros_per(sync_us, iters_u64);
    let async_us_per_chain = avg_micros_per(async_us, iters_u64);
    let blk_us_per_chain = avg_micros_per(blk_us, iters_u64);

    let sync_ns_per_inner = nanos_per_call(sync_us, inner_calls_u64);
    let async_ns_per_inner = nanos_per_call(async_us, inner_calls_u64);

    let sync_ms = micros_to_ms(sync_us);
    let async_ms = micros_to_ms(async_us);
    let blk_ms = micros_to_ms(blk_us);

    let q_ms = micros_to_ms(q_us);
    let q_us_per_task = avg_micros_per(q_us, BLOCK_TASKS as u64);

    println!("[bench] iters={} depth={}", ITERS, DEPTH);
    println!(
        "[bench] sync:  total={:.3} ms  us/chain={:.3}  ns/inner_call={:.3}",
        sync_ms, sync_us_per_chain, sync_ns_per_inner
    );
    println!(
        "[bench] async: total={:.3} ms  us/chain={:.3}  ns/inner_call={:.3}",
        async_ms, async_us_per_chain, async_ns_per_inner
    );
    println!(
        "[bench] blk:   total={:.3} ms  us/chain={:.3}",
        blk_ms, blk_us_per_chain
    );
    println!(
        "[bench] blkq:  tasks={} total={:.3} ms  us/task={:.3}",
        BLOCK_TASKS, q_ms, q_us_per_task
    );

    // Everything relative to sync baseline
    let sm_vs_sync = safe_ratio(async_us, sync_us);
    let blk_vs_sync = safe_ratio(blk_us, sync_us);
    let blk_vs_blkq = safe_ratio(blk_us, q_us);

    // Isolate pure overhead costs (us per chain, relative to sync)
    let sm_overhead_us = async_us_per_chain - sync_us_per_chain;
    let blk_overhead_us = blk_us_per_chain - sync_us_per_chain;
    // pending+wake = blk - async (the spawn/wake cost on top of state machine)
    let pw_overhead_us = blk_us_per_chain - async_us_per_chain;

    println!("[bench] --- vs sync baseline ---");
    println!(
        "[bench] state_machine/sync  = {:.3}x  (async overhead: {:.3} us/chain)",
        sm_vs_sync, sm_overhead_us
    );
    println!(
        "[bench] blk/sync            = {:.3}x  (spawn+wake+sm overhead: {:.3} us/chain)",
        blk_vs_sync, blk_overhead_us
    );
    let pw_vs_sync = if async_us_per_chain == 0.0 {
        0.0
    } else {
        blk_us_per_chain / async_us_per_chain
    };
    println!(
        "[bench] pending+wake/sync   = {:.3}x  (blk/async, pure spawn+wake cost)",
        pw_vs_sync
    );
    println!(
        "[bench] blk/blkq            = {:.3}x  (sequential blocking vs bulk queue)",
        blk_vs_blkq
    );
}

// =====================
// Realistic traffic benchmark
// =====================

// Simulates a driver-like workload: async setup -> blocking device work -> async postprocess
// Runs at varying concurrency levels to find saturation point and measure scheduling overhead.

const TRAFFIC_TOTAL_TASKS: usize = 100_000;
const TRAFFIC_CONCURRENCY: &[usize] = &[4, 8, 16, 32, 64, 128, 256, 512, 1024, 0x1000];
const TRAFFIC_WORK_NS: u64 = 1000; // simulated device work per blocking task
const TRAFFIC_ASYNC_DEPTH: usize = 10; // async setup + postprocess depth
#[inline(never)]
fn traffic_blocking_work(seed: u64) -> u64 {
    // Simulate real device work: spin for TRAFFIC_WORK_NS then do a small compute
    if TRAFFIC_WORK_NS > 0 {
        crate::drivers::interrupt_index::wait_duration(Duration::from_nanos(TRAFFIC_WORK_NS));
    }
    let mut x = seed;
    for _ in 0..100 {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
    }
    x
}

#[inline(never)]
async fn traffic_async_work(mut x: u64, depth: usize) -> u64 {
    for _ in 0..depth {
        x = async_leaf(x).await;
    }
    x
}

/// One "request": async setup -> spawn_blocking device work -> async postprocess
#[inline(never)]
async fn traffic_one_request(seed: u64) -> u64 {
    let prepared = traffic_async_work(seed, TRAFFIC_ASYNC_DEPTH / 2).await;

    let device_result = spawn_blocking(move || traffic_blocking_work(prepared)).await;

    let result = traffic_async_work(device_result, TRAFFIC_ASYNC_DEPTH / 2).await;
    result
}

/// One "request" using bulk queue for the blocking phase
#[inline(never)]
async fn traffic_batch_request(seeds: Vec<u64>) -> Vec<u64> {
    let count = seeds.len();

    let mut prepared = Vec::with_capacity(count);
    for &seed in &seeds {
        prepared.push(traffic_async_work(seed, TRAFFIC_ASYNC_DEPTH / 2).await);
    }

    let funcs: Vec<_> = prepared
        .iter()
        .map(|&p| move || traffic_blocking_work(p))
        .collect();
    let joins = spawn_blocking_many(funcs);
    let device_results = JoinAll::new(joins).await;

    let mut results = Vec::with_capacity(count);
    for device_result in device_results {
        results.push(traffic_async_work(device_result, TRAFFIC_ASYNC_DEPTH / 2).await);
    }
    results
}

// =====================
// Config
// =====================

pub const BENCH_CSV_PATH: &str = "C:\\bench_async.csv";

pub const BENCH_INFLIGHT_START: u64 = 1_000;
pub const BENCH_INFLIGHT_END: u64 = 500_000;
pub const BENCH_INFLIGHT_STEP: u64 = 5_000;

pub const BENCH_WARMUP_ITERS: u64 = 1;
pub const BENCH_ITERS: u64 = 5;

pub const BENCH_USE_BATCH_SPAWN: bool = true;

// Per blocking task work. 0 => no wait.
pub const BENCH_WORK_NS: u64 = 0;

// 0 = keep all samples. Otherwise cap latency samples by keeping every k-th sample.
pub const BENCH_MAX_LAT_SAMPLES: usize = 0;

// =====================
// Helpers
// =====================

#[inline(always)]
fn cycles_to_ns(delta_cycles: u64, tsc_hz: u64) -> u64 {
    if tsc_hz == 0 {
        return 0;
    }
    ((delta_cycles as u128 * 1_000_000_000u128) / (tsc_hz as u128)) as u64
}

#[inline(always)]
fn percentile_from_sorted(sorted: &[u64], permille: u32) -> u64 {
    let n = sorted.len();
    if n == 0 {
        return 0;
    }
    if n == 1 {
        return sorted[0];
    }
    let idx = ((permille as usize) * (n - 1)) / 1000;
    sorted[idx]
}

#[inline(always)]
fn should_keep_sample(sample_idx: usize, total_target: usize) -> bool {
    if BENCH_MAX_LAT_SAMPLES == 0 {
        return true;
    }
    if total_target <= BENCH_MAX_LAT_SAMPLES {
        return true;
    }
    let stride = total_target.div_ceil(BENCH_MAX_LAT_SAMPLES);
    sample_idx.is_multiple_of(stride)
}

#[inline(always)]
fn ilog2_u64(mut x: u64) -> u32 {
    if x <= 1 {
        return 0;
    }
    let mut r = 0u32;
    while x > 1 {
        x >>= 1;
        r += 1;
    }
    r
}

async fn open_for_append(path: &Path) -> Result<File, FileStatus> {
    let try_existing = File::open(
        path,
        &[
            OpenFlags::Open,
            OpenFlags::WriteOnly,
            OpenFlags::WriteThrough,
        ],
    )
    .await;

    if try_existing.is_ok() {
        return try_existing;
    }

    File::open(
        path,
        &[
            OpenFlags::Create,
            OpenFlags::Open,
            OpenFlags::WriteOnly,
            OpenFlags::WriteThrough,
        ],
    )
    .await
}

async fn ensure_csv_header(path: &Path, header: &str) -> Result<(), FileStatus> {
    if let Ok(f) = File::open(
        path,
        &[
            OpenFlags::Open,
            OpenFlags::ReadOnly,
            OpenFlags::WriteThrough,
        ],
    )
    .await
    {
        if f.size != 0 {
            return Ok(());
        }
    }

    let mut f = open_for_append(path).await?;
    let mut s = String::new();
    s.push_str(header);
    s.push('\n');
    let _ = f.append(s.as_bytes()).await?;
    Ok(())
}

async fn append_csv_line(path: &Path, line: &str) -> Result<(), FileStatus> {
    let mut f = open_for_append(path).await?;
    let mut s = String::new();
    s.push_str(line);
    s.push('\n');
    let _ = f.append(s.as_bytes()).await?;
    Ok(())
}

// =====================
// Entry point
// =====================

pub fn benchmark_async() {
    spawn_detached(async {
        benchmark_async_async().await;
    });
}

// =====================
// Benchmark
// =====================
const DISK_BENCH_DIR: &str = "C:\\bench";
const DISK_BENCH_FILE: &str = "io_bench.bin";
const DISK_BENCH_TOTAL_BYTES: usize = 10 * 1024 * 1024;
const DISK_BENCH_SIZES: &[usize] = &[
    1 * 1024,
    //64 * 1024,
    // 512 * 1024,
    // 1024 * 1024,
    // 2 * 1024 * 1024,
    //4 * 1024 * 1024,
    //64 * 1024 * 1024,
];

#[inline(always)]
fn mib_per_sec(bytes: u64, elapsed_ns: u64) -> f64 {
    if elapsed_ns == 0 {
        return 0.0;
    }
    let secs = elapsed_ns as f64 / 1_000_000_000.0;
    let mib = bytes as f64 / (1024.0 * 1024.0);
    mib / secs
}

fn lin_regress_overhead(bytes: &[u64], ns_per_op: &[u64]) -> Option<(f64, f64)> {
    if bytes.len() < 2 || ns_per_op.len() < 2 || bytes.len() != ns_per_op.len() {
        return None;
    }

    let n = bytes.len() as f64;
    let mut sum_x = 0.0;
    let mut sum_y = 0.0;
    let mut sum_xx = 0.0;
    let mut sum_xy = 0.0;

    for (b, t) in bytes.iter().zip(ns_per_op.iter()) {
        let x = *b as f64;
        let y = *t as f64;
        sum_x += x;
        sum_y += y;
        sum_xx += x * x;
        sum_xy += x * y;
    }

    let denom = n * sum_xx - sum_x * sum_x;
    if denom.abs() < core::f64::EPSILON {
        return None;
    }

    let slope = (n * sum_xy - sum_x * sum_y) / denom;
    let intercept = (sum_y * sum_xx - sum_x * sum_xy) / denom;
    Some((intercept, slope))
}

pub fn bench_c_drive_io() {
    spawn_detached(async {
        bench_c_drive_io_async().await;
    });
}

pub async fn bench_c_drive_io_async() {
    // Ensure the target directory exists so the benchmark file can be created.
    let mut dir_path = Path::from_string(DISK_BENCH_DIR);
    if let Err(e) = File::make_dir(&dir_path).await {
        println!(
            "[disk-bench] failed to create bench dir {}: {:?}",
            DISK_BENCH_DIR, e
        );
        return;
    }
    dir_path.push(DISK_BENCH_FILE);
    let mut file = match File::open(
        &dir_path,
        &[
            OpenFlags::Create,
            OpenFlags::ReadWrite,
            OpenFlags::WriteThrough,
        ],
    )
    .await
    {
        Ok(f) => f,
        Err(e) => {
            println!(
                "[disk-bench] failed to open {} for read/write: {:?}",
                DISK_BENCH_FILE, e
            );
            return;
        }
    };

    let bench_len = DISK_BENCH_TOTAL_BYTES as u64;
    if file.size != bench_len {
        if let Err(e) = file.set_len(bench_len).await {
            println!(
                "[disk-bench] failed to size benchmark file to {} bytes: {:?}",
                bench_len, e
            );
            return;
        }
        if let Err(e) = file.flush().await {
            println!(
                "[disk-bench] failed to flush benchmark file sizing: {:?}",
                e
            );
            return;
        }
    }

    let mut size_bytes: Vec<u64> = Vec::new();
    let mut write_ns_per_op: Vec<u64> = Vec::new();
    let mut read_ns_per_op: Vec<u64> = Vec::new();
    let mut write_throughput: Vec<f64> = Vec::new();
    let mut read_throughput: Vec<f64> = Vec::new();

    for &chunk_sz in DISK_BENCH_SIZES {
        let ops = (DISK_BENCH_TOTAL_BYTES / chunk_sz).max(1);

        let mut chunk = vec![0u8; chunk_sz];

        let sw_write = Stopwatch::start();
        let mut write_elapsed = 0;
        let mut total_written = 0u64;
        let mut offset = 0u64;
        println!("starting chunk size: {}", chunk_sz);
        for op in 0..ops {
            chunk[..8].copy_from_slice(&(op as u64).to_le_bytes());
            let sw_write = Stopwatch::start();
            match file.write_at(offset, &chunk).await {
                Ok(n) => {
                    total_written = total_written.saturating_add(n as u64);
                    offset = offset.saturating_add(n as u64);
                    if n != chunk_sz {
                        println!(
                            "[disk-bench] short write at op {} (size {}): {} of {}",
                            op, chunk_sz, n, chunk_sz
                        );
                        break;
                    }
                }
                Err(e) => {
                    println!(
                        "[disk-bench] write failed at op {} (size {}): {:?}",
                        op, chunk_sz, e
                    );
                    continue;
                }
            }
            write_elapsed += sw_write.elapsed_nanos();
        }
        let write_mib_s = mib_per_sec(total_written, write_elapsed);
        let per_write_ns = write_elapsed / ops as u64;

        if let Err(e) = file.flush().await {
            println!(
                "[disk-bench] flush after writes failed for size {}: {:?}",
                chunk_sz, e
            );
        }

        let sw_read = Stopwatch::start();
        let mut total_read = 0u64;
        let mut offset = 0u64;
        for op in 0..ops {
            match file.read_at(offset, chunk_sz).await {
                Ok(buf) => {
                    total_read = total_read.saturating_add(buf.len() as u64);
                    offset = offset.saturating_add(chunk_sz as u64);
                }
                Err(e) => {
                    println!(
                        "[disk-bench] read failed at op {} (size {}): {:?}",
                        op, chunk_sz, e
                    );
                    continue;
                }
            }
        }
        let read_elapsed = sw_read.elapsed_nanos();
        let read_mib_s = mib_per_sec(total_read, read_elapsed);
        let per_read_ns = read_elapsed / ops as u64;

        size_bytes.push(chunk_sz as u64);
        write_ns_per_op.push(per_write_ns);
        read_ns_per_op.push(per_read_ns);
        write_throughput.push(write_mib_s);
        read_throughput.push(read_mib_s);
    }

    let write_overhead = lin_regress_overhead(&size_bytes, &write_ns_per_op);
    let read_overhead = lin_regress_overhead(&size_bytes, &read_ns_per_op);

    if let Some((over_ns, slope_ns_per_byte)) = write_overhead {
        let bw = if slope_ns_per_byte > 0.0 {
            1_000_000_000.0 / (slope_ns_per_byte * 1024.0 * 1024.0)
        } else {
            0.0
        };
        println!(
            "[disk-bench] write overhead ~= {:.0} ns/op, est device BW {:.2} MiB/s",
            over_ns, bw
        );
    } else {
        println!("[disk-bench] write overhead estimation unavailable");
    }

    if let Some((over_ns, slope_ns_per_byte)) = read_overhead {
        let bw = if slope_ns_per_byte > 0.0 {
            1_000_000_000.0 / (slope_ns_per_byte * 1024.0 * 1024.0)
        } else {
            0.0
        };
        println!(
            "[disk-bench] read overhead ~= {:.0} ns/op, est device BW {:.2} MiB/s",
            over_ns, bw
        );
    } else {
        println!("[disk-bench] read overhead estimation unavailable");
    }

    for idx in 0..size_bytes.len() {
        let size = size_bytes[idx];
        let measured_w = write_throughput[idx];
        let measured_r = read_throughput[idx];
        let adj_w = if let Some((over, _)) = write_overhead {
            let adj_ns = (write_ns_per_op[idx] as f64 - over).max(1.0);
            (size as f64 / adj_ns) * (1_000_000_000.0 / (1024.0 * 1024.0))
        } else {
            measured_w
        };
        let adj_r = if let Some((over, _)) = read_overhead {
            let adj_ns = (read_ns_per_op[idx] as f64 - over).max(1.0);
            (size as f64 / adj_ns) * (1_000_000_000.0 / (1024.0 * 1024.0))
        } else {
            measured_r
        };

        println!(
            "[disk-bench] size={:>7} KiB write={:>7.2} MiB/s adj_write={:>7.2} MiB/s read={:>7.2} MiB/s adj_read={:>7.2} MiB/s",
            size / 1024,
            measured_w,
            adj_w,
            measured_r,
            adj_r
        );
    }

    let seek_iters: u64 = 10_000;
    let seek_sw = Stopwatch::start();
    let mut seek_ok = true;
    for _ in 0..seek_iters {
        if let Err(e) = file.seek(0, FsSeekWhence::Cur).await {
            println!("[disk-bench] fs_seek baseline failed: {:?}", e);
            seek_ok = false;
            break;
        }
    }
    if seek_ok {
        let seek_ns = seek_sw.elapsed_nanos();
        let seek_ms = seek_ns / 1_000_000;
        let seek_ops_sec = if seek_ns == 0 {
            0
        } else {
            (seek_iters.saturating_mul(1_000_000_000) / seek_ns)
        };
        let ops_1 = seek_ops_sec;
        let ops_5 = seek_ops_sec / 5;
        let ops_10 = seek_ops_sec / 10;
        println!(
            "[disk-bench] fs_seek baseline: iters={} elapsed={} ms ops/sec={} (est per-stack: 1drv={} 5drv={} 10drv={})",
            seek_iters,
            seek_ms,
            seek_ops_sec,
            ops_1,
            ops_5,
            ops_10
        );
    }
}

pub async fn benchmark_async_async() {
    let tsc_hz = TSC_HZ.load(Ordering::SeqCst);
    assert!(tsc_hz != 0, "TSC not calibrated");

    let csv_path = Path::from_string(BENCH_CSV_PATH);

    let header = "run_id,x_inflight,x_inflight_log2,ops,elapsed_cycles,elapsed_ns,cycles_per_op,ns_per_op,ops_per_sec,p50_ns,p99_ns,p999_ns,work_ns,use_batch,iters,warmup";
    let _ = ensure_csv_header(&csv_path, header).await;

    println!("{header}");

    let run_id = cpu::get_cycles();

    let mut inflight = BENCH_INFLIGHT_START;
    while inflight <= BENCH_INFLIGHT_END {
        let target_samples = (inflight as usize).saturating_mul(BENCH_ITERS as usize);

        let mut lats_ns: Vec<u64> = Vec::new();
        if BENCH_MAX_LAT_SAMPLES == 0 || target_samples <= BENCH_MAX_LAT_SAMPLES {
            lats_ns.reserve(target_samples);
        } else {
            lats_ns.reserve(BENCH_MAX_LAT_SAMPLES);
        }

        let mut total_cycles: u64 = 0;
        let mut total_ns: u64 = 0;
        let mut ops_total: u64 = 0;

        let mut iter: u64 = 0;
        while iter < (BENCH_WARMUP_ITERS + BENCH_ITERS) {
            let gate = Arc::new(AtomicBool::new(false));

            if BENCH_USE_BATCH_SPAWN {
                let mut funcs = Vec::with_capacity(inflight as usize);

                let mut i = 0u64;
                while i < inflight {
                    let gate = gate.clone();
                    funcs.push(move || -> u64 {
                        while !gate.load(Ordering::Acquire) {
                            core::hint::spin_loop();
                        }
                        let start = cpu::get_cycles();
                        if BENCH_WORK_NS != 0 {
                            wait_duration(Duration::from_nanos(BENCH_WORK_NS));
                        }
                        let end = cpu::get_cycles();
                        end.wrapping_sub(start)
                    });

                    i += 1;
                }

                let joins = spawn_blocking_many(funcs);

                let sw = Stopwatch::start();
                gate.store(true, Ordering::Release);

                for join in joins.into_iter() {
                    let lat_cycles = join.await;

                    if iter >= BENCH_WARMUP_ITERS {
                        let lat = cycles_to_ns(lat_cycles, tsc_hz);

                        let sample_idx = ops_total as usize;
                        if should_keep_sample(sample_idx, target_samples) {
                            lats_ns.push(lat);
                        }
                        ops_total = ops_total.wrapping_add(1);
                    }
                }

                if iter >= BENCH_WARMUP_ITERS {
                    total_cycles = total_cycles.wrapping_add(sw.elapsed_cycles());
                    total_ns = total_ns.wrapping_add(sw.elapsed_nanos());
                }
            } else {
                let mut joins = Vec::with_capacity(inflight as usize);

                let mut i = 0u64;
                while i < inflight {
                    let gate = gate.clone();
                    let join = spawn_blocking(move || -> u64 {
                        while !gate.load(Ordering::Acquire) {
                            core::hint::spin_loop();
                        }
                        let start = cpu::get_cycles();
                        if BENCH_WORK_NS != 0 {
                            wait_duration(Duration::from_nanos(BENCH_WORK_NS));
                        }
                        let end = cpu::get_cycles();
                        end.wrapping_sub(start)
                    });

                    joins.push(join);
                    i += 1;
                }

                let sw = Stopwatch::start();
                gate.store(true, Ordering::Release);

                for join in joins.into_iter() {
                    let lat_cycles = join.await;

                    if iter >= BENCH_WARMUP_ITERS {
                        let lat = cycles_to_ns(lat_cycles, tsc_hz);

                        let sample_idx = ops_total as usize;
                        if should_keep_sample(sample_idx, target_samples) {
                            lats_ns.push(lat);
                        }
                        ops_total = ops_total.wrapping_add(1);
                    }
                }

                if iter >= BENCH_WARMUP_ITERS {
                    total_cycles = total_cycles.wrapping_add(sw.elapsed_cycles());
                    total_ns = total_ns.wrapping_add(sw.elapsed_nanos());
                }
            }

            iter += 1;
        }

        lats_ns.sort_unstable();
        let p50 = percentile_from_sorted(&lats_ns, 500);
        let p99 = percentile_from_sorted(&lats_ns, 990);
        let p999 = percentile_from_sorted(&lats_ns, 999);

        let cycles_per_op = if ops_total == 0 {
            0
        } else {
            total_cycles / ops_total
        };
        let ns_per_op = if ops_total == 0 {
            0
        } else {
            total_ns / ops_total
        };
        let ops_per_sec = if total_ns == 0 {
            0
        } else {
            ((ops_total as u128 * 1_000_000_000u128) / (total_ns as u128)) as u64
        };

        let use_batch = if BENCH_USE_BATCH_SPAWN { 1u64 } else { 0u64 };
        let x_log2 = ilog2_u64(inflight) as u64;

        let line = format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            run_id,
            inflight,
            x_log2,
            ops_total,
            total_cycles,
            total_ns,
            cycles_per_op,
            ns_per_op,
            ops_per_sec,
            p50,
            p99,
            p999,
            BENCH_WORK_NS,
            use_batch,
            BENCH_ITERS,
            BENCH_WARMUP_ITERS
        );

        println!("{line}");

        match append_csv_line(&csv_path, &line).await {
            Ok(_) => {}
            Err(e) => println!("bench csv append failed: {:?}", e),
        }

        inflight = inflight.saturating_add(BENCH_INFLIGHT_STEP);
        if inflight == 0 {
            break;
        }
    }
}

// =============================================================================
// VirtIO Disk Benchmark Sweep
// =============================================================================

/// Convert TSC cycles to milliseconds.
pub const IOCTL_BLOCK_BENCH_SWEEP_BOTH: u32 = 0xB000_8004;

#[inline]
fn cycles_to_ms(cycles: u64, tsc_hz: u64) -> f64 {
    if tsc_hz == 0 {
        return 0.0;
    }
    (cycles as f64 / tsc_hz as f64) * 1000.0
}

fn csv_escape(s: &str, out: &mut String) {
    let needs = s
        .as_bytes()
        .iter()
        .any(|&b| b == b',' || b == b'"' || b == b'\n' || b == b'\r');
    if !needs {
        out.push_str(s);
        return;
    }
    out.push('"');
    for ch in s.chars() {
        if ch == '"' {
            out.push('"');
            out.push('"');
        } else {
            out.push(ch);
        }
    }
    out.push('"');
}

#[inline]
fn clamp_pct(v: f64) -> f64 {
    if v < 0.0 {
        0.0
    } else if v > 100.0 {
        100.0
    } else {
        v
    }
}

fn csv_push_header(out: &mut String) {
    out.push_str(
        "run_id,trial,mode,\
req_version,req_flags,req_total_bytes,req_request_size_bytes,req_start_sector,req_max_inflight,\
used_version,used_flags,used_total_bytes,used_request_size_bytes,used_start_sector,used_max_inflight,\
tsc_hz,queue_count,queue0_size,indirect,msix,\
level_inflight,request_count,total_cycles,total_ms,avg_cycles,avg_ms,p50_cycles,p50_ms,p99_cycles,p99_ms,p999_cycles,p999_ms,\
min_cycles,min_ms,max_cycles,max_ms,\
wait_pct,active_pct,throughput_mib_s,iops\n",
    );
}

fn csv_push_level(
    out: &mut String,
    run_id: u32,
    trial: u32,
    mode: &str,
    requested: &BenchSweepParams,
    used_params: &BenchSweepParams,
    tsc_hz: u64,
    queue_count: u16,
    queue0_size: u16,
    indirect_enabled: bool,
    msix_enabled: bool,
    lvl: BenchLevelResult,
) {
    let total_ms = cycles_to_ms(lvl.total_time_cycles, tsc_hz);
    let avg_ms = cycles_to_ms(lvl.avg_cycles, tsc_hz);
    let p50_ms = cycles_to_ms(lvl.p50_cycles, tsc_hz);
    let p99_ms = cycles_to_ms(lvl.p99_cycles, tsc_hz);
    let p999_ms = cycles_to_ms(lvl.p999_cycles, tsc_hz);
    let min_ms = cycles_to_ms(lvl.min_cycles, tsc_hz);
    let max_ms = cycles_to_ms(lvl.max_cycles, tsc_hz);

    // lvl.idle_pct is actually "wait pct": percent of benchmark wall time spent inside irq_wait().await.
    let wait_pct = clamp_pct(lvl.idle_pct);
    let active_pct = 100.0 - wait_pct;

    let secs = total_ms / 1000.0;
    let throughput_mib_s = if secs > 0.0 {
        (used_params.total_bytes as f64 / (1024.0 * 1024.0)) / secs
    } else {
        0.0
    };
    let iops = if secs > 0.0 {
        (lvl.request_count as f64) / secs
    } else {
        0.0
    };

    out.push_str(&run_id.to_string());
    out.push(',');
    out.push_str(&trial.to_string());
    out.push(',');

    csv_escape(mode, out);
    out.push(',');

    out.push_str(&requested.version.to_string());
    out.push(',');
    out.push_str(&requested.flags.to_string());
    out.push(',');
    out.push_str(&requested.total_bytes.to_string());
    out.push(',');
    out.push_str(&requested.request_size.to_string());
    out.push(',');
    out.push_str(&requested.start_sector.to_string());
    out.push(',');
    out.push_str(&requested.max_inflight.to_string());
    out.push(',');

    out.push_str(&used_params.version.to_string());
    out.push(',');
    out.push_str(&used_params.flags.to_string());
    out.push(',');
    out.push_str(&used_params.total_bytes.to_string());
    out.push(',');
    out.push_str(&used_params.request_size.to_string());
    out.push(',');
    out.push_str(&used_params.start_sector.to_string());
    out.push(',');
    out.push_str(&used_params.max_inflight.to_string());
    out.push(',');

    out.push_str(&tsc_hz.to_string());
    out.push(',');
    out.push_str(&queue_count.to_string());
    out.push(',');
    out.push_str(&queue0_size.to_string());
    out.push(',');
    out.push_str(if indirect_enabled { "1" } else { "0" });
    out.push(',');
    out.push_str(if msix_enabled { "1" } else { "0" });
    out.push(',');

    out.push_str(&lvl.inflight.to_string());
    out.push(',');
    out.push_str(&lvl.request_count.to_string());
    out.push(',');

    out.push_str(&lvl.total_time_cycles.to_string());
    out.push(',');
    out.push_str(&format!("{:.3}", total_ms));
    out.push(',');

    out.push_str(&lvl.avg_cycles.to_string());
    out.push(',');
    out.push_str(&format!("{:.6}", avg_ms));
    out.push(',');

    out.push_str(&lvl.p50_cycles.to_string());
    out.push(',');
    out.push_str(&format!("{:.6}", p50_ms));
    out.push(',');

    out.push_str(&lvl.p99_cycles.to_string());
    out.push(',');
    out.push_str(&format!("{:.6}", p99_ms));
    out.push(',');

    out.push_str(&lvl.p999_cycles.to_string());
    out.push(',');
    out.push_str(&format!("{:.6}", p999_ms));
    out.push(',');

    out.push_str(&lvl.min_cycles.to_string());
    out.push(',');
    out.push_str(&format!("{:.6}", min_ms));
    out.push(',');

    out.push_str(&lvl.max_cycles.to_string());
    out.push(',');
    out.push_str(&format!("{:.6}", max_ms));
    out.push(',');

    out.push_str(&format!("{:.3}", wait_pct));
    out.push(',');
    out.push_str(&format!("{:.3}", active_pct));
    out.push(',');

    out.push_str(&format!("{:.3}", throughput_mib_s));
    out.push(',');
    out.push_str(&format!("{:.3}", iops));
    out.push('\n');
}

fn bench_sweep_append_csv_rows(
    out: &mut String,
    run_id: u32,
    trial: u32,
    mode: &str,
    requested: &BenchSweepParams,
    both: &BenchSweepBothResult,
    sweep: &BenchSweepResult,
    tsc_hz: u64,
) {
    let indirect = both.indirect_enabled != 0;
    let msix = both.msix_enabled != 0;

    let used = sweep.used as usize;
    let mut i = 0usize;
    while i < used && i < sweep.levels.len() {
        let lvl = &sweep.levels[i];
        csv_push_level(
            out,
            run_id,
            trial,
            mode,
            requested,
            &both.params_used,
            tsc_hz,
            both.queue_count,
            both.queue0_size,
            indirect,
            msix,
            *lvl,
        );
        i += 1;
    }
}

async fn open_csv_root_c_create(name: &str) -> Result<File, FileStatus> {
    let mut path_str = String::from("C:\\");
    path_str.push_str(name);

    let path = Path::from_string(&path_str);

    let flags: [OpenFlags; 3] = [
        OpenFlags::Create,
        OpenFlags::WriteOnly,
        OpenFlags::WriteThrough,
    ];

    File::open(&path, &flags).await
}

async fn write_csv_header_to_file(f: &mut File) -> Result<(), FileStatus> {
    let mut hdr = String::new();
    csv_push_header(&mut hdr);
    f.append(hdr.as_bytes()).await?;
    Ok(())
}

async fn write_csv_chunk_to_file(f: &mut File, chunk: &str) -> Result<(), FileStatus> {
    if chunk.is_empty() {
        return Ok(());
    }
    f.append(chunk.as_bytes()).await?;
    Ok(())
}

fn build_params(
    version: u32,
    flags: u32,
    total_bytes: u64,
    request_size: u32,
    start_sector: u64,
    max_inflight: u16,
) -> BenchSweepParams {
    BenchSweepParams {
        version,
        flags,
        total_bytes,
        request_size,
        start_sector,
        max_inflight,
        _reserved0: 0,
        _reserved1: 0,
    }
}

pub struct BenchSweepMatrix<'a> {
    pub version: u32,
    pub flags_list: &'a [u32],
    pub total_bytes_list: &'a [u64],
    pub request_size_list: &'a [u32],
    pub start_sector_list: &'a [u64],
    pub max_inflight_list: &'a [u16],
    pub trials: u32,
    pub discard_first_per_combo: bool,
    pub file_prefix: &'a str,
}

/// Result of a single benchmark run iteration.
pub struct BenchRunResult {
    pub run_id: u32,
    pub trial: u32,
    pub requested: BenchSweepParams,
    pub both: BenchSweepBothResult,
    pub tsc_hz: u64,
}

/// Runs the benchmark matrix and returns all results.
pub async fn bench_virtio_disk_sweep_both_matrix_run(
    matrix: &BenchSweepMatrix<'_>,
) -> Option<Vec<BenchRunResult>> {
    let target = match pnp_get_device_target("VirtIO\\Disk_0") {
        Some(t) => t,
        None => {
            println!("[virtio-bench] VirtIO disk not found");
            return None;
        }
    };

    let tsc_hz = TSC_HZ.load(Ordering::SeqCst);
    if tsc_hz == 0 {
        println!("[virtio-bench] TSC not calibrated");
        return None;
    }

    let mut results = Vec::new();
    let mut run_id: u32 = 0;

    let mut fi = 0usize;
    while fi < matrix.flags_list.len() {
        let flags = matrix.flags_list[fi];

        let mut ti = 0usize;
        while ti < matrix.total_bytes_list.len() {
            let total_bytes = matrix.total_bytes_list[ti];

            let mut ri = 0usize;
            while ri < matrix.request_size_list.len() {
                let request_size = matrix.request_size_list[ri];

                let mut si = 0usize;
                while si < matrix.start_sector_list.len() {
                    let start_sector = matrix.start_sector_list[si];

                    let mut mi = 0usize;
                    while mi < matrix.max_inflight_list.len() {
                        let max_inflight = matrix.max_inflight_list[mi];

                        let mut trial: u32 = 0;
                        while trial < matrix.trials {
                            let requested = build_params(
                                matrix.version,
                                flags,
                                total_bytes,
                                request_size,
                                start_sector,
                                max_inflight,
                            );

                            if matrix.discard_first_per_combo && trial == 0 {
                                let mut warm = RequestHandle::new(
                                    RequestType::DeviceControl(IOCTL_BLOCK_BENCH_SWEEP_BOTH),
                                    RequestData::from_t(requested),
                                );
                                warm.set_traversal_policy(TraversalPolicy::ForwardLower);
                                let _ = PNP_MANAGER.send_request(target.clone(), &mut warm).await;
                                trial += 1;
                                continue;
                            }

                            let mut req = RequestHandle::new(
                                RequestType::DeviceControl(IOCTL_BLOCK_BENCH_SWEEP_BOTH),
                                RequestData::from_t(requested),
                            );
                            req.set_traversal_policy(TraversalPolicy::ForwardLower);
                            println!(
                                "[virtio-bench] Starting trial {} for run_id {} with params: flags=0x{:X} total_bytes={} request_size={} start_sector={} max_inflight={}",
                                trial, run_id, flags, total_bytes, request_size, start_sector, max_inflight
                            );
                            let st = PNP_MANAGER.send_request(target.clone(), &mut req).await;
                            println!(
                                "[virtio-bench] Completed trial {} for run_id {} with status: {:?}",
                                trial, run_id, st
                            );
                            if st != DriverStatus::Success {
                                println!(
                                    "[virtio-bench] IOCTL_BOTH failed: {:?} (run_id={})",
                                    st, run_id
                                );
                                run_id = run_id.wrapping_add(1);
                                trial += 1;
                                continue;
                            }

                            let both = {
                                let data = req.data().read_only();
                                match data.view::<BenchSweepBothResult>() {
                                    Some(r) => *r,
                                    None => {
                                        println!(
                                            "[virtio-bench] Failed to parse BenchSweepBothResult (run_id={})",
                                            run_id
                                        );
                                        run_id = run_id.wrapping_add(1);
                                        trial += 1;
                                        continue;
                                    }
                                }
                            };

                            results.push(BenchRunResult {
                                run_id,
                                trial,
                                requested,
                                both,
                                tsc_hz,
                            });

                            run_id = run_id.wrapping_add(1);
                            trial += 1;
                        }

                        mi += 1;
                    }

                    si += 1;
                }

                ri += 1;
            }

            ti += 1;
        }

        fi += 1;
    }

    Some(results)
}

pub async fn bench_virtio_disk_sweep_both_matrix_to_csv(matrix: &BenchSweepMatrix<'_>) {
    let results = match bench_virtio_disk_sweep_both_matrix_run(matrix).await {
        Some(r) => r,
        None => return,
    };

    let mut irq_name = String::new();
    irq_name.push_str(matrix.file_prefix);
    irq_name.push_str("virtio_bench_irq_all.csv");

    let mut poll_name = String::new();
    poll_name.push_str(matrix.file_prefix);
    poll_name.push_str("virtio_bench_poll_all.csv");

    let mut request_name = String::new();
    request_name.push_str(matrix.file_prefix);
    request_name.push_str("virtio_bench_request_all.csv");

    let mut irq_f = match open_csv_root_c_create(&irq_name).await {
        Ok(f) => f,
        Err(e) => {
            println!("[virtio-bench] Failed opening C:\\{}: {:?}", irq_name, e);
            return;
        }
    };

    let mut poll_f = match open_csv_root_c_create(&poll_name).await {
        Ok(f) => f,
        Err(e) => {
            println!("[virtio-bench] Failed opening C:\\{}: {:?}", poll_name, e);
            let _ = irq_f.close().await;
            return;
        }
    };

    let mut request_f = match open_csv_root_c_create(&request_name).await {
        Ok(f) => f,
        Err(e) => {
            println!(
                "[virtio-bench] Failed opening C:\\{}: {:?}",
                request_name, e
            );
            let _ = irq_f.close().await;
            let _ = poll_f.close().await;
            return;
        }
    };

    if write_csv_header_to_file(&mut irq_f).await.is_err() {
        println!("[virtio-bench] Failed writing header to C:\\{}", irq_name);
        let _ = irq_f.close().await;
        let _ = poll_f.close().await;
        let _ = request_f.close().await;
        return;
    }
    if write_csv_header_to_file(&mut poll_f).await.is_err() {
        println!("[virtio-bench] Failed writing header to C:\\{}", poll_name);
        let _ = irq_f.close().await;
        let _ = poll_f.close().await;
        let _ = request_f.close().await;
        return;
    }
    if write_csv_header_to_file(&mut request_f).await.is_err() {
        println!(
            "[virtio-bench] Failed writing header to C:\\{}",
            request_name
        );
        let _ = irq_f.close().await;
        let _ = poll_f.close().await;
        let _ = request_f.close().await;
        return;
    }

    for res in &results {
        let mut irq_chunk = String::new();
        bench_sweep_append_csv_rows(
            &mut irq_chunk,
            res.run_id,
            res.trial,
            "irq",
            &res.requested,
            &res.both,
            &res.both.irq,
            res.tsc_hz,
        );

        let mut poll_chunk = String::new();
        bench_sweep_append_csv_rows(
            &mut poll_chunk,
            res.run_id,
            res.trial,
            "poll",
            &res.requested,
            &res.both,
            &res.both.poll,
            res.tsc_hz,
        );

        let mut request_chunk = String::new();
        bench_sweep_append_csv_rows(
            &mut request_chunk,
            res.run_id,
            res.trial,
            "request",
            &res.requested,
            &res.both,
            &res.both.request,
            res.tsc_hz,
        );

        if write_csv_chunk_to_file(&mut irq_f, &irq_chunk)
            .await
            .is_err()
        {
            println!("[virtio-bench] Failed writing C:\\{}", irq_name);
            let _ = irq_f.close().await;
            let _ = poll_f.close().await;
            let _ = request_f.close().await;
            return;
        }
        if write_csv_chunk_to_file(&mut poll_f, &poll_chunk)
            .await
            .is_err()
        {
            println!("[virtio-bench] Failed writing C:\\{}", poll_name);
            let _ = irq_f.close().await;
            let _ = poll_f.close().await;
            let _ = request_f.close().await;
            return;
        }
        if write_csv_chunk_to_file(&mut request_f, &request_chunk)
            .await
            .is_err()
        {
            println!("[virtio-bench] Failed writing C:\\{}", request_name);
            let _ = irq_f.close().await;
            let _ = poll_f.close().await;
            let _ = request_f.close().await;
            return;
        }

        let _ = irq_f.flush().await;
        let _ = poll_f.flush().await;
        let _ = request_f.flush().await;
    }

    let _ = irq_f.close().await;
    let _ = poll_f.close().await;
    let _ = request_f.close().await;

    println!(
        "[virtio-bench] Wrote C:\\{}, C:\\{}, and C:\\{}",
        irq_name, poll_name, request_name
    );
}

fn format_size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        let mut s = String::new();
        s.push_str(&format!("{:.1}", bytes as f64 / (1024.0 * 1024.0 * 1024.0)));
        s.push_str(" GiB");
        s
    } else if bytes >= 1024 * 1024 {
        let mut s = String::new();
        s.push_str(&format!("{:.1}", bytes as f64 / (1024.0 * 1024.0)));
        s.push_str(" MiB");
        s
    } else if bytes >= 1024 {
        let mut s = String::new();
        s.push_str(&format!("{:.1}", bytes as f64 / 1024.0));
        s.push_str(" KiB");
        s
    } else {
        let mut s = String::new();
        s.push_str(&bytes.to_string());
        s.push_str(" B");
        s
    }
}

fn print_level_table_row(mode: &str, lvl: &BenchLevelResult, request_size: u32, tsc_hz: u64) {
    let tsc_hz_f = tsc_hz as f64;
    let avg_ms = (lvl.avg_cycles as f64 / tsc_hz_f) * 1000.0;
    let p50_ms = (lvl.p50_cycles as f64 / tsc_hz_f) * 1000.0;
    let p99_ms = (lvl.p99_cycles as f64 / tsc_hz_f) * 1000.0;
    let min_ms = (lvl.min_cycles as f64 / tsc_hz_f) * 1000.0;
    let max_ms = (lvl.max_cycles as f64 / tsc_hz_f) * 1000.0;
    let total_ms = (lvl.total_time_cycles as f64 / tsc_hz_f) * 1000.0;
    let throughput_mib_s = if lvl.total_time_cycles != 0 {
        let bytes = lvl.request_count as f64 * request_size as f64;
        let secs = lvl.total_time_cycles as f64 / tsc_hz_f;
        (bytes / (1024.0 * 1024.0)) / secs
    } else {
        0.0
    };

    let wait_pct = lvl.idle_pct;

    println!(
        "| {:>4} | {:>8} | {:>10} | {:>10.3} | {:>8.3} | {:>8.3} | {:>8.3} | {:>8.3} | {:>8.3} | {:>8.3} | {:>6.1}% |",
        mode,
        lvl.inflight,
        lvl.request_count,
        total_ms,
        avg_ms,
        p50_ms,
        p99_ms,
        throughput_mib_s,
        min_ms,
        max_ms,
        wait_pct,
    );
}

fn print_bench_result_table(res: &BenchRunResult) {
    let req = &res.requested;
    let both = &res.both;

    println!();
    println!(
        "+-----------------------------------------------------------------------------------+"
    );
    println!(
        "|                          VirtIO Disk Benchmark Results                           |"
    );
    println!(
        "+-----------------------------------------------------------------------------------+"
    );
    println!(
        "| Run ID: {:>4}  | Trial: {:>3}  | Flags: 0x{:04X}                                   |",
        res.run_id, res.trial, req.flags
    );
    println!(
        "| Total: {:>12}  | Request Size: {:>10}  | Start Sector: {:>10} |",
        format_size(both.params_used.total_bytes),
        format_size(both.params_used.request_size as u64),
        both.params_used.start_sector
    );
    println!(
        "| Queues: {:>2}  | Queue0 Size: {:>4}  | Indirect: {:>3}  | MSI-X: {:>3}             |",
        both.queue_count,
        both.queue0_size,
        if both.indirect_enabled != 0 {
            "Yes"
        } else {
            "No"
        },
        if both.msix_enabled != 0 { "Yes" } else { "No" }
    );
    println!("+------+----------+------------+------------+----------+----------+----------+----------+----------+----------+---------+");
    println!("| Mode | Inflight |   Requests |  Total(ms) |  Avg(ms) |  P50(ms) |  P99(ms) |    MiB/s |  Min(ms) |  Max(ms) |  Wait%  |");
    println!("+------+----------+------------+------------+----------+----------+----------+----------+----------+----------+---------+");

    let irq_used = both.irq.used as usize;
    let mut i = 0usize;
    while i < irq_used && i < both.irq.levels.len() {
        print_level_table_row(
            "IRQ",
            &both.irq.levels[i],
            both.params_used.request_size,
            res.tsc_hz,
        );
        i += 1;
    }

    let poll_used = both.poll.used as usize;
    i = 0;
    while i < poll_used && i < both.poll.levels.len() {
        print_level_table_row(
            "POLL",
            &both.poll.levels[i],
            both.params_used.request_size,
            res.tsc_hz,
        );
        i += 1;
    }

    let request_used = both.request.used as usize;
    i = 0;
    while i < request_used && i < both.request.levels.len() {
        print_level_table_row(
            "REQ",
            &both.request.levels[i],
            both.params_used.request_size,
            res.tsc_hz,
        );
        i += 1;
    }

    println!("+------+----------+------------+------------+----------+----------+----------+----------+----------+----------+---------+");
}

/// Runs the benchmark matrix and prints results as a clean user-readable table.
pub async fn bench_virtio_disk_sweep_both_matrix_to_table(matrix: &BenchSweepMatrix<'_>) {
    let results = match bench_virtio_disk_sweep_both_matrix_run(matrix).await {
        Some(r) => r,
        None => return,
    };

    for res in &results {
        print_bench_result_table(res);
    }

    println!();
    println!("[virtio-bench] Completed {} benchmark runs", results.len());
}

pub async fn bench_virtio_disk_sweep_both_to_csv(params: BenchSweepParams) {
    let flags_list: [u32; 1] = [params.flags];
    let total_bytes_list: [u64; 1] = [params.total_bytes];
    let request_size_list: [u32; 1] = [params.request_size];
    let start_sector_list: [u64; 1] = [params.start_sector];
    let max_inflight_list: [u16; 1] = [params.max_inflight];

    let matrix = BenchSweepMatrix {
        version: params.version,
        flags_list: &flags_list,
        total_bytes_list: &total_bytes_list,
        request_size_list: &request_size_list,
        start_sector_list: &start_sector_list,
        max_inflight_list: &max_inflight_list,
        trials: 1,
        discard_first_per_combo: false,
        file_prefix: "",
    };

    bench_virtio_disk_sweep_both_matrix_to_csv(&matrix).await;
}
pub async fn run_virtio_bench_matrix() {
    let flags_list: [u32; 1] = [BENCH_FLAG_IRQ | BENCH_FLAG_POLL | BENCH_FLAG_REQUEST];
    let total_bytes_list: [u64; 1] = [4 * 1024 * 1024 * 1024];

    let request_size_list: [u32; _] = [
        4 * 1024,
        8 * 1024,
        16 * 1024,
        64 * 1024,
        256 * 1024,
        1024 * 1024,
        4 * 1024 * 1024,
    ];

    let start_sector_list: [u64; _] = [
        0,
        // 2 * 1024 * 1024,
        // 4 * 1024 * 1024,
        // 8 * 1024 * 1024
    ];

    let max_inflight_list: [u16; _] = [0];

    let matrix = BenchSweepMatrix {
        version: BENCH_PARAMS_VERSION_1,
        flags_list: &flags_list,
        total_bytes_list: &total_bytes_list,
        request_size_list: &request_size_list,
        start_sector_list: &start_sector_list,
        max_inflight_list: &max_inflight_list,
        trials: 3,
        discard_first_per_combo: false,
        file_prefix: "exp1_",
    };

    bench_virtio_disk_sweep_both_matrix_to_csv(&matrix).await;
}
pub async fn run_virtio_bench_matrix_print() {
    let flags_list: [u32; 1] = [BENCH_FLAG_IRQ | BENCH_FLAG_POLL | BENCH_FLAG_REQUEST];
    let total_bytes_list: [u64; 1] = [10 * 1024 * 1024];

    let request_size_list: [u32; _] = [
        1 * 1024,
        //4 * 1024,
        // 8 * 1024,
        // 16 * 1024,
        //
        //64 * 1024,
        // 256 * 1024,
        // 1024 * 1024,
        //4 * 1024 * 1024,
    ];

    let start_sector_list: [u64; _] = [
        0,
        // 2 * 1024 * 1024,
        // 4 * 1024 * 1024,
        // 8 * 1024 * 1024
    ];

    let max_inflight_list: [u16; _] = [0];

    let matrix = BenchSweepMatrix {
        version: BENCH_PARAMS_VERSION_1,
        flags_list: &flags_list,
        total_bytes_list: &total_bytes_list,
        request_size_list: &request_size_list,
        start_sector_list: &start_sector_list,
        max_inflight_list: &max_inflight_list,
        trials: 1,
        discard_first_per_combo: false,
        file_prefix: "exp1_",
    };
    bench_virtio_disk_sweep_both_matrix_to_table(&matrix).await;
}
fn console_print_header() {
    let mut hdr = String::new();
    csv_push_header(&mut hdr);
    println!("{}", hdr.trim_end_matches('\n'));
}
