use crate::alloc::format;
use crate::drivers::interrupt_index::{self, TSC_HZ};
use crate::drivers::timer_driver::{PER_CORE_SWITCHES, TIMER_TIME_SCHED};
use crate::file_system::file::File;
use crate::memory::{
    heap::HEAP_SIZE,
    paging::frame_alloc::{total_usable_bytes, USED_MEMORY},
};
use crate::scheduling::runtime::runtime::{
    block_on, spawn, spawn_blocking, spawn_blocking_many, spawn_detached, JoinAll,
};
use crate::static_handlers::wait_duration;
use crate::structs::stopwatch::Stopwatch;
use crate::util::{boot_info, TOTAL_TIME};
use crate::{cpu, print, println, vec};

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write;
use core::future::Future;
use core::hint::black_box;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use core::task::{Context, Poll};
use core::time::Duration;
use kernel_types::benchmark::BenchWindowConfig;
use kernel_types::fs::{FsSeekWhence, OpenFlags, Path};
use kernel_types::status::FileStatus;
use spin::{Mutex, Once};
use x86_64::instructions::interrupts;

//const BENCH_ENABLED: bool = cfg!(debug_assertions);
const BENCH_ENABLED: bool = false;

const MAX_STACK_DEPTH: usize = 8;
const BENCH_RING_CAPACITY: usize = 8192;

// ===== Global event stream =====

#[derive(Clone, Copy, Debug)]
struct BenchSampleEvent {
    rip: u64,
    depth: u8,
    stack: [u64; MAX_STACK_DEPTH],
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

#[derive(Clone, Copy, Debug)]
enum BenchEventData {
    None,
    Sample(BenchSampleEvent),
    Span(BenchSpanEvent),
    Metrics(BenchMetricsEvent),
}

impl Default for BenchEventData {
    fn default() -> Self {
        BenchEventData::None
    }
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

struct BenchRing {
    next_seq: u64,
    buffer: Vec<BenchEvent>,
}

impl BenchRing {
    fn new(initial_capacity: usize) -> Self {
        BenchRing {
            next_seq: 1,
            buffer: Vec::with_capacity(initial_capacity),
        }
    }

    fn log(&mut self, mut event: BenchEvent) {
        event.seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        self.buffer.push(event);
    }
}

struct BenchState {
    rings: Vec<Mutex<BenchRing>>,
    next_span_id: AtomicU32,
}

impl BenchState {
    fn new() -> Self {
        let cores = unsafe { TIMER_TIME_SCHED.iter() }.count().max(1);
        let mut rings = Vec::with_capacity(cores);
        for _ in 0..cores {
            rings.push(Mutex::new(BenchRing::new(BENCH_RING_CAPACITY)));
        }
        BenchState {
            rings,
            next_span_id: AtomicU32::new(1),
        }
    }

    fn ring_for_core(&self, core: usize) -> Option<&Mutex<BenchRing>> {
        self.rings.get(core)
    }

    fn alloc_span_id(&self) -> u32 {
        self.next_span_id.fetch_add(1, Ordering::Relaxed)
    }

    fn ncores(&self) -> usize {
        self.rings.len().max(1)
    }
}

static BENCH_STATE: Once<BenchState> = Once::new();
static BENCH_READY: AtomicBool = AtomicBool::new(false);

static METRICS_REFCOUNT: AtomicU32 = AtomicU32::new(0);

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

fn bench_capture_metrics(core_id: usize, ts: u64) {
    if !BENCH_ENABLED || !bench_metrics_enabled() {
        return;
    }

    let heap_used = interrupts::without_interrupts(|| used_memory()) as u64;

    let mut used_bytes = USED_MEMORY.load(Ordering::SeqCst) as u64;
    used_bytes = used_bytes.saturating_add(boot_info().kernel_len as u64);
    let total_bytes = total_usable_bytes() as u64;

    let heap_total_bytes = HEAP_SIZE as u64;

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
    if !BENCH_ENABLED {
        return;
    }
    return;
    let ts = bench_now_ns();

    let mut sample = BenchSampleEvent {
        rip,
        depth: 0,
        stack: [0; MAX_STACK_DEPTH],
    };

    let depth = stack.len().min(MAX_STACK_DEPTH);
    sample.depth = depth as u8;
    for i in 0..depth {
        sample.stack[i] = stack[i];
    }

    let event = BenchEvent {
        seq: 0,
        timestamp_ns: ts,
        core_id: core_id as u16,
        kind: BenchEventKind::Sample,
        data: BenchEventData::Sample(sample),
    };

    bench_log_event_for_core(core_id, event);
    bench_capture_metrics(core_id, ts);
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
    g.log(event);
}

#[inline]
fn bench_capture_metrics_try(core_id: usize, ts: u64) {
    if !BENCH_ENABLED || !bench_metrics_enabled() {
        return;
    }

    let heap_used = interrupts::without_interrupts(|| used_memory()) as u64;

    let mut used_bytes = USED_MEMORY.load(Ordering::SeqCst) as u64;
    used_bytes = used_bytes.saturating_add(boot_info().kernel_len as u64);
    let total_bytes = total_usable_bytes() as u64;

    let heap_total_bytes = HEAP_SIZE as u64;

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

pub fn bench_submit_rip_sample_current_core(rip: u64, stack_ptr: *const u64, stack_len: usize) {
    if !BENCH_ENABLED {
        return;
    }
    return;
    if !BENCH_READY.load(Ordering::Acquire) {
        return;
    }

    let stack = if stack_ptr.is_null() || stack_len == 0 || !stack_ptr.is_aligned_to(8) {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(stack_ptr, stack_len) }
    };

    let core_id = interrupt_index::current_cpu_id() as usize;
    let ts = bench_now_ns();

    let mut sample = BenchSampleEvent {
        rip,
        depth: 0,
        stack: [0; MAX_STACK_DEPTH],
    };

    let depth = stack.len().min(MAX_STACK_DEPTH);
    sample.depth = depth as u8;
    for i in 0..depth {
        sample.stack[i] = stack[i];
    }

    let event = BenchEvent {
        seq: 0,
        timestamp_ns: ts,
        core_id: core_id as u16,
        kind: BenchEventKind::Sample,
        data: BenchEventData::Sample(sample),
    };

    bench_log_event_for_core_try(core_id, event);
    bench_capture_metrics_try(core_id, ts);
}

// ===== Spans =====

fn bench_alloc_span_id() -> Option<u32> {
    bench_state().map(|s| s.alloc_span_id())
}

fn bench_log_span_begin(span_id: u32, tag: &'static str, object_id: u64) {
    if !BENCH_ENABLED {
        return;
    }

    let core_id = interrupt_index::current_cpu_id() as usize;
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
    if !BENCH_ENABLED {
        return;
    }

    let core_id = interrupt_index::current_cpu_id() as usize;
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
        if !BENCH_ENABLED {
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
    session_dir: String,
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
    name[8..].parse::<u32>().ok()
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
    let session_dir = join_path2(root, &format!("session_{new_id}"));

    let _ = File::make_dir(&Path::from_string(&session_dir)).await;
    let cores_dir = join_path2(&session_dir, "cores");
    let avg_dir = join_path2(&session_dir, "avg");
    let avg_windows_dir = join_path2(&avg_dir, "windows");
    let _ = File::make_dir(&Path::from_string(&cores_dir)).await;
    let _ = File::make_dir(&Path::from_string(&avg_dir)).await;
    let _ = File::make_dir(&Path::from_string(&avg_windows_dir)).await;

    let ncores = bench_ncores();
    for i in 0..ncores {
        let core_dir = join_path2(&cores_dir, &format!("core-{i}"));
        let _ = File::make_dir(&Path::from_string(&core_dir)).await;
        let _ = File::make_dir(&Path::from_string(&join_path2(&core_dir, "windows"))).await;
    }

    let info = BenchSessionInfo {
        session_dir,
        ncores,
    };

    let mut reg = session_registry().lock();
    reg.insert(root.to_string(), info.clone());
    info
}

async fn compute_next_window_suffix_async(windows_root_avg: &str, name: &str) -> u32 {
    let entries = File::list_dir(&Path::from_string(windows_root_avg))
        .await
        .unwrap_or_else(|_| Vec::new());
    let mut has_base = false;
    let mut max_suffix: u32 = 0;

    for entry in entries {
        let e = basename(&entry);

        if e == name {
            has_base = true;
            continue;
        }
        if e.starts_with(name) {
            let rest = &e[name.len()..];
            if rest.starts_with('-') {
                let suffix = &rest[1..];
                if let Ok(n) = suffix.parse::<u32>() {
                    if n > max_suffix {
                        max_suffix = n;
                    }
                }
            }
        }
    }

    if !has_base {
        0
    } else {
        max_suffix.saturating_add(1).max(1)
    }
}
async fn allocate_window_name_async(session_dir: &str, name: &str, ncores: usize) -> String {
    let windows_avg = join_path2(&join_path2(session_dir, "avg"), "windows");

    let mut reg = window_dir_registry().lock();
    let mut key = String::new();
    key.push_str(session_dir);
    key.push('|');
    key.push_str(name);

    let suffix = match reg.get(&key).copied() {
        Some(v) => v,
        None => compute_next_window_suffix_async(&windows_avg, name).await,
    };

    let window_dir = if suffix == 0 {
        name.to_string()
    } else {
        format!("{name}-{suffix}")
    };

    reg.insert(key, suffix.saturating_add(1));
    drop(reg);

    let avg_win = join_path2(&windows_avg, &window_dir);
    let _ = File::make_dir(&Path::from_string(&avg_win)).await;

    for i in 0..ncores {
        let core_windows = join_path2(
            &join_path2(&join_path2(session_dir, "cores"), &format!("core-{i}")),
            "windows",
        );
        let core_win = join_path2(&core_windows, &window_dir);
        let _ = File::make_dir(&Path::from_string(&core_win)).await;
    }

    window_dir
}
fn window_path_for_target(
    session_dir: &str,
    window_dir: &str,
    target: usize,
    ncores: usize,
) -> String {
    if target == ncores {
        join_path2(
            &join_path2(&join_path2(session_dir, "avg"), "windows"),
            window_dir,
        )
    } else {
        let base = join_path2(
            &join_path2(&join_path2(session_dir, "cores"), &format!("core-{target}")),
            "windows",
        );
        join_path2(&base, window_dir)
    }
}

// ===== Export build (cursor-based; persist "clears" by advancing last_export_seq) =====

struct ExportBundle {
    samples_rows: Vec<String>,
    spans_rows: Vec<String>,
    mem_rows: Vec<String>,  // includes heap+mem+sched counters per event
    max_seq_seen: Vec<u64>, // per core
}

#[derive(Clone, Copy)]
struct SpanRowRec {
    tag: &'static str,
    object_id: u64,
    start_core: u16,
    start_ts: u64,
    dur: u64,
}

fn make_empty_bundle(ncores: usize) -> ExportBundle {
    let mut samples_rows = Vec::with_capacity(ncores + 1);
    let mut spans_rows = Vec::with_capacity(ncores + 1);
    let mut mem_rows = Vec::with_capacity(ncores + 1);

    for _ in 0..(ncores + 1) {
        samples_rows.push(String::new());
        spans_rows.push(String::new());
        mem_rows.push(String::new());
    }

    ExportBundle {
        samples_rows,
        spans_rows,
        mem_rows,
        max_seq_seen: vec![0u64; ncores],
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

fn write_sample_row(
    row: &mut String,
    run_id: u32,
    ts: u64,
    core_id: u16,
    rip: u64,
    depth: u16,
    stack: &[u64; MAX_STACK_DEPTH],
) {
    let _ = core::write!(
        row,
        "{},{},{},0x{:016x},{}",
        run_id,
        ts,
        core_id,
        rip,
        depth
    );

    let depth = depth as usize;
    for di in 0..MAX_STACK_DEPTH {
        if di < depth {
            let v = stack[di];
            let _ = core::write!(row, ",0x{:016x}", v);
        } else {
            row.push(',');
        }
    }

    row.push('\n');
}

fn write_metrics_row(row: &mut String, run_id: u32, ts: u64, core_id: u16, m: &BenchMetricsEvent) {
    let _ = core::write!(
        row,
        "{},{},{},{},{},{},{},{},{}\n",
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
    let _ = core::write!(
        row,
        "{},{},0x{:016x},{},{},{}\n",
        run_id,
        tag,
        object_id,
        start_core,
        start_ts,
        dur
    );
}
pub async fn build_exports_for_window(
    cfg: &BenchWindowConfig,
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
                Some(self.events[idx])
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
        let st = state.clone();
        let last_seq = *last_export_seq.get(core).unwrap_or(&0);

        gather_joins.push(crate::scheduling::runtime::runtime::spawn_blocking(
            move || -> Vec<BenchEvent> {
                let ring_m = match st.ring_for_core(core) {
                    Some(r) => r,
                    None => return Vec::new(),
                };

                let mut ring = ring_m.lock();
                let mut out = Vec::new();

                for ev in ring.buffer.iter() {
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

                    out.push(*ev);
                }

                ring.buffer.clear();

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

    let desired_chunks = ncores.max(4);
    let min_chunk_size = 256usize;
    let chunks = core::cmp::min(
        desired_chunks,
        (total_events + min_chunk_size - 1) / min_chunk_size,
    )
    .max(1);
    let chunk_size = (total_events + chunks - 1) / chunks;

    let mut out = Vec::with_capacity(chunks);
    for _ in 0..chunks {
        out.push(make_empty_bundle(ncores));
    }

    let k = iterators.len();
    let mut heap: Vec<(u64, u16, u64, usize)> = Vec::with_capacity(k);

    for (iter_idx, iter) in iterators.iter().enumerate() {
        if let Some(ev) = iter.peek() {
            heap.push((ev.timestamp_ns, ev.core_id, ev.seq, iter_idx));
        }
    }
    heap_build(&mut heap);

    let avg = ncores;
    let mut global_idx = 0usize;
    let shrink_interval = 2048usize;

    while !heap.is_empty() {
        let (_, _, _, iter_idx) = heap[0];

        let iter = &mut iterators[iter_idx];
        let scan_core = iter.core;
        let ev = iter.pop().unwrap();

        if global_idx % shrink_interval == 0 {
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
                    write_sample_row(
                        &mut bundle.samples_rows[scan_core],
                        run_id,
                        ev.timestamp_ns,
                        ev.core_id,
                        s.rip,
                        s.depth.into(),
                        &s.stack,
                    );
                    write_sample_row(
                        &mut bundle.samples_rows[avg],
                        run_id,
                        ev.timestamp_ns,
                        ev.core_id,
                        s.rip,
                        s.depth.into(),
                        &s.stack,
                    );
                }
            }
            BenchEventKind::Metrics if want_mem_stream => {
                if let BenchEventData::Metrics(m) = ev.data {
                    write_metrics_row(
                        &mut bundle.mem_rows[scan_core],
                        run_id,
                        ev.timestamp_ns,
                        ev.core_id,
                        &m,
                    );
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
                        if start_idx < ncores {
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

    session_dir: String,
    window_dir: String,
    ncores: usize,

    running: bool,
    start_ns: u64,
    stop_ns: Option<u64>,

    run_id_counter: u32,
    current_run_id: u32,

    last_export_seq: Vec<u64>,

    samples_header_written: Vec<bool>,
    spans_header_written: Vec<bool>,
    mem_header_written: Vec<bool>,

    open_spans: BTreeMap<u32, (BenchSpanEvent, u64, u16)>,
}

impl BenchWindowInner {
    fn new(cfg: BenchWindowConfig, session_dir: String, window_dir: String, ncores: usize) -> Self {
        BenchWindowInner {
            cfg,
            session_dir,
            window_dir,
            ncores,
            running: false,
            start_ns: 0,
            stop_ns: None,
            run_id_counter: 1,
            current_run_id: 0,
            last_export_seq: vec![0; ncores],
            samples_header_written: vec![false; ncores + 1],
            spans_header_written: vec![false; ncores + 1],
            mem_header_written: vec![false; ncores + 1],
            open_spans: BTreeMap::new(),
        }
    }

    fn reset_run_state(&mut self) {
        self.last_export_seq.fill(0);
        for v in &mut self.samples_header_written {
            *v = false;
        }
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
        if !BENCH_ENABLED {
            let inner = BenchWindowInner::new(cfg, String::new(), String::new(), 1);
            return BenchWindow {
                inner: Arc::new(Mutex::new(inner)),
                init_state: Arc::new(AtomicU32::new(INIT_READY)),
            };
        }

        if cfg.log_mem_on_persist {
            METRICS_REFCOUNT.fetch_add(1, Ordering::Relaxed);
        }

        let ncores = bench_ncores();
        let inner = BenchWindowInner::new(cfg, String::new(), String::new(), ncores);

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

        let (folder, name, ncores) = {
            let inner = self.inner.lock();
            (inner.cfg.folder, inner.cfg.name, inner.ncores)
        };

        let session = ensure_session_async(folder).await;
        let window_dir =
            allocate_window_name_async(&session.session_dir, name, session.ncores).await;

        {
            let mut inner = self.inner.lock();
            if inner.session_dir.is_empty() {
                inner.session_dir = session.session_dir;
                inner.window_dir = window_dir;
                inner.ncores = session.ncores;
            }
        }

        self.init_state.store(INIT_READY, Ordering::Release);
        true
    }
    pub fn start(&self) {
        if !BENCH_ENABLED {
            return;
        }

        let auto_persist_secs_opt;
        let timeout_ms_opt;

        {
            let mut inner = self.inner.lock();
            if inner.running {
                return;
            }

            inner.running = true;
            inner.start_ns = bench_now_ns();
            inner.stop_ns = None;

            inner.current_run_id = inner.run_id_counter;
            inner.run_id_counter = inner.run_id_counter.wrapping_add(1);

            inner.reset_run_state();

            auto_persist_secs_opt = inner.cfg.auto_persist_secs;
            timeout_ms_opt = inner.cfg.timeout_ms;
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
        let mut inner = self.inner.lock();
        if !inner.running {
            return;
        }
        inner.running = false;
        inner.stop_ns = Some(bench_now_ns());
    }

    pub fn span_guard(&self, tag: &'static str, object_id: u64) -> BenchSpanGuard {
        BenchSpanGuard::new(tag, object_id)
    }

    pub async fn persist(&self) {
        use alloc::sync::Arc;

        if !BENCH_ENABLED {
            return;
        }
        if !self.ensure_fs_ready().await {
            return;
        }

        let cfg: BenchWindowConfig;
        let run_id: u32;
        let start_ns: u64;
        let to_ns: u64;

        let session_dir: String;
        let window_dir: String;
        let ncores: usize;

        let last_export_seq: Vec<u64>;
        let mut samples_header_written: Vec<bool>;
        let mut spans_header_written: Vec<bool>;
        let mut mem_header_written: Vec<bool>;

        let mut open_spans: BTreeMap<u32, (BenchSpanEvent, u64, u16)>;

        {
            let inner = self.inner.lock();
            if inner.start_ns == 0 {
                return;
            }

            cfg = inner.cfg.clone();
            run_id = inner.current_run_id;

            start_ns = inner.start_ns;
            to_ns = match inner.stop_ns {
                Some(stop) => stop,
                None => bench_now_ns(),
            };

            session_dir = inner.session_dir.clone();
            window_dir = inner.window_dir.clone();
            ncores = inner.ncores;

            last_export_seq = inner.last_export_seq.clone();
            samples_header_written = inner.samples_header_written.clone();
            spans_header_written = inner.spans_header_written.clone();
            mem_header_written = inner.mem_header_written.clone();

            open_spans = inner.open_spans.clone();
        }

        if start_ns >= to_ns {
            return;
        }

        let exports_vec = build_exports_for_window(
            &cfg,
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

        let exports = Arc::new(exports_vec);

        let mut joins = Vec::new();

        if cfg.log_samples {
            let header: &'static str = "run_id,timestamp_ns,core,rip,depth,frame0,frame1,frame2,frame3,frame4,frame5,frame6,frame7\n";

            for target in 0..(ncores + 1) {
                let ex = exports.clone();
                let session_dir = session_dir.clone();
                let window_dir = window_dir.clone();
                let mut header_written = samples_header_written[target];

                joins.push(crate::scheduling::runtime::runtime::spawn(async move {
                    let path = window_path_for_target(&session_dir, &window_dir, target, ncores);
                    let file_name = format!("run_{run_id}_samples.csv");

                    for b in ex.iter() {
                        let rows = &b.samples_rows[target];
                        if rows.is_empty() {
                            continue;
                        }

                        if !header_written {
                            let mut csv = String::new();
                            csv.push_str(header);
                            csv.push_str(rows);
                            if append_named_file(&path, &file_name, csv.as_bytes())
                                .await
                                .is_err()
                            {
                                return (false, target, header_written);
                            }
                            header_written = true;
                        } else {
                            if append_named_file(&path, &file_name, rows.as_bytes())
                                .await
                                .is_err()
                            {
                                return (false, target, header_written);
                            }
                        }
                    }

                    (true, target, header_written)
                }));
            }
        }

        if cfg.log_spans {
            let header: &'static str = "run_id,tag,object_id,core,start_ns,duration_ns\n";

            for target in 0..(ncores + 1) {
                let ex = exports.clone();
                let session_dir = session_dir.clone();
                let window_dir = window_dir.clone();
                let mut header_written = spans_header_written[target];

                joins.push(crate::scheduling::runtime::runtime::spawn(async move {
                    let path = window_path_for_target(&session_dir, &window_dir, target, ncores);
                    let file_name = format!("run_{run_id}_spans.csv");

                    for b in ex.iter() {
                        let rows = &b.spans_rows[target];
                        if rows.is_empty() {
                            continue;
                        }

                        if !header_written {
                            let mut csv = String::new();
                            csv.push_str(header);
                            csv.push_str(rows);
                            if append_named_file(&path, &file_name, csv.as_bytes())
                                .await
                                .is_err()
                            {
                                return (false, target, header_written);
                            }
                            header_written = true;
                        } else {
                            if append_named_file(&path, &file_name, rows.as_bytes())
                                .await
                                .is_err()
                            {
                                return (false, target, header_written);
                            }
                        }
                    }

                    (true, target, header_written)
                }));
            }
        }

        if cfg.log_mem_on_persist {
            let header: &'static str = "run_id,timestamp_ns,core,used_bytes,total_bytes,heap_used_bytes,heap_total_bytes,core_sched_ns,core_switches\n";

            for target in 0..(ncores + 1) {
                let ex = exports.clone();
                let session_dir = session_dir.clone();
                let window_dir = window_dir.clone();
                let mut header_written = mem_header_written[target];

                joins.push(crate::scheduling::runtime::runtime::spawn(async move {
                    let path = window_path_for_target(&session_dir, &window_dir, target, ncores);
                    let file_name = format!("run_{run_id}_memory.csv");

                    for b in ex.iter() {
                        let rows = &b.mem_rows[target];
                        if rows.is_empty() {
                            continue;
                        }

                        if !header_written {
                            let mut csv = String::new();
                            csv.push_str(header);
                            csv.push_str(rows);
                            if append_named_file(&path, &file_name, csv.as_bytes())
                                .await
                                .is_err()
                            {
                                return (false, target, header_written);
                            }
                            header_written = true;
                        } else {
                            if append_named_file(&path, &file_name, rows.as_bytes())
                                .await
                                .is_err()
                            {
                                return (false, target, header_written);
                            }
                        }
                    }

                    (true, target, header_written)
                }));
            }
        }

        let mut ok = true;
        let results = JoinAll::new(joins).await;

        for (this_ok, target, header_written) in results {
            if !this_ok {
                ok = false;
                continue;
            }

            if cfg.log_samples {
                samples_header_written[target] = header_written;
            }
            if cfg.log_spans {
                spans_header_written[target] = header_written;
            }
            if cfg.log_mem_on_persist {
                mem_header_written[target] = header_written;
            }
        }

        if !ok {
            return;
        }

        let mut merged_max_seq = vec![0u64; ncores];
        for b in exports.iter() {
            for i in 0..ncores {
                let s = b.max_seq_seen[i];
                if s > merged_max_seq[i] {
                    merged_max_seq[i] = s;
                }
            }
        }

        let mut inner = self.inner.lock();
        inner.samples_header_written = samples_header_written;
        inner.spans_header_written = spans_header_written;
        inner.mem_header_written = mem_header_written;

        inner.open_spans = open_spans;

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
        let mut dec_metrics = false;

        {
            let mut inner = self.inner.lock();
            if inner.running && inner.cfg.end_on_drop {
                inner.running = false;
                inner.stop_ns = Some(bench_now_ns());
                do_flush = true;
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

    let mut file = match File::open(&file_path, &[OpenFlags::Create]).await {
        Ok(f) => f,
        Err(_) => File::open(&file_path, &[OpenFlags::Open])
            .await
            .map_err(|_| ())?,
    };

    if file.seek(0, FsSeekWhence::End).await.is_err() {
        return Err(());
    }

    file.write(data).await.map_err(|_| ())?;
    file.close().await;
    Ok(())
}

pub fn used_memory() -> usize {
    // HEAP_SIZE - ALLOCATOR.free_memory()
    0
}

const DEPTH: usize = 1_000;
const ITERS: usize = 50_000;

const BLOCK_TASKS: usize = 50000;

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
        let ret = sync_chain(x);
        if ret % 10_000 == 0 {
            //println!("blocking done num: {}", ret);
        }
        ret
    })
    .await
}

#[inline(never)]
async fn blocking_queue_stress(seed: u64) -> u64 {
    let mut funcs = Vec::with_capacity(BLOCK_TASKS);
    for i in 0..BLOCK_TASKS {
        let x = seed.wrapping_add(i as u64);
        funcs.push(move || {
            let ret = sync_chain(x);
            if ret % 10_000 == 0 {
                //println!("blocking done num: {}", ret);
            }
            ret
        });
    }

    let joins = spawn_blocking_many(funcs);
    let _results = JoinAll::new(joins).await;
    BLOCK_TASKS as u64
}

#[inline(always)]
fn ms_fixed_3(micros: u64) -> (u64, u16) {
    let ms = micros / 1_000;
    let frac = (micros % 1_000) as u16;
    (ms, frac)
}

#[inline(always)]
fn div_u64_round(n: u64, d: u64) -> u64 {
    if d == 0 {
        return 0;
    }
    (n + (d / 2)) / d
}

#[inline(always)]
fn div_u128_round(n: u128, d: u128) -> u128 {
    if d == 0 {
        return 0;
    }
    (n + (d / 2)) / d
}

#[inline(always)]
fn sub_i64(a: u64, b: u64) -> i64 {
    a as i64 - b as i64
}

#[inline(always)]
fn ratio_1e3(num: u64, den: u64) -> u64 {
    if den == 0 {
        return 0;
    }
    div_u128_round((num as u128) * 1000u128, den as u128) as u64
}

#[inline(always)]
fn frac_1e3(part: i64, whole: u64) -> i64 {
    if whole == 0 {
        return 0;
    }
    ((part as i128) * 1000i128 / (whole as i128)) as i64
}

async fn bench_async_vs_sync_call_latency_async() {
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
    for _ in 0..2_000 {
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

    let sync_us_per_chain = div_u64_round(sync_us, iters_u64);
    let async_us_per_chain = div_u64_round(async_us, iters_u64);
    let blk_us_per_chain = div_u64_round(blk_us, iters_u64);

    let sync_ns_per_inner =
        div_u128_round((sync_us as u128) * 1000u128, inner_calls_u64 as u128) as u64;
    let async_ns_per_inner =
        div_u128_round((async_us as u128) * 1000u128, inner_calls_u64 as u128) as u64;

    let (sync_ms, sync_ms_frac) = ms_fixed_3(sync_us);
    let (async_ms, async_ms_frac) = ms_fixed_3(async_us);
    let (blk_ms, blk_ms_frac) = ms_fixed_3(blk_us);

    let (q_ms, q_ms_frac) = ms_fixed_3(q_us);
    let q_us_per_task = div_u64_round(q_us, BLOCK_TASKS as u64);

    println!("[bench] iters={} depth={}", ITERS, DEPTH);
    println!(
        "[bench] sync:  total={} .{:03} ms  us/chain={}  ns/inner_call={}",
        sync_ms, sync_ms_frac, sync_us_per_chain, sync_ns_per_inner
    );
    println!(
        "[bench] async: total={} .{:03} ms  us/chain={}  ns/inner_call={}",
        async_ms, async_ms_frac, async_us_per_chain, async_ns_per_inner
    );
    println!(
        "[bench] blk:   total={} .{:03} ms  us/chain={}",
        blk_ms, blk_ms_frac, blk_us_per_chain
    );
    println!(
        "[bench] blkq:  tasks={} total={} .{:03} ms  us/task={}",
        BLOCK_TASKS, q_ms, q_ms_frac, q_us_per_task
    );

    // Everything relative to sync baseline
    let sm_vs_sync = ratio_1e3(async_us, sync_us);
    let blk_vs_sync = ratio_1e3(blk_us, sync_us);
    let blk_vs_blkq = ratio_1e3(blk_us, q_us);

    // Isolate pure overhead costs (us per chain, relative to sync)
    let sm_overhead_us = sub_i64(async_us_per_chain, sync_us_per_chain);
    let blk_overhead_us = sub_i64(blk_us_per_chain, sync_us_per_chain);
    // pending+wake = blk - async (the spawn/wake cost on top of state machine)
    let pw_overhead_us = sub_i64(blk_us_per_chain, async_us_per_chain);

    println!("[bench] --- vs sync baseline ---");
    println!(
        "[bench] state_machine/sync  = {}.{:03}x  (async overhead: {} us/chain)",
        sm_vs_sync / 1000,
        sm_vs_sync % 1000,
        sm_overhead_us
    );
    println!(
        "[bench] blk/sync            = {}.{:03}x  (spawn+wake+sm overhead: {} us/chain)",
        blk_vs_sync / 1000,
        blk_vs_sync % 1000,
        blk_overhead_us
    );
    let pw_vs_sync = ratio_1e3(blk_us_per_chain, async_us_per_chain);
    println!(
        "[bench] pending+wake/sync   = {}.{:03}x  (blk/async, pure spawn+wake cost)",
        pw_vs_sync / 1000,
        pw_vs_sync % 1000
    );
    println!(
        "[bench] blk/blkq            = {}.{:03}x  (sequential blocking vs bulk queue)",
        blk_vs_blkq / 1000,
        blk_vs_blkq % 1000
    );
}

// =====================
// Realistic traffic benchmark
// =====================

// Simulates a driver-like workload: async setup -> blocking device work -> async postprocess
// Runs at varying concurrency levels to find saturation point and measure scheduling overhead.

const TRAFFIC_TOTAL_TASKS: usize = 10_000;
const TRAFFIC_CONCURRENCY: &[usize] = &[1, 4, 8, 16, 32, 64, 128, 256, 512];
const TRAFFIC_WORK_NS: u64 = 500; // simulated device work per blocking task
const TRAFFIC_ASYNC_DEPTH: usize = 20; // async setup + postprocess depth

pub fn bench_realistic_traffic() {
    spawn_detached(async {
        bench_realistic_traffic_async().await;
    });
}

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
    // Phase 1: async setup (simulate parsing, validation, etc.)
    let prepared = traffic_async_work(seed, TRAFFIC_ASYNC_DEPTH / 2).await;

    // Phase 2: blocking device work
    let device_result = spawn_blocking(move || traffic_blocking_work(prepared)).await;

    // Phase 3: async postprocess (simulate response building, etc.)
    let result = traffic_async_work(device_result, TRAFFIC_ASYNC_DEPTH / 2).await;
    result
}

/// One "request" using bulk queue for the blocking phase
#[inline(never)]
async fn traffic_batch_request(seeds: Vec<u64>) -> Vec<u64> {
    let count = seeds.len();

    // Phase 1: async setup for all
    let mut prepared = Vec::with_capacity(count);
    for &seed in &seeds {
        prepared.push(traffic_async_work(seed, TRAFFIC_ASYNC_DEPTH / 2).await);
    }

    // Phase 2: blocking device work in bulk
    let funcs: Vec<_> = prepared
        .iter()
        .map(|&p| move || traffic_blocking_work(p))
        .collect();
    let joins = spawn_blocking_many(funcs);
    let device_results = JoinAll::new(joins).await;

    // Phase 3: async postprocess for all
    let mut results = Vec::with_capacity(count);
    for device_result in device_results {
        results.push(traffic_async_work(device_result, TRAFFIC_ASYNC_DEPTH / 2).await);
    }
    results
}

async fn bench_realistic_traffic_async() {
    println!("[traffic] === realistic traffic benchmark ===");
    println!(
        "[traffic] tasks={} work_ns={} async_depth={}",
        TRAFFIC_TOTAL_TASKS, TRAFFIC_WORK_NS, TRAFFIC_ASYNC_DEPTH
    );
    println!(
        "[traffic] {:>6} {:>10} {:>10} {:>10} {:>10}",
        "conc", "total_ms", "us/task", "ops/s", "vs_seq"
    );

    // Warmup
    for i in 0..100u64 {
        black_box(traffic_one_request(i).await);
    }

    // Baseline: fully sequential (concurrency=1)
    let sw_seq = Stopwatch::start();
    for i in 0..TRAFFIC_TOTAL_TASKS as u64 {
        black_box(traffic_one_request(i).await);
    }
    let seq_us = sw_seq.elapsed_micros();
    let seq_us_per_task = div_u64_round(seq_us, TRAFFIC_TOTAL_TASKS as u64);
    let seq_ops_sec = if seq_us == 0 {
        0
    } else {
        (TRAFFIC_TOTAL_TASKS as u128 * 1_000_000u128 / seq_us as u128) as u64
    };
    let (seq_ms, seq_ms_frac) = ms_fixed_3(seq_us);

    println!(
        "[traffic] {:>6} {:>7}.{:03} {:>10} {:>10} {:>10}",
        1, seq_ms, seq_ms_frac, seq_us_per_task, seq_ops_sec, "1.000x"
    );

    // Concurrent: spawn N tasks at a time, process in waves
    for &conc in TRAFFIC_CONCURRENCY {
        if conc <= 1 {
            continue;
        }

        let sw = Stopwatch::start();
        let mut done = 0usize;

        while done < TRAFFIC_TOTAL_TASKS {
            let batch = (TRAFFIC_TOTAL_TASKS - done).min(conc);
            let mut joins = Vec::with_capacity(batch);
            for j in 0..batch {
                let seed = (done + j) as u64;
                joins.push(spawn(traffic_one_request(seed)));
            }
            let _results = JoinAll::new(joins).await;
            done += batch;
        }

        let conc_us = sw.elapsed_micros();
        let conc_us_per_task = div_u64_round(conc_us, TRAFFIC_TOTAL_TASKS as u64);
        let conc_ops_sec = if conc_us == 0 {
            0
        } else {
            (TRAFFIC_TOTAL_TASKS as u128 * 1_000_000u128 / conc_us as u128) as u64
        };
        let (conc_ms, conc_ms_frac) = ms_fixed_3(conc_us);
        let speedup = ratio_1e3(seq_us, conc_us);

        println!(
            "[traffic] {:>6} {:>7}.{:03} {:>10} {:>10} {}.{:03}x",
            conc, conc_ms, conc_ms_frac, conc_us_per_task, conc_ops_sec,
            speedup / 1000, speedup % 1000
        );
    }

    // Bulk queue test: batch all blocking work together
    println!("[traffic] --- bulk queue (batch blocking phase) ---");
    let batch_sizes: &[usize] = &[64, 256, 1024, TRAFFIC_TOTAL_TASKS];
    for &bs in batch_sizes {
        let sw = Stopwatch::start();
        let mut done = 0usize;

        while done < TRAFFIC_TOTAL_TASKS {
            let batch = (TRAFFIC_TOTAL_TASKS - done).min(bs);
            let seeds: Vec<u64> = (done..done + batch).map(|i| i as u64).collect();
            let _results = traffic_batch_request(seeds).await;
            done += batch;
        }

        let bulk_us = sw.elapsed_micros();
        let bulk_us_per_task = div_u64_round(bulk_us, TRAFFIC_TOTAL_TASKS as u64);
        let bulk_ops_sec = if bulk_us == 0 {
            0
        } else {
            (TRAFFIC_TOTAL_TASKS as u128 * 1_000_000u128 / bulk_us as u128) as u64
        };
        let (bulk_ms, bulk_ms_frac) = ms_fixed_3(bulk_us);
        let speedup = ratio_1e3(seq_us, bulk_us);

        println!(
            "[traffic] {:>6} {:>7}.{:03} {:>10} {:>10} {}.{:03}x",
            bs, bulk_ms, bulk_ms_frac, bulk_us_per_task, bulk_ops_sec,
            speedup / 1000, speedup % 1000
        );
    }
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
    let stride = (total_target + BENCH_MAX_LAT_SAMPLES - 1) / BENCH_MAX_LAT_SAMPLES;
    sample_idx % stride == 0
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
    let try_existing = File::open(path, &[OpenFlags::Open, OpenFlags::WriteOnly]).await;

    if try_existing.is_ok() {
        return try_existing;
    }

    File::open(
        path,
        &[OpenFlags::Create, OpenFlags::Open, OpenFlags::WriteOnly],
    )
    .await
}

async fn ensure_csv_header(path: &Path, header: &str) -> Result<(), FileStatus> {
    match File::open(path, &[OpenFlags::Open, OpenFlags::ReadOnly]).await {
        Ok(f) => {
            if f.size != 0 {
                return Ok(());
            }
        }
        Err(_) => {}
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
            let sw = Stopwatch::start();

            if BENCH_USE_BATCH_SPAWN {
                let mut starts: Vec<u64> = Vec::with_capacity(inflight as usize);
                let mut funcs = Vec::with_capacity(inflight as usize);

                let mut i = 0u64;
                while i < inflight {
                    let start = cpu::get_cycles();
                    starts.push(start);

                    funcs.push(move || -> u64 {
                        if BENCH_WORK_NS != 0 {
                            wait_duration(Duration::from_nanos(BENCH_WORK_NS));
                        }
                        cpu::get_cycles()
                    });

                    i += 1;
                }

                let joins = spawn_blocking_many(funcs);

                for (j, join) in joins.into_iter().enumerate() {
                    let end = join.await;

                    if iter >= BENCH_WARMUP_ITERS {
                        let lat_cycles = end.wrapping_sub(starts[j]);
                        let lat = cycles_to_ns(lat_cycles, tsc_hz);

                        let sample_idx = ops_total as usize;
                        if should_keep_sample(sample_idx, target_samples) {
                            lats_ns.push(lat);
                        }
                        ops_total = ops_total.wrapping_add(1);
                    }
                }
            } else {
                let mut starts: Vec<u64> = Vec::with_capacity(inflight as usize);
                let mut joins = Vec::with_capacity(inflight as usize);

                let mut i = 0u64;
                while i < inflight {
                    let start = cpu::get_cycles();
                    starts.push(start);

                    let join = spawn_blocking(move || -> u64 {
                        if BENCH_WORK_NS != 0 {
                            wait_duration(Duration::from_nanos(BENCH_WORK_NS));
                        }
                        cpu::get_cycles()
                    });

                    joins.push(join);
                    i += 1;
                }

                for (j, join) in joins.into_iter().enumerate() {
                    let end = join.await;

                    if iter >= BENCH_WARMUP_ITERS {
                        let lat_cycles = end.wrapping_sub(starts[j]);
                        let lat = cycles_to_ns(lat_cycles, tsc_hz);

                        let sample_idx = ops_total as usize;
                        if should_keep_sample(sample_idx, target_samples) {
                            lats_ns.push(lat);
                        }
                        ops_total = ops_total.wrapping_add(1);
                    }
                }
            }

            if iter >= BENCH_WARMUP_ITERS {
                total_cycles = total_cycles.wrapping_add(sw.elapsed_cycles());
                total_ns = total_ns.wrapping_add(sw.elapsed_nanos());
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
