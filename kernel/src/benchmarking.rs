use crate::alloc::format;
use crate::drivers::interrupt_index::{self, TSC_HZ};
use crate::drivers::pnp::manager::PNP_MANAGER;
use crate::drivers::timer_driver::{PER_CORE_SWITCHES, TIMER_TIME_SCHED};
use crate::file_system::file::File;
use crate::memory::allocator::ALLOCATOR;
use crate::memory::{
    heap::HEAP_SIZE,
    paging::frame_alloc::{total_usable_bytes, USED_MEMORY},
};
use crate::scheduling::runtime::runtime::{
    block_on, spawn_blocking, spawn_blocking_many, spawn_detached, JoinAll,
};
use crate::static_handlers::{idle_tracking_stop, pnp_get_device_target, wait_duration};
use crate::structs::stopwatch::Stopwatch;
use crate::util::{boot_info, TOTAL_TIME};
use crate::{cpu, println, vec};

use crate::drivers::timer_driver::idle_tracking_start;
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
use kernel_types::benchmark::{
    BenchLevelResult, BenchSweepParams, BenchSweepResult, BenchWindowConfig, BENCH_FLAG_IRQ,
};
use kernel_types::benchmark::{BenchSweepBothResult, BENCH_FLAG_POLL, BENCH_PARAMS_VERSION_1};
use kernel_types::fs::{FsSeekWhence, OpenFlags, Path};
use kernel_types::request::{RequestData, RequestHandle, RequestType, TraversalPolicy};
use kernel_types::status::{DriverStatus, FileStatus};
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

pub fn bench_submit_rip_sample_current_core(rip: u64, stack_ptr: *const u64, stack_len: usize) {
    if !BENCH_ENABLED {
        return;
    }
    todo!();
    if !BENCH_READY.load(Ordering::Acquire) {
        return;
    }

    let stack = if stack_ptr.is_null() || stack_len == 0 || !stack_ptr.is_aligned_to(8) {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(stack_ptr, stack_len) }
    };

    let core_id = interrupt_index::current_cpu_id();
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
    if !BENCH_ENABLED {
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

async fn ensure_session_async(root: &str, per_core_enabled: bool) -> BenchSessionInfo {
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
    if per_core_enabled {
        for i in 0..ncores {
            let core_dir = join_path2(&cores_dir, &format!("core-{i}"));
            let _ = File::make_dir(&Path::from_string(&core_dir)).await;
            let _ = File::make_dir(&Path::from_string(&join_path2(&core_dir, "windows"))).await;
        }
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
        if let Some(rest) = e.strip_prefix(name) {
            if let Some(suffix) = rest.strip_prefix('-') {
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
async fn allocate_window_name_async(
    session_dir: &str,
    name: &str,
    ncores: usize,
    per_core_enabled: bool,
) -> String {
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

    if per_core_enabled {
        for i in 0..ncores {
            let core_windows = join_path2(
                &join_path2(&join_path2(session_dir, "cores"), &format!("core-{i}")),
                "windows",
            );
            let core_win = join_path2(&core_windows, &window_dir);
            let _ = File::make_dir(&Path::from_string(&core_win)).await;
        }
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
        let st = state;
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
    let chunks = core::cmp::min(desired_chunks, total_events.div_ceil(min_chunk_size)).max(1);
    let chunk_size = total_events.div_ceil(chunks);

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
                    if per_core_enabled && scan_core < ncores {
                        write_sample_row(
                            &mut bundle.samples_rows[scan_core],
                            run_id,
                            ev.timestamp_ns,
                            ev.core_id,
                            s.rip,
                            s.depth.into(),
                            &s.stack,
                        );
                    }
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

        let (folder, name, ncores, per_core_enabled) = {
            let inner = self.inner.lock();
            (
                inner.cfg.folder,
                inner.cfg.name,
                inner.ncores,
                !inner.cfg.disable_per_core,
            )
        };

        let session = ensure_session_async(folder, per_core_enabled).await;
        let window_dir = allocate_window_name_async(
            &session.session_dir,
            name,
            session.ncores,
            per_core_enabled,
        )
        .await;

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
                if cfg.disable_per_core && target != ncores {
                    continue;
                }

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
                        } else if append_named_file(&path, &file_name, rows.as_bytes())
                            .await
                            .is_err()
                        {
                            return (false, target, header_written);
                        }
                    }

                    (true, target, header_written)
                }));
            }
        }

        if cfg.log_spans {
            let header: &'static str = "run_id,tag,object_id,core,start_ns,duration_ns\n";

            for target in 0..(ncores + 1) {
                if cfg.disable_per_core && target != ncores {
                    continue;
                }

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
                        } else if append_named_file(&path, &file_name, rows.as_bytes())
                            .await
                            .is_err()
                        {
                            return (false, target, header_written);
                        }
                    }

                    (true, target, header_written)
                }));
            }
        }

        if cfg.log_mem_on_persist {
            let header: &'static str = "run_id,timestamp_ns,core,used_bytes,total_bytes,heap_used_bytes,heap_total_bytes,core_sched_ns,core_switches\n";

            for target in 0..(ncores + 1) {
                if cfg.disable_per_core && target != ncores {
                    continue;
                }

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
                        } else if append_named_file(&path, &file_name, rows.as_bytes())
                            .await
                            .is_err()
                        {
                            return (false, target, header_written);
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

    file.append(data).await.map_err(|_| ())?;
    let _ = file.close().await;
    Ok(())
}

pub fn used_memory() -> usize {
    HEAP_SIZE as usize - ALLOCATOR.free_memory()
}

const DEPTH: usize = 1_000;
const ITERS: usize = 50_000;

const BLOCK_TASKS: usize = 50_000;

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
    if let Ok(f) = File::open(path, &[OpenFlags::Open, OpenFlags::ReadOnly]).await {
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
const DISK_BENCH_FILE: &str = "C:\\bench\\io_bench.bin";
const DISK_BENCH_TOTAL_BYTES: usize = 4 * 1024 * 1024;
const DISK_BENCH_SIZES: &[usize] = &[
    64 * 1024,
    512 * 1024,
    1024 * 1024,
    2 * 1024 * 1024,
    4 * 1024 * 1024,
    // 8 * 1024 * 1024,
    // 16 * 1024 * 1024,
    // 32 * 1024 * 1024,
    // 1024 * 1024 * 1024,
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
    let dir_path = Path::from_string(DISK_BENCH_DIR);
    if let Err(e) = File::make_dir(&dir_path).await {
        println!(
            "[disk-bench] failed to create bench dir {}: {:?}",
            DISK_BENCH_DIR, e
        );
        return;
    }

    let test_path = Path::from_string(DISK_BENCH_FILE);
    let mut file = match File::open(
        &test_path,
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

    if let Err(e) = file.set_len(0).await {
        println!("[disk-bench] failed to truncate benchmark file: {:?}", e);
        return;
    }

    let span_cfg = BenchWindowConfig {
        name: "disk-io-spans",
        folder: "C:\\system\\logs",
        log_samples: false,
        log_spans: true,
        disable_per_core: true,
        log_mem_on_persist: false,
        end_on_drop: false,
        timeout_ms: None,
        auto_persist_secs: None,
        sample_reserve: 64,
        span_reserve: 4096,
    };
    let span_window = BenchWindow::new(span_cfg);
    span_window.start();

    let mut size_bytes: Vec<u64> = Vec::new();
    let mut write_ns_per_op: Vec<u64> = Vec::new();
    let mut read_ns_per_op: Vec<u64> = Vec::new();
    let mut write_throughput: Vec<f64> = Vec::new();
    let mut read_throughput: Vec<f64> = Vec::new();

    for &chunk_sz in DISK_BENCH_SIZES {
        if let Err(e) = file.set_len(0).await {
            println!("[disk-bench] failed to truncate benchmark file: {:?}", e);
            return;
        }
        let ops = (DISK_BENCH_TOTAL_BYTES / chunk_sz).max(1);

        let mut chunk = vec![0u8; chunk_sz];

        let sw_write = Stopwatch::start();
        let mut write_elapsed = 0;
        let mut total_written = 0u64;
        println!("starting chunk size: {}", chunk_sz);
        for op in 0..ops {
            chunk[..8].copy_from_slice(&(op as u64).to_le_bytes());
            let sw_write = Stopwatch::start();
            match file.append(&chunk).await {
                Ok(_) => {
                    total_written = total_written.saturating_add(chunk_sz as u64);
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

    span_window.stop_and_persist().await;
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
                                let g = req.read();
                                match g.data.view::<BenchSweepBothResult>() {
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

    if write_csv_header_to_file(&mut irq_f).await.is_err() {
        println!("[virtio-bench] Failed writing header to C:\\{}", irq_name);
        let _ = irq_f.close().await;
        let _ = poll_f.close().await;
        return;
    }
    if write_csv_header_to_file(&mut poll_f).await.is_err() {
        println!("[virtio-bench] Failed writing header to C:\\{}", poll_name);
        let _ = irq_f.close().await;
        let _ = poll_f.close().await;
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

        if write_csv_chunk_to_file(&mut irq_f, &irq_chunk)
            .await
            .is_err()
        {
            println!("[virtio-bench] Failed writing C:\\{}", irq_name);
            let _ = irq_f.close().await;
            let _ = poll_f.close().await;
            return;
        }
        if write_csv_chunk_to_file(&mut poll_f, &poll_chunk)
            .await
            .is_err()
        {
            println!("[virtio-bench] Failed writing C:\\{}", poll_name);
            let _ = irq_f.close().await;
            let _ = poll_f.close().await;
            return;
        }

        let _ = irq_f.flush().await;
        let _ = poll_f.flush().await;
    }

    let _ = irq_f.close().await;
    let _ = poll_f.close().await;

    println!(
        "[virtio-bench] Wrote C:\\{} and C:\\{}",
        irq_name, poll_name
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

fn print_level_table_row(mode: &str, lvl: &BenchLevelResult, tsc_hz: u64) {
    let tsc_hz_f = tsc_hz as f64;
    let avg_ms = (lvl.avg_cycles as f64 / tsc_hz_f) * 1000.0;
    let p50_ms = (lvl.p50_cycles as f64 / tsc_hz_f) * 1000.0;
    let p99_ms = (lvl.p99_cycles as f64 / tsc_hz_f) * 1000.0;
    let p999_ms = (lvl.p999_cycles as f64 / tsc_hz_f) * 1000.0;
    let min_ms = (lvl.min_cycles as f64 / tsc_hz_f) * 1000.0;
    let max_ms = (lvl.max_cycles as f64 / tsc_hz_f) * 1000.0;
    let total_ms = (lvl.total_time_cycles as f64 / tsc_hz_f) * 1000.0;

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
        p999_ms,
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
    println!("| Mode | Inflight |   Requests |  Total(ms) |  Avg(ms) |  P50(ms) |  P99(ms) | P999(ms) |  Min(ms) |  Max(ms) |  Wait%  |");
    println!("+------+----------+------------+------------+----------+----------+----------+----------+----------+----------+---------+");

    let irq_used = both.irq.used as usize;
    let mut i = 0usize;
    while i < irq_used && i < both.irq.levels.len() {
        print_level_table_row("IRQ", &both.irq.levels[i], res.tsc_hz);
        i += 1;
    }

    let poll_used = both.poll.used as usize;
    i = 0;
    while i < poll_used && i < both.poll.levels.len() {
        print_level_table_row("POLL", &both.poll.levels[i], res.tsc_hz);
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
    let flags_list: [u32; 1] = [BENCH_FLAG_IRQ | BENCH_FLAG_POLL];
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
    let flags_list: [u32; 1] = [BENCH_FLAG_IRQ | BENCH_FLAG_POLL];
    let total_bytes_list: [u64; 1] = [10 * 1024 * 1024 * 1024];

    let request_size_list: [u32; _] = [
        // 4 * 1024,
        // 8 * 1024,
        // 16 * 1024,
        64 * 1024,
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
