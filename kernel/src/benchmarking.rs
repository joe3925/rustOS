#![no_std]

extern crate alloc;
use crate::alloc::format;
use crate::drivers::interrupt_index;
use crate::drivers::timer_driver::{PER_CORE_SWITCHES, TIMER_TIME_SCHED};
use crate::file_system::file::File;
use crate::memory::{
    allocator::ALLOCATOR,
    heap::HEAP_SIZE,
    paging::frame_alloc::{total_usable_bytes, USED_MEMORY},
};
use crate::scheduling::runtime::runtime::{block_on, spawn_blocking};
use crate::util::{boot_info, TOTAL_TIME};
use crate::vec;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use core::time::Duration;
use kernel_types::benchmark::BenchWindowConfig;
use kernel_types::fs::{FsSeekWhence, OpenFlags};
use spin::{Mutex, Once};
use x86_64::instructions::interrupts;

const BENCH_ENABLED: bool = cfg!(debug_assertions);
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
    write_idx: usize,
}

impl BenchRing {
    fn new(capacity: usize) -> Self {
        let mut buffer = Vec::with_capacity(capacity);
        buffer.resize(capacity, BenchEvent::default());
        BenchRing {
            next_seq: 1,
            buffer,
            write_idx: 0,
        }
    }

    fn log(&mut self, mut event: BenchEvent) {
        if self.buffer.is_empty() {
            return;
        }
        event.seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);

        let idx = self.write_idx % self.buffer.len();
        self.buffer[idx] = event;
        self.write_idx = self.write_idx.wrapping_add(1);
    }
}

struct BenchState {
    rings: Vec<Mutex<BenchRing>>,
    next_span_id: AtomicU32,
}

impl BenchState {
    fn new() -> Self {
        let cores = TIMER_TIME_SCHED.iter().count().max(1);
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
    TOTAL_TIME.wait().elapsed_millis() as u64 * 1_000_000
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

    let core_sched_ns = TIMER_TIME_SCHED
        .iter()
        .nth(core_id)
        .map(|a| a.load(Ordering::SeqCst) as u64)
        .unwrap_or(0);

    let core_switches = PER_CORE_SWITCHES
        .iter()
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

    let core_sched_ns = TIMER_TIME_SCHED
        .iter()
        .nth(core_id)
        .map(|a| a.load(Ordering::SeqCst) as u64)
        .unwrap_or(0);

    let core_switches = PER_CORE_SWITCHES
        .iter()
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

fn parse_session_suffix(entry: &str) -> Option<u32> {
    if !entry.starts_with("session_") {
        return None;
    }
    let rest = &entry[8..];
    rest.parse::<u32>().ok()
}

fn ensure_session(root: &str) -> BenchSessionInfo {
    let mut reg = session_registry().lock();

    if let Some(info) = reg.get(root) {
        return info.clone();
    }

    let _ = block_on(File::make_dir(root.to_string()));

    let entries = block_on(File::list_dir(root)).unwrap_or_else(|_| Vec::new());
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

    let _ = block_on(File::make_dir(session_dir.clone()));
    let _ = block_on(File::make_dir(join_path2(&session_dir, "cores")));
    let _ = block_on(File::make_dir(join_path2(&session_dir, "avg")));
    let _ = block_on(File::make_dir(join_path2(
        &join_path2(&session_dir, "avg"),
        "windows",
    )));

    let ncores = bench_ncores();
    for i in 0..ncores {
        let core_dir = join_path2(&join_path2(&session_dir, "cores"), &format!("core-{i}"));
        let _ = block_on(File::make_dir(core_dir.clone()));
        let _ = block_on(File::make_dir(join_path2(&core_dir, "windows")));
    }

    let info = BenchSessionInfo {
        session_dir,
        ncores,
    };
    reg.insert(root.to_string(), info.clone());
    info
}

fn compute_next_window_suffix(windows_root_avg: &str, name: &str) -> u32 {
    let entries = block_on(File::list_dir(windows_root_avg)).unwrap_or_else(|_| Vec::new());
    let mut has_base = false;
    let mut max_suffix: u32 = 0;

    for entry in entries {
        if entry == name {
            has_base = true;
            continue;
        }
        if entry.starts_with(name) {
            let rest = &entry[name.len()..];
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

fn allocate_window_name(session_dir: &str, name: &str, ncores: usize) -> String {
    let windows_avg = join_path2(&join_path2(session_dir, "avg"), "windows");

    let mut reg = window_dir_registry().lock();
    let mut key = String::new();
    key.push_str(session_dir);
    key.push('|');
    key.push_str(name);

    let suffix = match reg.get(&key).copied() {
        Some(v) => v,
        None => compute_next_window_suffix(&windows_avg, name),
    };

    let window_dir = if suffix == 0 {
        name.to_string()
    } else {
        format!("{name}-{suffix}")
    };

    reg.insert(key, suffix.saturating_add(1));

    let avg_win = join_path2(&windows_avg, &window_dir);
    let _ = block_on(File::make_dir(avg_win));

    for i in 0..ncores {
        let core_windows = join_path2(
            &join_path2(&join_path2(session_dir, "cores"), &format!("core-{i}")),
            "windows",
        );
        let core_win = join_path2(&core_windows, &window_dir);
        let _ = block_on(File::make_dir(core_win));
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

fn build_exports_for_window(
    cfg: &BenchWindowConfig,
    run_id: u32,
    start_ns: u64,
    to_ns: u64,
    last_export_seq: &[u64],
    ncores: usize,
) -> ExportBundle {
    let mut samples_rows = Vec::with_capacity(ncores + 1);
    let mut spans_rows = Vec::with_capacity(ncores + 1);
    let mut mem_rows = Vec::with_capacity(ncores + 1);

    for _ in 0..(ncores + 1) {
        samples_rows.push(String::new());
        spans_rows.push(String::new());
        mem_rows.push(String::new());
    }

    let mut max_seq_seen = vec![0u64; ncores];

    if !BENCH_ENABLED {
        return ExportBundle {
            samples_rows,
            spans_rows,
            mem_rows,
            max_seq_seen,
        };
    }

    let state = match bench_state() {
        Some(s) => s,
        None => {
            return ExportBundle {
                samples_rows,
                spans_rows,
                mem_rows,
                max_seq_seen,
            }
        }
    };

    let mut open_spans: BTreeMap<u32, (BenchSpanEvent, u64, u16)> = BTreeMap::new();
    let want_mem_stream = cfg.log_mem_on_persist;

    for core in 0..ncores {
        let ring_m = match state.ring_for_core(core) {
            Some(r) => r,
            None => continue,
        };

        let ring = ring_m.lock();
        let last_seq = *last_export_seq.get(core).unwrap_or(&0);

        for ev in ring.buffer.iter() {
            if ev.is_empty() {
                continue;
            }
            if ev.seq <= last_seq {
                continue;
            }
            if ev.timestamp_ns < start_ns || ev.timestamp_ns > to_ns {
                continue;
            }

            if ev.seq > max_seq_seen[core] {
                max_seq_seen[core] = ev.seq;
            }

            match ev.kind {
                BenchEventKind::Sample if cfg.log_samples => {
                    if let BenchEventData::Sample(s) = ev.data {
                        let avg = ncores;

                        samples_rows[core].push_str(&format!(
                            "{},{},{},0x{:016x},{}",
                            run_id, ev.timestamp_ns, ev.core_id, s.rip, s.depth
                        ));
                        samples_rows[avg].push_str(&format!(
                            "{},{},{},0x{:016x},{}",
                            run_id, ev.timestamp_ns, ev.core_id, s.rip, s.depth
                        ));

                        let depth = s.depth as usize;
                        for i in 0..MAX_STACK_DEPTH {
                            samples_rows[core].push(',');
                            samples_rows[avg].push(',');
                            if i < depth {
                                let v = format!("0x{:016x}", s.stack[i]);
                                samples_rows[core].push_str(&v);
                                samples_rows[avg].push_str(&v);
                            }
                        }
                        samples_rows[core].push('\n');
                        samples_rows[avg].push('\n');
                    }
                }
                BenchEventKind::SpanBegin if cfg.log_spans => {
                    if let BenchEventData::Span(span) = ev.data {
                        open_spans.insert(span.span_id, (span, ev.timestamp_ns, ev.core_id));
                    }
                }
                BenchEventKind::SpanEnd if cfg.log_spans => {
                    if let BenchEventData::Span(span) = ev.data {
                        if let Some((start_span, start_ts, start_core)) =
                            open_spans.remove(&span.span_id)
                        {
                            let dur = ev.timestamp_ns.saturating_sub(start_ts);
                            let avg = ncores;

                            let row = format!(
                                "{},{},0x{:016x},{},{},{}\n",
                                run_id,
                                start_span.tag,
                                start_span.object_id,
                                start_core,
                                start_ts,
                                dur
                            );

                            spans_rows[core].push_str(&row);
                            spans_rows[avg].push_str(&row);
                        }
                    }
                }
                BenchEventKind::Metrics if want_mem_stream => {
                    if let BenchEventData::Metrics(m) = ev.data {
                        let avg = ncores;
                        let row = format!(
                            "{},{},{},{},{},{},{},{},{}\n",
                            run_id,
                            ev.timestamp_ns,
                            ev.core_id,
                            m.used_bytes,
                            m.total_bytes,
                            m.heap_used_bytes,
                            m.heap_total_bytes,
                            m.core_sched_ns,
                            m.core_switches
                        );
                        mem_rows[core].push_str(&row);
                        mem_rows[avg].push_str(&row);
                    }
                }
                _ => {}
            }
        }
    }

    ExportBundle {
        samples_rows,
        spans_rows,
        mem_rows,
        max_seq_seen,
    }
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

    last_export_seq: Vec<u64>, // per core, advanced on persist

    samples_header_written: Vec<bool>, // [core0..coreN-1, avg]
    spans_header_written: Vec<bool>,   // [core0..coreN-1, avg]
    mem_header_written: Vec<bool>,     // [core0..coreN-1, avg]
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
    }
}

#[derive(Clone)]
pub struct BenchWindow {
    inner: Arc<Mutex<BenchWindowInner>>,
}

impl BenchWindow {
    pub fn new(cfg: BenchWindowConfig) -> Self {
        if !BENCH_ENABLED {
            let inner = BenchWindowInner::new(cfg, String::new(), String::new(), 1);
            return BenchWindow {
                inner: Arc::new(Mutex::new(inner)),
            };
        }

        if cfg.log_mem_on_persist {
            METRICS_REFCOUNT.fetch_add(1, Ordering::Relaxed);
        }

        let root = cfg.folder;
        let session = ensure_session(root);
        let window_dir = allocate_window_name(&session.session_dir, cfg.name, session.ncores);

        let inner = BenchWindowInner::new(cfg, session.session_dir, window_dir, session.ncores);

        BenchWindow {
            inner: Arc::new(Mutex::new(inner)),
        }
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
                block_on(this.persist());
            });
        }

        if let Some(secs) = auto_persist_secs_opt {
            if !secs.is_zero() {
                let interval = secs;
                let this = self.clone();
                spawn_blocking(move || loop {
                    interrupt_index::wait_duration(interval);
                    if !BENCH_ENABLED {
                        return;
                    }
                    {
                        let inner = this.inner.lock();
                        if !inner.running {
                            break;
                        }
                    }
                    block_on(this.persist());
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
        if !BENCH_ENABLED {
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
        }

        if start_ns >= to_ns {
            return;
        }

        let exports =
            build_exports_for_window(&cfg, run_id, start_ns, to_ns, &last_export_seq, ncores);

        let mut ok = true;

        if cfg.log_samples {
            let header =
                "run_id,timestamp_ns,core,rip,depth,frame0,frame1,frame2,frame3,frame4,frame5,frame6,frame7\n";

            for target in 0..(ncores + 1) {
                let rows = &exports.samples_rows[target];
                if rows.is_empty() {
                    continue;
                }

                let mut csv = String::new();
                if !samples_header_written[target] {
                    csv.push_str(header);
                }
                csv.push_str(rows);

                let path = window_path_for_target(&session_dir, &window_dir, target, ncores);
                let file_name = format!("run_{run_id}_samples.csv");
                if append_named_file(&path, &file_name, csv.as_bytes())
                    .await
                    .is_err()
                {
                    ok = false;
                } else {
                    samples_header_written[target] = true;
                }
            }
        }

        if cfg.log_spans {
            let header = "run_id,tag,object_id,core,start_ns,duration_ns\n";

            for target in 0..(ncores + 1) {
                let rows = &exports.spans_rows[target];
                if rows.is_empty() {
                    continue;
                }

                let mut csv = String::new();
                if !spans_header_written[target] {
                    csv.push_str(header);
                }
                csv.push_str(rows);

                let path = window_path_for_target(&session_dir, &window_dir, target, ncores);
                let file_name = format!("run_{run_id}_spans.csv");
                if append_named_file(&path, &file_name, csv.as_bytes())
                    .await
                    .is_err()
                {
                    ok = false;
                } else {
                    spans_header_written[target] = true;
                }
            }
        }

        if cfg.log_mem_on_persist {
            let header = "run_id,timestamp_ns,core,used_bytes,total_bytes,heap_used_bytes,heap_total_bytes,core_sched_ns,core_switches\n";

            for target in 0..(ncores + 1) {
                let rows = &exports.mem_rows[target];
                if rows.is_empty() {
                    continue;
                }

                let mut csv = String::new();
                if !mem_header_written[target] {
                    csv.push_str(header);
                }
                csv.push_str(rows);

                let path = window_path_for_target(&session_dir, &window_dir, target, ncores);
                let file_name = format!("run_{run_id}_memory.csv");
                if append_named_file(&path, &file_name, csv.as_bytes())
                    .await
                    .is_err()
                {
                    ok = false;
                } else {
                    mem_header_written[target] = true;
                }
            }
        }

        if ok {
            let mut inner = self.inner.lock();
            inner.samples_header_written = samples_header_written;
            inner.spans_header_written = spans_header_written;
            inner.mem_header_written = mem_header_written;

            for i in 0..ncores {
                let max_seq = exports.max_seq_seen[i];
                if max_seq != 0 && max_seq > inner.last_export_seq[i] {
                    inner.last_export_seq[i] = max_seq;
                }
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
    File::make_dir(path.to_string()).await;

    let file_path = format!("{path}\\{file_name}");

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
    HEAP_SIZE - ALLOCATOR.free_memory()
}
