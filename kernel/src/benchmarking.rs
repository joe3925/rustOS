use crate::alloc::format;
use crate::alloc::vec;
use crate::drivers::interrupt_index;
use crate::drivers::timer_driver::{PER_CORE_SWITCHES, TIMER_TIME_SCHED};
use crate::file_system::file::File;
use crate::memory::{
    allocator::ALLOCATOR,
    heap::HEAP_SIZE,
    paging::frame_alloc::{total_usable_bytes, USED_MEMORY},
};
use crate::println;
use crate::syscalls::syscall_impl::list_dir;
use crate::util::{boot_info, TOTAL_TIME};

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;
use kernel_types::fs::{FsSeekWhence, OpenFlags};
use nostd_runtime::{block_on, spawn_blocking};
use spin::{Mutex, Once};
use x86_64::instructions::interrupts;

const BENCH_ENABLED: bool = cfg!(debug_assertions);
const MAX_STACK_DEPTH: usize = 8;
const BENCH_RING_CAPACITY: usize = 8192;

#[derive(Clone)]
pub struct BenchWindowConfig {
    /// Logical name of the window.
    ///
    /// Used to derive the per-window log directory. For example, a window
    /// named "io_window" will write into a directory like:
    ///   `<folder>\io_window`
    /// or, if another window with the same name is created:
    ///   `<folder>\io_window-1`, `<folder>\io_window-2`, etc.
    pub name: &'static str,

    /// Root directory under which this window's subfolder will be created.
    ///
    /// For a window named "io_window" and `folder = "C:\system\logs"`,
    /// the actual directory becomes:
    ///   "C:\system\logs\io_window" (first instance),
    ///   "C:\system\logs\io_window-1" (second instance with same name),
    /// etc. All CSV files for the window are written into that subfolder.
    pub folder: &'static str,

    /// Enable recording of RIP/stack samples for this window.
    ///
    /// When true, `persist` will export sampled RIP/stack data that falls
    /// inside this window's time range into `samples.csv`.
    pub log_samples: bool,

    /// Enable recording of span timings for this window.
    ///
    /// When true, `persist` will reconstruct span lifetimes from the
    /// global span stream and export completed spans that fall inside
    /// this window’s time range into `spans.csv`.
    pub log_spans: bool,

    /// Enable collection of scheduler-level summary metrics.
    ///
    /// When true, `sample_scheduler()` accumulates scheduler data for
    /// this window, and `persist` emits a summary row for the run into
    /// `scheduler.csv`.
    pub log_scheduler: bool,

    /// Enable recording of a memory snapshot on each `persist` call.
    ///
    /// When true, `persist` will take a memory usage sample
    /// (used/total and heap usage) and append it to `memory.csv`.
    pub log_mem_on_persist: bool,

    /// If true, dropping the `BenchWindow` will implicitly stop it.
    ///
    /// This only affects the running state: when the last handle is
    /// dropped and this is true, the window is marked as stopped at the
    /// current timestamp. It does not call `persist` automatically.
    pub end_on_drop: bool,

    /// Optional maximum lifetime for a single run of this window
    ///
    /// When set, `start()` spawns a blocking worker that sleeps for this
    /// duration and then calls `stop()` on the window. When `None`, the
    /// run ends only when `stop()` is called or the window is dropped
    /// with `end_on_drop = true`.
    pub timeout_ms: Option<Duration>,

    /// Optional auto-persist interval
    ///
    /// When set, `start()` spawns a worker that periodically calls
    /// `persist()` while the window is running, so large runs can flush
    /// partial data to disk. When `None`, `persist()` is only invoked
    /// when the caller explicitly calls it.
    pub auto_persist_secs: Option<Duration>,

    /// Initial capacity hint for sample export.
    ///
    /// This is only a sizing hint for internal buffers and does not
    /// change what is recorded in the global stream.
    pub sample_reserve: usize,

    /// Initial capacity hint for span export.
    ///
    /// This is only a sizing hint for internal buffers and does not
    /// change what is recorded in the global stream.
    pub span_reserve: usize,
}

impl Default for BenchWindowConfig {
    fn default() -> Self {
        BenchWindowConfig {
            name: "default",
            folder: "C:\\system\\logs",
            log_samples: true,
            log_spans: true,
            log_scheduler: true,
            log_mem_on_persist: false,
            end_on_drop: true,
            timeout_ms: None,
            auto_persist_secs: None,
            sample_reserve: 8192,
            span_reserve: 1024,
        }
    }
}

// ===== Global event stream (samples + spans) =====

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BenchEventKind {
    None,
    Sample,
    SpanBegin,
    SpanEnd,
}

#[derive(Clone, Copy, Debug)]
enum BenchEventData {
    None,
    Sample(BenchSampleEvent),
    Span(BenchSpanEvent),
}

impl Default for BenchEventData {
    fn default() -> Self {
        BenchEventData::None
    }
}

#[derive(Clone, Copy, Debug)]
struct BenchEvent {
    timestamp_ns: u64,
    core_id: u16,
    kind: BenchEventKind,
    data: BenchEventData,
}

impl Default for BenchEvent {
    fn default() -> Self {
        BenchEvent {
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
    write_idx: usize,
    buffer: Vec<BenchEvent>,
}

impl BenchRing {
    fn new(capacity: usize) -> Self {
        let mut buffer = Vec::with_capacity(capacity);
        buffer.resize(capacity, BenchEvent::default());
        BenchRing {
            write_idx: 0,
            buffer,
        }
    }

    fn log(&mut self, event: BenchEvent) {
        if self.buffer.is_empty() {
            return;
        }
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
}

static BENCH_STATE: Once<BenchState> = Once::new();

static WINDOW_DIR_REGISTRY: Once<Mutex<BTreeMap<String, u32>>> = Once::new();

fn bench_state() -> Option<&'static BenchState> {
    if !BENCH_ENABLED {
        return None;
    }
    Some(BENCH_STATE.call_once(BenchState::new))
}

fn window_dir_registry() -> &'static Mutex<BTreeMap<String, u32>> {
    WINDOW_DIR_REGISTRY.call_once(|| Mutex::new(BTreeMap::new()))
}

fn allocate_window_folder(root: &str, name: &str) -> String {
    let registry = window_dir_registry();
    let mut map = registry.lock();

    let mut key = String::new();
    key.push_str(root);
    key.push('|');
    key.push_str(name);

    let mut base = String::new();
    base.push_str(root);
    if !root.ends_with('\\') && !root.ends_with('/') {
        base.push('\\');
    }
    base.push_str(name);

    let _ = block_on(File::make_dir(base.clone()));

    let next_idx = match map.get(&key).copied() {
        Some(n) => n,
        None => {
            let entries = block_on(File::list_dir(&base)).unwrap_or_else(|_| Vec::new());

            let mut max_suffix: u32 = 0;

            for entry in entries {
                if entry.starts_with(name) {
                    let rest = &entry[name.len()..];
                    if rest.starts_with('-') {
                        let suffix = &rest[1..];
                        if !suffix.is_empty() {
                            if let Ok(n) = suffix.parse::<u32>() {
                                if n > max_suffix {
                                    max_suffix = n;
                                }
                            }
                        }
                    }
                }
            }

            max_suffix.saturating_add(1)
        }
    };

    let mut folder = base;
    folder.push('\\');
    folder.push_str(name);
    folder.push('-');
    folder.push_str(next_idx.to_string().as_str());

    let _ = block_on(File::make_dir(folder.clone()));

    map.insert(key, next_idx.saturating_add(1));

    folder
}

fn bench_log_event_for_core(core_id: usize, event: BenchEvent) {
    if let Some(state) = bench_state() {
        if let Some(ring) = state.ring_for_core(core_id) {
            let mut r = ring.lock();
            r.log(event);
        }
    }
}

fn bench_now_ns() -> u64 {
    TOTAL_TIME.wait().elapsed_millis() as u64 * 1_000_000
}

// Global sampling API (independent of windows)

pub fn bench_log_sample(core_id: usize, timestamp_ns: u64, rip: u64, stack: &[u64]) {
    if !BENCH_ENABLED {
        return;
    }

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
        timestamp_ns,
        core_id: core_id as u16,
        kind: BenchEventKind::Sample,
        data: BenchEventData::Sample(sample),
    };
    bench_log_event_for_core(core_id, event);
}

pub fn bench_log_sample_current_core(rip: u64, stack: &[u64]) {
    if !BENCH_ENABLED {
        return;
    }
    let core_id = interrupt_index::current_cpu_id() as usize;
    let ts = bench_now_ns();
    bench_log_sample(core_id, ts, rip, stack);
}

fn bench_alloc_span_id() -> Option<u32> {
    bench_state().map(|s| s.alloc_span_id())
}

fn bench_log_span_begin(span_id: u32, tag: &'static str, object_id: u64) {
    if !BENCH_ENABLED {
        return;
    }
    let core_id = interrupt_index::current_cpu_id() as usize;
    let event = BenchEvent {
        timestamp_ns: bench_now_ns(),
        core_id: core_id as u16,
        kind: BenchEventKind::SpanBegin,
        data: BenchEventData::Span(BenchSpanEvent {
            span_id,
            tag,
            object_id,
        }),
    };
    bench_log_event_for_core(core_id, event);
}

fn bench_log_span_end(span_id: u32, tag: &'static str, object_id: u64) {
    if !BENCH_ENABLED {
        return;
    }
    let core_id = interrupt_index::current_cpu_id() as usize;
    let event = BenchEvent {
        timestamp_ns: bench_now_ns(),
        core_id: core_id as u16,
        kind: BenchEventKind::SpanEnd,
        data: BenchEventData::Span(BenchSpanEvent {
            span_id,
            tag,
            object_id,
        }),
    };
    bench_log_event_for_core(core_id, event);
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

fn snapshot_events_range(from_ns: u64, to_ns: u64) -> Vec<BenchEvent> {
    let mut out = Vec::new();
    if let Some(state) = bench_state() {
        for ring in &state.rings {
            let ring = ring.lock();
            for ev in &ring.buffer {
                if !ev.is_empty() && ev.timestamp_ns >= from_ns && ev.timestamp_ns <= to_ns {
                    out.push(*ev);
                }
            }
        }
    }
    out.sort_by_key(|e| e.timestamp_ns);
    out
}

fn build_export_strings_for_window(
    cfg: &BenchWindowConfig,
    run_id: u32,
    from_ns: u64,
    to_ns: u64,
) -> (String, String) {
    let events = snapshot_events_range(from_ns, to_ns);

    let mut samples_rows = String::new();
    let mut spans_rows = String::new();

    if events.is_empty() {
        return (samples_rows, spans_rows);
    }

    let mut open_spans: BTreeMap<u32, (BenchSpanEvent, u64, u16)> = BTreeMap::new();

    for ev in events {
        match ev.kind {
            BenchEventKind::Sample if cfg.log_samples => {
                if let BenchEventData::Sample(s) = ev.data {
                    samples_rows.push_str(&format!(
                        "{},{},{},0x{:016x},{}",
                        run_id, ev.timestamp_ns, ev.core_id, s.rip, s.depth
                    ));
                    let depth = s.depth as usize;
                    for i in 0..MAX_STACK_DEPTH {
                        samples_rows.push(',');
                        if i < depth {
                            samples_rows.push_str(&format!("0x{:016x}", s.stack[i]));
                        }
                    }
                    samples_rows.push('\n');
                }
            }
            BenchEventKind::SpanBegin if cfg.log_spans => {
                if let BenchEventData::Span(span) = ev.data {
                    open_spans.insert(span.span_id, (span, ev.timestamp_ns, ev.core_id));
                }
            }
            BenchEventKind::SpanEnd if cfg.log_spans => {
                if let BenchEventData::Span(span) = ev.data {
                    if let Some((start_span, start_ts, core_id)) = open_spans.remove(&span.span_id)
                    {
                        let dur = ev.timestamp_ns.saturating_sub(start_ts);
                        spans_rows.push_str(&format!(
                            "{},{},0x{:016x},{},{},{}\n",
                            run_id, start_span.tag, start_span.object_id, core_id, start_ts, dur
                        ));
                    }
                }
            }
            _ => {}
        }
    }

    (samples_rows, spans_rows)
}

// ===== Scheduler + memory summary rows =====

#[derive(Clone, Debug)]
pub struct SchedulerSummaryRow {
    pub run_id: u32,
    pub window_total_ms: u64,
    pub ncores: u32,
    pub avg_util_x100000: u64,
    pub total_ctx_per_sec: u64,
    pub avg_ctx_per_sec_per_core: u64,
    pub avg_ns_per_switch: u64,
    pub timer_overhead_x100000: u64,
    pub mean_util_x1000: u64,
    pub median_util_x1000: u64,
    pub stddev_util_x1000: u64,
    pub mad_util_x1000: u64,
    pub cv_util_x1000: u64,
    pub min_core_idx: u32,
    pub max_core_idx: u32,
    pub max_gap_x1000: u64,
}

#[derive(Clone, Debug)]
pub struct MemSampleRow {
    pub run_id: u32,
    pub timestamp_ns: u64,
    pub used_mb: u64,
    pub total_mb: u64,
    pub heap_used_kb: u64,
    pub heap_total_kb: u64,
}

#[derive(Clone, Debug)]
struct SchedulerAcc {
    prev_total_ms: u128,
    prev_core_ms: Vec<u128>,
    prev_core_sw: Vec<u64>,
    prev_sched_ns: Vec<u128>,

    acc_total_ms: u128,
    acc_core_ms: Vec<u128>,
    acc_core_sw: Vec<u128>,
    acc_total_sw: u128,
    acc_sched_ns: Vec<u128>,
    acc_total_sched_ns: u128,
}

impl SchedulerAcc {
    fn new() -> Self {
        let prev_core_ms = read_all_core_timer_ms();
        let prev_core_sw = read_all_core_switches();
        let prev_sched_ns = read_all_core_sched_ns();
        let prev_total_ms = TOTAL_TIME.wait().elapsed_millis() as u128;

        let cores = prev_core_ms.len().max(1);

        SchedulerAcc {
            prev_total_ms,
            prev_core_ms,
            prev_core_sw,
            prev_sched_ns,
            acc_total_ms: 0,
            acc_core_ms: vec![0; cores],
            acc_core_sw: vec![0; cores],
            acc_total_sw: 0,
            acc_sched_ns: vec![0; cores],
            acc_total_sched_ns: 0,
        }
    }

    fn reset(&mut self) {
        *self = SchedulerAcc::new();
    }

    fn sample(&mut self) {
        let core_ms_now = read_all_core_timer_ms();
        let total_ms_now = TOTAL_TIME.wait().elapsed_millis() as u128;
        let delta_total_ms = total_ms_now.saturating_sub(self.prev_total_ms);
        if delta_total_ms == 0 {
            return;
        }

        let n = core_ms_now.len();
        if self.prev_core_ms.len() != n {
            self.prev_core_ms = vec![0; n];
            self.acc_core_ms = vec![0; n];
        }
        if self.prev_core_sw.len() != n {
            self.prev_core_sw = vec![0; n];
            self.acc_core_sw = vec![0; n];
        }
        if self.prev_sched_ns.len() != n {
            self.prev_sched_ns = vec![0; n];
            self.acc_sched_ns = vec![0; n];
        }

        for (i, &now) in core_ms_now.iter().enumerate() {
            let prev = *self.prev_core_ms.get(i).unwrap_or(&0);
            let d = now.saturating_sub(prev);
            self.acc_core_ms[i] = self.acc_core_ms[i].saturating_add(d);
            self.prev_core_ms[i] = now;
        }

        let core_sw_now = read_all_core_switches();
        let mut total_delta_sw: u128 = 0;
        for (i, &now) in core_sw_now.iter().enumerate() {
            let prev = *self.prev_core_sw.get(i).unwrap_or(&0);
            let d = now.saturating_sub(prev);
            total_delta_sw = total_delta_sw.saturating_add(d as u128);
            self.acc_core_sw[i] = self.acc_core_sw[i].saturating_add(d as u128);
            self.prev_core_sw[i] = now;
        }
        self.acc_total_sw = self.acc_total_sw.saturating_add(total_delta_sw);

        let sched_ns_now = read_all_core_sched_ns();
        let mut total_sched_ns: u128 = 0;
        for (i, &ns) in sched_ns_now.iter().enumerate() {
            let ps = *self.prev_sched_ns.get(i).unwrap_or(&0);
            let d = ns.saturating_sub(ps);
            total_sched_ns = total_sched_ns.saturating_add(d);
            self.acc_sched_ns[i] = self.acc_sched_ns[i].saturating_add(d);
            self.prev_sched_ns[i] = ns;
        }
        self.acc_total_sched_ns = self.acc_total_sched_ns.saturating_add(total_sched_ns);

        self.acc_total_ms = self.acc_total_ms.saturating_add(delta_total_ms);
        self.prev_total_ms = total_ms_now;
    }

    fn build_summary(&self, run_id: u32) -> Option<SchedulerSummaryRow> {
        let window_total_ms = self.acc_total_ms;
        if window_total_ms == 0 {
            return None;
        }

        let core_ms = &self.acc_core_ms;
        let core_sw_u128 = &self.acc_core_sw;
        let total_sw: u128 = core_sw_u128.iter().copied().sum();
        let total_sched_ns = self.acc_total_sched_ns;

        let percs = per_core_percent_x1000(window_total_ms, core_ms);
        if percs.is_empty() {
            return None;
        }

        let ncores_u128 = percs.len() as u128;
        let ncores_u32 = percs.len() as u32;

        let sum_ms: u128 = core_ms.iter().copied().sum();
        let avg_ms = sum_ms / ncores_u128;

        let avg_util_x100000 = if window_total_ms == 0 {
            0
        } else {
            (avg_ms * 100_000) / window_total_ms
        };

        let total_ctx_per_sec = if window_total_ms == 0 {
            0
        } else {
            (total_sw * 1000) / window_total_ms
        };

        let avg_ctx_per_sec_per_core = if ncores_u128 == 0 {
            0
        } else {
            total_ctx_per_sec / ncores_u128
        };

        let avg_ns_per_switch = if total_sw == 0 {
            0
        } else {
            total_sched_ns / total_sw
        };

        let total_cpu_ns_window = window_total_ms * ncores_u128 * 1_000_000;
        let timer_overhead_x100000 = if total_cpu_ns_window == 0 {
            0
        } else {
            (total_sched_ns * 100_000) / total_cpu_ns_window
        };

        let sd = stddev_percent_x1000(&percs);
        let cv = cv_x1000(&percs);
        let median = median_x1000(percs.clone());
        let mad = mad_percent_x1000(&percs);
        let (min_core_idx, max_core_idx, max_gap) = max_gap_x1000(&percs);

        let mean_util_x1000 = avg_util_x100000 / 100;

        Some(SchedulerSummaryRow {
            run_id,
            window_total_ms: window_total_ms as u64,
            ncores: ncores_u32,
            avg_util_x100000: avg_util_x100000 as u64,
            total_ctx_per_sec: total_ctx_per_sec as u64,
            avg_ctx_per_sec_per_core: avg_ctx_per_sec_per_core as u64,
            avg_ns_per_switch: avg_ns_per_switch as u64,
            timer_overhead_x100000: timer_overhead_x100000 as u64,
            mean_util_x1000: mean_util_x1000 as u64,
            median_util_x1000: median as u64,
            stddev_util_x1000: sd as u64,
            mad_util_x1000: mad as u64,
            cv_util_x1000: cv as u64,
            min_core_idx: min_core_idx as u32,
            max_core_idx: max_core_idx as u32,
            max_gap_x1000: max_gap as u64,
        })
    }
}

// ===== BenchWindow: view over global stream =====

struct BenchWindowInner {
    cfg: BenchWindowConfig,

    running: bool,
    start_ns: u64,
    last_persist_ns: u64,
    stop_ns: Option<u64>,

    run_id_counter: u32,
    current_run_id: u32,

    sched: Option<SchedulerAcc>,
    samples_header_written: bool,
    spans_header_written: bool,
    sched_header_written: bool,
    mem_header_written: bool,
}

impl BenchWindowInner {
    fn new(cfg: BenchWindowConfig) -> Self {
        BenchWindowInner {
            cfg,
            running: false,
            start_ns: 0,
            last_persist_ns: 0,
            stop_ns: None,
            run_id_counter: 1,
            current_run_id: 0,
            sched: None,
            samples_header_written: false,
            spans_header_written: false,
            sched_header_written: false,
            mem_header_written: false,
        }
    }
}

#[derive(Clone)]
pub struct BenchWindow {
    inner: Arc<Mutex<BenchWindowInner>>,
}

impl BenchWindow {
    pub fn new(mut cfg: BenchWindowConfig) -> Self {
        if BENCH_ENABLED {
            let root = cfg.folder;
            let name = cfg.name;
            let folder_string = allocate_window_folder(root, name);
            let leaked: &'static str = Box::leak(folder_string.into_boxed_str());
            cfg.folder = leaked;
        }

        let inner = BenchWindowInner::new(cfg);
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
            inner.last_persist_ns = inner.start_ns;
            inner.stop_ns = None;
            inner.current_run_id = inner.run_id_counter;
            inner.run_id_counter = inner.run_id_counter.wrapping_add(1);

            if inner.cfg.log_scheduler {
                match inner.sched {
                    Some(ref mut sched) => sched.reset(),
                    None => {
                        inner.sched = Some(SchedulerAcc::new());
                    }
                }
            }

            auto_persist_secs_opt = inner.cfg.auto_persist_secs;
            timeout_ms_opt = inner.cfg.timeout_ms;
        }

        if let Some(timeout_ms) = timeout_ms_opt {
            let this = self.clone();
            spawn_blocking(move || {
                interrupt_index::wait_duration(timeout_ms);
                this.stop();
            });
        }

        if let Some(secs) = auto_persist_secs_opt {
            if !secs.is_zero() {
                let interval_ms = secs.saturating_mul(1000);
                let this = self.clone();
                spawn_blocking(move || loop {
                    interrupt_index::wait_duration(interval_ms);
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

    pub async fn persist(&self) {
        if !BENCH_ENABLED {
            return;
        }

        let should_sample = {
            let inner = self.inner.lock();
            inner.running && inner.cfg.log_scheduler
        };
        if should_sample {
            self.sample_scheduler();
        }

        let (
            cfg,
            run_id,
            from_ns,
            to_ns,
            samples_header_written,
            spans_header_written,
            mut sched_csv,
            mut mem_csv,
        ) = {
            let mut inner = self.inner.lock();
            if inner.start_ns == 0 {
                return;
            }

            let from_ns = if inner.last_persist_ns == 0 {
                inner.start_ns
            } else {
                inner.last_persist_ns
            };

            let to_ns = match inner.stop_ns {
                Some(stop) => stop,
                None => bench_now_ns(),
            };

            if from_ns >= to_ns {
                return;
            }

            inner.last_persist_ns = to_ns;

            let cfg = inner.cfg.clone();
            let run_id = inner.current_run_id;

            let mut sched_csv_local = String::new();
            if cfg.log_scheduler {
                if let Some(ref sched) = inner.sched {
                    if let Some(row) = sched.build_summary(run_id) {
                        if !inner.sched_header_written {
                            sched_csv_local.push_str(
                                "run_id,window_total_ms,ncores,avg_util_x100000,\
                                 total_ctx_per_sec,avg_ctx_per_sec_per_core,avg_ns_per_switch,\
                                 timer_overhead_x100000,mean_util_x1000,median_util_x1000,\
                                 stddev_util_x1000,mad_util_x1000,cv_util_x1000,\
                                 min_core_idx,max_core_idx,max_gap_x1000\n",
                            );
                            inner.sched_header_written = true;
                        }
                        sched_csv_local.push_str(&format!(
                            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
                            row.run_id,
                            row.window_total_ms,
                            row.ncores,
                            row.avg_util_x100000,
                            row.total_ctx_per_sec,
                            row.avg_ctx_per_sec_per_core,
                            row.avg_ns_per_switch,
                            row.timer_overhead_x100000,
                            row.mean_util_x1000,
                            row.median_util_x1000,
                            row.stddev_util_x1000,
                            row.mad_util_x1000,
                            row.cv_util_x1000,
                            row.min_core_idx,
                            row.max_core_idx,
                            row.max_gap_x1000
                        ));
                    }
                }
            }

            let mut mem_csv_local = String::new();
            if cfg.log_mem_on_persist {
                let row = sample_memory(run_id);
                if !inner.mem_header_written {
                    mem_csv_local.push_str(
                        "run_id,timestamp_ns,used_mb,total_mb,heap_used_kb,heap_total_kb\n",
                    );
                    inner.mem_header_written = true;
                }
                mem_csv_local.push_str(&format!(
                    "{},{},{},{},{},{}\n",
                    row.run_id,
                    row.timestamp_ns,
                    row.used_mb,
                    row.total_mb,
                    row.heap_used_kb,
                    row.heap_total_kb
                ));
            }

            (
                cfg,
                run_id,
                from_ns,
                to_ns,
                inner.samples_header_written,
                inner.spans_header_written,
                sched_csv_local,
                mem_csv_local,
            )
        };

        let (samples_rows, spans_rows) =
            build_export_strings_for_window(&cfg, run_id, from_ns, to_ns);

        let mut samples_csv = String::new();
        if !samples_rows.is_empty() && cfg.log_samples {
            if !samples_header_written {
                samples_csv.push_str(
                    "run_id,timestamp_ns,core,rip,depth,\
                     frame0,frame1,frame2,frame3,frame4,frame5,frame6,frame7\n",
                );
            }
            samples_csv.push_str(&samples_rows);
        }

        let mut spans_csv = String::new();
        if !spans_rows.is_empty() && cfg.log_spans {
            if !spans_header_written {
                spans_csv.push_str("run_id,tag,object_id,core,start_ns,duration_ns\n");
            }
            spans_csv.push_str(&spans_rows);
        }

        {
            let mut inner = self.inner.lock();
            if !samples_rows.is_empty() && cfg.log_samples && !inner.samples_header_written {
                inner.samples_header_written = true;
            }
            if !spans_rows.is_empty() && cfg.log_spans && !inner.spans_header_written {
                inner.spans_header_written = true;
            }
        }

        if !samples_csv.is_empty() {
            let _ = append_named_file(cfg.folder, "samples.csv", samples_csv.as_bytes()).await;
        }
        if !spans_csv.is_empty() {
            let _ = append_named_file(cfg.folder, "spans.csv", spans_csv.as_bytes()).await;
        }
        if !sched_csv.is_empty() {
            let _ = append_named_file(cfg.folder, "scheduler.csv", sched_csv.as_bytes()).await;
        }
        if !mem_csv.is_empty() {
            let _ = append_named_file(cfg.folder, "memory.csv", mem_csv.as_bytes()).await;
        }
    }

    pub fn span_guard(&self, tag: &'static str, object_id: u64) -> BenchSpanGuard {
        BenchSpanGuard::new(tag, object_id)
    }

    pub fn log_sample_current_core(&self, rip: u64, stack: &[u64]) {
        bench_log_sample_current_core(rip, stack);
    }

    pub fn log_sample_for_core(&self, core_id: u16, timestamp_ns: u64, rip: u64, stack: &[u64]) {
        bench_log_sample(core_id as usize, timestamp_ns, rip, stack);
    }

    pub fn sample_scheduler(&self) {
        if !BENCH_ENABLED {
            return;
        }

        let mut inner = self.inner.lock();
        if !inner.running || !inner.cfg.log_scheduler {
            return;
        }

        if let Some(ref mut sched) = inner.sched {
            sched.sample();
        }
    }
}

impl Drop for BenchWindow {
    fn drop(&mut self) {
        if !BENCH_ENABLED {
            return;
        }

        let mut inner = self.inner.lock();
        if inner.running && inner.cfg.end_on_drop {
            inner.running = false;
            inner.stop_ns = Some(bench_now_ns());
        }
    }
}

// ===== Helpers: scheduler counters, stats, memory, file IO =====

fn read_all_core_timer_ms() -> Vec<u128> {
    TIMER_TIME_SCHED
        .iter()
        .map(|a| {
            let ns = a.load(Ordering::SeqCst) as u128;
            (ns + 500_000) / 1_000_000
        })
        .collect()
}

fn read_all_core_sched_ns() -> Vec<u128> {
    TIMER_TIME_SCHED
        .iter()
        .map(|a| a.load(Ordering::SeqCst) as u128)
        .collect()
}

fn read_all_core_switches() -> Vec<u64> {
    PER_CORE_SWITCHES
        .iter()
        .map(|a| a.load(Ordering::SeqCst) as u64)
        .collect()
}

fn per_core_percent_x1000(total_ms: u128, core_ms: &[u128]) -> Vec<u128> {
    let mut out = Vec::with_capacity(core_ms.len());
    if total_ms == 0 {
        return out;
    }
    for &ms in core_ms {
        out.push((ms * 100_000 + total_ms / 2) / total_ms);
    }
    out
}

fn stddev_percent_x1000(percs: &[u128]) -> u128 {
    if percs.is_empty() {
        return 0;
    }
    let n = percs.len() as u128;
    let sum: u128 = percs.iter().copied().sum();
    let mean = sum / n;
    let mut ssd: u128 = 0;
    for &p in percs {
        let d = if p >= mean { p - mean } else { mean - p };
        ssd = ssd.saturating_add(d * d);
    }
    isqrt_u128(ssd / n)
}

fn isqrt_u128(n: u128) -> u128 {
    if n == 0 {
        return 0;
    }
    let mut x = n;
    let mut y = (x + n / x) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

fn cv_x1000(percs: &[u128]) -> u128 {
    if percs.is_empty() {
        return 0;
    }
    let n = percs.len() as u128;
    let mean = percs.iter().copied().sum::<u128>() / n;
    if mean == 0 {
        return 0;
    }
    (stddev_percent_x1000(percs) * 1000) / mean
}

fn median_x1000(mut percs: Vec<u128>) -> u128 {
    if percs.is_empty() {
        return 0;
    }
    percs.sort_unstable();
    let n = percs.len();
    if n & 1 == 1 {
        percs[n / 2]
    } else {
        (percs[n / 2 - 1] + percs[n / 2]) / 2
    }
}

fn mad_percent_x1000(percs: &[u128]) -> u128 {
    if percs.is_empty() {
        return 0;
    }
    let mut v = percs.to_vec();
    v.sort_unstable();
    let n = v.len();
    let med = if n & 1 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2
    };
    let mut devs: Vec<u128> = v
        .into_iter()
        .map(|p| if p >= med { p - med } else { med - p })
        .collect();
    devs.sort_unstable();
    let m = devs.len();
    if m & 1 == 1 {
        devs[m / 2]
    } else {
        (devs[m / 2 - 1] + devs[m / 2]) / 2
    }
}

fn max_gap_x1000(percs: &[u128]) -> (usize, usize, u128) {
    if percs.len() < 2 {
        return (0, 0, 0);
    }
    let mut min_val = percs[0];
    let mut max_val = percs[0];
    let mut min_idx = 0;
    let mut max_idx = 0;
    for (i, &p) in percs.iter().enumerate().skip(1) {
        if p < min_val {
            min_val = p;
            min_idx = i;
        }
        if p > max_val {
            max_val = p;
            max_idx = i;
        }
    }
    (min_idx, max_idx, max_val - min_val)
}

fn sample_memory(run_id: u32) -> MemSampleRow {
    let heap_used = interrupts::without_interrupts(move || used_memory());
    let mut used_bytes = USED_MEMORY.load(Ordering::SeqCst);
    used_bytes += boot_info().kernel_len as usize;
    let total_bytes = total_usable_bytes();

    let used_mb = (used_bytes / 1_048_576) as u64;
    let total_mb = (total_bytes / 1_048_576) as u64;

    let heap_used_kb = (heap_used / 1000) as u64;
    let heap_total_kb = (HEAP_SIZE / 1000) as u64;

    MemSampleRow {
        run_id,
        timestamp_ns: bench_now_ns(),
        used_mb,
        total_mb,
        heap_used_kb,
        heap_total_kb,
    }
}

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
