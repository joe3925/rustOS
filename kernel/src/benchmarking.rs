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
use crate::util::{boot_info, TOTAL_TIME};

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use kernel_types::fs::{FsSeekWhence, OpenFlags};
use nostd_runtime::{block_on, spawn_blocking};
use spin::Mutex;
use x86_64::instructions::interrupts;

const BENCH_ENABLED: bool = cfg!(debug_assertions);
const MAX_STACK_DEPTH: usize = 8;

#[derive(Clone)]
pub struct BenchWindowConfig {
    /// Logical name of the window.
    ///
    /// This does not affect behavior, but is useful when inspecting logs
    /// on the host side (e.g., choosing which window a CSV came from or
    /// labeling plots).
    pub name: &'static str,

    /// Directory on the target where this window writes its CSV files.
    ///
    /// The window will create (if needed) and append to CSVs inside this
    /// folder (e.g., `samples.csv`, `spans.csv`, `scheduler.csv`,
    /// `memory.csv`) when `persist` is called.
    pub folder: &'static str,

    /// Enable recording of RIP/stack samples for this window.
    ///
    /// When true, calls to `log_sample_*` while the window is running will
    /// append `StackSample` entries and eventually export them to
    /// `samples.csv` on `persist`.
    pub log_samples: bool,

    /// Enable recording of span timings for this window.
    ///
    /// When true, `span_guard(...)` will track span begin/end pairs and
    /// accumulate `SpanRecord` entries, which are exported to `spans.csv`
    /// on `persist`.
    pub log_spans: bool,

    /// Enable collection of scheduler-level summary metrics.
    ///
    /// When true, calls to `sample_scheduler()` while the window is running
    /// will feed a `SchedulerAcc` accumulator, and `persist` will emit
    /// summary rows to `scheduler.csv`.
    pub log_scheduler: bool,

    /// Enable recording of a memory snapshot on each `persist` call.
    ///
    /// When true, `persist` will take a single memory usage sample for the
    /// current run (used/total and heap usage) and append it to
    /// `memory.csv`.
    pub log_mem_on_persist: bool,

    /// If true, dropping the `BenchWindow` will implicitly stop it.
    ///
    /// This only affects the running state: the window is marked as stopped
    /// when the last `BenchWindow` handle is dropped. It does *not*
    /// automatically call `persist`; you must still call `persist`
    /// explicitly if you want data flushed to disk.
    pub end_on_drop: bool,

    /// Optional maximum lifetime for a single run of this window, in
    /// milliseconds.
    ///
    /// When set, `start()` may spawn a blocking worker that sleeps for this
    /// duration and then calls `stop()` for this window. If `None`, the
    /// window runs until `stop()` is called or the handle is dropped (and
    /// `end_on_drop` is true).
    pub timeout_ms: Option<u64>,

    /// Optional auto-persist interval, in seconds.
    ///
    /// When set, the intended behavior is that a worker thread periodically
    /// calls `persist()` while the window is running, so large runs can
    /// flush partial data to disk without manual intervention. If `None`,
    /// `persist()` is only invoked when the caller explicitly calls it.
    pub auto_persist_secs: Option<u64>,

    /// Initial capacity for the per-window sample buffer.
    ///
    /// This controls the `reserve` used for `Vec<StackSample>` when the
    /// window is created. A larger value reduces reallocations (and their
    /// noise) during heavy sampling at the cost of more upfront memory.
    pub sample_reserve: usize,

    /// Initial capacity for the per-window span buffer.
    ///
    /// This controls the `reserve` used for `Vec<SpanRecord>` when the
    /// window is created. A larger value reduces reallocations when many
    /// spans are recorded in a single run.
    pub span_reserve: usize,
}

impl Default for BenchWindowConfig {
    fn default() -> Self {
        BenchWindowConfig {
            name: "default",
            folder: "C:\\system\\logs\\default",
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

#[derive(Clone, Copy, Debug)]
struct SpanBegin {
    tag: &'static str,
    object_id: u64,
    start_ns: u64,
    core_id: u16,
}

#[derive(Clone, Copy, Debug)]
pub struct SpanRecord {
    pub run_id: u32,
    pub tag: &'static str,
    pub object_id: u64,
    pub core_id: u16,
    pub start_ns: u64,
    pub duration_ns: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct StackSample {
    pub run_id: u32,
    pub timestamp_ns: u64,
    pub core_id: u16,
    pub rip: u64,
    pub depth: u8,
    pub stack: [u64; MAX_STACK_DEPTH],
}

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

struct BenchWindowInner {
    cfg: BenchWindowConfig,

    running: bool,
    start_ns: u64,

    run_id_counter: u32,
    current_run_id: u32,

    next_span_id: u32,
    open_spans: BTreeMap<u32, SpanBegin>,
    spans: Vec<SpanRecord>,
    samples: Vec<StackSample>,
    sched: Option<SchedulerAcc>,
    sched_rows: Vec<SchedulerSummaryRow>,
    mem_rows: Vec<MemSampleRow>,

    last_flushed_sample_idx: usize,
    last_flushed_span_idx: usize,
    last_flushed_sched_idx: usize,
    last_flushed_mem_idx: usize,
}

impl BenchWindowInner {
    fn new(cfg: BenchWindowConfig) -> Self {
        let mut spans = Vec::new();
        let mut samples = Vec::new();
        if cfg.log_spans {
            spans.reserve(cfg.span_reserve);
        }
        if cfg.log_samples {
            samples.reserve(cfg.sample_reserve);
        }

        let sched = if cfg.log_scheduler {
            Some(SchedulerAcc::new())
        } else {
            None
        };

        BenchWindowInner {
            cfg,
            running: false,
            start_ns: 0,
            run_id_counter: 1,
            current_run_id: 0,
            next_span_id: 1,
            open_spans: BTreeMap::new(),
            spans,
            samples,
            sched,
            sched_rows: Vec::new(),
            mem_rows: Vec::new(),
            last_flushed_sample_idx: 0,
            last_flushed_span_idx: 0,
            last_flushed_sched_idx: 0,
            last_flushed_mem_idx: 0,
        }
    }

    fn build_export_strings(&mut self) -> (String, String, String, String) {
        let mut samples_out = String::new();
        let mut spans_out = String::new();
        let mut sched_out = String::new();
        let mut mem_out = String::new();

        if self.samples.len() > self.last_flushed_sample_idx {
            if self.last_flushed_sample_idx == 0 {
                samples_out.push_str(
                    "run_id,timestamp_ns,core,rip,depth,\
                     frame0,frame1,frame2,frame3,frame4,frame5,frame6,frame7\n",
                );
            }
            for s in &self.samples[self.last_flushed_sample_idx..] {
                samples_out.push_str(&format!(
                    "{},{},{},0x{:016x},{}",
                    s.run_id, s.timestamp_ns, s.core_id, s.rip, s.depth
                ));
                let depth = s.depth as usize;
                for i in 0..MAX_STACK_DEPTH {
                    samples_out.push(',');
                    if i < depth {
                        samples_out.push_str(&format!("0x{:016x}", s.stack[i]));
                    }
                }
                samples_out.push('\n');
            }
            self.last_flushed_sample_idx = self.samples.len();
        }

        if self.spans.len() > self.last_flushed_span_idx {
            if self.last_flushed_span_idx == 0 {
                spans_out.push_str("run_id,tag,object_id,core,start_ns,duration_ns\n");
            }
            for s in &self.spans[self.last_flushed_span_idx..] {
                spans_out.push_str(&format!(
                    "{},{},0x{:016x},{},{},{}\n",
                    s.run_id, s.tag, s.object_id, s.core_id, s.start_ns, s.duration_ns
                ));
            }
            self.last_flushed_span_idx = self.spans.len();
        }

        if self.sched_rows.len() > self.last_flushed_sched_idx {
            if self.last_flushed_sched_idx == 0 {
                sched_out.push_str(
                    "run_id,window_total_ms,ncores,avg_util_x100000,\
                     total_ctx_per_sec,avg_ctx_per_sec_per_core,avg_ns_per_switch,\
                     timer_overhead_x100000,mean_util_x1000,median_util_x1000,\
                     stddev_util_x1000,mad_util_x1000,cv_util_x1000,\
                     min_core_idx,max_core_idx,max_gap_x1000\n",
                );
            }
            for r in &self.sched_rows[self.last_flushed_sched_idx..] {
                sched_out.push_str(&format!(
                    "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
                    r.run_id,
                    r.window_total_ms,
                    r.ncores,
                    r.avg_util_x100000,
                    r.total_ctx_per_sec,
                    r.avg_ctx_per_sec_per_core,
                    r.avg_ns_per_switch,
                    r.timer_overhead_x100000,
                    r.mean_util_x1000,
                    r.median_util_x1000,
                    r.stddev_util_x1000,
                    r.mad_util_x1000,
                    r.cv_util_x1000,
                    r.min_core_idx,
                    r.max_core_idx,
                    r.max_gap_x1000
                ));
            }
            self.last_flushed_sched_idx = self.sched_rows.len();
        }

        if self.mem_rows.len() > self.last_flushed_mem_idx {
            if self.last_flushed_mem_idx == 0 {
                mem_out
                    .push_str("run_id,timestamp_ns,used_mb,total_mb,heap_used_kb,heap_total_kb\n");
            }
            for r in &self.mem_rows[self.last_flushed_mem_idx..] {
                mem_out.push_str(&format!(
                    "{},{},{},{},{},{}\n",
                    r.run_id,
                    r.timestamp_ns,
                    r.used_mb,
                    r.total_mb,
                    r.heap_used_kb,
                    r.heap_total_kb
                ));
            }
            self.last_flushed_mem_idx = self.mem_rows.len();
        }

        (samples_out, spans_out, sched_out, mem_out)
    }
}

#[derive(Clone)]
pub struct BenchWindow {
    inner: Arc<Mutex<BenchWindowInner>>,
}

impl BenchWindow {
    pub fn new(cfg: BenchWindowConfig) -> Self {
        let inner = BenchWindowInner::new(cfg);
        BenchWindow {
            inner: Arc::new(Mutex::new(inner)),
        }
    }

    pub async fn start(&self) {
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
            inner.current_run_id = inner.run_id_counter;
            inner.run_id_counter = inner.run_id_counter.wrapping_add(1);

            if let Some(ref mut sched) = inner.sched {
                sched.reset();
            }

            auto_persist_secs_opt = inner.cfg.auto_persist_secs;
            timeout_ms_opt = inner.cfg.timeout_ms;
        }

        if let Some(timeout_ms) = timeout_ms_opt {
            let this = self.clone();
            spawn_blocking(move || {
                interrupt_index::wait_millis_idle(timeout_ms);
                this.stop();
            });
        }

        if let Some(secs) = auto_persist_secs_opt {
            if secs > 0 {
                let interval_ms = secs.saturating_mul(1000);
                let this = self.clone();
                spawn_blocking(move || loop {
                    interrupt_index::wait_millis_idle(interval_ms);
                    if !BENCH_ENABLED {
                        return;
                    }
                    {
                        let inner = this.inner.lock();
                        if !inner.running {
                            break;
                        }
                    }
                    this.persist();
                });
            }
        }
    }

    pub fn stop(&self) {
        if !BENCH_ENABLED {
            return;
        }
        let mut inner = self.inner.lock();
        inner.running = false;
    }

    pub fn persist(&self) {
        if !BENCH_ENABLED {
            return;
        }

        let (cfg_folder, samples, spans, sched, mem) = {
            let mut inner = self.inner.lock();

            if inner.cfg.log_scheduler {
                if let Some(ref sched) = inner.sched {
                    if let Some(row) = sched.build_summary(inner.current_run_id) {
                        inner.sched_rows.push(row);
                    }
                }
            }

            if inner.cfg.log_mem_on_persist {
                let mem_row = sample_memory(inner.current_run_id);
                inner.mem_rows.push(mem_row);
            }

            let (samples, spans, sched, mem) = inner.build_export_strings();
            (inner.cfg.folder, samples, spans, sched, mem)
        };

        if !samples.is_empty() {
            let _ = block_on(append_named_file(
                cfg_folder,
                "samples.csv",
                samples.as_bytes(),
            ));
        }
        if !spans.is_empty() {
            let _ = block_on(append_named_file(cfg_folder, "spans.csv", spans.as_bytes()));
        }
        if !sched.is_empty() {
            let _ = block_on(append_named_file(
                cfg_folder,
                "scheduler.csv",
                sched.as_bytes(),
            ));
        }
        if !mem.is_empty() {
            let _ = block_on(append_named_file(cfg_folder, "memory.csv", mem.as_bytes()));
        }
    }

    pub fn span_guard(&self, tag: &'static str, object_id: u64) -> BenchSpanGuard {
        if !BENCH_ENABLED {
            return BenchSpanGuard {
                window: self.clone(),
                span_id: 0,
                enabled: false,
            };
        }

        let mut inner = self.inner.lock();
        if !inner.running || !inner.cfg.log_spans {
            return BenchSpanGuard {
                window: self.clone(),
                span_id: 0,
                enabled: false,
            };
        }

        let span_id = inner.next_span_id;
        inner.next_span_id = inner.next_span_id.wrapping_add(1);

        let start_ns = bench_now_ns();
        let core_id = interrupt_index::current_cpu_id() as u16;

        inner.open_spans.insert(
            span_id,
            SpanBegin {
                tag,
                object_id,
                start_ns,
                core_id,
            },
        );

        BenchSpanGuard {
            window: self.clone(),
            span_id,
            enabled: true,
        }
    }

    fn finish_span(&self, span_id: u32) {
        if !BENCH_ENABLED {
            return;
        }

        let now_ns = bench_now_ns();
        let mut inner = self.inner.lock();
        if !inner.running || !inner.cfg.log_spans {
            return;
        }

        if let Some(begin) = inner.open_spans.remove(&span_id) {
            let dur = now_ns.saturating_sub(begin.start_ns);
            let run_id = inner.current_run_id;
            inner.spans.push(SpanRecord {
                run_id,
                tag: begin.tag,
                object_id: begin.object_id,
                core_id: begin.core_id,
                start_ns: begin.start_ns,
                duration_ns: dur,
            });
        }
    }

    pub fn log_sample_current_core(&self, rip: u64, stack: &[u64]) {
        if !BENCH_ENABLED {
            return;
        }

        let core_id = interrupt_index::current_cpu_id() as u16;
        let ts = bench_now_ns();
        self.log_sample_for_core(core_id, ts, rip, stack);
    }

    pub fn log_sample_for_core(&self, core_id: u16, timestamp_ns: u64, rip: u64, stack: &[u64]) {
        if !BENCH_ENABLED {
            return;
        }

        let mut inner = self.inner.lock();
        if !inner.running || !inner.cfg.log_samples {
            return;
        }

        let mut sample = StackSample {
            run_id: inner.current_run_id,
            timestamp_ns,
            core_id,
            rip,
            depth: 0,
            stack: [0; MAX_STACK_DEPTH],
        };

        let depth = stack.len().min(MAX_STACK_DEPTH);
        sample.depth = depth as u8;
        for i in 0..depth {
            sample.stack[i] = stack[i];
        }

        inner.samples.push(sample);
    }

    // Intended to be called from your timer / scheduler path while the window is running.
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
        }
    }
}

pub struct BenchSpanGuard {
    window: BenchWindow,
    span_id: u32,
    enabled: bool,
}

impl Drop for BenchSpanGuard {
    fn drop(&mut self) {
        if self.enabled {
            self.window.finish_span(self.span_id);
        }
    }
}

fn bench_now_ns() -> u64 {
    TOTAL_TIME.wait().elapsed_millis() as u64 * 1_000_000
}

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

    Ok(())
}

pub fn used_memory() -> usize {
    HEAP_SIZE - ALLOCATOR.free_memory()
}
