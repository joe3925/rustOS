use core::time::Duration;

/// Max stack frames recorded per RIP sample.
/// Match the kernel implementation.
pub const MAX_STACK_DEPTH: usize = 8;

/// Logical CPU identifier used by the bench API.
///
/// Keep this stable for ABI/serialization. The kernel can map
/// from its internal CPU indexing to this representation.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BenchCoreId(pub u16);

/// Span identifier allocated by the kernel bench runtime.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BenchSpanId(pub u32);

/// User-defined object identifier for associating spans/samples with a logical object.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BenchObjectId(pub u64);

/// Static tag used to categorize spans.
pub type BenchTag = &'static str;

/// Result of a full benchmark sweep across multiple inflight levels.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BenchSweepResult {
    /// Number of levels actually tested
    pub used: u32,
    /// Padding for alignment
    pub _pad: u32,
    /// Results for each level (up to BENCH_MAX_LEVELS)
    pub levels: [BenchLevelResult; BENCH_MAX_LEVELS],
}
/// Maximum number of inflight levels supported by the benchmark sweep.
/// Covers power-of-two levels: 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024
pub const BENCH_MAX_LEVELS: usize = 11;

/// Result for a single inflight level benchmark.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct BenchLevelResult {
    /// Inflight level tested
    pub inflight: u32,
    /// Number of requests completed
    pub request_count: u32,
    /// Total wall-clock cycles for the entire run at this inflight level
    pub total_time_cycles: u64,
    /// Total cycles across all requests
    pub total_cycles: u64,
    /// Average cycles per request
    pub avg_cycles: u64,
    /// Maximum cycles for any single request
    pub max_cycles: u64,
    /// Minimum cycles for any single request (0 if no samples)
    pub min_cycles: u64,
    /// Median (p50) latency in cycles
    pub p50_cycles: u64,
    /// 99th percentile latency in cycles
    pub p99_cycles: u64,
    /// 99.9th percentile latency in cycles
    pub p999_cycles: u64,
    /// CPU idle percentage during this level (0.0 - 100.0)
    pub idle_pct: f64,
}

impl Default for BenchSweepResult {
    fn default() -> Self {
        Self {
            used: 0,
            _pad: 0,
            levels: [BenchLevelResult::default(); BENCH_MAX_LEVELS],
        }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BenchSweepParams {
    pub version: u32,
    pub flags: u32,
    pub total_bytes: u64,
    pub request_size: u32,
    pub start_sector: u64,
    pub max_inflight: u16, // 0 = auto
    pub _reserved0: u16,
    pub _reserved1: u32,
}

impl Default for BenchSweepParams {
    fn default() -> Self {
        Self {
            version: BENCH_PARAMS_VERSION_1,
            flags: BENCH_FLAG_IRQ | BENCH_FLAG_POLL,
            total_bytes: 1024 * 1024 * 1024,
            request_size: 64 * 1024,
            start_sector: 0,
            max_inflight: 0,
            _reserved0: 0,
            _reserved1: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BenchSweepBothResult {
    pub params_used: BenchSweepParams,
    pub irq: BenchSweepResult,
    pub poll: BenchSweepResult,
    pub queue_count: u16,
    pub queue0_size: u16,
    pub indirect_enabled: u8,
    pub msix_enabled: u8,
    pub _pad0: u16,
}
pub const BENCH_PARAMS_VERSION_1: u32 = 1;

pub const BENCH_FLAG_IRQ: u32 = 1 << 0; // allow irq waits
pub const BENCH_FLAG_POLL: u32 = 1 << 1; // pure polling (no waits)

/// Configuration for a benchmark window.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct BenchWindowConfig {
    pub name: &'static str,
    pub folder: &'static str,

    pub log_samples: bool,
    pub log_spans: bool,
    /// When true, skip per-core exports to avoid the overhead of per-core processing.
    pub disable_per_core: bool,

    // When true, export a per-event "memory.csv" stream that includes BOTH
    // heap/memory and scheduler counters. Sampling is driven by span/sample
    // events (not persist).
    pub log_mem_on_persist: bool,

    pub end_on_drop: bool,
    pub timeout_ms: Option<Duration>,
    pub auto_persist_secs: Option<Duration>,

    pub sample_reserve: usize,
    pub span_reserve: usize,
}

impl Default for BenchWindowConfig {
    fn default() -> Self {
        BenchWindowConfig {
            name: "default",
            folder: "C:\\system\\logs",
            log_samples: true,
            log_spans: true,
            disable_per_core: false,
            log_mem_on_persist: false,
            end_on_drop: true,
            timeout_ms: None,
            auto_persist_secs: None,
            sample_reserve: 8192,
            span_reserve: 1024,
        }
    }
}

/// Opaque handle to a bench window owned by the kernel.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BenchWindowHandle(pub u32);
