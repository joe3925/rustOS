use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::time::Duration;

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

pub const BENCH_SAMPLE_PROTO_SCHEMA_VERSION: u32 = 2;

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BenchOverflowPolicy {
    /// Panic immediately when a per-core sample buffer fills; intended for profiler debugging.
    Panic = 0,
    /// Drop the new sample, increment overflow/drop counters, and leave the workload unperturbed.
    DropAndCount = 1,
    /// Stop accepting new samples after the first full buffer, but allow the workload to continue.
    StopSampling = 2,
    /// Queue one background drain worker when buffers are full or near full; marks the run perturbed.
    QueueDrainWorker = 3,
    /// Pause measured workload time, flush buffers, shift logical time forward, then resume sampling.
    PauseFlushCompactTime = 4,
    /// Pause measured workload time, flush buffers without shifting timestamps, then resume sampling.
    PauseFlushWallTime = 5,
    /// Reuse the per-core buffer as a circular buffer, keeping newest samples and counting overwrites.
    OverwriteOldest = 6,
}

impl Default for BenchOverflowPolicy {
    fn default() -> Self {
        BenchOverflowPolicy::DropAndCount
    }
}

pub const BENCH_FRAME_KIND_UNKNOWN: u32 = 0;
pub const BENCH_FRAME_KIND_PE_X64: u32 = 2;

pub const BENCH_UNWIND_STATUS_OK: u32 = 0;
pub const BENCH_UNWIND_STATUS_TRUNCATED: u32 = 1 << 0;
pub const BENCH_UNWIND_STATUS_NO_UNWIND_INFO: u32 = 1 << 1;
pub const BENCH_UNWIND_STATUS_BAD_STACK_READ: u32 = 1 << 2;
pub const BENCH_UNWIND_STATUS_BAD_UNWIND_INFO: u32 = 1 << 3;
pub const BENCH_UNWIND_STATUS_UNSUPPORTED_OPCODE: u32 = 1 << 4;
pub const BENCH_UNWIND_STATUS_LEAF_FALLBACK: u32 = 1 << 5;
pub const BENCH_UNWIND_STATUS_PE_UNWIND: u32 = 1 << 6;
pub const BENCH_UNWIND_STATUS_UNKNOWN_FRAME: u32 = 1 << 8;
pub const BENCH_UNWIND_STATUS_STACK_BOUNDS_MISSING: u32 = 1 << 9;

#[derive(Clone, PartialEq, prost::Message)]
pub struct BenchSampleChunkProto {
    #[prost(uint32, tag = "1")]
    pub schema_version: u32,
    #[prost(uint32, tag = "2")]
    pub run_id: u32,
    #[prost(uint32, tag = "3")]
    pub chunk_index: u32,
    #[prost(uint32, tag = "4")]
    pub target_core_id: u32,
    #[prost(bool, tag = "5")]
    pub aggregate: bool,
    #[prost(uint64, tag = "6")]
    pub start_ns: u64,
    #[prost(uint64, tag = "7")]
    pub end_ns: u64,
    #[prost(uint32, tag = "8")]
    pub frame_limit: u32,
    #[prost(message, repeated, tag = "9")]
    pub samples: Vec<BenchSampleProto>,
    #[prost(message, repeated, tag = "10")]
    pub dropped: Vec<BenchDroppedSampleCounterProto>,
    #[prost(uint64, repeated, packed = "true", tag = "11")]
    pub max_seq_by_core: Vec<u64>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct BenchSampleProto {
    #[prost(uint64, tag = "1")]
    pub seq: u64,
    #[prost(uint64, tag = "2")]
    pub timestamp_ns: u64,
    #[prost(uint32, tag = "3")]
    pub core_id: u32,
    #[prost(uint64, tag = "4")]
    pub task_id: u64,
    #[prost(uint64, tag = "5")]
    pub sampled_rip: u64,
    #[prost(uint32, tag = "6")]
    pub unwind_status: u32,
    #[prost(uint64, repeated, packed = "true", tag = "7")]
    pub frames: Vec<u64>,
    #[prost(uint32, repeated, packed = "true", tag = "8")]
    pub frame_kinds: Vec<u32>,
    #[prost(uint64, tag = "9")]
    pub stack_low: u64,
    #[prost(uint64, tag = "10")]
    pub stack_high: u64,
    #[prost(uint64, optional, tag = "11")]
    pub adjusted_timestamp_ns: Option<u64>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct BenchDroppedSampleCounterProto {
    #[prost(uint32, tag = "1")]
    pub core_id: u32,
    #[prost(uint64, tag = "2")]
    pub ring_full: u64,
    #[prost(uint64, tag = "3")]
    pub ring_lock_busy: u64,
    #[prost(uint64, tag = "4")]
    pub bad_context: u64,
    #[prost(uint64, tag = "5")]
    pub unwind_failures: u64,
    #[prost(uint64, tag = "6")]
    pub samples_dropped: u64,
    #[prost(uint64, tag = "7")]
    pub samples_overwritten: u64,
    #[prost(uint64, tag = "8")]
    pub sampling_stopped: u64,
    #[prost(uint64, tag = "9")]
    pub flush_count: u64,
    #[prost(uint64, tag = "10")]
    pub pause_flush_ns: u64,
}

/// Configuration for a benchmark window.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct BenchWindowConfig {
    /// Human-readable window name used when allocating the benchmark output directory.
    pub name: String,
    /// Root folder path where benchmark session archives are written.
    pub folder: String,

    /// When true, capture and export sampled callchain events.
    pub log_samples: bool,
    /// When true, capture and export span events.
    pub log_spans: bool,
    /// When true, skip per-core exports and write only aggregate exports.
    pub disable_per_core: bool,

    /// When true, export a per-event `memory.csv` stream containing memory, heap, and scheduler counters.
    /// Rows are driven by span/sample events rather than by persist calls.
    pub log_mem_on_persist: bool,
    /// When true, include debug metadata such as kernel symbol information in each persist.
    pub export_debug_metadata: bool,

    /// When true, stop and asynchronously persist the window when the handle is dropped.
    pub end_on_drop: bool,
    /// Optional timeout duration after `start` before the window automatically stops and persists.
    pub timeout_ms: Option<Duration>,
    /// Optional interval duration between automatic persists while the window is running.
    pub auto_persist_secs: Option<Duration>,

    /// Default per-core sample event capacity, in events; zero falls back to the kernel default.
    pub sample_reserve: usize,
    /// Per-core span event capacity, in events, added only when span logging is enabled.
    pub span_reserve: usize,
    /// Optional policy applied when a sample cannot be inserted into the per-core event buffer.
    pub overflow_policy: Option<BenchOverflowPolicy>,
    /// Optional override for the per-core sample event budget, in events.
    /// When absent, `sample_reserve` is used, or the kernel default if `sample_reserve` is zero.
    /// This contributes to the shared per-core event buffer size, not a separate sample-only buffer.
    pub sample_capacity: Option<usize>,
    /// Optional maximum number of drained events per persisted export chunk, in events.
    /// This controls output chunking during persist and does not change in-memory buffer capacity.
    pub sample_chunk_capacity: Option<usize>,
    /// Optional maximum captured unwind depth, in frames.
    pub max_unwind_depth: Option<usize>,
}

impl Default for BenchWindowConfig {
    fn default() -> Self {
        BenchWindowConfig {
            name: "default".to_string(),
            folder: "C:\\system\\logs".to_string(),
            log_samples: true,
            log_spans: true,
            disable_per_core: false,
            log_mem_on_persist: false,
            export_debug_metadata: false,
            end_on_drop: true,
            timeout_ms: None,
            auto_persist_secs: None,
            sample_reserve: 8192,
            span_reserve: 1024,
            overflow_policy: None,
            sample_capacity: None,
            sample_chunk_capacity: None,
            max_unwind_depth: None,
        }
    }
}

/// Opaque handle to a bench window owned by the kernel.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BenchWindowHandle(pub u32);

/// Opaque handle for the suite invocation currently owned by the kernel runner.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BenchRunHandle(pub u32);

/// Whether a metric should increase or decrease when performance improves.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BenchMetricDirection {
    Informational = 0,
    LowerIsBetter = 1,
    HigherIsBetter = 2,
}

/// Unit attached to every raw measurement emitted by a suite.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BenchMetricUnit {
    Nanoseconds = 0,
    Cycles = 1,
    Bytes = 2,
    BytesPerSecond = 3,
    OperationsPerSecond = 4,
    Count = 5,
    Ratio = 6,
}

/// Completion state returned by an asynchronous suite callback.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BenchSuiteStatus {
    Passed = 0,
    Failed = 1,
    Skipped = 2,
}

pub type BenchSuiteCallback =
    extern "C" fn(BenchRunHandle) -> crate::async_ffi::AbiFuture<BenchSuiteStatus>;

/// Owned metadata copied into the kernel suite registry.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct BenchSuiteDescriptor {
    pub name: String,
    pub description: String,
    pub tags: Vec<String>,
    pub independent_boots: u16,
    pub callback: BenchSuiteCallback,
}

impl BenchSuiteDescriptor {
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        tags: Vec<String>,
        callback: BenchSuiteCallback,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            tags,
            independent_boots: 1,
            callback,
        }
    }

    /// Sets how many fresh kernel boots contribute independent observations.
    ///
    /// More boots make confidence intervals more trustworthy but increase execution time almost
    /// linearly. Eight to twelve boots is a useful range for high-confidence CI comparisons; one
    /// is appropriate only for correctness checks or informational metrics.
    pub fn with_independent_boots(mut self, boots: u16) -> Self {
        self.independent_boots = boots.max(1);
        self
    }
}
