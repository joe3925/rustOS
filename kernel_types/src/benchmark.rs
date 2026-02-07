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

/// Configuration for a benchmark window.
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
