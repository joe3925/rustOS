#[cfg(any(loom, feature = "loom"))]
pub mod atomic {
    pub use loom::sync::atomic::{
        AtomicBool, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering,
    };
}

#[cfg(not(any(loom, feature = "loom")))]
pub mod atomic {
    pub use core::sync::atomic::{
        AtomicBool, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering,
    };
}

pub use alloc::sync::Arc;

#[cfg(not(any(loom, feature = "loom")))]
pub use spin::Mutex;

#[cfg(any(loom, feature = "loom"))]
pub struct Mutex<T>(loom::sync::Mutex<T>);

#[cfg(any(loom, feature = "loom"))]
impl<T> Mutex<T> {
    pub fn new(value: T) -> Self {
        Self(loom::sync::Mutex::new(value))
    }

    pub fn lock(&self) -> loom::sync::MutexGuard<'_, T> {
        self.0.lock().expect("loom mutex poisoned")
    }
}

#[cfg(not(any(loom, feature = "loom")))]
pub use core::hint::spin_loop;

#[cfg(any(loom, feature = "loom"))]
#[inline]
pub fn spin_loop() {
    loom::thread::yield_now();
}

#[cfg(all(test, any(loom, feature = "loom")))]
const DEFAULT_LOOM_MAX_BRANCHES: usize = 10_000_000;

#[cfg(all(test, any(loom, feature = "loom")))]
fn loom_max_branches() -> usize {
    std::env::var("KERNEL_EXECUTOR_LOOM_MAX_BRANCHES")
        .or_else(|_| std::env::var("LOOM_MAX_BRANCHES"))
        .map(|v| {
            v.parse()
                .expect("invalid value for Loom max branch setting")
        })
        .unwrap_or(DEFAULT_LOOM_MAX_BRANCHES)
}

#[cfg(all(test, any(loom, feature = "loom")))]
pub(crate) fn exhaustive_model<F>(f: F)
where
    F: Fn() + Send + Sync + 'static,
{
    let mut builder = loom::model::Builder::new();

    // Use full scheduler exploration for executor tests. The branch cap only
    // overrides Loom's low 1,000-branch default and can be raised for longer
    // runs with KERNEL_EXECUTOR_LOOM_MAX_BRANCHES or LOOM_MAX_BRANCHES.
    builder.max_branches = loom_max_branches();
    builder.max_duration = None;
    builder.max_permutations = None;
    builder.preemption_bound = None;

    builder.check(f);
}
