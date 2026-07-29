#[cfg(any(loom, feature = "loom"))]
pub mod atomic {
    pub use loom::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
}

#[cfg(not(any(loom, feature = "loom")))]
pub mod atomic {
    pub use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
}

#[cfg(any(loom, feature = "loom"))]
pub struct RwLock<T>(loom::sync::RwLock<T>);

#[cfg(any(loom, feature = "loom"))]
impl<T> RwLock<T> {
    pub fn new(value: T) -> Self {
        Self(loom::sync::RwLock::new(value))
    }

    pub fn read(&self) -> loom::sync::RwLockReadGuard<'_, T> {
        self.0.read().expect("loom rwlock poisoned")
    }

    pub fn write(&self) -> loom::sync::RwLockWriteGuard<'_, T> {
        self.0.write().expect("loom rwlock poisoned")
    }
}

#[cfg(not(any(loom, feature = "loom")))]
pub use spin::RwLock;

#[cfg(all(test, any(loom, feature = "loom")))]
pub fn model(f: impl Fn() + Send + Sync + 'static) {
    let mut builder = loom::model::Builder::new();
    builder.max_branches = std::env::var("KERNEL_SYNC_LOOM_MAX_BRANCHES")
        .or_else(|_| std::env::var("LOOM_MAX_BRANCHES"))
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(100_000);
    builder.max_duration = None;
    builder.check(f);
}
