#![no_std]

extern crate alloc;
#[cfg(any(test, loom, feature = "loom", feature = "hosted"))]
extern crate std;

pub mod async_ffi;
pub mod cancellation;
pub mod thread_state;

#[cfg(feature = "executor")]
mod domain;
pub mod future_allocation;
#[cfg(feature = "executor")]
pub mod global_async;
#[cfg(feature = "executor")]
pub mod growable_slab;
#[cfg(feature = "executor")]
pub mod platform;
#[cfg(feature = "executor")]
pub mod runtime;
#[cfg(feature = "executor")]
mod steal_queue;
#[cfg(feature = "executor")]
mod sync;

#[cfg(all(test, feature = "executor", not(any(loom, feature = "loom"))))]
mod test;

#[cfg(all(test, feature = "executor"))]
#[path = "test/support.rs"]
mod test_support;

#[cfg(feature = "executor")]
#[macro_export]
macro_rules! println {
    ($platform:ty;) => {
        <$platform as $crate::platform::ExecutorPlatform>::print("\n")
    };
    ($platform:ty; $($arg:tt)*) => {{
        use core::fmt::Write;
        let mut buf = alloc::string::String::new();
        core::write!(&mut buf, $($arg)*).unwrap();
        buf.push('\n');
        <$platform as $crate::platform::ExecutorPlatform>::print(&buf);
    }};
}

#[cfg(feature = "executor")]
#[macro_export]
macro_rules! spawn_join {
    ($platform:ty; $future:expr_2021) => {
        $crate::runtime::runtime::spawn_join_owned::<$platform, _, _>($future)
    };
    ($platform:ty; in $domain:expr_2021, $future:expr_2021) => {
        $crate::runtime::runtime::spawn_join_owned_in_executor_domain::<$platform, _, _>($domain, $future)
    };
}

#[cfg(feature = "executor")]
pub mod worker_pool;
