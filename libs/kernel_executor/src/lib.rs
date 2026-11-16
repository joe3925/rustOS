#![no_std]
#![cfg_attr(
    all(feature = "executor", not(any(test, loom, feature = "loom"))),
    feature(thread_local)
)]

extern crate alloc;
#[cfg(any(test, loom, feature = "loom"))]
extern crate std;

pub mod async_ffi;
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
mod sync;

#[cfg(all(test, feature = "executor", not(any(loom, feature = "loom"))))]
mod test;

#[cfg(all(test, feature = "executor", any(loom, feature = "loom")))]
#[path = "test/support.rs"]
mod test_support;

#[cfg(feature = "executor")]
#[macro_export]
macro_rules! println {
    () => {
        $crate::platform::print("\n")
    };
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let mut buf = alloc::string::String::new();
        core::write!(&mut buf, $($arg)*).unwrap();
        buf.push('\n');
        $crate::platform::print(&buf);
    }};
}

#[cfg(feature = "executor")]
#[macro_export]
macro_rules! spawn_join {
    ($future:expr_2021) => {
        $crate::runtime::runtime::spawn_join_owned($future)
    };
    (in $domain:expr_2021, $future:expr_2021) => {
        $crate::runtime::runtime::spawn_join_owned_in_executor_domain($domain, $future)
    };
}
