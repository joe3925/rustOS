#![no_std]

extern crate alloc;
#[cfg(any(test, loom, feature = "loom"))]
extern crate std;

mod domain;
pub mod future_arena;
pub mod global_async;
pub mod growable_slab;
pub mod platform;
mod round_robin;
pub mod runtime;
mod sync;

#[cfg(all(test, not(any(loom, feature = "loom"))))]
mod test;

#[macro_export]
macro_rules! println {
    () => {
        $crate::platform::platform().print("\n")
    };
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let mut buf = alloc::string::String::new();
        core::write!(&mut buf, $($arg)*).unwrap();
        buf.push('\n');
        $crate::platform::platform().print(&buf);
    }};
}

#[macro_export]
macro_rules! spawn_join {
    ($future:expr) => {
        $crate::runtime::runtime::spawn_join_owned($future)
    };
    (in $domain:expr, $future:expr) => {
        $crate::runtime::runtime::spawn_join_owned_in_executor_domain($domain, $future)
    };
}
