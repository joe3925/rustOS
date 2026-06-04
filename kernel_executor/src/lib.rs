#![no_std]

extern crate alloc;
#[cfg(any(test, loom, feature = "loom"))]
extern crate std;

mod domain;
pub mod global_async;
pub mod platform;
pub mod runtime;
mod round_robin;
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
