#![no_std]

extern crate alloc;

pub mod global_async;
pub mod platform;
pub mod runtime;

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
