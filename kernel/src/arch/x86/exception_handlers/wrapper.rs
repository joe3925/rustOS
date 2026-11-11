#[allow(dead_code)]
#[macro_export]
macro_rules! platform_exception_handler_wrapper {
    ($vis:vis $wrapper:ident, $handler:ident, $kind:ident) => {
        $crate::x86_interrupt_entry!($vis $wrapper, $handler, $kind);
    };
}
