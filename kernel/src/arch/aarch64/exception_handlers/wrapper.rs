#[allow(dead_code)]
#[macro_export]
macro_rules! platform_exception_handler_wrapper {
    ($vis:vis $wrapper:ident, $handler:ident, exception_info) => {
        $vis extern "C" fn $wrapper(
            state: &mut crate::scheduling::state::State,
            info: crate::arch::aarch64::exception_handlers::Aarch64ExceptionInfo,
        ) {
            $handler(state, info)
        }
    };
}
