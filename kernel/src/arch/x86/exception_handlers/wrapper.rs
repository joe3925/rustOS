#[doc(hidden)]
#[macro_export]
macro_rules! x86_interrupt_call_template {
    ($before_call:literal, $handler:literal) => {
        concat!(
            "push r15\npush r14\npush r13\npush r12\npush r11\npush r10\n",
            "push r9\npush r8\npush rdi\npush rsi\npush rbp\npush rbx\n",
            "push rdx\npush rcx\npush rax\n",
            $before_call,
            "\nmov rcx, rsp\nmov rbx, rsp\ncld\nand rsp, -16\nsub rsp, 32\n",
            "call ", $handler, "\nmov rsp, rbx\n",
            "pop rax\npop rcx\npop rdx\npop rbx\npop rbp\npop rsi\npop rdi\n",
            "pop r8\npop r9\npop r10\npop r11\npop r12\npop r13\npop r14\npop r15\niretq"
        )
    };
}

#[allow(dead_code)]
#[macro_export]
macro_rules! platform_exception_handler_wrapper {
    ($vis:vis $wrapper:ident, $handler:ident, error_code) => {
        #[unsafe(naked)]
        $vis extern "C" fn $wrapper() {
            ::core::arch::naked_asm!(
                "cli",
                $crate::x86_interrupt_call_template!(
                    "mov rdx, [rsp + 120]\nmov rax, [rsp + 128]\nmov [rsp + 120], rax\nmov rax, [rsp + 136]\nmov [rsp + 128], rax\nmov rax, [rsp + 144]\nmov [rsp + 136], rax\nmov rax, [rsp + 152]\nmov [rsp + 144], rax\nmov rax, [rsp + 160]\nmov [rsp + 152], rax",
                    "{handler}"
                ),
                handler = sym $handler,
            );
        }
    };
    ($vis:vis $wrapper:ident, $handler:ident, no_error_code) => {
        #[unsafe(naked)]
        $vis extern "C" fn $wrapper() {
            ::core::arch::naked_asm!(
                "cli",
                $crate::x86_interrupt_call_template!("", "{handler}"),
                handler = sym $handler,
            );
        }
    };
}
