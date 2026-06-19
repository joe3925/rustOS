#[allow(dead_code)]
#[macro_export]
macro_rules! x86_exception_handler_wrapper {
    ($vis:vis $wrapper:ident, $handler:ident, error_code) => {
        #[unsafe(naked)]
        $vis extern "C" fn $wrapper() {
            ::core::arch::naked_asm!(
                "cli",

                "push r15",
                "push r14",
                "push r13",
                "push r12",
                "push r11",
                "push r10",
                "push r9",
                "push r8",
                "push rdi",
                "push rsi",
                "push rbp",
                "push rbx",
                "push rdx",
                "push rcx",
                "push rax",

                "mov  rdx, [rsp + 120]",

                "mov  rax, [rsp + 128]",
                "mov  [rsp + 120], rax",
                "mov  rax, [rsp + 136]",
                "mov  [rsp + 128], rax",
                "mov  rax, [rsp + 144]",
                "mov  [rsp + 136], rax",
                "mov  rax, [rsp + 152]",
                "mov  [rsp + 144], rax",
                "mov  rax, [rsp + 160]",
                "mov  [rsp + 152], rax",

                "mov  rcx, rsp",
                "mov  rbx, rsp",
                "cld",
                "and  rsp, -16",
                "sub  rsp, 32",
                "call {handler}",
                "mov  rsp, rbx",

                "pop  rax",
                "pop  rcx",
                "pop  rdx",
                "pop  rbx",
                "pop  rbp",
                "pop  rsi",
                "pop  rdi",
                "pop  r8",
                "pop  r9",
                "pop  r10",
                "pop  r11",
                "pop  r12",
                "pop  r13",
                "pop  r14",
                "pop  r15",

                "iretq",

                handler = sym $handler,
            );
        }
    };
    ($vis:vis $wrapper:ident, $handler:ident, no_error_code) => {
        #[unsafe(naked)]
        $vis extern "C" fn $wrapper() {
            ::core::arch::naked_asm!(
                "cli",

                "push r15",
                "push r14",
                "push r13",
                "push r12",
                "push r11",
                "push r10",
                "push r9",
                "push r8",
                "push rdi",
                "push rsi",
                "push rbp",
                "push rbx",
                "push rdx",
                "push rcx",
                "push rax",

                "mov  rcx, rsp",
                "mov  rbx, rsp",
                "cld",
                "and  rsp, -16",
                "sub  rsp, 32",
                "call {handler}",
                "mov  rsp, rbx",

                "pop  rax",
                "pop  rcx",
                "pop  rdx",
                "pop  rbx",
                "pop  rbp",
                "pop  rsi",
                "pop  rdi",
                "pop  r8",
                "pop  r9",
                "pop  r10",
                "pop  r11",
                "pop  r12",
                "pop  r13",
                "pop  r14",
                "pop  r15",

                "iretq",

                handler = sym $handler,
            );
        }
    };
}

pub(crate) mod exception_handlers;
