use core::mem::{align_of, size_of};

use super::super::scheduling::state::FpuState;

pub(crate) const FPU_STATE_OFFSET: usize = 32;
pub(crate) const PREVIOUS_FPU_FRAME_OFFSET: usize = FPU_STATE_OFFSET + size_of::<FpuState>();
pub(crate) const ENTRY_FRAME_SIZE: usize = PREVIOUS_FPU_FRAME_OFFSET + 16;

const _: () = {
    assert!(size_of::<FpuState>() == 512);
    assert!(align_of::<FpuState>() == 16);
    assert!(ENTRY_FRAME_SIZE % 16 == 0);
};

#[macro_export]
macro_rules! x86_entry_fpu_save {
    ($publish:literal, $early:literal) => {
        concat!(
            r#"
            mov rbx, rsp
            cld
            and rsp, -16
            sub rsp, {entry_frame_size}
            lea rdi, [rsp + {fpu_state_offset}]
            xor eax, eax
            mov ecx, 64
            rep stosq
            fxsave64 [rsp + {fpu_state_offset}]
            xor r12d, r12d
            "#,
            ".if ", stringify!($publish), "\n",
            ".if ", stringify!($early), "\n",
            r#"
            mov ecx, 0xc0000101
            rdmsr
            shl rdx, 32
            or rax, rdx
            mov r12, rax
            .else
            mov r12, qword ptr gs:[{percpu_self_offset}]
            .endif
            .endif
            mov qword ptr [rsp + {previous_fpu_frame_offset}], 0
            test r12, r12
            jz 2f
            mov rax, [r12 + {active_fpu_offset}]
            mov [rsp + {previous_fpu_frame_offset}], rax
            lea rax, [rsp + {fpu_state_offset}]
            mov [r12 + {active_fpu_offset}], rax
            2:
            "#
        )
    };
}

#[macro_export]
macro_rules! x86_entry_fpu_restore {
    () => {
        r#"
        test r12, r12
        jz 3f
        mov rax, [rsp + {previous_fpu_frame_offset}]
        mov [r12 + {active_fpu_offset}], rax
        3:
        fxrstor64 [rsp + {fpu_state_offset}]
        mov rsp, rbx
        "#
    };
}

#[macro_export]
macro_rules! x86_interrupt_entry {
    ($(#[$attr:meta])* $vis:vis $entry:ident, $handler:path $(,)?) => {
        $crate::x86_interrupt_entry!(
            @entry [$(#[$attr])*] $vis $entry, $handler, 0, "",
            "mov rcx, rbx\ncall {handler}\n", []
        );
    };
    ($(#[$attr:meta])* $vis:vis $entry:ident, $handler:path, eoi = $eoi:path $(,)?) => {
        $crate::x86_interrupt_entry!(
            @entry [$(#[$attr])*] $vis $entry, $handler, 0, "",
            "mov rcx, rbx\ncall {handler}\ncall {eoi}\n", [eoi = sym $eoi,]
        );
    };
    ($(#[$attr:meta])* $vis:vis $entry:ident, $handler:path, vector = $vector:expr $(,)?) => {
        $crate::x86_interrupt_entry!(
            @entry [$(#[$attr])*] $vis $entry, $handler, 0, "",
            "mov ecx, {vector}\nlea rdx, [rbx + {hardware_frame_offset}]\ncall {handler}\n",
            [
                vector = const $vector,
                hardware_frame_offset = const core::mem::offset_of!(
                    $crate::arch::x86::scheduling::state::State, rip
                ),
            ]
        );
    };
    ($(#[$attr:meta])* $vis:vis $entry:ident, $handler:path, idle_only = $eoi:path $(,)?) => {
        $crate::x86_interrupt_entry!(
            @entry [$(#[$attr])*] $vis $entry, $handler, 0, "",
            r#"
            mov rax, {idle_upper}
            cmp [rbx + {r10_offset}], rax
            jne 4f
            mov rax, {idle_lower}
            cmp [rbx + {r11_offset}], rax
            jne 4f
            mov rcx, rbx
            call {handler}
            jmp 5f
            4:
            call {eoi}
            5:
            "#,
            [
                idle_upper = const $crate::scheduling::task::IDLE_UUID_UPPER,
                idle_lower = const $crate::scheduling::task::IDLE_MAGIC_LOWER,
                r10_offset = const core::mem::offset_of!(
                    $crate::arch::x86::scheduling::state::State, r10
                ),
                r11_offset = const core::mem::offset_of!(
                    $crate::arch::x86::scheduling::state::State, r11
                ),
                eoi = sym $eoi,
            ]
        );
    };
    ($(#[$attr:meta])* $vis:vis $entry:ident, $handler:path, no_error_code $(,)?) => {
        $crate::x86_interrupt_entry!(
            @entry [$(#[$attr])*] $vis $entry, $handler, 1, "",
            "mov rcx, rbx\ncall {handler}\n", []
        );
    };
    ($(#[$attr:meta])* $vis:vis $entry:ident, $handler:path, error_code $(,)?) => {
        $crate::x86_interrupt_entry!(
            @entry [$(#[$attr])*] $vis $entry, $handler, 1,
            r#"
            mov r13, [rsp + {hardware_frame_offset}]
            mov rax, [rsp + {hardware_frame_offset} + 8]
            mov [rsp + {hardware_frame_offset}], rax
            mov rax, [rsp + {hardware_frame_offset} + 16]
            mov [rsp + {hardware_frame_offset} + 8], rax
            mov rax, [rsp + {hardware_frame_offset} + 24]
            mov [rsp + {hardware_frame_offset} + 16], rax
            mov rax, [rsp + {hardware_frame_offset} + 32]
            mov [rsp + {hardware_frame_offset} + 24], rax
            mov rax, [rsp + {hardware_frame_offset} + 40]
            mov [rsp + {hardware_frame_offset} + 32], rax
            "#,
            "mov rcx, rbx\nmov rdx, r13\ncall {handler}\n",
            [
                hardware_frame_offset = const core::mem::offset_of!(
                    $crate::arch::x86::scheduling::state::State, rip
                ),
            ]
        );
    };
    (@entry [$($attr:tt)*] $vis:vis $entry:ident, $handler:path, $early:literal,
        $normalize:literal, $call:literal, [$($operands:tt)*]) => {
        $($attr)*
        #[unsafe(naked)]
        $vis extern "C" fn $entry() {
            core::arch::naked_asm!(
                "cli",
                "push r15", "push r14", "push r13", "push r12",
                "push r11", "push r10", "push r9", "push r8",
                "push rdi", "push rsi", "push rbp", "push rbx",
                "push rdx", "push rcx", "push rax",
                $normalize,
                $crate::x86_entry_fpu_save!(1, $early),
                $call,
                "cli",
                $crate::x86_entry_fpu_restore!(),
                "pop rax", "pop rcx", "pop rdx", "pop rbx",
                "pop rbp", "pop rsi", "pop rdi", "pop r8",
                "pop r9", "pop r10", "pop r11", "pop r12",
                "pop r13", "pop r14", "pop r15",
                "iretq",
                entry_frame_size = const $crate::arch::x86::interrupts::entry::ENTRY_FRAME_SIZE,
                fpu_state_offset = const $crate::arch::x86::interrupts::entry::FPU_STATE_OFFSET,
                previous_fpu_frame_offset = const $crate::arch::x86::interrupts::entry::PREVIOUS_FPU_FRAME_OFFSET,
                percpu_self_offset = const $crate::structs::per_cpu::PERCPU_SELF_POINTER_OFF,
                active_fpu_offset = const $crate::structs::per_cpu::PERCPU_ACTIVE_EXCEPTION_FPU_OFF,
                handler = sym $handler,
                $($operands)*
            );
        }
    };
}
