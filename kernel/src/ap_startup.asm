bits 16

section .rodata

global smp_trampoline_start
smp_trampoline_start:
    cli
    cld

    o32 lidt [cs:(invalid_idt - smp_trampoline_start)]
    o32 lgdt [cs:(passed_info.gdtr - smp_trampoline_start)]

invalid_idt:
    times 2 dq 0

align 16
passed_info:
    .booted_flag:   db 0            ; +0x00
    .pad1:          db 0, 0, 0      ; +0x01 → +0x04

    .pagemap:       dq 0            ; +0x04 (4 bytes)

    .gdtr:
        dw 0                       ; +0x08 (2 bytes)
        dq 0                       ; +0x0A (8 bytes, unaligned)

    .hhdm:          dq 0            ; +0x12 (8 bytes)
    .temp_stack:    dq 0            ; +0x1A (8 bytes)
    .start_stack:   dw 0            ; +0x22 (2 bytes)

smp_trampoline_end:

global smp_trampoline_size
smp_trampoline_size dq smp_trampoline_end - smp_trampoline_start

section .note.GNU-stack noalloc noexec nowrite progbits