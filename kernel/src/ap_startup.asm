bits 16
section .rodata

global smp_trampoline_start
smp_trampoline_start:
    cli
    cld

    ; Load null IDT
    o32 lidt [invalid_idt]

    ; Load GDT
    o32 lgdt [passed_info.gdtr]

    ; Set segment registers
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    ; Setup temporary stack
    mov esp, [passed_info.temp_stack]

    ; Enter protected mode
    mov eax, cr0
    or eax, 1       ; PE
    mov cr0, eax
    jmp 0x08:pm_start

bits 32
pm_start:
    ; Enable PAE
    mov eax, cr4
    or eax, 1 << 5
    mov cr4, eax

    ; Load page tables
    mov eax, [passed_info.pagemap]
    mov cr3, eax

    ; Enable long mode via EFER
    mov ecx, 0xC0000080  ; IA32_EFER
    rdmsr
    or eax, 1 << 8       ; LME
    wrmsr

    ; Enable paging
    mov eax, cr0
    or eax, 1 << 31      ; PG
    mov cr0, eax

    ; Far jump to long mode
    jmp 0x28:lm_start

bits 64
lm_start:
    ; Set 64-bit stack
    mov rsp, [passed_info.start_stack]

    ; Jump to start_address (absolute jump)
    mov rax, [passed_info.start_address]
    jmp rax

    hlt

invalid_idt:
    dw 0
    dd 0

align 16
passed_info:
    .pagemap:       dq 0
    .gdtr:
        dw 0
        dq 0
    .temp_stack:    dd 0
    .start_stack:   dq 0
    .start_address: dq 0

smp_trampoline_end:

global smp_trampoline_size
smp_trampoline_size dq smp_trampoline_end - smp_trampoline_start

section .note.GNU-stack noalloc noexec nowrite progbits
