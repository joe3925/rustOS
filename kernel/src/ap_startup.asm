

ORG 0x8000
SECTION .text
USE16

trampoline:
    jmp short startup_ap
    times 8 - ($ - trampoline) nop      

    .pagemap       dq 0     
    .gdtr_limit    dw 0     
    .gdtr_base     dq 0     
    .temp_stack    dd 0     
    .start_stack   dq 0     
    .start_address dq 0      

startup_ap:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, word [trampoline.temp_stack] 

    mov eax, dword [trampoline.pagemap]
    mov cr3, eax                           

    mov eax, cr4
    or  eax, 1 << 5                        ; CR4.PAE
    mov cr4, eax

    mov ecx, 0xC0000080                   ; IA32_EFER MSR
    rdmsr
    or  eax, 1 << 8                       ; EFER.LME
    wrmsr

    mov eax, cr0
    or  eax, 1 << 31 | 1                  ; CR0.PG | CR0.PE
    mov cr0, eax

    lgdt [trampoline.gdtr_limit]         

    jmp 0x08:long_mode_entry

USE64
long_mode_entry:
    mov ax, 0x10        
    mov ds, ax
    mov es, ax
    mov ss, ax

    mov rsp, [trampoline.start_stack]      
    mov rax, [trampoline.start_address]    
    jmp rax                               

SECTION .rodata
align 8
gdt:
    dq 0                                   
    dq 0x00AF9A000000FFFF                  
    dq 0x00AF92000000FFFF                  
gdt_end:

gdtr:
    dw gdt_end - gdt - 1
    dq gdt
