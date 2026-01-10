
; Ripped straight from redox
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
    .longmode_limit dw 0
    .longmode_base dq 0      

startup_ap:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, word [trampoline.temp_stack] 

    mov eax, dword [trampoline.pagemap]
    mov cr3, eax    

    mov eax, cr0
    and al, 11110011b 
    or al, 00100010b 
    mov cr0, eax

    mov eax, cr4
    or  eax, 1 << 9 | 1 << 7 | 1 << 5 | 1 << 4                    ; CR4.PAE
    mov cr4, eax

    fninit

    lgdt [gdtr]     

    mov ecx, 0xC0000080                   ; IA32_EFER MSR
    rdmsr
    or  eax, 1 << 11 | 1 << 8                     ; EFER.LME
    wrmsr

    mov eax, cr0
    or  eax, 1 << 31 | 1 << 16 | 1                  ; CR0.PG | CR0.PE
    mov cr0, eax


     jmp gdt.kernel_code:long_mode_entry

USE64
long_mode_entry:
    mov rax, gdt.kernel_data
    mov ds, rax
    mov es, rax
    mov fs, rax
    mov gs, rax
    mov ss, rax


    mov rsp, [trampoline.start_stack]      

    lgdt [trampoline.longmode_limit]

    mov rax, [trampoline.start_address]
    jmp rax                               

struc GDTEntry
    .limitl resw 1
    .basel resw 1
    .basem resb 1
    .attribute resb 1
    .flags__limith resb 1
    .baseh resb 1
endstruc

attrib:
    .present              equ 1 << 7
    .ring1                equ 1 << 5
    .ring2                equ 1 << 6
    .ring3                equ 1 << 5 | 1 << 6
    .user                 equ 1 << 4
;user
    .code                 equ 1 << 3
;   code
    .conforming           equ 1 << 2
    .readable             equ 1 << 1
;   data
    .expand_down          equ 1 << 2
    .writable             equ 1 << 1
    .accessed             equ 1 << 0
;system
;   legacy
    .tssAvailabe16        equ 0x1
    .ldt                  equ 0x2
    .tssBusy16            equ 0x3
    .call16               equ 0x4
    .task                 equ 0x5
    .interrupt16          equ 0x6
    .trap16               equ 0x7
    .tssAvailabe32        equ 0x9
    .tssBusy32            equ 0xB
    .call32               equ 0xC
    .interrupt32          equ 0xE
    .trap32               equ 0xF
;   long mode
    .ldt32                equ 0x2
    .tssAvailabe64        equ 0x9
    .tssBusy64            equ 0xB
    .call64               equ 0xC
    .interrupt64          equ 0xE
    .trap64               equ 0xF

flags:
    .granularity equ 1 << 7
    .available equ 1 << 4
;user
    .default_operand_size equ 1 << 6
;   code
    .long_mode equ 1 << 5
;   data
    .reserved equ 1 << 5

gdtr:
    dw gdt.end + 1  ; size
    dq gdt          ; offset

gdt:
.null equ $ - gdt
    dq 0

.kernel_code equ $ - gdt
istruc GDTEntry
    at GDTEntry.limitl, dw 0
    at GDTEntry.basel, dw 0
    at GDTEntry.basem, db 0
    at GDTEntry.attribute, db attrib.present | attrib.user | attrib.code
    at GDTEntry.flags__limith, db flags.long_mode
    at GDTEntry.baseh, db 0
iend

.kernel_data equ $ - gdt
istruc GDTEntry
    at GDTEntry.limitl, dw 0
    at GDTEntry.basel, dw 0
    at GDTEntry.basem, db 0
; AMD System Programming Manual states that the writeable bit is ignored in long mode, but ss can not be set to this descriptor without it
    at GDTEntry.attribute, db attrib.present | attrib.user | attrib.writable
    at GDTEntry.flags__limith, db 0
    at GDTEntry.baseh, db 0
iend

.end equ $ - gdt