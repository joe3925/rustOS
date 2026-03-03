/* ap_startup.s
   Layout- and encoding-compatible with the original NASM trampoline.

   Must be copied to physical 0x8000 and executed there (SIPI vector 0x08).
   Offsets of the patched fields MUST match the Rust constants:

     PAGEMAP_OFF              = 0x08
     GDTR_LIMIT_OFF           = 0x10
     GDTR_BASE_OFF            = 0x12
     TEMP_STACK_OFF           = 0x1A
     START_STACK_OFF          = 0x1E
     START_ADDR_OFF           = 0x26
     LONGMODE_GDTR_LIMIT_OFF  = 0x2E
     LONGMODE_GDTR_BASE_OFF   = 0x30
*/

.intel_syntax noprefix

.set TRAMPOLINE_BASE, 0x8000

.section .text.trampoline, "ax", @progbits
.global trampoline
.global trampoline_end
.type trampoline, @function

/* Absolute addresses inside the copied blob (no relocations at runtime). */
.set TRAMPOLINE_PAGEMAP_ABS,         TRAMPOLINE_BASE + (trampoline.pagemap        - trampoline)
.set TRAMPOLINE_GDTR_LIMIT_ABS,      TRAMPOLINE_BASE + (trampoline.gdtr_limit     - trampoline)
.set TRAMPOLINE_GDTR_BASE_ABS,       TRAMPOLINE_BASE + (trampoline.gdtr_base      - trampoline)
.set TRAMPOLINE_TEMP_STACK_ABS,      TRAMPOLINE_BASE + (trampoline.temp_stack     - trampoline)
.set TRAMPOLINE_START_STACK_ABS,     TRAMPOLINE_BASE + (trampoline.start_stack    - trampoline)
.set TRAMPOLINE_START_ADDRESS_ABS,   TRAMPOLINE_BASE + (trampoline.start_address  - trampoline)
.set TRAMPOLINE_LONGMODE_LIMIT_ABS,  TRAMPOLINE_BASE + (trampoline.longmode_limit - trampoline)
.set TRAMPOLINE_LONGMODE_BASE_ABS,   TRAMPOLINE_BASE + (trampoline.longmode_base  - trampoline)

.set GDTR_ABS, TRAMPOLINE_BASE + (gdtr - trampoline)
.set GDT_ABS,  TRAMPOLINE_BASE + (gdt  - trampoline)

/* Selectors are offsets in the GDT (TI=0, RPL=0). */
.set GDT_KERNEL_CODE, (gdt.kernel_code - gdt)
.set GDT_KERNEL_DATA, (gdt.kernel_data - gdt)

.set LONG_MODE_ENTRY_ABS, TRAMPOLINE_BASE + (long_mode_entry - trampoline)

.code16
trampoline:
    jmp short startup_ap
    /* Ensure the next byte is exactly offset 0x08 from 'trampoline'. */
    .fill 8 - (. - trampoline), 1, 0x90

    /* Data block: MUST match NASM field order and packing exactly. */
trampoline.pagemap:         .quad 0          /* +0x08 */
trampoline.gdtr_limit:      .word 0          /* +0x10 */
trampoline.gdtr_base:       .quad 0          /* +0x12 */
trampoline.temp_stack:      .long 0          /* +0x1A */
trampoline.start_stack:     .quad 0          /* +0x1E */
trampoline.start_address:   .quad 0          /* +0x26 */
trampoline.longmode_limit:  .word 0          /* +0x2E */
trampoline.longmode_base:   .quad 0          /* +0x30 */

startup_ap:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, word ptr [TRAMPOLINE_TEMP_STACK_ABS]

    mov eax, dword ptr [TRAMPOLINE_PAGEMAP_ABS]
    mov cr3, eax

    mov eax, cr0
    and al, 0xF3
    or  al, 0x22
    mov cr0, eax

    mov eax, cr4
    or  eax, (1 << 9) | (1 << 7) | (1 << 5) | (1 << 4)
    mov cr4, eax

    fninit

    lgdt [GDTR_ABS]

    mov ecx, 0xC0000080
    rdmsr
    or  eax, (1 << 11) | (1 << 8)
    wrmsr

    mov eax, cr0
    or  eax, (1 << 31) | (1 << 16) | 1
    mov cr0, eax

    .byte 0x66, 0xEA
    .long LONG_MODE_ENTRY_ABS
    .word GDT_KERNEL_CODE

.code64
long_mode_entry:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    mov rsp, qword ptr [TRAMPOLINE_START_STACK_ABS]

    lgdt [TRAMPOLINE_LONGMODE_LIMIT_ABS]

    mov rax, qword ptr [TRAMPOLINE_START_ADDRESS_ABS]
    jmp rax

gdtr:
    .word (gdt_end - gdt + 1)
    .quad GDT_ABS

gdt:
gdt.null:
    .quad 0x0000000000000000

gdt.kernel_code:
    /* access=0x98, flags(L)=0x20 => 00 00 00 00 00 98 20 00 */
    .quad 0x0020980000000000

gdt.kernel_data:
    /* access=0x92, flags=0x00 => 00 00 00 00 00 92 00 00 */
    .quad 0x0000920000000000

gdt_end:

trampoline_end:
.size trampoline, trampoline_end - trampoline
