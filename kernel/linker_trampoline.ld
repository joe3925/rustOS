INSERT AFTER .text;

.trampoline 0x8000 : AT(0x8000) 
{
    KEEP(*(.trampoline))
}  /* size will be ≈ 4 KiB (your NASM blob) */
