INSERT AFTER .text;

.trampoline 0x8000 : AT(0x8000) 
{
    KEEP(*(.trampoline))
} 
