set confirm off
set architecture i386:x86-64
set osabi none
target remote localhost:1234
add-symbol-file kernel.efi 0xffff800000000000
directory ../../kernel/src
