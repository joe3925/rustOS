Build Instructions:
- run "cargo install bootimage"
- run "rustup component add llvm-tools-preview"
- run "cargo bootimage --target os.json"
- to start the project if using qemu run "& 'C:\Program Files\qemu\qemu-system-x86_64w.exe' -drive 'file=C:\path\to\project\RustOS\target\OS\debug\bootimage-RustOS.bin,format=raw'"
