Build Instructions:
- run "cargo install bootimage"
- run "rustup component add llvm-tools-preview"
- run "cargo bootimage --target os.json"
- to start the project if using qemu run "& 'C:\Program Files\qemu\qemu-system-x86_64w.exe' -m 1024M -drive 'file=C:\Users\boden\RustroverProjects\RustOS\target\OS\debug\bootimage-RustOS.bin,format=raw' -drive 'id=disk,file=C:\Users\boden\RustroverProjects\RustOS\target\OS\debug\disk_image.img,format=raw,if=none' -device ich9-ahci,id=ahci -device ide-hd,drive=disk,bus=ahci.1"
