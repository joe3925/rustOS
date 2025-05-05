use std::process::Command;

fn main() {
    if cfg!(debug_assertions) {
        // Launch QEMU with GDB server
        let mut qemu = Command::new(r#"C:\Program Files\qemu\qemu-system-x86_64w.exe"#)
            .args([
                "-m", "1024M",
                "-no-reboot",
                "-cpu", "qemu64,+apic,+acpi",
                "-machine", "type=pc,accel=tcg",
                "-smp", "2",
                "-gdb", "tcp::1234",   // <- GDB server
                "-S",                 // <- Start paused
                "-drive", "if=pflash,format=raw,readonly=on,file=C:\\Program Files\\qemu\\OVMF_X64.fd",
                "-drive", "file=boot.img,format=raw",
                "-drive", "file=rustOS.vhdx,if=ide",
            ])
            .spawn()
            .expect("Failed to start QEMU");

        // Launch GDB in a separate process
        let mut gdb = Command::new("gdb")
            .args([
                "-ex", "target remote localhost:1234",
                "-ex", "symbol-file target\\debug\\kernel.efi",
            ])
            .spawn()
            .expect("Failed to launch GDB");

        let qemu_status = qemu.wait().expect("Failed to wait on QEMU");
        println!("qemu exited with: {}", qemu_status);

        let _ = gdb.wait();
    } else {
        // Release mode → run QEMU
        let status = Command::new(r#"C:\Program Files\qemu\qemu-system-x86_64w.exe"#)
            .args([
                "-m", "1024M",
                "-no-reboot",
                "-cpu", "qemu64,+apic,+acpi",
                "-machine", "type=pc,accel=tcg",
                "-smp", "2",
                // UEFI firmware
                "-drive", "if=pflash,format=raw,readonly=on,file=C:\\Program Files\\qemu\\OVMF_X64.fd",
                // Kernel image
                "-drive", "file=boot.img,format=raw",
                // Disk
                "-drive", "file=rustOS.vhdx,if=ide",
            ])
            .status()
            .expect("Failed to run QEMU");

        println!("QEMU exited with: {}", status);
    }
}
