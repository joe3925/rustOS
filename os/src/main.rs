use std::process::Command;

fn main() {
    if cfg!(debug_assertions) {
        // Launch QEMU with GDB server
        let mut qemu = match Command::new(r#"C:\Program Files\qemu\qemu-system-x86_64w.exe"#)
            .args([
                "-m", "1024M",
                "-no-reboot",
                "-cpu", "qemu64,+apic,+acpi",
                "-machine", "type=pc,accel=tcg",
                "-smp", "2",
                "-gdb", "tcp::1234",
                "-S",
                "-drive", "if=pflash,format=raw,readonly=on,file=C:\\Program Files\\qemu\\OVMF_X64.fd",
                "-drive", "file=boot.img,format=raw",
                "-drive", "file=rustOS.vhdx,if=ide",
            ])
            .spawn()
        {
            Ok(child) => child,
            Err(e) => {
                eprintln!("Failed to start QEMU: {}", e);
                return;
            }
        };

        std::thread::sleep(std::time::Duration::from_secs(1));
        let cwd = std::env::current_dir().expect("Failed to get current dir");
        let source_path = cwd.join("../../kernel/src");
        let source_path_str = source_path.to_string_lossy().replace("\\", "/");

        let kernel_path = "kernel.efi"; // or from env
        let load_addr = "0xFFFF800000000000";

        let mut gdb = match Command::new("gdbgui")
            .args([
                "-g", "gdb",
                "--gdb-args", &format!(
                    "-ex=\"set confirm off\" \
             -ex=\"set architecture i386:x86-64\" \
             -ex=\"target remote localhost:1234\" \
             -ex=\"add-symbol-file {} -o {}\" \
             -ex=\"directory {}\"",
                    kernel_path,
                    load_addr,
                    source_path_str
                ),
            ])
            .spawn()
        {
            Ok(child) => child,
            Err(e) => {
                eprintln!("Failed to launch GDB: {}", e);
                let _ = qemu.kill(); // Terminate QEMU if GDB fails
                return;
            }
        };

        let qemu_status = match qemu.wait() {
            Ok(status) => {
                println!("qemu exited with: {}", status);

                // Kill GDB when QEMU exits
                if let Err(e) = gdb.kill() {
                    eprintln!("Failed to kill GDB: {}", e);
                }
                status
            }
            Err(e) => {
                eprintln!("Failed to wait on QEMU: {}", e);

                // Try to kill GDB in case QEMU wait failed
                let _ = gdb.kill();
                return;
            }
        };

        // Reap GDB
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
