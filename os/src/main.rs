use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::Duration;

const GUI: bool = false;

fn spawn_in_new_terminal(title: &str, command: &str, args: &[&str]) -> std::io::Result<Child> {
    Command::new("cmd")
        .args([
            "/C", "start", // new terminal
            title,
            command,
        ])
        .args(args)
        .spawn()
}

fn main() {
    if cfg!(debug_assertions) {
        // === Launch QEMU ===
        let qemu = spawn_in_new_terminal(
            "QEMU",
            r#""C:\Program Files\qemu\qemu-system-x86_64w.exe""#,
            &[
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
            ],
        );

        let mut qemu = match qemu {
            Ok(child) => child,
            Err(e) => {
                eprintln!("Failed to start QEMU: {}", e);
                return;
            }
        };

        sleep(Duration::from_secs(1));

        let cwd = std::env::current_dir().expect("Failed to get current dir");
        let source_path = cwd.join("../../kernel/src");
        let source_path_str = source_path.to_string_lossy().replace("\\", "/");

        let kernel_path = "kernel.efi";
        let load_addr = "0xFFFF800000000000";

        // === Launch GDB or GDBGUI ===
        let gdb = if GUI {
            spawn_in_new_terminal(
                "GDBGUI",
                "gdbgui",
                &[
                    "-g", "gdb",
                    "--gdb-args",
                    &format!(
                        "-ex=\"set confirm off\" \
                         -ex=\"set architecture i386:x86-64\" \
                         -ex=\"target remote localhost:1234\" \
                         -ex=\"add-symbol-file {} -o {}\" \
                         -ex=\"directory {}\"",
                        kernel_path,
                        load_addr,
                        source_path_str
                    ),
                    "-n",
                ],
            )
        } else {
            spawn_in_new_terminal(
                "GDB",
                "gdb",
                &[
                    "-ex", "set confirm off",
                    "-ex", "set architecture i386:x86-64",
                    "-ex", "target remote localhost:1234",
                    "-ex", &format!("add-symbol-file {} {}", kernel_path, load_addr),
                    "-ex", &format!("directory {}", source_path_str),
                ],
            )
        };

        let mut gdb = match gdb {
            Ok(child) => child,
            Err(e) => {
                eprintln!("Failed to launch GDB: {}", e);
                let _ = qemu.kill();
                return;
            }
        };

        // === Monitor QEMU ===
        let qemu_status = match qemu.wait() {
            Ok(status) => {
                println!("QEMU exited with: {}", status);
                let _ = gdb.kill();
                status
            }
            Err(e) => {
                eprintln!("Failed to wait on QEMU: {}", e);
                let _ = gdb.kill();
                return;
            }
        };

        // Reap GDB
        let _ = gdb.wait();
    } else {
        // === Release mode ===
        let status = Command::new(r#"C:\Program Files\qemu\qemu-system-x86_64w.exe"#)
            .args([
                "-m", "1024M",
                "-no-reboot",
                "-cpu", "qemu64,+apic,+acpi",
                "-machine", "type=pc,accel=tcg",
                "-smp", "2",
                "-drive", "if=pflash,format=raw,readonly=on,file=C:\\Program Files\\qemu\\OVMF_X64.fd",
                "-drive", "file=boot.img,format=raw",
                "-drive", "file=rustOS.vhdx,if=ide",
            ])
            .status()
            .expect("Failed to run QEMU");

        println!("QEMU exited with: {}", status);
    }
}
