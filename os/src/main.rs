use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::Duration;

const GUI: bool = true;
//legacy
fn spawn_in_new_terminal(title: &str, command: &str, args: &[&str]) -> std::io::Result<Child> {
    let mut cmd_args = vec!["/C", "start", command, command];
    cmd_args.extend_from_slice(args);

    Command::new("cmd").args(&cmd_args).spawn()
}

fn main() {
    if cfg!(debug_assertions) {
        // === Launch QEMU ===
        let qemu = spawn_in_new_terminal(
            "C:\\Program Files\\qemu\\qemu-system-x86_64w.exe",
            "C:\\Program Files\\qemu\\qemu-system-x86_64w.exe",
            &[
                "-m",
                "1024M",
                "-no-reboot",
                "-cpu",
                "qemu64,+apic,+acpi",
                "-machine",
                "type=pc,accel=tcg",
                "-smp",
                "2",
                "-gdb",
                "tcp::1234",
                "-S",
                "-drive",
                "if=pflash,format=raw,readonly=on,file=C:\\Program Files\\qemu\\OVMF_X64.fd",
                "-drive",
                "file=boot.img,format=raw",
                "-drive",
                "file=rustOS.vhdx,if=ide",
            ],
        );

        let qemu = match qemu {
            Ok(child) => child,
            Err(e) => {
                eprintln!("Failed to start QEMU: {}", e);
                return;
            }
        };

    } else {
        // === Release mode ===
        let status = Command::new(r#"C:\Program Files\qemu\qemu-system-x86_64w.exe"#)
            .args([
                "-m",
                "1024M",
                "-no-reboot",
                "-cpu",
                "qemu64,+apic,+acpi",
                "-machine",
                "type=pc,accel=tcg",
                "-smp",
                "2",
                "-drive",
                "if=pflash,format=raw,readonly=on,file=C:\\Program Files\\qemu\\OVMF_X64.fd",
                "-drive",
                "file=boot.img,format=raw",
                "-drive",
                "file=rustOS.vhdx,if=ide",
            ])
            .status()
            .expect("Failed to run QEMU");

        println!("QEMU exited with: {}", status);
    }
}
