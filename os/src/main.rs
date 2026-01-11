use std::process::{Child, Command};

//legacy
fn spawn_in_new_terminal(command: &str, args: &[&str]) -> std::io::Result<Child> {
    let mut cmd_args = vec!["/C", "start", command, command];
    cmd_args.extend_from_slice(args);

    Command::new("cmd").args(&cmd_args).spawn()
}

fn main() {
    if cfg!(debug_assertions) {
        // === Launch QEMU (debug) ===
        // let qemu = spawn_in_new_terminal(
        //     r#"C:\Program Files\qemu\qemu-system-x86_64w.exe"#,
        //     &[
        //         "-m",
        //         "8G",
        //         "-no-reboot",
        //         "-cpu",
        //         "qemu64,+x2apic,+acpi",
        //         "-machine",
        //         "q35,accel=tcg",
        //         "-smp",
        //         "2",
        //         "-gdb",
        //         "tcp::1234",
        //         "-S",
        //         "-drive",
        //         "if=pflash,format=raw,readonly=on,file=C:\\Program Files\\qemu\\OVMF_X64.fd",
        //         "-device",
        //         "ahci,id=ahci0",
        //         "-drive",
        //         "file=boot.img,if=none,format=raw,id=bootimg",
        //         "-device",
        //         "ide-hd,drive=bootimg,bus=ahci0.0",
        //         "-drive",
        //         "file=rustOS.vhdx,if=none,format=vhdx,id=sysdisk",
        //         "-device",
        //         "ide-hd,drive=sysdisk,bus=ahci0.1",
        //     ],
        // );
        let qemu = spawn_in_new_terminal(
            r#"C:\Program Files\qemu\qemu-system-x86_64w.exe"#,
            &[
                "-m",
                "8G",
                "-cpu",
                "qemu64,+apic,+acpi",
                "-machine",
                "type=pc,accel=tcg",
                "-smp",
                "6",
                "-gdb",
                "tcp::1234",
                "-S",
                "-drive",
                "if=pflash,format=raw,readonly=on,file=C:\\Program Files\\qemu\\OVMF_X64.fd",
                "-drive",
                "file=boot.img,format=raw",
                "-drive",
                "file=../../rustOS.vhdx,if=ide",
            ],
        );

        if let Err(e) = qemu {
            eprintln!("Failed to start QEMU: {e}");
        }
    } else {
        // === Release mode ===
        // let status = Command::new(r#"C:\Program Files\qemu\qemu-system-x86_64w.exe"#)
        //     .args([
        //         "-m",
        //         "1024M",
        //         "-no-reboot",
        //         "-cpu",
        //         "qemu64,+apic,+acpi,invtsc,tsc-frequency=3800000000",
        //         "-machine",
        //         "type=pc,accel=tcg",
        //         "-smp",
        //         "2",
        //         "-drive",
        //         "if=pflash,format=raw,readonly=on,file=C:\\Program Files\\qemu\\OVMF_X64.fd",
        //         "-drive",
        //         "file=boot.img,format=raw",
        //         "-drive",
        //         "file=rustOS.vhdx,if=ide",
        //     ])
        //     .status()
        //     .expect("Failed to run QEMU");

        // println!("QEMU exited with: {status}");
    }
}
