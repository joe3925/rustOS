use std::process::Command;

fn main() {
    if cfg!(debug_assertions) {
        // Debug mode → run Bochs
        let status = Command::new("cmd")
            .args([
                "/C",
                r#"cd /D D:\Tools\Bochs-2.8 && bochsdbg -unlock -q -f bochsrc.txt"#,
            ])
            .status()
            .expect("Failed to run Bochs");

        println!("Bochs exited with: {}", status);
    } else {
        // Release mode → run QEMU
        let status = Command::new(r#"C:\Program Files\qemu\qemu-system-x86_64w.exe"#)
            .args([
                "-m", "1024M",
                "-drive", "file=D:\\RustroverProjects\\RustOS\\target\\OS\\release\\bootimage-RustOS.bin,format=raw",
                "-drive", "file=D:\\RustroverProjects\\RustOS\\target\\OS\\release\\rustOS.vhdx,if=ide",
            ])
            .status()
            .expect("Failed to run QEMU");

        println!("QEMU exited with: {}", status);
    }
}
