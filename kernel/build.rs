use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let bin_out = out_dir.join("ap_startup.bin");

    let status = Command::new("nasm")
        .args(&["-f", "bin", "src/ap_startup.asm", "-o"])
        .arg(&bin_out)
        .status()
        .expect("Failed to run nasm");
    assert!(status.success(), "nasm failed");

    // Tell Cargo to re-run if ASM changes
    println!("cargo:rerun-if-changed=src/ap_startup.asm");

    // Export location of the binary to kernel code
    println!("cargo:rustc-env=AP_STARTUP_BIN={}", bin_out.display());
}
