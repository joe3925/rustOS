use std::{env, path::PathBuf, process::Command};

fn run(cmd: &mut Command) {
    let status = cmd.status().expect("failed to spawn command");
    assert!(status.success(), "command failed: {cmd:?}");
}

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let asm_src = PathBuf::from("src/ap_startup.asm");

    let bin_out = out_dir.join("ap_startup.bin"); // flat page
    let _lib_out = out_dir.join("libap_startup.a"); // static archive

    run(Command::new("nasm")
        .args(["-f", "bin"])
        .arg(&asm_src)
        .args(["-o"])
        .arg(&bin_out));

    println!("cargo:rerun-if-changed={}", asm_src.display());
    println!("cargo:rustc-env=AP_STARTUP_BIN={}", bin_out.display());
    println!("cargo:rustc-link-search=native={}", out_dir.display());
}
