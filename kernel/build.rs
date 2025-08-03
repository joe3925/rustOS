use std::{env, fs, path::PathBuf, process::Command};

fn run(cmd: &mut Command) {
    let status = cmd.status().expect("failed to spawn command");
    assert!(status.success(), "command failed: {cmd:?}");
}

fn generate_def_file(exports_path: &PathBuf, def_out_path: &PathBuf) {
    let contents = fs::read_to_string(exports_path).expect("Failed to read exports.rs");

    let export_block = contents
        .lines()
        .find(|line| line.trim_start().starts_with("export!"))
        .expect("export! macro not found");

    // Capture inside export! { ... }
    let start = contents.find('{').unwrap();
    let end = contents.find('}').unwrap();
    let export_body = &contents[start + 1..end];

    let mut lines = vec!["LIBRARY KRNL".to_string(), "EXPORTS".to_string()];

    for line in export_body.lines() {
        let trimmed = line.trim().trim_end_matches(',');
        if !trimmed.is_empty() {
            lines.push(format!("    {}", trimmed));
        }
    }

    fs::write(def_out_path, lines.join("\n")).expect("Failed to write .DEF file");
}

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let target_dir = out_dir
        .ancestors()
        .nth(3)
        .expect("unexpected OUT_DIR layout")
        .to_path_buf();

    // === Compile ASM ===
    let asm_src = PathBuf::from("src/ap_startup.asm");
    let bin_out = out_dir.join("ap_startup.bin");

    run(Command::new("nasm")
        .args(["-f", "bin"])
        .arg(&asm_src)
        .args(["-o"])
        .arg(&bin_out));
    println!("cargo:rerun-if-changed={}", asm_src.display());
    println!("cargo:rustc-env=AP_STARTUP_BIN={}", bin_out.display());

    // === Generate .DEF file ===
    let def_path = out_dir.join("KRNL.DEF");
    generate_def_file(&PathBuf::from("src/exports.rs"), &def_path);
    println!("cargo:rerun-if-changed=src/exports.rs");

    // === Build import LIB ===
    let lib_out = target_dir.join("KRNL.lib");
    run(Command::new("lib").args([
        &format!("/DEF:{}", def_path.display()),
        "/MACHINE:X64",
        &format!("/OUT:{}", lib_out.display()),
    ]));
    println!("cargo:rustc-env=KRNL_LIB={}", lib_out.display());
    println!("cargo:rustc-link-search=native={}", target_dir.display());
}
