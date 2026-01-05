use std::{env, error::Error, fs, path::PathBuf, process::Command};

fn run(cmd: &mut Command) {
    let status = cmd.status().expect("failed to spawn command");
    assert!(status.success(), "command failed: {cmd:?}");
}

fn generate_def_file(exports_path: &PathBuf, def_out_path: &PathBuf) -> Result<(), Box<dyn Error>> {
    let contents = fs::read_to_string(exports_path)
        .map_err(|e| format!("Failed to read {}: {}", exports_path.display(), e))?;

    let _export_block = contents
        .lines()
        .find(|line| line.trim_start().starts_with("export!"))
        .ok_or("export! macro not found")?;

    let start = contents
        .find('{')
        .ok_or("Missing opening `{` in export! macro")?;
    let end = contents
        .find('}')
        .ok_or("Missing closing `}` in export! macro")?;
    let export_body = &contents[start + 1..end];

    let mut lines = vec!["LIBRARY KRNL".to_string(), "EXPORTS".to_string()];

    for line in export_body.lines() {
        let trimmed = line.trim().trim_end_matches(',');
        if !trimmed.is_empty() {
            lines.push(format!("    {}", trimmed));
        }
    }

    fs::write(def_out_path, lines.join("\n"))
        .map_err(|e| format!("Failed to write {}: {}", def_out_path.display(), e))?;

    Ok(())
}

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let target_dir = out_dir
        .ancestors()
        .nth(5)
        .expect("unexpected OUT_DIR layout")
        .to_path_buf();

    let asm_src = PathBuf::from("src/ap_startup.asm");
    let bin_out = target_dir.join("ap_startup.bin");

    run(Command::new("nasm")
        .args(["-f", "bin"])
        .arg(&asm_src)
        .args(["-o"])
        .arg(&bin_out));
    println!("cargo:rerun-if-changed={}", asm_src.display());
    println!("cargo:rustc-env=AP_STARTUP_BIN={}", bin_out.display());

    let def_path = out_dir.join("KRNL.DEF");
    generate_def_file(&PathBuf::from("src/exports.rs"), &def_path)
        .expect("Failed to generate .DEF file");
    println!("cargo:rerun-if-changed=src/exports.rs");

    let lib_out = target_dir.join("KRNL.lib");
    run(Command::new("lib").args([
        &format!("/DEF:{}", def_path.display()),
        "/MACHINE:X64",
        &format!("/OUT:{}", lib_out.display()),
    ]));
    println!("cargo:rustc-env=KRNL_LIB={}", lib_out.display());
    println!("cargo:rustc-link-search=native={}", target_dir.display());

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let repo_root = manifest_dir
        .parent()
        .expect("kernel crate must be under repo root")
        .to_path_buf();

    let pal_dir = repo_root.join("third_party").join("snmalloc_pal");
    let pal_h = pal_dir.join("pal.h");
    let pal_cc = pal_dir.join("snmalloc_rust.cc");

    if !pal_h.is_file() {
        panic!("missing snmalloc PAL header: {}", pal_h.display());
    }
    if !pal_cc.is_file() {
        panic!("missing snmalloc PAL TU: {}", pal_cc.display());
    }

    let snmalloc_inc = repo_root.join("third_party").join("snmalloc").join("src");
    if !snmalloc_inc.is_dir() {
        panic!("missing snmalloc include dir: {}", snmalloc_inc.display());
    }

    println!("cargo:rerun-if-changed={}", pal_h.display());
    println!("cargo:rerun-if-changed={}", pal_cc.display());

    let mut b = cc::Build::new();
    b.cpp(true);

    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    let clang_triple = if arch == "x86_64" && os == "none" {
        "x86_64-unknown-none-elf"
    } else {
        panic!("unsupported C++ build for arch={arch} os={os}");
    };

    let mut b = cc::Build::new();
    b.cpp(true);

    // Don't link against libstdc++ - we're freestanding
    b.cpp_link_stdlib(None);

    // Force clang++, not cl.exe
    b.compiler("clang++");

    // Stop cc-rs from trying to be clever for Windows/MSVC
    b.no_default_flags(true);

    // Make the object format ELF, not COFF
    b.flag(&format!("--target={clang_triple}"));

    // Your freestanding/kernel flags
    b.flag("-std=c++20");
    b.flag("-ffreestanding");
    b.flag("-fno-exceptions");
    b.flag("-fno-rtti");
    b.flag("-fno-stack-protector");
    b.flag("-fno-asynchronous-unwind-tables");
    b.flag("-fno-unwind-tables");
    b.flag("-fno-pic");
    b.flag("-fno-pie");
    b.flag("-mno-red-zone");
    b.flag("-msse2");
    b.flag("-mcx16");
    b.flag("-mcmodel=large"); // Place code/data anywhere in high-half kernel
    b.flag("-fPIC");
    b.define("_HAS_EXCEPTIONS", "0");
    b.define("SNMALLOC_USE_WAIT_ON_ADDRESS", "1");
    b.define("SNMALLOC_USE_SELF_VENDORED_STL", "1");
    // Tell snmalloc we provide entropy via PAL (avoids <random> include)
    b.define("SNMALLOC_PLATFORM_HAS_GETENTROPY", "1");
    // Define to prevent <chrono> include. On x86_64, the clock_gettime code path
    // is never taken (if constexpr checks NoCpuCycleCounters), so it's safe.
    b.define("SNMALLOC_TICK_USE_CLOCK_GETTIME", "1");

    // Newlib headers for freestanding C library support
    let newlib_inc = repo_root.join("third_party/newlib/newlib/libc/include");
    b.include(&newlib_inc);

    b.include(&snmalloc_inc);
    b.include(&repo_root);

    b.file(&pal_cc);
    b.file(pal_dir.join("clock_shim.c"));
    b.compile("snmalloc_myos");

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=snmalloc_myos");
}
