use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

struct KernelTarget {
    mimalloc: Option<MimallocTarget>,
}

struct MimallocTarget {
    clang_target: &'static str,
    flags: &'static [&'static str],
}

fn kernel_target(target: &str) -> Result<KernelTarget, Box<dyn Error>> {
    if target.contains("x86_64") {
        return Ok(KernelTarget {
            mimalloc: Some(MimallocTarget {
                clang_target: "x86_64-pc-windows-msvc",
                flags: &["-mno-red-zone", "-mcmodel=large"],
            }),
        });
    }

    if target.contains("aarch64") {
        return Ok(KernelTarget { mimalloc: None });
    }

    Err(format!("unsupported kernel target architecture: {target}").into())
}

fn compile_mimalloc(
    manifest_dir: &std::path::Path,
    target: &str,
    out_dir: &PathBuf,
) -> Result<(), Box<dyn Error>> {
    let workspace_dir = manifest_dir
        .parent()
        .ok_or("kernel manifest directory has no parent")?;
    let mimalloc_dir = workspace_dir.join("third_party").join("mimalloc-v2");
    let shim_include_dir = manifest_dir.join("c").join("include");
    let include_dir = mimalloc_dir.join("include");
    let src_dir = mimalloc_dir.join("src");

    println!(
        "cargo:rerun-if-changed={}",
        manifest_dir.join("c").display()
    );
    println!("cargo:rerun-if-changed={}", include_dir.display());
    println!("cargo:rerun-if-changed={}", src_dir.display());

    let target_config = kernel_target(target)?;
    let mimalloc_target = target_config
        .mimalloc
        .ok_or_else(|| format!("rustOS mimalloc platform is not implemented for {target}"))?;

    let mut build = cc::Build::new();
    let clang_target_flag = format!("--target={}", mimalloc_target.clang_target);

    build
        .compiler("clang")
        .include(&shim_include_dir)
        .include(&include_dir)
        .include(&src_dir)
        .file(manifest_dir.join("c").join("mimalloc_static.c"))
        .file(manifest_dir.join("c").join("mimalloc_rustos_platform.c"))
        .file(manifest_dir.join("c").join("rustos_libc.c"))
        .flag(&clang_target_flag)
        .flag("-U_WIN32")
        .flag("-U_WIN64")
        .flag("-U_MSC_VER")
        .flag("-U_MSC_FULL_VER")
        .flag("-U_MSC_BUILD")
        .flag("-std=c11")
        .flag("-ffreestanding")
        .flag("-fno-builtin")
        .flag("-fno-stack-protector")
        .flag("-Wno-unused-parameter")
        .flag("-Wno-unused-function")
        .flag("-Wno-unused-macros")
        .flag("-Wno-missing-braces")
        .define("MI_DEBUG", "0")
        .define("MI_SECURE", "0")
        .define("MI_STAT", "0")
        .define("MI_NO_GETENV", "1")
        .define("MI_RUSTOS_HIGH_HALF", "1")
        .define("NDEBUG", "1")
        .define("MI_USE_BUILTIN_THREAD_POINTER", "0");

    for flag in mimalloc_target.flags {
        build.flag(flag);
    }

    let objects = build.compile_intermediates();
    let lib_out = out_dir.join("rustos_mimalloc.lib");
    archive_msvc_static_library(&objects, &lib_out)?;

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=rustos_mimalloc");

    Ok(())
}

fn archive_msvc_static_library(
    objects: &[PathBuf],
    lib_out: &PathBuf,
) -> Result<(), Box<dyn Error>> {
    let attempts = [MsvcLibTool::LlvmLib, MsvcLibTool::LldLink];
    let mut errors = Vec::new();

    for tool in attempts {
        match tool.archive(objects, lib_out) {
            Ok(status) if status.success() => return Ok(()),
            Ok(status) => errors.push(format!("{} exited with {status}", tool.name())),
            Err(err) => errors.push(format!("{} failed to start: {err}", tool.name())),
        }
    }

    Err(format!("failed to archive rustos_mimalloc: {}", errors.join("; ")).into())
}

#[derive(Clone, Copy)]
enum MsvcLibTool {
    LlvmLib,
    LldLink,
}

impl MsvcLibTool {
    fn name(self) -> &'static str {
        match self {
            Self::LlvmLib => "llvm-lib",
            Self::LldLink => "lld-link",
        }
    }

    fn archive(
        self,
        objects: &[PathBuf],
        lib_out: &PathBuf,
    ) -> Result<std::process::ExitStatus, std::io::Error> {
        let mut command = tool_command(self.name());

        match self {
            Self::LlvmLib => {
                command.arg("/NOLOGO");
            }
            Self::LldLink => {
                command.arg("/lib").arg("/NOLOGO");
            }
        }

        command.arg(format!("/OUT:{}", lib_out.display()));
        command.args(objects);
        command.status()
    }
}

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let target = env::var("TARGET").unwrap();

    emit_kernel_pe_link_args(&target);
    if env::var_os("CARGO_FEATURE_ALLOCATOR_MIMALLOC").is_some() {
        compile_mimalloc(&manifest_dir, &target, &out_dir).expect("Failed to compile mimalloc");
    }

    println!("cargo:rerun-if-changed=build.rs");
}

fn tool_command(name: &str) -> Command {
    find_tool(name)
        .map(Command::new)
        .unwrap_or_else(|| Command::new(name))
}

fn find_tool(name: &str) -> Option<PathBuf> {
    if let Some(path) = find_tool_in_path(name) {
        return Some(path);
    }

    let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let output = Command::new(rustc)
        .args(["--print", "sysroot"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let sysroot = String::from_utf8_lossy(&output.stdout);
    let rustlib = PathBuf::from(sysroot.trim()).join("lib").join("rustlib");
    let entries = fs::read_dir(rustlib).ok()?;

    for entry in entries.flatten() {
        let bin = entry.path().join("bin");
        let gcc_ld = bin.join("gcc-ld").join(name);
        if gcc_ld.is_file() {
            return Some(gcc_ld);
        }

        let direct = bin.join(name);
        if direct.is_file() {
            return Some(direct);
        }
    }

    None
}

fn find_tool_in_path(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    for dir in env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }

    None
}

fn emit_kernel_pe_link_args(target: &str) {
    if !target.ends_with("windows-msvc") {
        return;
    }

    for arg in [
        "/NOLOGO",
        "/NODEFAULTLIB",
        "/SUBSYSTEM:NATIVE",
        "/ENTRY:kernel_pe_entry",
        "/FIXED",
        "/DYNAMICBASE:NO",
        "/BASE:0xFFFF850000000000",
        "/EXPORT:kernel_pe_entry",
    ] {
        println!("cargo:rustc-link-arg-bin=kernel={arg}");
    }
}
