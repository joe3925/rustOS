use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn generate_def_file(exports_path: &PathBuf, def_out_path: &PathBuf) -> Result<(), Box<dyn Error>> {
    let contents = fs::read_to_string(exports_path)?;

    let start = contents
        .find('{')
        .ok_or("Missing opening `{` in export! macro")?;
    let end = contents
        .rfind('}')
        .ok_or("Missing closing `}` in export! macro")?;
    let export_body = &contents[start + 1..end];

    let mut lines = Vec::new();
    lines.push("LIBRARY kernel".to_string());
    lines.push("EXPORTS".to_string());

    for line in export_body.lines() {
        let trimmed = line.trim().trim_end_matches(',');
        if !trimmed.is_empty() {
            lines.push(format!("    {}", trimmed));
        }
    }

    fs::write(def_out_path, lines.join("\n"))?;
    Ok(())
}

fn machine_from_target(target: &str) -> &'static str {
    if target.contains("aarch64") {
        "ARM64"
    } else if target.contains("arm") {
        "ARM"
    } else if target.contains("i686") || (target.contains("x86") && !target.contains("x86_64")) {
        "X86"
    } else {
        "X64"
    }
}

fn generate_import_library(
    target: &str,
    def_path: &PathBuf,
    lib_out: &PathBuf,
) -> Result<(), Box<dyn Error>> {
    let attempts = if target.contains("gnu") {
        vec![ImportLibTool::LlvmDlltool]
    } else {
        vec![ImportLibTool::LlvmLib, ImportLibTool::LldLink]
    };
    let mut errors = Vec::new();

    for tool in attempts {
        match tool.run(target, def_path, lib_out) {
            Ok(status) if status.success() => return Ok(()),
            Ok(status) => errors.push(format!("{} exited with {status}", tool.name())),
            Err(err) => errors.push(format!("{} failed to start: {err}", tool.name())),
        }
    }

    Err(format!(
        "failed to generate kernel import library: {}",
        errors.join("; ")
    )
    .into())
}

#[derive(Clone, Copy)]
enum ImportLibTool {
    LlvmDlltool,
    LlvmLib,
    LldLink,
}

impl ImportLibTool {
    fn name(self) -> &'static str {
        match self {
            Self::LlvmDlltool => "llvm-dlltool",
            Self::LlvmLib => "llvm-lib",
            Self::LldLink => "lld-link",
        }
    }

    fn run(
        self,
        target: &str,
        def_path: &PathBuf,
        lib_out: &PathBuf,
    ) -> Result<std::process::ExitStatus, std::io::Error> {
        match self {
            Self::LlvmDlltool => Command::new(self.name())
                .arg("-d")
                .arg(def_path)
                .arg("-l")
                .arg(lib_out)
                .arg("-m")
                .arg("i386:x86-64")
                .status(),
            Self::LlvmLib => Command::new(self.name())
                .arg("/NOLOGO")
                .arg(format!("/DEF:{}", def_path.display()))
                .arg(format!("/MACHINE:{}", machine_from_target(target)))
                .arg(format!("/OUT:{}", lib_out.display()))
                .status(),
            Self::LldLink => Command::new(self.name())
                .arg("/lib")
                .arg("/NOLOGO")
                .arg(format!("/DEF:{}", def_path.display()))
                .arg(format!("/MACHINE:{}", machine_from_target(target)))
                .arg(format!("/OUT:{}", lib_out.display()))
                .status(),
        }
    }
}

fn compile_mimalloc(
    manifest_dir: &std::path::Path,
    target: &str,
    out_dir: &PathBuf,
) -> Result<(), Box<dyn Error>> {
    let mimalloc_dir = manifest_dir.join("vendor").join("mimalloc-v2");
    let shim_include_dir = manifest_dir.join("c").join("include");
    let include_dir = mimalloc_dir.join("include");
    let src_dir = mimalloc_dir.join("src");

    println!(
        "cargo:rerun-if-changed={}",
        manifest_dir.join("c").display()
    );
    println!("cargo:rerun-if-changed={}", include_dir.display());
    println!("cargo:rerun-if-changed={}", src_dir.display());

    if !target.contains("x86_64") {
        panic!("rustOS mimalloc platform is currently implemented for x86_64 only");
    }

    let mut build = cc::Build::new();

    build
        .compiler("clang")
        .include(&shim_include_dir)
        .include(&include_dir)
        .include(&src_dir)
        .file(manifest_dir.join("c").join("mimalloc_static.c"))
        .file(manifest_dir.join("c").join("mimalloc_rustos_platform.c"))
        .file(manifest_dir.join("c").join("rustos_libc.c"))
        .flag("--target=x86_64-pc-windows-msvc")
        .flag("-U_WIN32")
        .flag("-U_WIN64")
        .flag("-U_MSC_VER")
        .flag("-U_MSC_FULL_VER")
        .flag("-U_MSC_BUILD")
        .flag("-std=c11")
        .flag("-ffreestanding")
        .flag("-fno-builtin")
        .flag("-fno-stack-protector")
        .flag("-mno-red-zone")
        .flag("-mcmodel=large")
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
        let mut command = Command::new(self.name());

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
    compile_mimalloc(&manifest_dir, &target, &out_dir).expect("Failed to compile mimalloc");

    let exports_path = manifest_dir.join("src").join("exports.rs");
    println!("cargo:rerun-if-changed={}", exports_path.display());

    let def_path = out_dir.join("kernel.def");
    generate_def_file(&exports_path, &def_path).expect("Failed to generate .def file");

    let lib_out = out_dir.join("kernel.lib");
    generate_import_library(&target, &def_path, &lib_out).expect("Failed to generate kernel.lib");

    let target_dir = env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            out_dir
                .ancestors()
                .nth(5) // .../target/<profile>/build/<pkg>/out -> target is 4 up
                .expect("unexpected OUT_DIR layout")
                .to_path_buf()
        });

    let shared_lib = target_dir.join("kernel.lib");
    fs::copy(&lib_out, &shared_lib).expect("Failed to copy kernel.lib to target/");

    println!("cargo:rerun-if-changed=build.rs");
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
