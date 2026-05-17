use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

fn main() {
    let release = env::args().any(|arg| arg == "--release");
    let root = workspace_root();
    let profile = if release { "release" } else { "debug" };
    let target_json = root.join("x86_64-rustos-kernel.json");

    let mut kernel = cargo(&root);
    kernel
        .args(["build", "-p", "kernel", "--target"])
        .arg(&target_json)
        .args(build_std_args());
    if release {
        kernel.arg("--release");
    }
    run(kernel, "building PE kernel");

    let kernel_pe = root
        .join("target")
        .join("x86_64-rustos-kernel")
        .join(profile)
        .join("kernel.exe");
    assert_exists(&kernel_pe, "PE kernel image");

    let mut stub = cargo(&root);
    stub.args([
        "build",
        "-p",
        "kernel_stub",
        "--target",
        "x86_64-unknown-none",
    ])
    .env("KERNEL_PE_PATH", &kernel_pe);
    if release {
        stub.arg("--release");
    }
    run(stub, "building bootloader-visible kernel stub");

    let stub_image = root
        .join("target")
        .join("x86_64-unknown-none")
        .join(profile)
        .join("kernel_stub");
    assert_exists(&stub_image, "kernel stub ELF");

    let mut os = cargo(&root);
    os.args(["build", "-p", "OS"])
        .env("KERNEL_STUB_PATH", &stub_image);
    if release {
        os.arg("--release");
    }
    run(os, "building boot image");
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask should live under workspace root")
        .to_path_buf()
}

fn cargo(root: &Path) -> Command {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut command = Command::new(cargo);
    command.current_dir(root);
    command
}

fn build_std_args() -> [&'static str; 4] {
    [
        "-Zbuild-std=core,alloc,compiler_builtins,panic_abort",
        "-Zbuild-std-features=compiler-builtins-mem",
        "-Zunstable-options",
        "-Zjson-target-spec",
    ]
}

fn run(mut command: Command, step: &str) {
    let status = command
        .status()
        .unwrap_or_else(|err| panic!("failed to start {step}: {err}"));
    check_status(status, step);
}

fn check_status(status: ExitStatus, step: &str) {
    if !status.success() {
        panic!("{step} failed with {status}");
    }
}

fn assert_exists(path: &Path, what: &str) {
    if !path.exists() {
        panic!("expected {what} at {}", path.display());
    }
}
