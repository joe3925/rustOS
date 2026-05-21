use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

fn main() {
    let release = env::args().any(|arg| arg == "--release");
    let root = workspace_root();
    let kernel_dir = root.join("kernel");
    let profile = if release { "release" } else { "debug" };
    let target_json = root.join("x86_64-rustos-kernel.json");

    let mut kernel = cargo(&kernel_dir);
    kernel
        .env("CARGO_TARGET_DIR", root.join("target"))
        .args(["build", "--target"])
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
    publish_stable_kernel_artifacts(&root, profile, &kernel_pe);

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

    assert_exists(&stub_image, "kernel stub image");

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

fn cargo(dir: &Path) -> Command {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut command = Command::new(cargo);
    command.current_dir(dir);
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

fn publish_stable_kernel_artifacts(root: &Path, profile: &str, kernel_pe: &Path) {
    let stable_kernel_pe = root.join("target").join(profile).join("kernel.exe");
    copy_artifact(kernel_pe, &stable_kernel_pe, "kernel PE");

    let kernel_pdb = kernel_pe.with_extension("pdb");

    if kernel_pdb.is_file() {
        copy_artifact(
            &kernel_pdb,
            &stable_kernel_pe.with_extension("pdb"),
            "kernel PDB",
        );
    }
}

fn copy_artifact(source: &Path, destination: &Path, what: &str) {
    let destination_dir = destination.parent().unwrap_or_else(|| {
        panic!(
            "stable {what} path has no parent: {}",
            destination.display()
        )
    });

    fs::create_dir_all(destination_dir).unwrap_or_else(|err| {
        panic!(
            "failed to create stable {what} directory {}: {err}",
            destination_dir.display()
        )
    });

    fs::copy(source, destination).unwrap_or_else(|err| {
        panic!(
            "failed to copy {what} from {} to {}: {err}",
            source.display(),
            destination.display()
        )
    });
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
