use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command as ProcessCommand, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const DEFAULT_GDB_PORT: u16 = 1234;
fn main() {
    if let Err(err) = try_main() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn try_main() -> Result<(), String> {
    let root = workspace_root();
    let cli = Cli::parse(env::args().skip(1))?;

    match cli.command {
        CliCommand::Build { release, drivers } => {
            if drivers {
                ensure_kernel_import_library(&root)?;
                build_drivers(&root, release)?;
            }

            build_boot_image(&root, release)
        }
        CliCommand::Qemu(options) => run_qemu(&root, options),
    }
}

struct Cli {
    command: CliCommand,
}

enum CliCommand {
    Build { release: bool, drivers: bool },
    Qemu(QemuOptions),
}

struct QemuOptions {
    release: bool,
    debug: bool,
    detach: bool,
    no_build: bool,
    dry_run: bool,
    gdb_port: u16,
}

impl Cli {
    fn parse<I>(args: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = String>,
    {
        let mut args = args.into_iter().peekable();

        match args.peek().map(String::as_str) {
            Some("build") => {
                args.next();
                let mut release = false;
                let mut drivers = false;

                while let Some(arg) = args.next() {
                    match arg.as_str() {
                        "--release" => release = true,
                        "--drivers" => drivers = true,
                        "-h" | "--help" => return Err(usage()),
                        other => {
                            return Err(format!("unknown build argument `{other}`\n\n{}", usage()))
                        }
                    }
                }

                Ok(Self {
                    command: CliCommand::Build { release, drivers },
                })
            }
            Some("qemu") => {
                args.next();
                let mut options = QemuOptions {
                    release: false,
                    debug: false,
                    detach: false,
                    no_build: false,
                    dry_run: false,
                    gdb_port: DEFAULT_GDB_PORT,
                };

                while let Some(arg) = args.next() {
                    match arg.as_str() {
                        "--release" => options.release = true,
                        "--debug" => options.debug = true,
                        "--detach" => options.detach = true,
                        "--no-build" => options.no_build = true,
                        "--dry-run" => options.dry_run = true,
                        "--gdb-port" => {
                            let port = args
                                .next()
                                .ok_or_else(|| "--gdb-port requires a port".to_string())?;
                            options.gdb_port = port
                                .parse()
                                .map_err(|_| format!("invalid gdb port `{port}`"))?;
                        }
                        "-h" | "--help" => return Err(usage()),
                        other => {
                            return Err(format!("unknown qemu argument `{other}`\n\n{}", usage()))
                        }
                    }
                }

                Ok(Self {
                    command: CliCommand::Qemu(options),
                })
            }
            Some("--release") => {
                args.next();

                if let Some(arg) = args.next() {
                    return Err(format!("unknown argument `{arg}`\n\n{}", usage()));
                }

                Ok(Self {
                    command: CliCommand::Build {
                        release: true,
                        drivers: false,
                    },
                })
            }
            Some("-h" | "--help") => Err(usage()),
            Some(other) => Err(format!("unknown command `{other}`\n\n{}", usage())),
            None => Ok(Self {
                command: CliCommand::Build {
                    release: false,
                    drivers: false,
                },
            }),
        }
    }
}

fn usage() -> String {
    [
        "usage:",
        "  cargo run -p xtask",
        "  cargo run -p xtask -- --release",
        "  cargo run -p xtask -- build [--drivers] [--release]",
        "  cargo run -p xtask -- qemu [--debug] [--detach] [--no-build] [--dry-run] [--release] [--gdb-port PORT]",
        "",
        "environment:",
        "  RUSTOS_QEMU       path to qemu-system-x86_64",
        "  RUSTOS_OVMF_CODE  path to OVMF/EDK2 x86_64 code firmware",
        "  OVMF_CODE         fallback firmware path",
        "  RUSTOS_DISK       path to an existing system disk image",
        "  RUSTOS_DISK_FORMAT disk format for RUSTOS_DISK, e.g. raw or vhdx",
        "                    defaults to rustOS.vhdx on Windows, rustOS.dmg elsewhere",
        "  RUSTOS_QEMU_ACCEL QEMU accelerator, defaults to tcg",
        "  RUSTOS_QEMU_MEMORY QEMU memory size, defaults to 8G",
        "  RUSTOS_QEMU_SMP   QEMU CPU count, defaults to 4",
    ]
    .join("\n")
}

fn run_qemu(root: &Path, options: QemuOptions) -> Result<(), String> {
    if !options.no_build {
        ensure_kernel_import_library(root)?;
        build_drivers(root, options.release)?;
        build_boot_image(root, options.release)?;
    }

    let profile = profile(options.release);
    let target_dir = root.join("target").join(profile);
    let boot_image = target_dir.join("boot.img");
    let qemu = find_qemu()?;
    let firmware = find_ovmf_code(root, &qemu)?;
    let system_disk = system_disk(root)?;
    let args = qemu_args(&firmware, &boot_image, &system_disk, &options)?;

    assert_exists(&boot_image, "boot image")?;

    if options.dry_run {
        print_command(&qemu, &args);
        return Ok(());
    }

    if options.detach {
        spawn_qemu_detached(root, &qemu, &args, options.debug, options.gdb_port)
    } else {
        run_qemu_foreground(root, &qemu, &args)
    }
}

fn build_boot_image(root: &Path, release: bool) -> Result<(), String> {
    let kernel_dir = root.join("kernel");
    let profile = profile(release);
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

    run(kernel, "building PE kernel")?;

    let kernel_pe = root
        .join("target")
        .join("x86_64-rustos-kernel")
        .join(profile)
        .join("kernel.exe");

    assert_exists(&kernel_pe, "PE kernel image")?;
    publish_stable_kernel_artifacts(root, profile, &kernel_pe)?;

    let mut stub = cargo(root);
    stub.args([
        "build",
        "-p",
        "kernel_stub",
        "--target",
        "x86_64-unknown-none",
    ])
    .args(build_std_args())
    .env(
        "CARGO_TARGET_X86_64_UNKNOWN_NONE_RUSTFLAGS",
        kernel_stub_rustflags(),
    )
    .env("KERNEL_PE_PATH", &kernel_pe);

    if release {
        stub.arg("--release");
    }

    run(stub, "building bootloader-visible kernel stub")?;

    let stub_image = root
        .join("target")
        .join("x86_64-unknown-none")
        .join(profile)
        .join("kernel_stub");

    assert_exists(&stub_image, "kernel stub image")?;

    let mut os = cargo(root);
    os.args(["build", "-p", "OS"])
        .env("KERNEL_STUB_PATH", &stub_image);

    if release {
        os.arg("--release");
    }

    run(os, "building boot image")
}

fn build_drivers(root: &Path, release: bool) -> Result<(), String> {
    let mut drivers = cargo(&root.join("drivers"));
    drivers.arg("build");

    if release {
        drivers.arg("--release");
    }

    run(drivers, "building drivers")
}

fn ensure_kernel_import_library(root: &Path) -> Result<(), String> {
    let target_dir = root.join("target");
    let kernel_lib = target_dir.join("kernel.lib");

    if kernel_lib.is_file() {
        return Ok(());
    }

    fs::create_dir_all(&target_dir).map_err(|err| {
        format!(
            "failed to create target directory {}: {err}",
            target_dir.display()
        )
    })?;

    let def_path = target_dir.join("kernel.def");
    generate_kernel_def(root, &def_path)?;
    let lld_link = find_tool_in_augmented_path("lld-link").ok_or_else(|| {
        "could not find lld-link for kernel import library generation".to_string()
    })?;
    let mut command = ProcessCommand::new(lld_link);
    command
        .arg("/lib")
        .arg("/NOLOGO")
        .arg(format!("/DEF:{}", def_path.display()))
        .arg("/MACHINE:X64")
        .arg(format!("/OUT:{}", kernel_lib.display()))
        .current_dir(root);

    if let Some(path) = path_with_rust_linkers() {
        command.env("PATH", path);
    }

    run(command, "generating kernel import library")
}

fn generate_kernel_def(root: &Path, def_path: &Path) -> Result<(), String> {
    let exports_path = root.join("kernel").join("src").join("exports.rs");
    let contents = fs::read_to_string(&exports_path)
        .map_err(|err| format!("failed to read {}: {err}", exports_path.display()))?;
    let start = contents
        .find('{')
        .ok_or_else(|| "missing opening `{` in export! macro".to_string())?;
    let end = contents
        .rfind('}')
        .ok_or_else(|| "missing closing `}` in export! macro".to_string())?;
    let export_body = &contents[start + 1..end];
    let mut lines = vec!["LIBRARY kernel".to_string(), "EXPORTS".to_string()];

    for line in export_body.lines() {
        let trimmed = line.trim().trim_end_matches(',');

        if !trimmed.is_empty() {
            lines.push(format!("    {trimmed}"));
        }
    }

    fs::write(def_path, lines.join("\n"))
        .map_err(|err| format!("failed to write {}: {err}", def_path.display()))
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask should live under workspace root")
        .to_path_buf()
}

fn cargo(dir: &Path) -> ProcessCommand {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut command = ProcessCommand::new(cargo);
    command.current_dir(dir);

    if let Some(path) = path_with_rust_linkers() {
        command.env("PATH", path);
    }

    command
}

fn path_with_rust_linkers() -> Option<OsString> {
    let mut paths = rust_linker_paths();
    let current_path = env::var_os("PATH").unwrap_or_default();
    paths.extend(env::split_paths(&current_path));

    env::join_paths(paths).ok()
}

fn rust_linker_paths() -> Vec<PathBuf> {
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let output = match ProcessCommand::new(rustc)
        .args(["--print", "sysroot"])
        .output()
    {
        Ok(output) if output.status.success() => output,
        _ => return Vec::new(),
    };
    let sysroot = String::from_utf8_lossy(&output.stdout);
    let rustlib = PathBuf::from(sysroot.trim()).join("lib").join("rustlib");
    let entries = match fs::read_dir(rustlib) {
        Ok(entries) => entries,
        Err(_) => return Vec::new(),
    };
    let mut paths = Vec::new();

    for entry in entries.flatten() {
        let bin = entry.path().join("bin");
        let gcc_ld = bin.join("gcc-ld");

        if gcc_ld.is_dir() {
            paths.push(gcc_ld);
        }

        if bin.is_dir() {
            paths.push(bin);
        }
    }

    paths
}

fn build_std_args() -> [&'static str; 4] {
    [
        "-Zbuild-std=core,alloc,compiler_builtins,panic_abort",
        "-Zbuild-std-features=compiler-builtins-mem",
        "-Zunstable-options",
        "-Zjson-target-spec",
    ]
}

fn kernel_stub_rustflags() -> &'static str {
    "-C link-args=--image-base=0xFFFF880000000000 -C link-arg=-no-pie -C relocation-model=static -C code-model=large"
}

fn profile(release: bool) -> &'static str {
    if release {
        "release"
    } else {
        "debug"
    }
}

fn publish_stable_kernel_artifacts(
    root: &Path,
    profile: &str,
    kernel_pe: &Path,
) -> Result<(), String> {
    let stable_kernel_pe = root.join("target").join(profile).join("kernel.exe");
    copy_artifact(kernel_pe, &stable_kernel_pe, "kernel PE")?;

    let kernel_pdb = kernel_pe.with_extension("pdb");

    if kernel_pdb.is_file() {
        copy_artifact(
            &kernel_pdb,
            &stable_kernel_pe.with_extension("pdb"),
            "kernel PDB",
        )?;
    }

    Ok(())
}

fn copy_artifact(source: &Path, destination: &Path, what: &str) -> Result<(), String> {
    let destination_dir = destination.parent().ok_or_else(|| {
        format!(
            "stable {what} path has no parent: {}",
            destination.display()
        )
    })?;

    fs::create_dir_all(destination_dir).map_err(|err| {
        format!(
            "failed to create stable {what} directory {}: {err}",
            destination_dir.display()
        )
    })?;

    fs::copy(source, destination).map_err(|err| {
        format!(
            "failed to copy {what} from {} to {}: {err}",
            source.display(),
            destination.display()
        )
    })?;

    Ok(())
}

fn find_qemu() -> Result<PathBuf, String> {
    if let Some(path) = env_path("RUSTOS_QEMU") {
        return require_file(path, "RUSTOS_QEMU");
    }

    let names: &[&str] = if cfg!(windows) {
        &[
            "qemu-system-x86_64w.exe",
            "qemu-system-x86_64.exe",
            "qemu-system-x86_64",
        ]
    } else {
        &["qemu-system-x86_64"]
    };

    for name in names {
        if let Some(path) = find_in_path(name) {
            return Ok(path);
        }
    }

    for path in qemu_fallback_paths() {
        if path.is_file() {
            return Ok(path);
        }
    }

    Err("could not find qemu-system-x86_64; set RUSTOS_QEMU to the QEMU executable".to_string())
}

fn qemu_fallback_paths() -> Vec<PathBuf> {
    let mut paths = vec![
        PathBuf::from("/opt/homebrew/bin/qemu-system-x86_64"),
        PathBuf::from("/usr/local/bin/qemu-system-x86_64"),
        PathBuf::from("/opt/local/bin/qemu-system-x86_64"),
        PathBuf::from("/usr/bin/qemu-system-x86_64"),
    ];

    if cfg!(windows) {
        paths.extend([
            PathBuf::from(r"C:\Program Files\qemu\qemu-system-x86_64w.exe"),
            PathBuf::from(r"C:\Program Files\qemu\qemu-system-x86_64.exe"),
            PathBuf::from(r"C:\Program Files (x86)\qemu\qemu-system-x86_64w.exe"),
            PathBuf::from(r"C:\Program Files (x86)\qemu\qemu-system-x86_64.exe"),
        ]);
    }

    paths
}

fn find_ovmf_code(root: &Path, qemu: &Path) -> Result<PathBuf, String> {
    for var in ["RUSTOS_OVMF_CODE", "OVMF_CODE", "OVMF_X64"] {
        if let Some(path) = env_path(var) {
            return require_file(path, var);
        }
    }

    let mut candidates = vec![
        root.join("qemu").join("OVMF_X64.fd"),
        root.join("qemu").join("OVMF_CODE.fd"),
        root.join("qemu").join("edk2-x86_64-code.fd"),
    ];

    candidates.extend(ovmf_paths_from_qemu(qemu));
    candidates.extend([
        PathBuf::from("/opt/homebrew/share/qemu/edk2-x86_64-code.fd"),
        PathBuf::from("/opt/homebrew/share/qemu/edk2-x86_64-secure-code.fd"),
        PathBuf::from("/usr/local/share/qemu/edk2-x86_64-code.fd"),
        PathBuf::from("/usr/local/share/qemu/edk2-x86_64-secure-code.fd"),
        PathBuf::from("/opt/local/share/qemu/edk2-x86_64-code.fd"),
        PathBuf::from("/usr/share/qemu/edk2-x86_64-code.fd"),
        PathBuf::from("/usr/share/OVMF/OVMF_CODE.fd"),
        PathBuf::from("/usr/share/OVMF/OVMF_CODE_4M.fd"),
        PathBuf::from("/usr/share/ovmf/OVMF.fd"),
        PathBuf::from("/usr/share/edk2/x64/OVMF_CODE.fd"),
        PathBuf::from("/usr/share/edk2-ovmf/x64/OVMF_CODE.fd"),
        PathBuf::from(r"C:\Program Files\qemu\OVMF_X64.fd"),
        PathBuf::from(r"C:\Program Files\qemu\edk2-x86_64-code.fd"),
        PathBuf::from(r"C:\Program Files (x86)\qemu\OVMF_X64.fd"),
    ]);

    candidates
        .into_iter()
        .find(|path| path.is_file())
        .ok_or_else(|| {
            "could not find OVMF/EDK2 x86_64 firmware; set RUSTOS_OVMF_CODE or OVMF_CODE"
                .to_string()
        })
}

fn ovmf_paths_from_qemu(qemu: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    for prefix in qemu_prefixes(qemu) {
        let share = prefix.join("share").join("qemu");
        paths.push(share.join("edk2-x86_64-code.fd"));
        paths.push(share.join("edk2-x86_64-secure-code.fd"));
        paths.push(share.join("OVMF_X64.fd"));
        paths.push(share.join("OVMF_CODE.fd"));
    }

    paths
}

fn qemu_prefixes(qemu: &Path) -> Vec<PathBuf> {
    let mut prefixes = Vec::new();

    if let Some(bin_dir) = qemu.parent() {
        if let Some(prefix) = bin_dir.parent() {
            prefixes.push(prefix.to_path_buf());
        }
    }

    if qemu
        .components()
        .any(|component| component.as_os_str() == std::ffi::OsStr::new("Cellar"))
    {
        if let Some(version_dir) = qemu.parent().and_then(|bin_dir| bin_dir.parent()) {
            prefixes.push(version_dir.to_path_buf());
        }
    }

    prefixes
}

struct SystemDisk {
    path: PathBuf,
    format: String,
}

fn system_disk(root: &Path) -> Result<SystemDisk, String> {
    if let Some(path) = env_path("RUSTOS_DISK") {
        assert_exists(&path, "system disk from RUSTOS_DISK")?;
        return Ok(SystemDisk {
            format: disk_format(&path),
            path,
        });
    }

    let default_disk = default_system_disk(root);
    assert_exists(&default_disk.path, "default system disk")?;
    Ok(default_disk)
}

fn default_system_disk(root: &Path) -> SystemDisk {
    if cfg!(windows) {
        SystemDisk {
            path: root.join("rustOS.vhdx"),
            format: "vhdx".to_string(),
        }
    } else {
        SystemDisk {
            path: root.join("rustOS.dmg"),
            format: "raw".to_string(),
        }
    }
}

fn disk_format(path: &Path) -> String {
    if let Ok(format) = env::var("RUSTOS_DISK_FORMAT") {
        return format;
    }

    match path.extension().and_then(|extension| extension.to_str()) {
        Some("vhdx") => "vhdx".to_string(),
        Some("qcow2") => "qcow2".to_string(),
        Some("dmg") => "raw".to_string(),
        _ => "raw".to_string(),
    }
}

fn qemu_args(
    firmware: &Path,
    boot_image: &Path,
    system_disk: &SystemDisk,
    options: &QemuOptions,
) -> Result<Vec<OsString>, String> {
    let memory = env::var("RUSTOS_QEMU_MEMORY").unwrap_or_else(|_| "8G".to_string());
    let smp = env::var("RUSTOS_QEMU_SMP").unwrap_or_else(|_| "4".to_string());
    let accel = env::var("RUSTOS_QEMU_ACCEL").unwrap_or_else(|_| "tcg".to_string());
    let machine = format!("q35,accel={accel}");
    let gdb = format!("tcp::{}", options.gdb_port);
    let firmware_path = path_string(firmware)?;
    let boot_image_path = path_string(boot_image)?;
    let system_disk_path = path_string(&system_disk.path)?;
    let firmware_drive = drive_arg(&[
        ("if", "pflash"),
        ("format", "raw"),
        ("readonly", "on"),
        ("file", &firmware_path),
    ]);
    let boot_drive = drive_arg(&[("file", &boot_image_path), ("format", "raw")]);
    let system_drive = drive_arg(&[
        ("file", &system_disk_path),
        ("if", "none"),
        ("format", &system_disk.format),
        ("id", "sysdisk"),
    ]);

    let mut args: Vec<OsString> = vec![
        "-m".into(),
        memory.into(),
        "-cpu".into(),
        "qemu64,+apic,+acpi".into(),
        "-machine".into(),
        machine.into(),
        "-smp".into(),
        smp.into(),
    ];

    if options.debug {
        args.extend(["-S".into(), "-gdb".into(), gdb.into()]);
    }

    args.extend([
        "-device".into(),
        "amd-iommu,dma-remap=on,dma-translation=on".into(),
        "-drive".into(),
        firmware_drive.into(),
        "-drive".into(),
        boot_drive.into(),
        "-drive".into(),
        system_drive.into(),
        "-device".into(),
        "virtio-blk-pci,drive=sysdisk,disable-legacy=on,disable-modern=off,iommu_platform=on"
            .into(),
    ]);

    Ok(args)
}

fn drive_arg(options: &[(&str, &str)]) -> String {
    options
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn path_string(path: &Path) -> Result<String, String> {
    path.to_str()
        .map(str::to_string)
        .ok_or_else(|| format!("path is not valid UTF-8: {}", path.display()))
}

fn spawn_qemu_detached(
    root: &Path,
    qemu: &Path,
    args: &[OsString],
    debug: bool,
    gdb_port: u16,
) -> Result<(), String> {
    let mut command = ProcessCommand::new(qemu);
    command
        .args(args)
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }

    let mut child = command
        .spawn()
        .map_err(|err| format!("failed to launch QEMU {}: {err}", qemu.display()))?;

    if debug {
        wait_for_qemu_to_settle(&mut child)?;
        println!(
            "QEMU started with pid {} and GDB port {gdb_port}",
            child.id()
        );
    } else {
        println!("QEMU started with pid {}", child.id());
    }

    Ok(())
}

fn run_qemu_foreground(root: &Path, qemu: &Path, args: &[OsString]) -> Result<(), String> {
    let status = ProcessCommand::new(qemu)
        .args(args)
        .current_dir(root)
        .status()
        .map_err(|err| format!("failed to launch QEMU {}: {err}", qemu.display()))?;

    check_status(status, "running QEMU")
}

fn wait_for_qemu_to_settle(child: &mut Child) -> Result<(), String> {
    let start = Instant::now();
    let settle_time = Duration::from_secs(1);

    while start.elapsed() < settle_time {
        if let Some(status) = child
            .try_wait()
            .map_err(|err| format!("failed to query QEMU status: {err}"))?
        {
            return Err(format!(
                "QEMU exited before the debugger could attach: {status}"
            ));
        }

        thread::sleep(Duration::from_millis(100));
    }

    Ok(())
}

fn print_command(qemu: &Path, args: &[OsString]) {
    print!("{}", qemu.display());

    for arg in args {
        let arg = arg.to_string_lossy();
        print!(" {}", shell_quote(arg.as_ref()));
    }

    println!();
}

fn shell_quote(value: &str) -> String {
    if value.chars().all(|ch| {
        ch.is_ascii_alphanumeric() || matches!(ch, '/' | '.' | '_' | '-' | ':' | ',' | '=')
    }) {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

fn env_path(name: &str) -> Option<PathBuf> {
    env::var_os(name)
        .filter(|value| !value.as_os_str().is_empty())
        .map(PathBuf::from)
}

fn find_in_path(name: &str) -> Option<PathBuf> {
    let name_path = Path::new(name);

    if name_path.components().count() > 1 && name_path.is_file() {
        return Some(name_path.to_path_buf());
    }

    let path = env::var_os("PATH")?;

    for dir in env::split_paths(&path) {
        let candidate = dir.join(name);

        if candidate.is_file() {
            return Some(candidate);
        }

        if cfg!(windows) && candidate.extension().is_none() {
            let exe = candidate.with_extension("exe");

            if exe.is_file() {
                return Some(exe);
            }
        }
    }

    None
}

fn find_tool_in_augmented_path(name: &str) -> Option<PathBuf> {
    let path = path_with_rust_linkers()?;

    for dir in env::split_paths(&path) {
        let candidate = dir.join(name);

        if candidate.is_file() {
            return Some(candidate);
        }

        if cfg!(windows) && candidate.extension().is_none() {
            let exe = candidate.with_extension("exe");

            if exe.is_file() {
                return Some(exe);
            }
        }
    }

    None
}

fn require_file(path: PathBuf, name: &str) -> Result<PathBuf, String> {
    if path.is_file() {
        Ok(path)
    } else {
        Err(format!(
            "{name} points to a missing file: {}",
            path.display()
        ))
    }
}

fn run(mut command: ProcessCommand, step: &str) -> Result<(), String> {
    let status = command
        .status()
        .map_err(|err| format!("failed to start {step}: {err}"))?;

    check_status(status, step)
}

fn check_status(status: ExitStatus, step: &str) -> Result<(), String> {
    if status.success() {
        Ok(())
    } else {
        Err(format!("{step} failed with {status}"))
    }
}

fn assert_exists(path: &Path, what: &str) -> Result<(), String> {
    if path.exists() {
        Ok(())
    } else {
        Err(format!("expected {what} at {}", path.display()))
    }
}
