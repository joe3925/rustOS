mod artifacts;
mod bench;
mod config;
mod driver;

use artifacts::{
    ArtifactManifest, BootArtifact, KernelArtifact, KernelSdkArtifact, PublishedKernel,
    PublishedSdk, StubArtifact,
};
use config::{BuildPlan, HostPlan, LaunchPlan};
use serde::Serialize;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const DEFAULT_GDB_PORT: u16 = 1234;
const DEFAULT_META_PORT: u16 = 4322;

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
        CliCommand::Build(options) => {
            let platform = options
                .platform
                .as_deref()
                .ok_or_else(|| "build requires --platform NAME|FILE".to_string())?;
            let plan = config::load_platform(&root, platform)?;
            build_platform(
                &root,
                &plan,
                options.release,
                options.offline,
                &options.kernel_features,
            )
            .map(|_| ())
        }
        CliCommand::Qemu(options) => {
            let platform = options
                .platform
                .as_deref()
                .ok_or_else(|| "qemu requires --platform NAME|FILE".to_string())?;
            let launch = options
                .launch
                .as_deref()
                .ok_or_else(|| "qemu requires --launch NAME|FILE".to_string())?;
            let plan = config::load_platform(&root, platform)?;
            let launch = config::load_launch(&root, launch)?;
            let host_selector = options.host.as_deref().unwrap_or(std::env::consts::OS);
            let host = config::load_host(&root, host_selector)?;
            run_qemu(&root, &plan, &launch, &host, options)
        }
        CliCommand::Bench(command) => bench::execute(&root, command),
    }
}

struct Cli {
    command: CliCommand,
}

enum CliCommand {
    Build(BuildOptions),
    Qemu(QemuOptions),
    Bench(bench::BenchCommand),
}

struct BuildOptions {
    release: bool,
    offline: bool,
    platform: Option<String>,
    kernel_features: Vec<String>,
}

struct QemuOptions {
    release: bool,
    debug: bool,
    detach: bool,
    dry_run: bool,
    console_serial: bool,
    gdb_port: u16,
    /// Enable the COM2 LLDB metadata socket.
    lldb_meta: bool,
    /// TCP port for the COM2 LLDB metadata socket.
    meta_port: u16,
    platform: Option<String>,
    launch: Option<String>,
    host: Option<String>,
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
                let mut offline = false;
                let mut platform = None;
                let mut kernel_features = Vec::new();

                while let Some(arg) = args.next() {
                    match arg.as_str() {
                        "--release" => release = true,
                        "--drivers" => {}
                        "--offline" => offline = true,
                        "--platform" => {
                            platform = Some(args.next().ok_or_else(|| {
                                "--platform requires a name or TOML path".to_string()
                            })?);
                        }
                        "--kernel-feature" => {
                            kernel_features.push(args.next().ok_or_else(|| {
                                "--kernel-feature requires a feature name".to_string()
                            })?);
                        }
                        "-h" | "--help" => return Err(usage()),
                        other => {
                            return Err(format!("unknown build argument `{other}`\n\n{}", usage()));
                        }
                    }
                }

                Ok(Self {
                    command: CliCommand::Build(BuildOptions {
                        release,
                        offline,
                        platform,
                        kernel_features,
                    }),
                })
            }
            Some("qemu") => {
                args.next();
                let mut options = QemuOptions {
                    release: false,
                    debug: false,
                    detach: false,
                    dry_run: false,
                    console_serial: false,
                    gdb_port: DEFAULT_GDB_PORT,
                    lldb_meta: false,
                    meta_port: DEFAULT_META_PORT,
                    platform: None,
                    launch: None,
                    host: None,
                };

                while let Some(arg) = args.next() {
                    match arg.as_str() {
                        "--release" => options.release = true,
                        "--debug" => options.debug = true,
                        "--detach" => options.detach = true,
                        "--dry-run" => options.dry_run = true,
                        "--console-serial" => options.console_serial = true,
                        "--gdb-port" => {
                            let port = args
                                .next()
                                .ok_or_else(|| "--gdb-port requires a port".to_string())?;
                            options.gdb_port = port
                                .parse()
                                .map_err(|_| format!("invalid gdb port `{port}`"))?;
                        }
                        "--lldb-meta" => options.lldb_meta = true,
                        "--meta-port" => {
                            let port = args
                                .next()
                                .ok_or_else(|| "--meta-port requires a port".to_string())?;
                            options.meta_port = port
                                .parse()
                                .map_err(|_| format!("invalid meta port `{port}`"))?;
                        }
                        "--platform" => {
                            options.platform = Some(args.next().ok_or_else(|| {
                                "--platform requires a name or TOML path".to_string()
                            })?);
                        }
                        "--launch" => {
                            options.launch = Some(args.next().ok_or_else(|| {
                                "--launch requires a name or TOML path".to_string()
                            })?);
                        }
                        "--host" => {
                            options.host = Some(args.next().ok_or_else(|| {
                                "--host requires a name or TOML path".to_string()
                            })?);
                        }
                        "-h" | "--help" => return Err(usage()),
                        other => {
                            return Err(format!("unknown qemu argument `{other}`\n\n{}", usage()));
                        }
                    }
                }

                if options.detach && options.console_serial {
                    return Err("--console-serial cannot be used with --detach".to_string());
                }

                Ok(Self {
                    command: CliCommand::Qemu(options),
                })
            }
            Some("bench") => {
                args.next();
                bench::parse(args).map(|command| Self {
                    command: CliCommand::Bench(command),
                })
            }
            Some("-h" | "--help") => Err(usage()),
            Some(other) => Err(format!("unknown command `{other}`\n\n{}", usage())),
            None => Err(usage()),
        }
    }
}

fn usage() -> String {
    [
        "usage:",
        "  cargo run -p xtask -- build --platform NAME|FILE [--release] [--offline] [--kernel-feature NAME]",
        "  cargo run -p xtask -- qemu --platform NAME|FILE --launch NAME|FILE [--host NAME|FILE] [--debug] [--detach] [--console-serial] [--dry-run] [--release] [--gdb-port PORT] [--lldb-meta] [--meta-port PORT]",
        "  cargo run -p xtask -- bench [--platform NAME] [--launch NAME] [--cpus 1,2,4] [--suite NAME] [--tag TAG] [--output FILE] [--boot-timeout-secs N] [--timeout-secs N]",
        "  cargo run -p xtask -- bench compare --base FILE --head FILE [--output FILE]",
        "",
        "environment:",
        "  RUSTOS_QEMU       QEMU executable name or path; overrides launch and host discovery",
        "  RUSTOS_FIRMWARE   direct firmware path; bypasses candidate discovery",
        "  RUSTOS_FIRMWARE_CANDIDATES path-list prepended to host firmware discovery",
        "  RUSTOS_FIRMWARE_FILES_FROM_QEMU path-list overriding launch firmware filenames",
        "  RUSTOS_DISK       path to an existing system disk image",
        "  RUSTOS_DISK_FORMAT disk format for RUSTOS_DISK, e.g. raw or vhdx",
        "                    defaults to rustOS.vhdx on Windows, rustOS.dmg elsewhere",
        "  RUSTOS_QEMU_MEMORY QEMU memory size, overrides launch defaults",
        "  RUSTOS_QEMU_SMP   QEMU CPU count",
        "  RUSTOS_QEMU_SERIAL QEMU serial backend used unless --console-serial is passed",
        "",
        "serial ports:",
        "  COM1 (0x3F8)  normal kernel log output (controlled by RUSTOS_QEMU_SERIAL)",
        "  COM2 (0x2F8)  structured debugger metadata, enabled with --lldb-meta",
        "                host TCP port defaults to 4322 (override with --meta-port)",
        "                connect with: .zed/lldb/rustos_meta.py via rustos-meta-connect",
    ]
    .join("\n")
}

fn run_qemu(
    root: &Path,
    plan: &BuildPlan,
    launch: &LaunchPlan,
    host: &HostPlan,
    options: QemuOptions,
) -> Result<(), String> {
    if options.detach && options.console_serial {
        return Err("--console-serial cannot be used with --detach".to_string());
    }

    validate_launch(plan, launch, host, &options)?;
    let artifacts = load_artifact_manifest(root, plan, options.release)?;
    let boot_image = artifacts.boot_image.clone();
    let qemu = find_qemu(launch, host)?;
    let firmware = find_firmware(launch, host, &qemu)?;
    let system_disk = system_disk(root)?;
    let args = qemu_args(root, launch, &firmware, &boot_image, &system_disk, &options)?;

    assert_exists(&boot_image, "boot image")?;

    if options.debug {
        write_lldb_commands(root, &artifacts, &options)?;
    }

    if options.dry_run {
        print_command(&qemu, &args);
        return Ok(());
    }

    if options.detach {
        spawn_qemu_detached(root, &qemu, &args, options.debug, options.gdb_port)
    } else {
        run_qemu_foreground(root, &qemu, &args, options.console_serial)
    }
}

fn build_platform(
    root: &Path,
    plan: &BuildPlan,
    release: bool,
    offline: bool,
    kernel_features: &[String],
) -> Result<BootArtifact, String> {
    let output = artifact_root(root, plan, release);
    fs::create_dir_all(&output)
        .map_err(|err| format!("failed to create {}: {err}", output.display()))?;

    println!("==> building kernel");
    let kernel_artifact = build_kernel(root, plan, release, kernel_features)?;

    println!("==> generating kernel SDK");
    let sdk = create_kernel_sdk(root, plan, release)?;

    println!("==> building drivers");
    let mut drivers = driver::resolve_all(root, plan, &sdk, release, offline)?;

    println!("==> publishing drivers");
    publish_drivers(&output, &mut drivers)?;
    let debug_search_paths = vec![output.join("drivers")];

    println!("==> writing boot package manifest");
    let package_manifest = write_boot_package_manifest(&output, &drivers)?;

    println!("==> building bootloader-visible kernel stub");
    let stub = build_stub(root, plan, release, &kernel_artifact, &package_manifest)?;

    println!("==> creating UEFI boot image");
    let image_path = output.join("image").join(&plan.bootloader.output);
    let image = rustos_boot_image::create_uefi_image(&stub.executable, &image_path)?;

    let boot = BootArtifact { image };

    println!("==> writing artifact manifest");
    publish_artifact_manifest(
        plan,
        release,
        &output,
        &kernel_artifact,
        &sdk,
        &drivers,
        &stub,
        &boot,
        &debug_search_paths,
    )?;

    Ok(boot)
}
fn artifact_root(root: &Path, plan: &BuildPlan, release: bool) -> PathBuf {
    root.join("target")
        .join("rustos")
        .join(&plan.id)
        .join(profile(release))
}

fn build_kernel(
    root: &Path,
    plan: &BuildPlan,
    release: bool,
    extra_features: &[String],
) -> Result<KernelArtifact, String> {
    let (package_id, package_name) = driver::cargo_package_identity(&plan.kernel.manifest)?;
    if package_name != plan.kernel.package {
        return Err(format!(
            "kernel manifest contains package `{package_name}`, expected `{}`",
            plan.kernel.package
        ));
    }
    let mut kernel = cargo(root);
    kernel
        .arg("build")
        .args(["--manifest-path"])
        .arg(&plan.kernel.manifest)
        .args(["-p", &package_id, "--target"])
        .arg(&plan.kernel.target)
        .args(build_std_args())
        .args([
            "--message-format",
            "json-render-diagnostics",
            "--color",
            "always",
        ])
        .env(
            "CARGO_TARGET_DIR",
            root.join("target/cargo").join(&plan.id).join("kernel"),
        );

    if plan.kernel.no_default_features {
        kernel.arg("--no-default-features");
    }
    let mut features = plan.kernel.features.clone();
    for feature in extra_features {
        if !features.contains(feature) {
            features.push(feature.clone());
        }
    }
    if !features.is_empty() {
        kernel.arg("--features").arg(features.join(","));
    }
    if release {
        kernel.arg("--release");
    }
    let kernel_pe = driver::cargo_artifact(
        kernel,
        &package_id,
        &plan.kernel.binary,
        "exe",
        "building PE kernel",
    )?;
    let output = artifact_root(root, plan, release).join("kernel");
    let published = output.join("kernel.exe");
    copy_artifact(&kernel_pe, &published, "kernel PE")?;

    let published_pdb = if let Some(pdb) = find_pdb(&kernel_pe) {
        let destination = output.join("kernel.pdb");
        copy_artifact(&pdb, &destination, "kernel PDB")?;
        Some(destination)
    } else {
        None
    };

    Ok(KernelArtifact {
        pe: published,
        debug_info: published_pdb,
    })
}

fn build_stub(
    root: &Path,
    plan: &BuildPlan,
    release: bool,
    kernel: &KernelArtifact,
    boot_packages: &Path,
) -> Result<StubArtifact, String> {
    let (package_id, package_name) = driver::cargo_package_identity(&plan.stub.manifest)?;
    if package_name != plan.stub.package {
        return Err(format!(
            "stub manifest contains package `{package_name}`, expected `{}`",
            plan.stub.package
        ));
    }
    let mut stub = cargo(root);
    stub.arg("build")
        .args(["--manifest-path"])
        .arg(&plan.stub.manifest)
        .args(["-p", &package_id, "--target", &plan.stub.target])
        .args(build_std_args())
        .args([
            "--message-format",
            "json-render-diagnostics",
            "--color",
            "always",
        ])
        .env(
            "CARGO_TARGET_DIR",
            root.join("target/cargo").join(&plan.id).join("stub"),
        )
        .env(stub_rustflags_env(&plan.stub.target), &plan.stub.rustflags)
        .env("KERNEL_PE_PATH", &kernel.pe)
        .env("RUSTOS_BOOT_PACKAGES_MANIFEST", boot_packages);

    if release {
        stub.arg("--release");
    }
    let executable = driver::cargo_artifact(
        stub,
        &package_id,
        &plan.stub.binary,
        "",
        "building bootloader-visible kernel stub",
    )?;
    let published = artifact_root(root, plan, release)
        .join("stub")
        .join(&plan.stub.binary);
    copy_artifact(&executable, &published, "kernel stub")?;
    Ok(StubArtifact {
        executable: published,
    })
}

fn create_kernel_sdk(
    root: &Path,
    plan: &BuildPlan,
    release: bool,
) -> Result<KernelSdkArtifact, String> {
    let target_dir = artifact_root(root, plan, release).join("sdk");
    let kernel_lib = target_dir.join("kernel.lib");
    let exports_path = root.join("kernel").join("src").join("exports.rs");

    if kernel_lib.is_file() && !is_source_newer(&exports_path, &kernel_lib)? {
        return Ok(KernelSdkArtifact {
            definition_file: target_dir.join("kernel.def"),
            import_library: kernel_lib,
        });
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
    let mut command = Command::new(lld_link);
    command
        .arg("/lib")
        .arg("/NOLOGO")
        .arg(format!("/DEF:{}", def_path.display()))
        .arg(format!("/MACHINE:{}", plan.kernel.import_library_machine))
        .arg(format!("/OUT:{}", kernel_lib.display()))
        .current_dir(root);

    if let Some(path) = path_with_rust_linkers() {
        command.env("PATH", path);
    }

    run(command, "generating kernel import library")?;
    Ok(KernelSdkArtifact {
        definition_file: def_path,
        import_library: kernel_lib,
    })
}

fn is_source_newer(source: &Path, artifact: &Path) -> Result<bool, String> {
    let source_modified = fs::metadata(source)
        .map_err(|err| format!("failed to stat {}: {err}", source.display()))?
        .modified()
        .map_err(|err| format!("failed to read mtime for {}: {err}", source.display()))?;
    let artifact_modified = fs::metadata(artifact)
        .map_err(|err| format!("failed to stat {}: {err}", artifact.display()))?
        .modified()
        .map_err(|err| format!("failed to read mtime for {}: {err}", artifact.display()))?;

    Ok(source_modified > artifact_modified)
}

fn generate_kernel_def(root: &Path, def_path: &Path) -> Result<(), String> {
    let exports_path = root.join("kernel").join("src").join("exports.rs");
    let contents = fs::read_to_string(&exports_path)
        .map_err(|err| format!("failed to read {}: {err}", exports_path.display()))?;
    let export_macro = contents
        .find("export!")
        .ok_or_else(|| "missing `export!` macro".to_string())?;
    let start = contents[export_macro..]
        .find('{')
        .map(|offset| export_macro + offset)
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

#[derive(Serialize)]
struct EmbeddedPackageManifest<'a> {
    schema: u32,
    packages: &'a [artifacts::DriverPackageArtifact],
}

fn write_boot_package_manifest(
    output: &Path,
    packages: &[artifacts::DriverPackageArtifact],
) -> Result<PathBuf, String> {
    let generated = output.join("generated");
    fs::create_dir_all(&generated)
        .map_err(|err| format!("failed to create {}: {err}", generated.display()))?;
    let path = generated.join("boot-packages.toml");
    let encoded = toml::to_string_pretty(&EmbeddedPackageManifest {
        schema: 1,
        packages,
    })
    .map_err(|err| format!("failed to encode boot package manifest: {err}"))?;
    fs::write(&path, encoded)
        .map_err(|err| format!("failed to write {}: {err}", path.display()))?;
    Ok(path)
}

fn publish_drivers(
    output: &Path,
    packages: &mut [artifacts::DriverPackageArtifact],
) -> Result<(), String> {
    let directory = output.join("drivers");
    fs::create_dir_all(&directory)
        .map_err(|err| format!("failed to create {}: {err}", directory.display()))?;
    for package in packages {
        let binary = directory.join(package.binary.file_name().ok_or_else(|| {
            format!(
                "driver binary has no filename: {}",
                package.binary.display()
            )
        })?);
        let configuration = directory.join(format!("{}.toml", package.name));
        copy_artifact(&package.binary, &binary, "driver binary")?;
        copy_artifact(
            &package.configuration,
            &configuration,
            "driver configuration",
        )?;
        package.debug_info = if let Some(pdb) = &package.debug_info {
            let destination = directory.join(format!("{}.pdb", package.name));
            copy_artifact(pdb, &destination, "driver PDB")?;
            Some(destination)
        } else {
            None
        };
        package.binary = binary;
        package.configuration = configuration;
    }
    Ok(())
}

fn publish_artifact_manifest(
    plan: &BuildPlan,
    release: bool,
    output: &Path,
    kernel: &KernelArtifact,
    sdk: &KernelSdkArtifact,
    drivers: &[artifacts::DriverPackageArtifact],
    stub: &StubArtifact,
    boot: &BootArtifact,
    debug_search_paths: &[PathBuf],
) -> Result<(), String> {
    let relative = |path: &Path| path.strip_prefix(output).unwrap_or(path).to_path_buf();
    let manifest = ArtifactManifest {
        schema: 2,
        platform: plan.id.clone(),
        profile: profile(release).to_string(),
        kernel: PublishedKernel {
            image: relative(&kernel.pe),
            debug: kernel.debug_info.as_deref().map(relative),
        },
        sdk: PublishedSdk {
            definition_file: relative(&sdk.definition_file),
            import_library: relative(&sdk.import_library),
        },
        stub: relative(&stub.executable),
        boot_image: relative(&boot.image),
        boot_packages: drivers
            .iter()
            .cloned()
            .map(|mut package| {
                package.configuration = relative(&package.configuration);
                package.binary = relative(&package.binary);
                package.debug_info = package.debug_info.as_deref().map(relative);
                package
            })
            .collect(),
        debug_search_paths: debug_search_paths.to_vec(),
    };
    let encoded = serde_json::to_string_pretty(&manifest)
        .map_err(|err| format!("failed to encode artifact manifest: {err}"))?;
    let path = output.join("artifacts.json");
    fs::write(&path, encoded).map_err(|err| format!("failed to write {}: {err}", path.display()))
}

fn stub_rustflags_env(target: &str) -> String {
    format!(
        "CARGO_TARGET_{}_RUSTFLAGS",
        target
            .chars()
            .map(|ch| if ch.is_ascii_alphanumeric() {
                ch.to_ascii_uppercase()
            } else {
                '_'
            })
            .collect::<String>()
    )
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask should live under a tooling/ directory")
        .parent()
        .expect("tooling/ should live under workspace root")
        .to_path_buf()
}

fn cargo(dir: &Path) -> Command {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut command = Command::new(cargo);
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
    let output = match Command::new(rustc).args(["--print", "sysroot"]).output() {
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

fn profile(release: bool) -> &'static str {
    if release {
        "release"
    } else {
        "debug"
    }
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

fn find_pdb(binary: &Path) -> Option<PathBuf> {
    let filename = binary.with_extension("pdb").file_name()?.to_owned();
    let parent = binary.parent()?;
    [parent.join(&filename), parent.join("deps").join(filename)]
        .into_iter()
        .find(|path| path.is_file())
}

struct ResolvedArtifacts {
    kernel: PathBuf,
    boot_image: PathBuf,
    debug_search_paths: Vec<PathBuf>,
}

fn validate_launch(
    plan: &BuildPlan,
    launch: &LaunchPlan,
    host: &HostPlan,
    options: &QemuOptions,
) -> Result<(), String> {
    if !launch
        .compatible_platforms
        .iter()
        .any(|platform| platform == &plan.id)
    {
        return Err(format!(
            "launch `{}` is not compatible with platform `{}`",
            launch.id, plan.id
        ));
    }
    if !launch.supported_hosts.iter().any(|name| name == &host.os) {
        return Err(format!(
            "launch `{}` does not support host OS `{}` selected by host configuration `{}`",
            launch.id, host.os, host.id
        ));
    }
    if !launch.supported_host_arches.is_empty()
        && !launch
            .supported_host_arches
            .iter()
            .any(|arch| arch == std::env::consts::ARCH)
    {
        return Err(format!(
            "launch `{}` does not support host architecture `{}`",
            launch.id,
            std::env::consts::ARCH
        ));
    }
    if options.debug && !launch.capabilities.debug {
        return Err(format!(
            "launch `{}` does not support debugging; select a debug-capable launch",
            launch.id
        ));
    }
    if options.lldb_meta && !launch.capabilities.lldb_metadata {
        return Err(format!(
            "launch `{}` does not support LLDB metadata",
            launch.id
        ));
    }
    Ok(())
}

fn load_artifact_manifest(
    root: &Path,
    plan: &BuildPlan,
    release: bool,
) -> Result<ResolvedArtifacts, String> {
    let output = artifact_root(root, plan, release);
    let path = output.join("artifacts.json");
    let build_command = format!(
        "cargo run -p xtask -- build --platform {}{}",
        plan.id,
        if release { " --release" } else { "" }
    );
    let source = fs::read_to_string(&path).map_err(|err| {
        format!(
            "cannot load artifacts for platform `{}` profile `{}` from {}: {err}\nrun: {build_command}",
            plan.id,
            profile(release),
            path.display()
        )
    })?;
    let manifest: ArtifactManifest = serde_json::from_str(&source).map_err(|err| {
        format!(
            "failed to parse artifact manifest {}: {err}\nrun: {build_command}",
            path.display()
        )
    })?;
    if manifest.schema != 2 {
        return Err(format!(
            "artifact manifest {} uses schema {}, expected 2\nrun: {build_command}",
            path.display(),
            manifest.schema
        ));
    }
    if manifest.platform != plan.id || manifest.profile != profile(release) {
        return Err(format!(
            "artifact manifest {} describes platform `{}` profile `{}`, expected `{}` `{}`\nrun: {build_command}",
            path.display(),
            manifest.platform,
            manifest.profile,
            plan.id,
            profile(release)
        ));
    }

    let resolve = |artifact: &Path| {
        if artifact.is_absolute() {
            artifact.to_path_buf()
        } else {
            output.join(artifact)
        }
    };
    let kernel = resolve(&manifest.kernel.image);
    let boot_image = resolve(&manifest.boot_image);
    let debug_search_paths: Vec<PathBuf> = manifest
        .debug_search_paths
        .iter()
        .map(|path| resolve(path))
        .collect();

    let mut required = vec![
        ("kernel image", kernel.clone()),
        ("boot image", boot_image.clone()),
        (
            "kernel definition file",
            resolve(&manifest.sdk.definition_file),
        ),
        (
            "kernel import library",
            resolve(&manifest.sdk.import_library),
        ),
        ("kernel stub", resolve(&manifest.stub)),
    ];
    if let Some(debug) = &manifest.kernel.debug {
        required.push(("kernel debug information", resolve(debug)));
    }
    for package in &manifest.boot_packages {
        required.push(("driver configuration", resolve(&package.configuration)));
        required.push(("driver binary", resolve(&package.binary)));
        if let Some(debug_info) = &package.debug_info {
            required.push(("driver debug information", resolve(debug_info)));
        }
    }
    for directory in &debug_search_paths {
        if !directory.is_dir() {
            return Err(format!(
                "artifact debug search directory is missing: {}\nrun: {build_command}",
                directory.display()
            ));
        }
    }
    for (what, path) in required {
        assert_exists(&path, what).map_err(|err| format!("{err}\nrun: {build_command}"))?;
    }

    Ok(ResolvedArtifacts {
        kernel,
        boot_image,
        debug_search_paths,
    })
}

fn find_qemu(launch: &LaunchPlan, host: &HostPlan) -> Result<PathBuf, String> {
    if let Some(executable) =
        env::var_os("RUSTOS_QEMU").filter(|value| !value.as_os_str().is_empty())
    {
        let executable = executable.to_string_lossy();
        return find_in_path(&executable)
            .ok_or_else(|| format!("RUSTOS_QEMU executable was not found: {executable}"));
    }

    if let Some(path) = find_in_path(&launch.executable) {
        return Ok(path);
    }

    for pattern in &host.executable_patterns {
        let rendered = pattern
            .to_string_lossy()
            .replace("{executable}", &launch.executable);
        let path = PathBuf::from(rendered);
        if path.is_file() {
            return Ok(path);
        }
    }

    Err(format!(
        "could not find QEMU executable `{}` for launch `{}` on host `{}`; set RUSTOS_QEMU",
        launch.executable, launch.id, host.id
    ))
}

fn find_firmware(launch: &LaunchPlan, host: &HostPlan, qemu: &Path) -> Result<PathBuf, String> {
    if let Some(path) = env_path("RUSTOS_FIRMWARE") {
        return require_file(path, "RUSTOS_FIRMWARE");
    }

    let firmware_files = env_path_list("RUSTOS_FIRMWARE_FILES_FROM_QEMU")
        .unwrap_or_else(|| launch.firmware_files.clone());
    let mut candidates = env_path_list("RUSTOS_FIRMWARE_CANDIDATES").unwrap_or_default();
    for directory in &host.data_directories {
        for file in &firmware_files {
            candidates.push(directory.join(file));
        }
    }
    candidates.extend(firmware_paths_from_qemu(qemu, &firmware_files));

    candidates
        .into_iter()
        .find(|path| path.is_file())
        .ok_or_else(|| "could not find configured firmware; set RUSTOS_FIRMWARE".to_string())
}

fn firmware_paths_from_qemu(qemu: &Path, files: &[PathBuf]) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    for prefix in qemu_prefixes(qemu) {
        let share = prefix.join("share").join("qemu");
        for file in files {
            paths.push(share.join(file));
        }
    }

    paths
}

fn env_path_list(name: &str) -> Option<Vec<PathBuf>> {
    let value = env::var_os(name).filter(|value| !value.as_os_str().is_empty())?;
    Some(env::split_paths(&value).collect())
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
        .any(|component| component.as_os_str() == OsStr::new("Cellar"))
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
    root: &Path,
    launch: &LaunchPlan,
    firmware: &Path,
    boot_image: &Path,
    system_disk: &SystemDisk,
    options: &QemuOptions,
) -> Result<Vec<OsString>, String> {
    let memory = env::var("RUSTOS_QEMU_MEMORY").unwrap_or_else(|_| launch.defaults.memory.clone());
    let cpus = env::var("RUSTOS_QEMU_SMP").unwrap_or_else(|_| launch.defaults.cpus.clone());
    let serial = qemu_serial_arg(root, options)?;
    let values = [
        ("memory", memory),
        ("cpus", cpus),
        ("firmware", portable_path(firmware)?),
        ("boot_image", portable_path(boot_image)?),
        ("system_disk", portable_path(&system_disk.path)?),
        ("system_disk_format", system_disk.format.clone()),
        ("primary_serial", serial),
        ("gdb_port", options.gdb_port.to_string()),
        ("meta_port", options.meta_port.to_string()),
    ];

    let mut templates = launch.args.clone();

    if options.debug {
        templates.extend(launch.debug_args.iter().cloned());
    }

    if options.lldb_meta {
        templates.extend(launch.lldb_metadata_args.iter().cloned());
    }

    templates
        .iter()
        .map(|template| render_launch_arg(template, &values).map(OsString::from))
        .collect()
}

fn render_launch_arg(template: &str, values: &[(&str, String)]) -> Result<String, String> {
    let mut rendered = template.to_string();
    for (name, value) in values {
        rendered = rendered.replace(&format!("{{{name}}}"), value);
    }
    if rendered.contains('{') || rendered.contains('}') {
        return Err(format!(
            "launch argument contains an unknown or unmatched placeholder: `{template}`"
        ));
    }
    Ok(rendered)
}

fn portable_path(path: &Path) -> Result<String, String> {
    path_string(path).map(|path| path.replace('\\', "/"))
}

fn qemu_serial_log_path(root: &Path) -> PathBuf {
    root.join("target").join("qemu-com1.log")
}

fn qemu_serial_arg(root: &Path, options: &QemuOptions) -> Result<String, String> {
    if options.console_serial {
        let path = qemu_serial_log_path(root);
        let path = qemu_path_string(root, &path)?;
        Ok(format!("file:{path}"))
    } else {
        Ok(env::var("RUSTOS_QEMU_SERIAL").unwrap_or_else(|_| "stdio".to_string()))
    }
}

fn path_string(path: &Path) -> Result<String, String> {
    path.to_str()
        .map(str::to_string)
        .ok_or_else(|| format!("path is not valid UTF-8: {}", path.display()))
}

fn qemu_path_string(root: &Path, path: &Path) -> Result<String, String> {
    let path = path.strip_prefix(root).unwrap_or(path);
    path_string(path).map(|path| path.replace('\\', "/"))
}

fn write_lldb_commands(
    root: &Path,
    artifacts: &ResolvedArtifacts,
    options: &QemuOptions,
) -> Result<(), String> {
    let driver_dir = artifacts.debug_search_paths.first().ok_or_else(|| {
        "artifact manifest does not contain a driver debug search path".to_string()
    })?;
    let metadata_script = root.join(".zed").join("lldb").join("rustos_meta.py");

    if options.lldb_meta {
        assert_exists(&metadata_script, "LLDB metadata script")?;
    }

    let search_paths = artifacts
        .debug_search_paths
        .iter()
        .map(|path| lldb_quote_path(path))
        .collect::<Result<Vec<_>, _>>()?
        .join(" ");
    let mut commands = vec![
        format!(
            "settings set target.debug-file-search-paths {}",
            search_paths
        ),
        format!("gdb-remote localhost:{}", options.gdb_port),
        format!(
            "target modules load --file {} --slide 0",
            lldb_quote_path(&artifacts.kernel)?
        ),
    ];

    if options.lldb_meta {
        commands.push(format!(
            "command script import {}",
            lldb_quote_path(&metadata_script)?
        ));
        commands.push(format!(
            "rustos-meta-connect 127.0.0.1 {} {}",
            options.meta_port,
            lldb_quote_path(&driver_dir)?
        ));
    }

    commands.push("process continue".to_string());

    let output = root.join("target").join("rustos").join("debug.lldb");
    let parent = output
        .parent()
        .ok_or_else(|| format!("LLDB command file has no parent: {}", output.display()))?;
    fs::create_dir_all(parent)
        .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    fs::write(&output, format!("{}\n", commands.join("\n")))
        .map_err(|err| format!("failed to write {}: {err}", output.display()))?;
    println!("Wrote LLDB commands to {}", output.display());
    Ok(())
}

fn lldb_quote_path(path: &Path) -> Result<String, String> {
    let path = path_string(path)?.replace('\\', "/").replace('"', "\\\"");
    Ok(format!("\"{path}\""))
}

fn spawn_qemu_detached(
    root: &Path,
    qemu: &Path,
    args: &[OsString],
    debug: bool,
    gdb_port: u16,
) -> Result<(), String> {
    let mut command = Command::new(qemu);
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

fn run_qemu_foreground(
    root: &Path,
    qemu: &Path,
    args: &[OsString],
    console_serial: bool,
) -> Result<(), String> {
    if !console_serial {
        let status = Command::new(qemu)
            .args(args)
            .current_dir(root)
            .status()
            .map_err(|err| format!("failed to launch QEMU {}: {err}", qemu.display()))?;

        return check_status(status, "running QEMU");
    }

    let serial_log = qemu_serial_log_path(root);

    if let Some(parent) = serial_log.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "failed to create serial log directory {}: {err}",
                parent.display()
            )
        })?;
    }

    fs::write(&serial_log, [])
        .map_err(|err| format!("failed to clear {}: {err}", serial_log.display()))?;

    let stop = Arc::new(AtomicBool::new(false));
    let tail_stop = Arc::clone(&stop);
    let tail_path = serial_log.clone();
    let tail = thread::spawn(move || tail_serial_file(&tail_path, &tail_stop));

    let status_result = Command::new(qemu).args(args).current_dir(root).status();

    stop.store(true, Ordering::Release);
    let _ = tail.join();

    let status =
        status_result.map_err(|err| format!("failed to launch QEMU {}: {err}", qemu.display()))?;

    check_status(status, "running QEMU")
}

fn tail_serial_file(path: &Path, stop: &AtomicBool) {
    use std::io::{Read, Seek, Write};

    let mut offset = 0u64;
    let mut buffer = [0u8; 4096];

    loop {
        let mut file = match fs::File::open(path) {
            Ok(file) => file,
            Err(_) => {
                if stop.load(Ordering::Acquire) {
                    return;
                }

                thread::sleep(Duration::from_millis(25));
                continue;
            }
        };

        if let Ok(metadata) = file.metadata() {
            if metadata.len() < offset {
                offset = metadata.len();
            }
        }

        if file.seek(std::io::SeekFrom::Start(offset)).is_err() {
            if stop.load(Ordering::Acquire) {
                return;
            }

            thread::sleep(Duration::from_millis(25));
            continue;
        }

        match file.read(&mut buffer) {
            Ok(0) => {
                if stop.load(Ordering::Acquire) {
                    return;
                }

                thread::sleep(Duration::from_millis(25));
            }
            Ok(read) => {
                offset += read as u64;
                let _ = std::io::stdout().write_all(&buffer[..read]);
                let _ = std::io::stdout().flush();
            }
            Err(_) => {
                if stop.load(Ordering::Acquire) {
                    return;
                }

                thread::sleep(Duration::from_millis(25));
            }
        }
    }
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

#[cfg(test)]
mod tests {
    use super::render_launch_arg;

    #[test]
    fn renders_launch_arguments_without_splitting_values() {
        let values = [("firmware", "C:/Program Files/qemu/OVMF.fd".to_string())];
        assert_eq!(
            render_launch_arg("file={firmware},readonly=on", &values).unwrap(),
            "file=C:/Program Files/qemu/OVMF.fd,readonly=on"
        );
    }

    #[test]
    fn rejects_unknown_launch_placeholders() {
        let error = render_launch_arg("{unknown}", &[]).unwrap_err();
        assert!(error.contains("unknown"));
    }
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

fn run(mut command: Command, step: &str) -> Result<(), String> {
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
