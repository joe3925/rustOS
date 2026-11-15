use crate::config::{self, BuildPlan};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) const MODE_ENV: [&str; 6] = [
    "RUSTOS_PGO_GENERATE",
    "RUSTOS_PGO_USE",
    "RUSTOS_PGO_DRIVERS",
    "RUSTOS_PGO_DRIVER_GENERATE",
    "RUSTOS_PGO_DRIVER_USE",
    "RUSTOS_PGO_DRIVER_BASELINE",
];

#[derive(Deserialize, Serialize)]
struct InstalledProfiles {
    schema: u32,
    platform: String,
    profile: String,
    launch: String,
    compiler: String,
    profiles: BTreeMap<String, PathBuf>,
}

struct Capture {
    expected: usize,
    next_chunk: u64,
    bytes: Vec<u8>,
}

pub struct BenchmarkImage {
    pub suites: Vec<String>,
    pub tags: Vec<String>,
    pub boot_timeout_secs: u64,
    pub timeout_secs: u64,
}

pub fn configure(
    command: &mut Command,
    root: &Path,
    plan: &BuildPlan,
    release: bool,
    component: &str,
    target: &Path,
) -> Result<bool, String> {
    let kernel = component == "kernel";
    let selected = env::var("RUSTOS_PGO_DRIVERS")
        .unwrap_or_default()
        .split(',')
        .any(|name| name == "all" || name.eq_ignore_ascii_case(component));
    let generate = if kernel {
        env::var_os("RUSTOS_PGO_GENERATE").is_some()
    } else {
        selected && env::var_os("RUSTOS_PGO_DRIVER_GENERATE").is_some()
    };
    let capture_drivers = kernel && env::var_os("RUSTOS_PGO_DRIVER_GENERATE").is_some();
    let baseline = !kernel && env::var_os("RUSTOS_PGO_DRIVER_BASELINE").is_some();
    let mut profile = if kernel {
        env::var_os("RUSTOS_PGO_USE").map(PathBuf::from)
    } else if selected {
        env::var_os("RUSTOS_PGO_DRIVER_USE").map(|directory| {
            PathBuf::from(directory).join(format!("{}.profdata", component.to_ascii_lowercase()))
        })
    } else {
        None
    };
    if generate && profile.is_some() {
        return Err(format!("Set only one PGO mode for {component}"));
    }
    if env::var_os("RUSTOS_PGO_DISABLE").is_none()
        && !MODE_ENV.iter().any(|name| env::var_os(name).is_some())
    {
        let path = crate::artifact_root(root, plan, release).join("pgo.json");
        if path.is_file() {
            let state: InstalledProfiles = serde_json::from_slice(
                &fs::read(&path)
                    .map_err(|error| format!("Cannot read {}: {error}", path.display()))?,
            )
            .map_err(|error| format!("Invalid PGO settings in {}: {error}", path.display()))?;
            if state.schema != 1
                || state.platform != plan.id
                || state.profile != crate::profile(release)
            {
                return Err(format!(
                    "PGO settings do not match this build: {}",
                    path.display()
                ));
            }
            profile = state.profiles.get(&component.to_ascii_lowercase()).cloned();
        }
    }
    if !generate && profile.is_none() && !baseline && !capture_drivers {
        return Ok(false);
    }
    let target_data: Value = serde_json::from_slice(
        &fs::read(target).map_err(|error| format!("Cannot read {}: {error}", target.display()))?,
    )
    .map_err(|error| format!("Invalid target specification: {error}"))?;
    let llvm_target = target_data["llvm-target"]
        .as_str()
        .ok_or_else(|| "The target has no LLVM target triple".to_string())?;
    if !llvm_target.ends_with("windows-msvc")
        || !llvm_target
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(format!(
            "PGO requires a supported PE target, got {llvm_target}"
        ));
    }
    let mut cflags = format!(
        "--target={llvm_target} -fno-profile-generate -fno-profile-instr-generate -fno-profile-use"
    );
    if llvm_target.starts_with("x86_64") {
        cflags.push_str(" -mno-red-zone");
    }
    command.env("CFLAGS", cflags).env("AR", "llvm-lib");
    if generate || profile.is_some() || baseline {
        let mut flags = "-Clinker-plugin-lto\x1f-Clto=fat\x1f-Clink-arg=/opt:lldlto=3".to_string();
        if llvm_target.starts_with("aarch64") {
            flags.push_str("\x1f--cfg\x1fportable_atomic_no_outline_atomics");
        }
        if generate {
            flags.push_str("\x1f-Cprofile-generate=rustos.profraw\x1f-Zno-profiler-runtime\x1f-Cllvm-args=-instrprof-atomic-counter-update-all");
        } else if let Some(path) = profile {
            let path = dunce::canonicalize(&path).map_err(|error| {
                format!("Cannot read PGO profile {}: {error}. Run xtask pgo again, or set RUSTOS_PGO_DISABLE=1", path.display())
            })?;
            if !path.is_file() {
                return Err(format!("PGO profile is not a file: {}", path.display()));
            }
            flags.push_str(&format!(
                "\x1f-Cprofile-use={}\x1f-Cllvm-args=-pgo-warn-missing-function",
                path.display()
            ));
            println!("==> using PGO for {component}: {}", path.display());
        }
        command.env("CARGO_ENCODED_RUSTFLAGS", flags);
    }
    if !kernel {
        command.args(["--features", "kernel_api/driver-pgo"]);
    }
    Ok(true)
}

fn stage_command(root: &Path, executable: &Path, staging: &Path, offline: bool) -> Command {
    let mut command = Command::new(executable);
    command.current_dir(root);
    for name in MODE_ENV {
        command.env_remove(name);
    }
    for name in [
        "RUSTOS_BENCH_SUITES",
        "RUSTOS_BENCH_TAGS",
        "RUSTOS_BENCH_AUTORUN",
    ] {
        command.env_remove(name);
    }
    command
        .env("RUSTOS_PGO_DISABLE", "1")
        .env("RUSTOS_PGO_ARTIFACT_ROOT", staging);
    if offline {
        command.env("CARGO_NET_OFFLINE", "true");
    }
    command
}

fn run_step(mut command: Command, log: &Path, step: &str) -> Result<(), String> {
    println!("==> {step}; log: {}", log.display());
    let output = fs::File::create(log)
        .map_err(|error| format!("Cannot create {}: {error}", log.display()))?;
    let errors = output.try_clone().map_err(|error| error.to_string())?;
    let status = command
        .stdin(Stdio::null())
        .stdout(output)
        .stderr(errors)
        .status()
        .map_err(|error| format!("Cannot start {step}: {error}"))?;
    if !status.success() {
        return Err(format!(
            "{step} failed ({status}). Read {}. Published binaries were not replaced",
            log.display()
        ));
    }
    Ok(())
}

fn copy_directory(source: &Path, destination: &Path) -> Result<(), String> {
    fs::create_dir(destination)
        .map_err(|error| format!("Cannot create {}: {error}", destination.display()))?;
    for entry in fs::read_dir(source).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let kind = entry.file_type().map_err(|error| error.to_string())?;
        let target = destination.join(entry.file_name());
        if kind.is_dir() {
            copy_directory(&entry.path(), &target)?;
        } else if kind.is_file() {
            fs::copy(entry.path(), &target)
                .map_err(|error| format!("Cannot copy {}: {error}", entry.path().display()))?;
        } else {
            return Err(format!(
                "Unsupported artifact entry: {}",
                entry.path().display()
            ));
        }
    }
    Ok(())
}

pub fn execute(
    root: &Path,
    args: Vec<String>,
    benchmark: Option<BenchmarkImage>,
) -> Result<PathBuf, String> {
    let mut launch_selector = None;
    let mut platform_selector = None;
    let mut host_selector = None;
    let mut cpu_selector = None;
    let mut output = None;
    let mut release = true;
    let mut offline = false;
    let mut args = args.into_iter();
    while let Some(argument) = args.next() {
        if matches!(argument.as_str(), "--help" | "-h") {
            println!(
                "cargo xtask pgo --launch NAME|FILE [--profile dev|release] [--platform NAME|FILE] [--host NAME|FILE] [--cpus N,N] [--output DIR] [--offline]\nRun all benchmarks once per CPU count, collect kernel and driver profiles, check the optimized benchmark build, then replace the published build. The default profile is release. The default CPU count comes from the launch. Drivers not loaded by the launch are left without PGO. Previous binaries are kept in a backup directory. Later xtask builds reuse the saved profiles. Set RUSTOS_PGO_DISABLE=1 to build without them."
            );
            return Ok(PathBuf::new());
        }
        if argument == "--offline" {
            offline = true;
            continue;
        }
        if !matches!(
            argument.as_str(),
            "--launch" | "--profile" | "--platform" | "--host" | "--cpus" | "--output"
        ) {
            return Err(format!("Unknown pgo argument `{argument}`"));
        }
        let value = args
            .next()
            .ok_or_else(|| format!("{argument} requires a value"))?;
        match argument.as_str() {
            "--launch" => launch_selector = Some(value),
            "--platform" => platform_selector = Some(value),
            "--host" => host_selector = Some(value),
            "--cpus" => cpu_selector = Some(value),
            "--output" => output = Some(PathBuf::from(value)),
            "--profile" => {
                release = match value.as_str() {
                    "release" => true,
                    "dev" | "debug" => false,
                    _ => return Err(format!("Unsupported build profile `{value}`")),
                }
            }
            _ => unreachable!(),
        }
    }
    let launch_selector =
        launch_selector.ok_or_else(|| "pgo requires --launch NAME|FILE".to_string())?;
    let launch = config::load_launch(root, &launch_selector)?;
    let platform_selector = match platform_selector {
        Some(platform) => platform,
        None if launch.compatible_platforms.len() == 1 => launch.compatible_platforms[0].clone(),
        None => return Err("This launch requires an explicit --platform".to_string()),
    };
    let plan = config::load_platform(root, &platform_selector)?;
    if !launch.compatible_platforms.contains(&plan.id) {
        return Err(format!("Launch {} does not support {}", launch.id, plan.id));
    }
    let host = config::load_host(root, host_selector.as_deref().unwrap_or(env::consts::OS))?;
    let qemu = crate::find_qemu(&launch, &host)?;
    crate::find_firmware(&launch, &host, &qemu)?;
    let disk = crate::system_disk(root)?;
    crate::assert_exists(&disk.path, "system disk")?;
    let cpus = cpu_selector.unwrap_or_else(|| launch.defaults.cpus.clone());
    let mut cpu_counts = BTreeSet::new();
    for cpu in cpus.split(',') {
        let cpu = cpu
            .parse::<usize>()
            .map_err(|_| "CPU counts must be positive integers".to_string())?;
        if cpu == 0 || !cpu_counts.insert(cpu) {
            return Err("CPU counts must be positive and must not repeat".to_string());
        }
    }
    let compiler_output = Command::new("rustc")
        .arg("-vV")
        .output()
        .map_err(|error| format!("Cannot read the Rust compiler version: {error}"))?;
    if !compiler_output.status.success() {
        return Err("rustc -vV failed".to_string());
    }
    let compiler = String::from_utf8(compiler_output.stdout).map_err(|error| error.to_string())?;
    let compiler_host = compiler
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .ok_or_else(|| "The compiler did not report its host".to_string())?;
    let sysroot_output = Command::new("rustc")
        .args(["--print", "sysroot"])
        .output()
        .map_err(|error| format!("Cannot find the Rust sysroot: {error}"))?;
    if !sysroot_output.status.success() {
        return Err("rustc --print sysroot failed".to_string());
    }
    let sysroot = String::from_utf8(sysroot_output.stdout).map_err(|error| error.to_string())?;
    let profdata = Path::new(sysroot.trim())
        .join("lib/rustlib")
        .join(compiler_host)
        .join("bin")
        .join(format!("llvm-profdata{}", env::consts::EXE_SUFFIX));
    if !profdata.is_file() {
        return Err(
            "Install the matching profile tool with: rustup component add llvm-tools-preview"
                .to_string(),
        );
    }
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_nanos();
    let output = output.unwrap_or_else(|| {
        root.join("target/pgo")
            .join(&plan.id)
            .join(crate::profile(release))
            .join(&launch.id)
            .join(format!("run-{stamp}"))
    });
    let output = if output.is_absolute() {
        output
    } else {
        root.join(output)
    };
    if output.exists() {
        return Err(format!(
            "Use a new PGO output directory: {}",
            output.display()
        ));
    }
    fs::create_dir_all(&output)
        .map_err(|error| format!("Cannot create {}: {error}", output.display()))?;
    let output = dunce::canonicalize(output).map_err(|error| error.to_string())?;
    let staging = output.join("staging");
    let profiles_dir = output.join("profiles");
    fs::create_dir(&profiles_dir).map_err(|error| error.to_string())?;
    let executable = env::current_exe().map_err(|error| error.to_string())?;
    let mut bench_args = vec![
        "bench".to_string(),
        "--all".to_string(),
        "--platform".to_string(),
        platform_selector.clone(),
        "--launch".to_string(),
        launch_selector.clone(),
        "--profile".to_string(),
        if release { "release" } else { "dev" }.to_string(),
        "--cpus".to_string(),
        cpus.clone(),
        "--max-repetitions".to_string(),
        "1".to_string(),
        "--boot-timeout-secs".to_string(),
        benchmark.as_ref().map_or(180, |options| options.boot_timeout_secs).to_string(),
        "--timeout-secs".to_string(),
        benchmark.as_ref().map_or(1200, |options| options.timeout_secs).to_string(),
    ];
    if let Some(host) = &host_selector {
        bench_args.extend(["--host".to_string(), host.clone()]);
    }
    if offline {
        bench_args.push("--offline".to_string());
    }
    let training_report = output.join("training/results.json");
    let mut train = stage_command(root, &executable, &staging, offline);
    train
        .args(&bench_args)
        .arg("--output")
        .arg(&training_report)
        .arg("--export-boot-image")
        .arg(output.join("instrumented.img"))
        .env("RUSTOS_PGO_GENERATE", "1")
        .env("RUSTOS_PGO_DRIVER_GENERATE", "1")
        .env("RUSTOS_PGO_DRIVERS", "all");
    run_step(
        train,
        &output.join("training.log"),
        "collecting PGO profiles",
    )?;
    let report: Value =
        serde_json::from_slice(&fs::read(&training_report).map_err(|error| error.to_string())?)
            .map_err(|error| format!("Invalid training report: {error}"))?;
    if report["schema"] != "rustos.bench-run.v1" || report["protocol_version"] != 1 {
        return Err("Unsupported training report format".to_string());
    }
    let runs = report["runs"]
        .as_array()
        .ok_or_else(|| "Training report has no runs".to_string())?;
    if runs.len() != cpu_counts.len() {
        return Err("Training did not complete each CPU configuration".to_string());
    }
    let mut raw_profiles = BTreeMap::<String, Vec<PathBuf>>::new();
    let mut completed_cpus = BTreeSet::new();
    for (run_index, run) in runs.iter().enumerate() {
        let cpu = run["cpus"]
            .as_u64()
            .and_then(|cpu| usize::try_from(cpu).ok())
            .ok_or_else(|| "Training run has an invalid CPU count".to_string())?;
        if !cpu_counts.contains(&cpu)
            || !completed_cpus.insert(cpu)
            || run["complete"] != true
            || run["status"] != "passed"
        {
            return Err(format!("Training run {run_index} did not pass"));
        }
        let mut captures = BTreeMap::<String, Capture>::new();
        let mut completed = BTreeSet::new();
        let events = run["events"]
            .as_array()
            .ok_or_else(|| "Training run has no events".to_string())?;
        for event in events {
            let kind = event["kind"].as_str().unwrap_or_default();
            if !kind.starts_with("pgo_") {
                continue;
            }
            let payload = &event["payload"];
            let component = payload["component"]
                .as_str()
                .ok_or_else(|| "Profile event has no component".to_string())?;
            if component.is_empty()
                || component.len() > 128
                || !component
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            {
                return Err("Invalid profile component name".to_string());
            }
            match kind {
                "pgo_start" => {
                    let expected = payload["bytes"]
                        .as_u64()
                        .and_then(|value| usize::try_from(value).ok())
                        .filter(|value| *value > 0 && *value <= 128 * 1024 * 1024)
                        .ok_or_else(|| format!("Invalid profile size for {component}"))?;
                    if completed.contains(component) || captures.contains_key(component) {
                        return Err(format!("Duplicate profile for {component}"));
                    }
                    let mut bytes = Vec::new();
                    bytes
                        .try_reserve_exact(expected)
                        .map_err(|error| error.to_string())?;
                    captures.insert(
                        component.to_string(),
                        Capture {
                            expected,
                            next_chunk: 0,
                            bytes,
                        },
                    );
                }
                "pgo_chunk" => {
                    let capture = captures
                        .get_mut(component)
                        .ok_or_else(|| format!("Profile chunk has no start: {component}"))?;
                    if payload["index"].as_u64() != Some(capture.next_chunk) {
                        return Err(format!("Missing profile chunk for {component}"));
                    }
                    let hex = payload["data"]
                        .as_str()
                        .ok_or_else(|| "Profile chunk has no data".to_string())?;
                    if hex.is_empty()
                        || hex.len() % 2 != 0
                        || !hex.bytes().all(|byte| byte.is_ascii_hexdigit())
                        || hex.len() / 2 > capture.expected - capture.bytes.len()
                    {
                        return Err(format!("Invalid profile chunk for {component}"));
                    }
                    for pair in hex.as_bytes().chunks_exact(2) {
                        let byte =
                            u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
                        capture.bytes.push(byte);
                    }
                    capture.next_chunk += 1;
                }
                "pgo_end" => {
                    let capture = captures
                        .remove(component)
                        .ok_or_else(|| format!("Profile end has no start: {component}"))?;
                    if capture.bytes.len() != capture.expected
                        || payload["bytes"].as_u64() != Some(capture.expected as u64)
                    {
                        return Err(format!("Incomplete profile for {component}"));
                    }
                    let path = profiles_dir.join(format!("{component}-{run_index}.profraw"));
                    fs::write(&path, capture.bytes).map_err(|error| error.to_string())?;
                    raw_profiles
                        .entry(component.to_string())
                        .or_default()
                        .push(path);
                    completed.insert(component.to_string());
                }
                _ => return Err(format!("Profile capture failed: {kind} ({component})")),
            }
        }
        if !captures.is_empty() || !completed.contains("kernel") {
            return Err(format!("Training run {run_index} has incomplete profiles"));
        }
    }
    let mut profiles = BTreeMap::new();
    for (component, raw) in &raw_profiles {
        let path = profiles_dir.join(format!("{component}.profdata"));
        let mut merge = Command::new(&profdata);
        merge.arg("merge").arg("-o").arg(&path).args(raw);
        run_step(
            merge,
            &output.join(format!("merge-{component}.log")),
            &format!("merging {component}"),
        )?;
        let mut show = Command::new(&profdata);
        show.arg("show").arg(&path);
        run_step(
            show,
            &output.join(format!("profile-{component}.log")),
            &format!("checking {component} profile"),
        )?;
        profiles.insert(component.clone(), path);
    }
    let stage = staging.join(&plan.id).join(crate::profile(release));
    let artifacts: crate::artifacts::ArtifactManifest = serde_json::from_slice(
        &fs::read(stage.join("artifacts.json")).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let skipped: Vec<_> = artifacts
        .boot_packages
        .iter()
        .filter(|driver| !profiles.contains_key(&driver.name.to_ascii_lowercase()))
        .map(|driver| driver.name.clone())
        .collect();
    if !skipped.is_empty() {
        println!("==> no profile was captured for: {}", skipped.join(", "));
    }
    let drivers = profiles
        .keys()
        .filter(|name| name.as_str() != "kernel")
        .cloned()
        .collect::<Vec<_>>()
        .join(",");
    let kernel_profile = profiles
        .get("kernel")
        .ok_or_else(|| "No kernel profile was captured".to_string())?;
    let verification_report = output.join("verification/results.json");
    if let Some(options) = &benchmark {
        bench_args.retain(|argument| argument != "--all");
        for suite in &options.suites {
            bench_args.extend(["--suite".to_string(), suite.clone()]);
        }
        for tag in &options.tags {
            bench_args.extend(["--tag".to_string(), tag.clone()]);
        }
        if options.suites.is_empty() && options.tags.is_empty() {
            bench_args.push("--all".to_string());
        }
    }
    let mut verify = stage_command(root, &executable, &staging, offline);
    verify
        .args(&bench_args)
        .arg("--output")
        .arg(&verification_report)
        .arg("--export-boot-image")
        .arg(output.join("optimized-benchmark.img"))
        .env("RUSTOS_PGO_USE", kernel_profile)
        .env("RUSTOS_PGO_DRIVER_USE", &profiles_dir)
        .env("RUSTOS_PGO_DRIVERS", &drivers);
    if benchmark.is_some() {
        verify.arg("--prepare-only");
    }
    run_step(
        verify,
        &output.join(if benchmark.is_some() { "image-build.log" } else { "verification.log" }),
        if benchmark.is_some() { "creating the PGO benchmark image" } else { "checking all benchmarks with PGO" },
    )?;
    if let Some(options) = benchmark {
        let image = output.join("optimized-benchmark.img");
        crate::assert_exists(&image, "PGO benchmark image")?;
        let result = json!({
            "schema": "rustos.pgo-benchmark-image.v1", "complete": true,
            "platform": plan.id, "profile": crate::profile(release), "launch": launch.id,
            "training_cpus": cpu_counts, "training_report": training_report,
            "profiles": profiles, "unprofiled_drivers": skipped,
            "suites": options.suites, "tags": options.tags, "image": image,
        });
        fs::write(output.join("image-build.json"), serde_json::to_vec_pretty(&result)
            .map_err(|error| error.to_string())?).map_err(|error| error.to_string())?;
        println!("PGO benchmark image: {}", image.display());
        println!("PGO image details: {}", output.join("image-build.json").display());
        return Ok(image);
    }
    let mut build = stage_command(root, &executable, &staging, offline);
    build
        .args(["build", "--platform", &platform_selector])
        .env("RUSTOS_PGO_USE", kernel_profile)
        .env("RUSTOS_PGO_DRIVER_USE", &profiles_dir)
        .env("RUSTOS_PGO_DRIVERS", &drivers);
    if release {
        build.arg("--release");
    }
    if offline {
        build.arg("--offline");
    }
    run_step(
        build,
        &output.join("build.log"),
        "building the normal PGO image",
    )?;
    let state = InstalledProfiles {
        schema: 1,
        platform: plan.id.clone(),
        profile: crate::profile(release).to_string(),
        launch: launch.id.clone(),
        compiler,
        profiles,
    };
    fs::write(
        stage.join("pgo.json"),
        serde_json::to_vec_pretty(&state).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let parent = root.join("target/rustos").join(&plan.id);
    fs::create_dir_all(&parent).map_err(|error| error.to_string())?;
    let parent = dunce::canonicalize(parent).map_err(|error| error.to_string())?;
    let workspace = dunce::canonicalize(root).map_err(|error| error.to_string())?;
    if !parent.starts_with(&workspace) {
        return Err("The publication directory is outside the workspace".to_string());
    }
    let published = parent.join(crate::profile(release));
    let incoming = parent.join(format!("{}-pgo-incoming-{stamp}", crate::profile(release)));
    let backup = parent.join(format!("{}-pgo-previous-{stamp}", crate::profile(release)));
    copy_directory(&stage, &incoming)?;
    let had_previous = published.exists();
    if had_previous {
        fs::rename(&published, &backup).map_err(|error| {
            format!(
                "Cannot back up {}: {error}. The previous build remains installed",
                published.display()
            )
        })?;
    }
    if let Err(error) = fs::rename(&incoming, &published) {
        if had_previous {
            fs::rename(&backup, &published).map_err(|restore| {
                format!("Publication failed: {error}. Restore failed: {restore}. Previous binaries are at {}", backup.display())
            })?;
        }
        return Err(format!(
            "Publication failed: {error}. The previous build was restored"
        ));
    }
    let result = json!({
        "schema": "rustos.pgo.v1", "complete": true,
        "platform": plan.id, "profile": crate::profile(release), "launch": launch.id,
        "cpus": cpu_counts, "profiles": state.profiles, "unprofiled_drivers": skipped,
        "training_report": training_report, "benchmark_verification_report": verification_report,
        "published": published, "backup": if had_previous { Some(&backup) } else { None },
        "normal_image_runtime_checked": false,
    });
    fs::write(
        output.join("results.json"),
        serde_json::to_vec_pretty(&result).map_err(|error| error.to_string())?,
    )
    .map_err(|error| {
        format!("PGO binaries were installed, but the result report could not be written: {error}")
    })?;
    println!("PGO binaries: {}", published.display());
    println!("PGO results: {}", output.join("results.json").display());
    if had_previous {
        println!("Previous binaries: {}", backup.display());
    }
    Ok(published)
}
