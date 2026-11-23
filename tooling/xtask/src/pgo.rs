use crate::config::{self, BuildPlan};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static GENERATE: AtomicBool = AtomicBool::new(false);

pub fn enable_generation() {
    GENERATE.store(true, Ordering::Relaxed);
}

static APPLY: std::sync::OnceLock<BTreeMap<String, PathBuf>> = std::sync::OnceLock::new();

#[derive(Deserialize, Serialize)]
struct ProfileSet {
    schema: u32,
    platform: String,
    profile: String,
    compiler: String,
    merged: bool,
    profiles: BTreeMap<String, PathBuf>,
}

struct Capture {
    expected: usize,
    next_chunk: u64,
    bytes: Vec<u8>,
}

pub fn configure(
    command: &mut Command,
    _root: &Path,
    _plan: &BuildPlan,
    _release: bool,
    component: &str,
    target: &Path,
) -> Result<bool, String> {
    let kernel = component == "kernel";
    let generate = GENERATE.load(Ordering::Relaxed);
    // Only the explicit `pgo` command populates APPLY. Builds never read saved
    // profile state or PGO environment variables.
    let profile = APPLY
        .get()
        .and_then(|profiles| profiles.get(&component.to_ascii_lowercase()))
        .cloned();
    if !generate && profile.is_none() {
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
    let archiver = crate::find_tool_in_augmented_path("llvm-lib")
        .or_else(|| crate::find_tool_in_augmented_path("llvm-ar"))
        .ok_or_else(|| {
            "PGO requires llvm-lib or llvm-ar; install rustup component add llvm-tools-preview"
                .to_string()
        })?;
    command.env("CFLAGS", cflags).env("AR", archiver);
    if generate || profile.is_some() {
        let mut flags = "-Clinker-plugin-lto\x1f-Clto=fat\x1f-Clink-arg=/opt:lldlto=3".to_string();
        // Favor runtime savings over code size in both rustc and linker LTO.
        flags.push_str(concat!(
            "\x1f-Cllvm-args=-inline-savings-multiplier=16",
            "\x1f-Clink-arg=/mllvm:-inline-savings-multiplier=16",
        ));
        if llvm_target.starts_with("aarch64") {
            flags.push_str("\x1f--cfg\x1fportable_atomic_no_outline_atomics");
        }
        if generate {
            flags.push_str("\x1f-Cprofile-generate=rustos.profraw\x1f-Zno-profiler-runtime\x1f-Cllvm-args=-instrprof-atomic-counter-update-all");
        } else if let Some(path) = profile {
            let path = dunce::canonicalize(&path)
                .map_err(|error| format!("Cannot read PGO profile {}: {error}", path.display()))?;
            if !path.is_file() {
                return Err(format!("PGO profile is not a file: {}", path.display()));
            }
            flags.push_str(&format!(
                "\x1f-Cprofile-use={}\x1f-Cllvm-args=-pgo-warn-missing-function",
                path.display()
            ));
            crate::bench::print_status!("==> using PGO for {component}: {}", path.display());
        }
        command.env("CARGO_ENCODED_RUSTFLAGS", flags);
    }
    if !kernel {
        command.args(["--features", "kernel_api/driver-pgo"]);
    }
    Ok(true)
}

fn run_step(mut command: Command, log: &Path, step: &str) -> Result<(), String> {
    crate::bench::print_status!("==> {step}; log: {}", log.display());
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
        return Err(format!("{step} failed ({status}). Read {}", log.display()));
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

fn compiler_version() -> Result<String, String> {
    let output = Command::new("rustc")
        .arg("-vV")
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err("rustc -vV failed".to_string());
    }
    String::from_utf8(output.stdout).map_err(|error| error.to_string())
}

fn profile_tool(compiler: &str) -> Result<PathBuf, String> {
    let host = compiler
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .ok_or_else(|| "Compiler did not report its host".to_string())?;
    let output = Command::new("rustc")
        .args(["--print", "sysroot"])
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err("rustc --print sysroot failed".to_string());
    }
    let sysroot = String::from_utf8(output.stdout).map_err(|error| error.to_string())?;
    let path = Path::new(sysroot.trim())
        .join("lib/rustlib")
        .join(host)
        .join("bin")
        .join(format!("llvm-profdata{}", env::consts::EXE_SUFFIX));
    if !path.is_file() {
        return Err(
            "Install the matching profile tool: rustup component add llvm-tools-preview"
                .to_string(),
        );
    }
    Ok(path)
}

pub fn check_merge_tool() -> Result<(), String> {
    let tool = profile_tool(&compiler_version()?)?;
    let output = Command::new(&tool)
        .arg("--version")
        .output()
        .map_err(|error| format!("Cannot run {}: {error}", tool.display()))?;
    if !output.status.success() {
        return Err(format!(
            "{} --version failed: {}",
            tool.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

fn stamp() -> Result<u128, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_nanos())
        .map_err(|error| error.to_string())
}

pub fn collect(
    report: &Value,
    report_directory: &Path,
    output: &Path,
    plan: &BuildPlan,
    release: bool,
    should_merge: bool,
) -> Result<(), String> {
    if output.exists() {
        return Err(format!(
            "Use a new PGO output directory: {}",
            output.display()
        ));
    }
    fs::create_dir_all(output).map_err(|error| error.to_string())?;
    let output = dunce::canonicalize(output).map_err(|error| error.to_string())?;
    let profiles_dir = &output;
    if report["schema"] != "rustos.bench-run.v1" || report["protocol_version"] != 1 {
        return Err("Unsupported training report format".to_string());
    }
    let runs = report["runs"]
        .as_array()
        .ok_or_else(|| "Training report has no runs".to_string())?;
    if runs.is_empty() {
        return Err("The benchmark report has no runs".to_string());
    }
    let mut raw_profiles = BTreeMap::<String, Vec<PathBuf>>::new();
    for (run_index, run) in runs.iter().enumerate() {
        if run["complete"] != true || run["status"] != "passed" {
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
                "pgo_file" => {
                    if completed.contains(component) || captures.contains_key(component) {
                        return Err(format!("Duplicate profile for {component}"));
                    }
                    let expected = payload["bytes"].as_u64()
                        .filter(|bytes| *bytes > 0 && *bytes <= 128 * 1024 * 1024)
                        .ok_or_else(|| format!("Invalid profile size for {component}"))?;
                    let file = payload["file"].as_str()
                        .ok_or_else(|| format!("Missing profile filename for {component}"))?;
                    let relative = Path::new(file);
                    if relative.is_absolute() || !relative.components().all(|part| matches!(part, std::path::Component::Normal(_))) {
                        return Err(format!("Invalid profile path for {component}"));
                    }
                    let source = report_directory.join(relative);
                    let path = profiles_dir.join(format!("{component}-{run_index}.profraw"));
                    if fs::metadata(&source).map_err(|error| error.to_string())?.len() != expected {
                        return Err(format!("Incomplete profile for {component}"));
                    }
                    let copied = fs::copy(&source, &path)
                        .map_err(|error| format!("Cannot copy {}: {error}", source.display()))?;
                    if copied != expected {
                        return Err(format!("Incomplete profile copy for {component}"));
                    }
                    raw_profiles.entry(component.to_string()).or_default().push(path);
                    completed.insert(component.to_string());
                }
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
    let compiler = compiler_version()?;
    let profiles = if should_merge {
        let profdata = profile_tool(&compiler)?;
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
            profiles.insert(
                component.clone(),
                PathBuf::from(format!("{component}.profdata")),
            );
        }
        profiles
    } else {
        BTreeMap::new()
    };
    let state = ProfileSet {
        schema: 1,
        platform: plan.id.clone(),
        profile: crate::profile(release).to_string(),
        compiler,
        merged: should_merge,
        profiles,
    };
    fs::write(
        output.join("profiles.json"),
        serde_json::to_vec_pretty(&state).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    crate::bench::print_status!(
        "PGO {}profiles: {}",
        if should_merge {
            "raw and merged "
        } else {
            "raw "
        },
        output.display()
    );
    Ok(())
}

pub fn default_output(root: &Path, plan: &BuildPlan, release: bool) -> Result<PathBuf, String> {
    Ok(root
        .join("target/pgo")
        .join(&plan.id)
        .join(crate::profile(release))
        .join(format!("run-{}", stamp()?)))
}

pub fn execute(root: &Path, args: Vec<String>) -> Result<PathBuf, String> {
    let mut platform = None;
    let mut profiles_dir = None;
    let mut release = true;
    let mut offline = false;
    let mut features = Vec::new();
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                crate::bench::print_status!(
                    "cargo xtask pgo --platform NAME --profiles DIR [--profile dev|release] [--kernel-feature NAME] [--offline]\nBuild using profiles collected by bench --pgo --merge. This command does not run benchmarks or merge profiles. Ordinary builds always ignore profiles."
                );
                return Ok(PathBuf::new());
            }
            "--offline" => offline = true,
            "--platform" | "--profiles" | "--profile" | "--kernel-feature" => {
                let value = args
                    .next()
                    .ok_or_else(|| format!("{arg} requires a value"))?;
                match arg.as_str() {
                    "--platform" => platform = Some(value),
                    "--profiles" => profiles_dir = Some(PathBuf::from(value)),
                    "--kernel-feature" => features.push(value),
                    "--profile" => {
                        release = match value.as_str() {
                            "release" => true,
                            "dev" | "debug" => false,
                            _ => return Err(format!("Unsupported profile `{value}`")),
                        }
                    }
                    _ => unreachable!(),
                }
            }
            _ => return Err(format!("Unknown pgo argument `{arg}`; use pgo --help")),
        }
    }
    let platform = platform.ok_or_else(|| "pgo requires --platform NAME".to_string())?;
    let plan = config::load_platform(root, &platform)?;
    let directory = profiles_dir
        .ok_or_else(|| "pgo requires --profiles DIR from bench --pgo --merge".to_string())?;
    let directory = if directory.is_absolute() {
        directory
    } else {
        root.join(directory)
    };
    let mut state: ProfileSet =
        serde_json::from_slice(&fs::read(directory.join("profiles.json")).map_err(|error| {
            format!("Cannot read profile set: {error}. Collect with bench --pgo --merge first")
        })?)
        .map_err(|error| error.to_string())?;
    if state.schema != 1
        || !state.merged
        || state.platform != plan.id
        || state.profile != crate::profile(release)
    {
        return Err(
            "Profiles must be merged and match the selected platform and build profile".to_string(),
        );
    }
    if state.compiler != compiler_version()? {
        return Err("Profiles were collected with a different compiler".to_string());
    }
    if !state.profiles.contains_key("kernel") {
        return Err("The profile set has no kernel profile".to_string());
    }
    for path in state.profiles.values_mut() {
        let source = if path.is_absolute() {
            path.clone()
        } else {
            directory.join(&*path)
        };
        crate::assert_exists(&source, "merged PGO profile")?;
        *path = dunce::canonicalize(&source).map_err(|error| error.to_string())?;
    }
    if features
        .iter()
        .any(|feature| feature == "kernel-correctness")
    {
        return Err("PGO application does not support kernel-correctness builds".to_string());
    }
    APPLY
        .set(state.profiles.clone())
        .map_err(|_| "PGO profiles already configured".to_string())?;
    let stamp = stamp()?;
    let output = root.join("target/pgo-build").join(format!("run-{stamp}"));
    let staging = output.join("staging");
    let previous_root = env::var_os("RUSTOS_PGO_ARTIFACT_ROOT");
    unsafe {
        env::set_var("RUSTOS_PGO_ARTIFACT_ROOT", &staging);
    }
    let result = crate::build_platform(root, &plan, release, offline, &features);
    unsafe {
        match previous_root {
            Some(value) => env::set_var("RUSTOS_PGO_ARTIFACT_ROOT", value),
            None => env::remove_var("RUSTOS_PGO_ARTIFACT_ROOT"),
        }
    }
    result?;
    let stage = staging.join(&plan.id).join(crate::profile(release));
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
    fs::write(
        output.join("results.json"),
        serde_json::to_vec_pretty(&json!({
            "schema": "rustos.pgo-build.v1", "complete": true, "platform": plan.id,
            "profile": crate::profile(release), "profiles": state.profiles, "published": published,
            "backup": if had_previous { Some(&backup) } else { None },
        }))
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    crate::bench::print_status!("PGO binaries: {}", published.display());
    Ok(published)
}
