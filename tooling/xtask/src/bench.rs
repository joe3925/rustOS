use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    cmp::Ordering as CmpOrdering,
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crate::{
    QemuOptions, SystemDisk, assert_exists, build_platform, config, find_firmware, find_qemu,
    qemu_args, system_disk,
};

// Console output is optional: a closed pipe or non-blocking terminal must not
// abort a benchmark or discard the profiles being collected.
pub(super) fn best_effort_output(writer: &mut impl Write, args: std::fmt::Arguments<'_>) {
    let _ = writeln!(writer, "{args}");
}

macro_rules! print_status {
    ($($args:tt)*) => {
        $crate::bench::best_effort_output(&mut std::io::stdout().lock(), format_args!($($args)*))
    };
}
pub(crate) use print_status;

const MAX_ACTION_ANNOTATIONS: usize = 3;
static ACTION_ANNOTATIONS: AtomicUsize = AtomicUsize::new(0);

pub enum BenchCommand {
    Run(BenchOptions),
    Compare(CompareOptions),
}

pub struct BenchOptions {
    correctness: bool,
    pgo: bool,
    merge: bool,
    pgo_output: Option<PathBuf>,
    release: bool,
    platform: String,
    launch: String,
    host: Option<String>,
    cpus: Vec<usize>,
    suites: Vec<String>,
    tags: Vec<String>,
    output: PathBuf,
    boot_image: Option<PathBuf>,
    export_boot_image: Option<PathBuf>,
    boot_timeout: Duration,
    timeout: Duration,
    offline: bool,
    max_repetitions: Option<usize>,
}

pub fn parse<I>(args: I, correctness: bool) -> Result<BenchCommand, String>
where
    I: IntoIterator<Item = String>,
{
    let mut args = args.into_iter().peekable();
    if args.peek().map(String::as_str) == Some("compare") {
        if correctness {
            return Err("this command does not support baseline comparison".to_string());
        }
        args.next();
        CompareOptions::parse(args).map(BenchCommand::Compare)
    } else {
        BenchOptions::parse(args, correctness).map(BenchCommand::Run)
    }
}

pub fn execute(root: &Path, command: BenchCommand) -> Result<(), String> {
    let annotations = match &command {
        BenchCommand::Run(_) => true,
        BenchCommand::Compare(options) => options.annotations,
    };
    let result = match command {
        BenchCommand::Run(options) => run(root, options),
        BenchCommand::Compare(options) => compare(root, options),
    };
    if annotations {
        if let Err(err) = &result {
            annotate_error("Kernel command failed", err);
        }
    }
    result
}

impl BenchOptions {
    fn parse<I>(args: I, correctness: bool) -> Result<Self, String>
    where
        I: IntoIterator<Item = String>,
    {
        let mut platform = "x86_64-uefi".to_string();
        let mut release = true;
        let mut all = false;
        let mut pgo = false;
        let mut merge = false;
        let mut pgo_output = None;
        let mut launch = "qemu-x86_64-q35-ci".to_string();
        let mut host = None;
        let mut cpus = vec![1, 2, 4];
        let mut cpus_explicit = false;
        let mut suites = Vec::new();
        let mut tags = Vec::new();
        let mut output = PathBuf::from(if correctness {
            "target/correctness/results.json"
        } else {
            "target/bench/results.json"
        });
        let mut boot_image = None;
        let mut export_boot_image = None;
        let mut boot_timeout = Duration::from_secs(2 * 60);
        let mut timeout = Duration::from_secs(15 * 60);
        let mut offline = false;
        let mut max_repetitions = None;
        let mut args = args.into_iter();

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--all" => all = true,
                "--pgo" if !correctness => pgo = true,
                "--merge" if !correctness => merge = true,
                "--pgo-output" if !correctness => pgo_output = Some(PathBuf::from(next_value(&mut args, "--pgo-output")?)),
                "--profile" => {
                    release = match next_value(&mut args, "--profile")?.as_str() {
                        "release" => true,
                        "dev" | "debug" => false,
                        value => return Err(format!("Unsupported build profile `{value}`")),
                    };
                }
                "--platform" => {
                    platform = next_value(&mut args, "--platform")?;
                }
                "--launch" => {
                    launch = next_value(&mut args, "--launch")?;
                }
                "--host" => host = Some(next_value(&mut args, "--host")?),
                "--cpus" => {
                    cpus_explicit = true;
                    let value = next_value(&mut args, "--cpus")?;
                    cpus = value
                        .split(',')
                        .map(|cpu| {
                            cpu.parse::<usize>()
                                .map_err(|_| format!("invalid CPU count `{cpu}`"))
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    if cpus.is_empty() || cpus.iter().any(|cpu| *cpu == 0) {
                        return Err("--cpus requires positive comma-separated counts".to_string());
                    }
                }
                "--suite" | "--tag" => {
                    let value = next_value(&mut args, &arg)?;
                    let selection = if arg == "--suite" { &mut suites } else { &mut tags };
                    for name in value.split(',').map(str::trim) {
                        if name.is_empty() || name.len() > 128 || !name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'/')) {
                            return Err(format!("Invalid {arg} value `{name}`; expected comma-separated names"));
                        }
                        if !selection.iter().any(|existing| existing == name) {
                            selection.push(name.to_string());
                        }
                    }
                    if selection.join(";").len() > 4095 {
                        return Err(format!("{arg} selection is too long (maximum 4095 bytes)"));
                    }
                }
                "--output" => output = PathBuf::from(next_value(&mut args, "--output")?),
                "--boot-image" => {
                    boot_image = Some(PathBuf::from(next_value(&mut args, "--boot-image")?))
                }
                "--export-boot-image" => {
                    export_boot_image =
                        Some(PathBuf::from(next_value(&mut args, "--export-boot-image")?))
                }
                "--boot-timeout-secs" => {
                    let value = next_value(&mut args, "--boot-timeout-secs")?;
                    boot_timeout = Duration::from_secs(
                        value
                            .parse()
                            .map_err(|_| format!("invalid boot timeout `{value}`"))?,
                    );
                }
                "--timeout-secs" => {
                    let value = next_value(&mut args, "--timeout-secs")?;
                    timeout = Duration::from_secs(
                        value
                            .parse()
                            .map_err(|_| format!("invalid timeout `{value}`"))?,
                    );
                }
                "--offline" => offline = true,
                "--max-repetitions" => {
                    let value = next_value(&mut args, "--max-repetitions")?;
                    let count = value.parse::<usize>()
                        .map_err(|_| "Invalid repetition count".to_string())?;
                    if count == 0 {
                        return Err("Repetition count must be positive".to_string());
                    }
                    max_repetitions = Some(count);
                }
                other => return Err(format!("unknown bench argument `{other}`")),
            }
        }

        if (merge || pgo_output.is_some()) && !pgo {
            return Err("--merge and --pgo-output require --pgo".to_string());
        }
        if all && (!suites.is_empty() || !tags.is_empty()) {
            return Err("Use --all without --suite or --tag".to_string());
        }
        if correctness && !all && suites.is_empty() && tags.is_empty() {
            tags.push("ci".to_string());
        }
        if pgo {
            if !cpus_explicit {
                cpus = vec![4];
            }
            max_repetitions.get_or_insert(5);
        }

        Ok(Self {
            correctness,
            pgo,
            merge,
            pgo_output,
            release,
            platform,
            launch,
            host,
            cpus,
            suites,
            tags,
            output,
            boot_image,
            export_boot_image,
            boot_timeout,
            timeout,
            offline,
            max_repetitions,
        })
    }
}

fn next_value<I>(args: &mut I, option: &str) -> Result<String, String>
where
    I: Iterator<Item = String>,
{
    args.next()
        .ok_or_else(|| format!("{option} requires a value"))
}

#[derive(Deserialize, Serialize)]
struct BenchReport {
    schema: String,
    protocol_version: u32,
    runs: Vec<TopologyRun>,
}

#[derive(Deserialize, Serialize)]
struct TopologyRun {
    cpus: usize,
    status: String,
    complete: bool,
    events: Vec<ProtocolEvent>,
    serial_log: PathBuf,
    panic: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
struct ProtocolEvent {
    kind: String,
    payload: Value,
}

fn existing_image(root: &Path, platform: &config::BuildPlan, release: bool) -> Result<PathBuf, String> {
    crate::load_artifact_manifest(root, platform, release)
        .map(|artifacts| artifacts.boot_image)
        .map_err(|error| format!("{error}\nBuild a benchmark image explicitly with: cargo xtask build --platform {}{} --kernel-feature kernel-bench", platform.id, if release { " --release" } else { "" }))
}

fn run(root: &Path, options: BenchOptions) -> Result<(), String> {
    let mode = if options.correctness {
        "correctness"
    } else {
        "benchmark"
    };
    let protocol_prefix = if options.correctness {
        "RUSTOS_CORRECTNESS\t"
    } else {
        "RUSTOS_BENCH\t"
    };
    let platform = config::load_platform(root, &options.platform)?;
    if options.merge {
        crate::pgo::check_merge_tool()?;
    }
    let pgo_output = if options.pgo {
        let directory = match &options.pgo_output {
            Some(path) => resolve(root, path),
            None => crate::pgo::default_output(root, &platform, options.release)?,
        };
        if directory.exists() { return Err(format!("Use a new PGO output directory: {}", directory.display())); }
        Some(directory)
    } else { None };
    let launch = config::load_launch(root, &options.launch)?;
    let host = config::load_host(
        root,
        options.host.as_deref().unwrap_or(std::env::consts::OS),
    )?;

    let boot_image = if let Some(path) = &options.boot_image {
        resolve(root, path)
    } else if options.correctness {
        unsafe {
            std::env::set_var("RUSTOS_CORRECTNESS_SUITES", options.suites.join(","));
            std::env::set_var("RUSTOS_CORRECTNESS_TAGS", options.tags.join(","));
        }
        build_platform(root, &platform, options.release, options.offline, &["kernel-correctness".to_string()])?;
        crate::load_artifact_manifest(root, &platform, options.release)?.boot_image
    } else {
        if options.pgo {
            crate::pgo::enable_generation();
        }
        unsafe {
            std::env::set_var("RUSTOS_BENCH_SUITES", options.suites.join(","));
            std::env::set_var("RUSTOS_BENCH_TAGS", options.tags.join(","));
            std::env::set_var("RUSTOS_BENCH_AUTORUN", "1");
        }
        build_platform(root, &platform, options.release, options.offline, &["kernel-bench".to_string()])?;
        existing_image(root, &platform, options.release)?
    };
    let qemu = find_qemu(&launch, &host)?;
    let firmware = find_firmware(&launch, &host, &qemu)?;
    let seed_disk = system_disk(root)?;
    assert_exists(&boot_image, "boot image")?;
    assert_exists(&seed_disk.path, "system disk")?;

    if let Some(export) = &options.export_boot_image {
        let export = resolve(root, export);
        if let Some(parent) = export.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
        }
        fs::copy(&boot_image, &export)
            .map_err(|err| format!("failed to export boot image to {}: {err}", export.display()))?;
    }

    let output = if options.output.is_absolute() {
        options.output.clone()
    } else {
        root.join(&options.output)
    };
    let bench_dir = output
        .parent()
        .ok_or_else(|| format!("benchmark output has no parent: {}", output.display()))?;
    fs::create_dir_all(bench_dir)
        .map_err(|err| format!("failed to create {}: {err}", bench_dir.display()))?;

    let mut runs = Vec::new();
    for cpus in options.cpus {
        let disk_path = bench_dir.join(format!("system-{cpus}cpu.img"));
        if !options.correctness {
            let sibling = qemu.with_file_name(format!("qemu-img{}", std::env::consts::EXE_SUFFIX));
            let image_tool = if sibling.is_file() {
                sibling
            } else {
                crate::find_tool_in_augmented_path("qemu-img")
                    .ok_or_else(|| "Install qemu-img to convert the benchmark disk to raw format".to_string())?
            };
            let status = Command::new(image_tool)
                .args(["convert", "-f", &seed_disk.format, "-O", "raw", "-S", "4k"])
                .arg(&seed_disk.path).arg(&disk_path)
                .status().map_err(|error| format!("Cannot convert the benchmark disk: {error}"))?;
            if !status.success() {
                let _ = fs::remove_file(&disk_path);
                return Err(format!("Benchmark disk conversion failed: {status}"));
            }
        } else {
            fs::copy(&seed_disk.path, &disk_path).map_err(|err| {
                format!(
                    "failed to clone benchmark disk {} to {}: {err}",
                    seed_disk.path.display(),
                    disk_path.display()
                )
            })?;
        }
        let disk = SystemDisk {
            path: disk_path,
            format: if options.correctness { seed_disk.format.clone() } else { "raw".to_string() },
        };
        let mut repetition = 1;
        let mut suite_boots = Vec::<(String, usize)>::new();
        loop {
            if repetition > 1 && !options.pgo && !suite_boots.iter().any(|(_, boots)| *boots >= repetition) {
                break;
            }
            print_status!("==> {mode} with {cpus} vCPU(s), repetition {repetition}");
            let serial_log =
                bench_dir.join(format!("{cpus}cpu-repetition-{repetition}.serial.log"));
            let topology = run_topology(
                root,
                &platform,
                &launch,
                &qemu,
                &firmware,
                &boot_image,
                &disk,
                cpus,
                repetition,
                &options.suites,
                &options.tags,
                options.pgo,
                options.boot_timeout,
                options.timeout,
                serial_log,
                protocol_prefix,
            );
            let topology = match topology {
                Ok(topology) => topology,
                Err(error) => {
                    return Err(format!("{error}\nBenchmark disk kept at {}", disk.path.display()));
                }
            };
            if repetition == 1 && !options.correctness {
                suite_boots = match suite_boot_plan(&topology) {
                    Ok(plan) => plan,
                    Err(error) => {
                        let _ = fs::remove_file(&disk.path);
                        return Err(error);
                    }
                };
            }
            runs.push(topology);
            if options.max_repetitions.is_some_and(|limit| repetition >= limit) {
                break;
            }
            repetition += 1;
        }
        if let Err(err) = fs::remove_file(&disk.path) {
            eprintln!(
                "warning: failed to remove temporary benchmark disk {}: {err}",
                disk.path.display()
            );
        }
    }

    let report = BenchReport {
        schema: if options.correctness {
            "rustos.correctness-run.v1"
        } else {
            "rustos.bench-run.v1"
        }
        .to_string(),
        protocol_version: 1,
        runs,
    };
    let encoded = serde_json::to_vec_pretty(&report)
        .map_err(|err| format!("failed to encode benchmark report: {err}"))?;
    fs::write(&output, encoded)
        .map_err(|err| format!("failed to write {}: {err}", output.display()))?;

    if report
        .runs
        .iter()
        .all(|run| run.complete && run.status == "passed")
    {
        if let Some(directory) = &pgo_output {
            crate::pgo::collect(&serde_json::to_value(&report).map_err(|error| error.to_string())?, bench_dir, directory, &platform, options.release, options.merge)?;
        }
        print_status!("{mode} results: {}", output.display());
        Ok(())
    } else {
        let failures = report.runs.iter()
            .filter(|run| !run.complete || run.status != "passed")
            .map(|run| {
                let reason = run.events.iter()
                    .find(|event| event.kind == "case_failure")
                    .map(|event| format!("{} / {}: {}",
                        event.payload["suite"].as_str().unwrap_or("unknown suite"),
                        event.payload["case"].as_str().unwrap_or("unknown case"),
                        event.payload["reason"].as_str().unwrap_or("case failed")))
                    .unwrap_or_else(|| run.status.clone());
                format!("{} vCPU(s): {reason}; serial log: {}", run.cpus, run.serial_log.display())
            }).collect::<Vec<_>>().join("\n");
        Err(format!(
            "one or more {mode} CPU configurations failed:\n{failures}\npartial results: {}",
            output.display()
        ))
    }
}

#[allow(clippy::too_many_arguments)]
fn run_topology(
    root: &Path,
    platform: &config::BuildPlan,
    launch: &config::LaunchPlan,
    qemu: &Path,
    firmware: &Path,
    boot_image: &Path,
    disk: &SystemDisk,
    cpus: usize,
    repetition: usize,
    suite_names: &[String],
    tags: &[String],
    pgo: bool,
    boot_timeout: Duration,
    timeout: Duration,
    serial_log: PathBuf,
    protocol_prefix: &str,
) -> Result<TopologyRun, String> {
    let qemu_options = QemuOptions {
        release: true,
        debug: false,
        detach: false,
        dry_run: false,
        console_serial: false,
        gdb_port: crate::DEFAULT_GDB_PORT,
        lldb_meta: false,
        platform: Some(platform.id.clone()),
        launch: Some(launch.id.clone()),
        host: None,
    };
    // FIXME: Audit that the environment access only happens in single-threaded code.
    unsafe { std::env::set_var("RUSTOS_QEMU_SMP", cpus.to_string()) };
    // FIXME: Audit that the environment access only happens in single-threaded code.
    unsafe { std::env::set_var("RUSTOS_QEMU_SERIAL", "stdio") };
    let mut args = qemu_args(root, launch, firmware, boot_image, disk, &qemu_options)?;
    let output_id = format!("run-{:x}-{}-{cpus}-{repetition}",
        SystemTime::now().duration_since(UNIX_EPOCH).map_err(|error| error.to_string())?.as_nanos(),
        std::process::id());
    if protocol_prefix == "RUSTOS_BENCH\t" {
        args.push("-fw_cfg".into());
        args.push(format!("name=opt/rustos/bench-output,string={output_id}").into());
        args.push("-fw_cfg".into());
        args.push(format!("name=opt/rustos/bench-repetition,string={repetition}").into());
        if pgo {
            args.push("-fw_cfg".into());
            args.push("name=opt/rustos/bench-pgo,string=1".into());
        }
        if !suite_names.is_empty() || !tags.is_empty() {
            for (key, values) in [("bench-suites", suite_names), ("bench-tags", tags)] {
                args.push("-fw_cfg".into());
                // QEMU rejects string= with no value. A separator encodes an
                // empty selection while still overriding the image defaults.
                let selection = if values.is_empty() { ";".to_string() } else { values.join(";") };
                args.push(format!("name=opt/rustos/{key},string={selection}").into());
            }
        }
    }

    // Write each serial line as it arrives rather than waiting for QEMU to exit.
    let mut serial_output = fs::File::create(&serial_log)
        .map_err(|err| format!("failed to create {}: {err}", serial_log.display()))?;
    let mut child = Command::new(qemu)
        .args(args)
        .current_dir(root)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|err| format!("failed to launch {}: {err}", qemu.display()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "failed to capture QEMU serial output".to_string())?;
    let (sender, receiver) = mpsc::channel();
    let reader_thread = thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let line = line.and_then(|line| {
                writeln!(serial_output, "{line}")?;
                Ok(line)
            });
            let failed = line.is_err();
            if sender.send(line).is_err() || failed {
                break;
            }
        }
    });

    let started = Instant::now();
    let mut events = Vec::new();
    let mut serial = String::new();
    let mut complete = false;
    let mut status = "incomplete".to_string();
    let mut panic_lines = Vec::new();
    let mut panic_seen_at = None;
    let mut benchmark_started = false;
    let mut selection_error = None;

    loop {
        while let Ok(line) = receiver.try_recv() {
            let line = line.map_err(|err| format!("failed reading QEMU serial output: {err}"))?;
            // Profile payloads are transport data. Keep them in the serial log
            // and event stream, but only mirror progress records to the terminal.
            let profile_chunk = line
                .strip_prefix(protocol_prefix)
                .and_then(|record| record.split_once('\t'))
                .is_some_and(|(_, record)| record.starts_with("pgo_chunk\t"));
            if !profile_chunk {
                print_status!("{line}");
            }
            benchmark_started |= record_serial_line(
                &line,
                protocol_prefix,
                &mut serial,
                &mut events,
                &mut complete,
                &mut status,
                &mut panic_lines,
                &mut panic_seen_at,
            )?;
        }

        if protocol_prefix == "RUSTOS_BENCH\t" && (!suite_names.is_empty() || !tags.is_empty()) && benchmark_started {
            if let Some(start) = events.iter().find(|event| event.kind == "run_start") {
                if start.payload.get("requested_suites") != Some(&serde_json::json!(suite_names))
                    || start.payload.get("requested_tags") != Some(&serde_json::json!(tags))
                {
                    selection_error = Some("The image does not acknowledge the requested benchmark filter; rebuild it with runtime selection support".to_string());
                    let _ = child.kill();
                    break;
                }
            }
        }

        if pgo && benchmark_started {
            if let Some(start) = events.iter().find(|event| event.kind == "run_start") {
                if start.payload.get("pgo") != Some(&Value::Bool(true)) {
                    selection_error = Some("bench --pgo requires an instrumented image with runtime PGO support; use build --pgo --kernel-feature kernel-bench first".to_string());
                    let _ = child.kill();
                    break;
                }
            }
        }

        if panic_seen_at.is_some_and(|seen| seen.elapsed() >= Duration::from_secs(1)) {
            if let Err(err) = child.kill() {
                eprintln!("warning: failed to stop QEMU after kernel panic: {err}");
            }
            status = "panicked".to_string();
            break;
        }
        if !benchmark_started && started.elapsed() >= boot_timeout {
            let _ = child.kill();
            status = "boot_timeout".to_string();
            break;
        }

        if child
            .try_wait()
            .map_err(|err| format!("failed waiting for QEMU: {err}"))?
            .is_some()
        {
            break;
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            status = "timeout".to_string();
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    let _ = child.wait();
    reader_thread
        .join()
        .map_err(|_| "QEMU serial reader thread panicked".to_string())?;
    while let Ok(line) = receiver.try_recv() {
        let line = line.map_err(|err| format!("failed reading QEMU serial output: {err}"))?;
        let _ = record_serial_line(
            &line,
            protocol_prefix,
            &mut serial,
            &mut events,
            &mut complete,
            &mut status,
            &mut panic_lines,
            &mut panic_seen_at,
        )?;
    }

    if let Some(error) = selection_error { return Err(error); }

    let disk_output = events.iter().any(|event| event.kind == "run_start"
        && event.payload["output_transport"] == "disk");
    if disk_output && panic_lines.is_empty() && !matches!(status.as_str(), "timeout" | "boot_timeout") {
        if let Some(error) = events.iter().find(|event| event.kind == "output_error") {
            return Err(format!("The kernel could not save benchmark output: {}", error.payload["reason"]));
        }
        let imported = read_disk_output(&disk.path, &serial_log, &output_id, cpus, repetition)?;
        let end = imported.last().ok_or_else(|| "The disk report has no events".to_string())?;
        let disk_status = end.payload["status"].as_str().unwrap_or("failed").to_string();
        if complete && status != disk_status {
            return Err("The serial status does not match the disk report".to_string());
        }
        events = imported;
        complete = true;
        status = disk_status;
    }

    let panic = (!panic_lines.is_empty()).then(|| panic_lines.join("\n"));
    if let Some(details) = &panic {
        report_panic(cpus, details);
        status = "panicked".to_string();
    } else if status == "timeout" {
        annotate_error(
            &format!("Kernel run timed out ({cpus} vCPUs)"),
            &format!("QEMU did not finish within {} seconds", timeout.as_secs()),
        );
    } else if status == "boot_timeout" {
        annotate_error(
            &format!("Kernel boot timed out ({cpus} vCPUs)"),
            &format!(
                "The kernel did not emit run_start within {} seconds",
                boot_timeout.as_secs()
            ),
        );
    } else if complete && status != "passed" {
        annotate_error(
            &format!("Kernel run failed ({cpus} vCPUs)"),
            &format!("The kernel runner reported status `{status}`"),
        );
    } else if !complete {
        annotate_error(
            &format!("Incomplete kernel run ({cpus} vCPUs)"),
            "QEMU exited without emitting a run_end event",
        );
    }

    if pgo && !events.iter().any(|event| matches!(event.kind.as_str(), "pgo_end" | "pgo_file") && event.payload["component"] == "kernel") {
        return Err("The benchmark did not finish collecting the kernel PGO profile".to_string());
    }

    Ok(TopologyRun {
        cpus,
        status,
        complete,
        events,
        serial_log,
        panic,
    })
}

fn read_disk_output(
    disk_path: &Path,
    serial_log: &Path,
    output_id: &str,
    cpus: usize,
    repetition: usize,
) -> Result<Vec<ProtocolEvent>, String> {
    let disk_size = fs::metadata(disk_path)
        .map_err(|error| format!("Cannot read {}: {error}", disk_path.display()))?.len();
    let mut partitions = Vec::new();
    for block_size in [gpt::disk::LogicalBlockSize::Lb512, gpt::disk::LogicalBlockSize::Lb4096] {
        if let Ok(disk) = gpt::GptConfig::new().writable(false).logical_block_size(block_size).open(disk_path) {
            let sector_size = u64::from(block_size);
            for partition in disk.partitions().values() {
                let start = partition.first_lba.checked_mul(sector_size);
                let end = partition.last_lba.checked_add(1).and_then(|lba| lba.checked_mul(sector_size));
                if let (Some(start), Some(end)) = (start, end) {
                    if start < end && end <= disk_size {
                        partitions.push((start, end));
                    }
                }
            }
            break;
        }
    }
    if partitions.is_empty() {
        let mut disk = fs::File::open(disk_path).map_err(|error| error.to_string())?;
        let mut mbr = [0; 512];
        disk.read_exact(&mut mbr).map_err(|error| format!("Cannot read the disk header: {error}"))?;
        if mbr[510..] == [0x55, 0xaa] {
            for entry in mbr[446..510].chunks_exact(16) {
                if !matches!(entry[4], 0x01 | 0x04 | 0x06 | 0x0b | 0x0c | 0x0e) {
                    continue;
                }
                let start = u64::from(u32::from_le_bytes(entry[8..12].try_into().unwrap())) * 512;
                let length = u64::from(u32::from_le_bytes(entry[12..16].try_into().unwrap())) * 512;
                if length > 0 && start + length <= disk_size {
                    partitions.push((start, start + length));
                }
            }
        }
        if partitions.is_empty() {
            partitions.push((0, disk_size));
        }
    }

    let report_path = format!("bench/{output_id}/results.json");
    let output_directory = serial_log.parent().ok_or_else(|| "The serial log has no parent directory".to_string())?;
    let files_directory = format!("{cpus}cpu-repetition-{repetition}.files");
    let destination = output_directory.join(&files_directory);
    for (start, end) in partitions {
        let disk = fs::File::open(disk_path).map_err(|error| error.to_string())?;
        let partition = fscommon::StreamSlice::new(disk, start, end).map_err(|error| error.to_string())?;
        let filesystem = match fatfs::FileSystem::new(partition, fatfs::FsOptions::new().update_accessed_date(false)) {
            Ok(filesystem) => filesystem,
            Err(_) => continue,
        };
        let root = filesystem.root_dir();
        let report_file = match root.open_file(&report_path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(format!("Cannot open {report_path}: {error}")),
        };
        let mut encoded = Vec::new();
        report_file.take(16 * 1024 * 1024 + 1).read_to_end(&mut encoded)
            .map_err(|error| format!("Cannot read {report_path}: {error}"))?;
        if encoded.len() > 16 * 1024 * 1024 {
            return Err("The disk report exceeds 16 MiB".to_string());
        }
        let report: Value = serde_json::from_slice(&encoded)
            .map_err(|error| format!("Invalid disk report: {error}"))?;
        if report["schema"] != "rustos.bench-disk.v1" || report["output_id"] != output_id {
            return Err("The disk report does not match this boot".to_string());
        }
        let mut events: Vec<ProtocolEvent> = serde_json::from_value(report["events"].clone())
            .map_err(|error| format!("Invalid disk report events: {error}"))?;
        let first = events.first().ok_or_else(|| "The disk report has no events".to_string())?;
        if first.kind != "run_start" || first.payload["output_id"] != output_id
            || first.payload["output_transport"] != "disk"
            || first.payload["cpu_count"].as_u64() != Some(cpus as u64)
            || first.payload["repetition"].as_u64() != Some(repetition as u64)
        {
            return Err("The disk report has incorrect boot metadata".to_string());
        }
        let last = events.last().ok_or_else(|| "The disk report has no completion event".to_string())?;
        if last.kind != "run_end" || !matches!(last.payload["status"].as_str(), Some("passed" | "failed"))
            || events.iter().filter(|event| event.kind == "run_start").count() != 1
            || events.iter().filter(|event| event.kind == "run_end").count() != 1
        {
            return Err("The disk report is incomplete".to_string());
        }
        fs::create_dir_all(&destination).map_err(|error| error.to_string())?;
        fs::write(destination.join("results.json"), &encoded).map_err(|error| error.to_string())?;
        let mut components = BTreeSet::new();
        let mut total_bytes = 0u64;
        for event in &mut events {
            if event.kind != "pgo_file" {
                continue;
            }
            let component = event.payload["component"].as_str()
                .ok_or_else(|| "The profile has no component name".to_string())?;
            if component.is_empty() || component.len() > 128
                || !component.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
                || !components.insert(component.to_string())
            {
                return Err("Invalid or duplicate profile component".to_string());
            }
            let file_name = format!("{component}.profraw");
            if event.payload["file"] != file_name {
                return Err(format!("Invalid profile filename for {component}"));
            }
            let expected = event.payload["bytes"].as_u64()
                .filter(|bytes| *bytes > 0 && *bytes <= 128 * 1024 * 1024)
                .ok_or_else(|| format!("Invalid profile size for {component}"))?;
            total_bytes += expected;
            if total_bytes > 512 * 1024 * 1024 {
                return Err("The boot profiles exceed 512 MiB".to_string());
            }
            let path = format!("bench/{output_id}/{file_name}");
            let profile = root.open_file(&path)
                .map_err(|error| format!("Cannot open {path}: {error}"))?;
            let mut bytes = Vec::new();
            profile.take(expected + 1).read_to_end(&mut bytes)
                .map_err(|error| format!("Cannot read {path}: {error}"))?;
            if bytes.len() as u64 != expected {
                return Err(format!("Incomplete profile for {component}"));
            }
            fs::write(destination.join(&file_name), &bytes)
                .map_err(|error| format!("Cannot save {file_name}: {error}"))?;
            event.payload["file"] = serde_json::json!(format!("{files_directory}/{file_name}"));
        }
        print_status!("Disk output: {}", destination.display());
        return Ok(events);
    }
    Err(format!("Cannot find {report_path} in {}", disk_path.display()))
}

fn suite_boot_plan(run: &TopologyRun) -> Result<Vec<(String, usize)>, String> {
    let Some(event) = run.events.iter().find(|event| event.kind == "run_start") else {
        return Err("benchmark run did not emit run_start metadata".to_string());
    };
    let Some(suites) = event.payload.get("suites").and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    suites
        .iter()
        .map(|suite| {
            let name = suite
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| "suite catalog entry missing `name`".to_string())?;
            let boots = suite
                .get("independent_boots")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    format!("suite catalog entry `{name}` missing `independent_boots`")
                })?;
            Ok((
                name.to_string(),
                usize::try_from(boots).unwrap_or(usize::MAX).max(1),
            ))
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn record_serial_line(
    line: &str,
    protocol_prefix: &str,
    serial: &mut String,
    events: &mut Vec<ProtocolEvent>,
    complete: &mut bool,
    status: &mut String,
    panic_lines: &mut Vec<String>,
    panic_seen_at: &mut Option<Instant>,
) -> Result<bool, String> {
    serial.push_str(line);
    serial.push('\n');

    if is_panic_start(line) {
        panic_seen_at.get_or_insert_with(Instant::now);
    }
    if panic_seen_at.is_some() {
        panic_lines.push(line.to_string());
    }

    let mut run_started = false;
    if let Some(event) = parse_event(line, protocol_prefix)? {
        run_started = event.kind == "run_start";
        if event.kind == "run_end" {
            *complete = true;
            *status = event
                .payload
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("failed")
                .to_string();
        }
        events.push(event);
    }
    Ok(run_started)
}

fn is_panic_start(line: &str) -> bool {
    line.contains("=== KERNEL PANIC [")
        || line.contains("kernel_stub panic:")
        || line.contains("panicked at ")
}

fn report_panic(cpus: usize, details: &str) {
    eprintln!();
    eprintln!("===== KERNEL PANIC ({cpus} vCPU(s)) =====");
    eprintln!("{details}");
    eprintln!("===== END KERNEL PANIC =====");

    let annotation = details.lines().take(8).collect::<Vec<_>>().join(" | ");
    annotate_error(&format!("Kernel panic ({cpus} vCPUs)"), &annotation);

    let Some(summary_path) = std::env::var_os("GITHUB_STEP_SUMMARY") else {
        return;
    };
    match fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&summary_path)
    {
        Ok(mut summary) => {
            let _ = writeln!(
                summary,
                "## Kernel panic ({cpus} vCPU(s))\n\n```text\n{details}\n```\n"
            );
        }
        Err(err) => eprintln!(
            "warning: failed to open GitHub step summary {}: {err}",
            Path::new(&summary_path).display()
        ),
    }
}

fn annotate_error(title: &str, message: &str) {
    if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true") {
        return;
    }
    if !reserve_action_annotation() {
        return;
    }

    let escape = |value: &str| {
        value
            .replace('%', "%25")
            .replace('\r', "%0D")
            .replace('\n', "%0A")
    };
    eprintln!("::error title={}::{}", escape(title), escape(message));
}

fn reserve_action_annotation() -> bool {
    let counter_path = std::env::var_os("RUNNER_TEMP")
        .map(PathBuf::from)
        .map(|dir| dir.join("rustos-bench-annotation-count"));
    let persisted = counter_path
        .as_deref()
        .and_then(|path| fs::read_to_string(path).ok())
        .and_then(|count| count.trim().parse::<usize>().ok())
        .unwrap_or(0);
    ACTION_ANNOTATIONS.fetch_max(persisted, Ordering::Relaxed);

    let Ok(previous) =
        ACTION_ANNOTATIONS.try_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
            (count < MAX_ACTION_ANNOTATIONS).then_some(count + 1)
        })
    else {
        return false;
    };

    if let Some(path) = counter_path {
        if let Err(err) = fs::write(&path, (previous + 1).to_string()) {
            eprintln!(
                "warning: failed to persist annotation count {}: {err}",
                path.display()
            );
        }
    }
    true
}

fn parse_event(line: &str, protocol_prefix: &str) -> Result<Option<ProtocolEvent>, String> {
    let Some(rest) = line.strip_prefix(protocol_prefix) else {
        return Ok(None);
    };
    let mut fields = rest.splitn(3, '\t');
    let version = fields
        .next()
        .ok_or_else(|| "benchmark event missing protocol version".to_string())?
        .parse::<u32>()
        .map_err(|_| "benchmark event has invalid protocol version".to_string())?;
    if version != 1 {
        return Err(format!("unsupported benchmark protocol version {version}"));
    }
    let kind = fields
        .next()
        .filter(|kind| !kind.is_empty())
        .ok_or_else(|| "benchmark event missing kind".to_string())?
        .to_string();
    let payload = serde_json::from_str(
        fields
            .next()
            .ok_or_else(|| "benchmark event missing JSON payload".to_string())?,
    )
    .map_err(|err| format!("invalid benchmark event JSON: {err}"))?;
    Ok(Some(ProtocolEvent { kind, payload }))
}

pub struct CompareOptions {
    base: PathBuf,
    head: PathBuf,
    output: PathBuf,
    title: String,
    annotations: bool,
}

impl CompareOptions {
    fn parse<I>(args: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = String>,
    {
        let mut base = None;
        let mut head = None;
        let mut output = PathBuf::from("target/bench/comparison.md");
        let mut title = "Kernel benchmark comparison".to_string();
        let mut annotations = true;
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--base" => base = Some(PathBuf::from(next_value(&mut args, "--base")?)),
                "--head" => head = Some(PathBuf::from(next_value(&mut args, "--head")?)),
                "--output" => output = PathBuf::from(next_value(&mut args, "--output")?),
                "--title" => title = next_value(&mut args, "--title")?,
                "--no-annotations" => annotations = false,
                other => return Err(format!("unknown bench compare argument `{other}`")),
            }
        }
        Ok(Self {
            base: base.ok_or_else(|| "bench compare requires --base".to_string())?,
            head: head.ok_or_else(|| "bench compare requires --head".to_string())?,
            output,
            title,
            annotations,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct MetricKey {
    cpus: usize,
    suite: String,
    case: String,
    metric: String,
}

#[derive(Default)]
struct MetricSamples {
    values: Vec<f64>,
    boot_medians: Vec<f64>,
    unit: u64,
    direction: u64,
    tolerance_percent: Option<f64>,
}

fn compare(root: &Path, options: CompareOptions) -> Result<(), String> {
    let base_path = resolve(root, &options.base);
    let head_path = resolve(root, &options.head);
    let output_path = resolve(root, &options.output);
    let base: BenchReport = serde_json::from_slice(
        &fs::read(&base_path)
            .map_err(|err| format!("failed to read {}: {err}", base_path.display()))?,
    )
    .map_err(|err| format!("failed to parse {}: {err}", base_path.display()))?;
    let head: BenchReport = serde_json::from_slice(
        &fs::read(&head_path)
            .map_err(|err| format!("failed to read {}: {err}", head_path.display()))?,
    )
    .map_err(|err| format!("failed to parse {}: {err}", head_path.display()))?;
    if base.schema != "rustos.bench-run.v1" || head.schema != "rustos.bench-run.v1" {
        return Err("bench compare only supports rustos.bench-run.v1".to_string());
    }

    let base_metrics = collect_metrics(&base)?;
    let head_metrics = collect_metrics(&head)?;
    let mut markdown = format!(
        "## {}\n\n\
         Tolerance is the largest literal percentage slowdown considered practically unchanged. \
         A regression requires the entire 99% confidence interval to exceed that tolerance; an uncertain result names the direction of the measured change when the interval cannot confirm it. \
         Repeated suites independently resample baseline and current boot medians with 100,000 bootstrap draws; \
         single-pair suites apply their tolerance directly. MAD reports boot-to-boot variability. \
         Positive and negative changes are interpreted according to whether higher or lower values are better.\n\n\
         | CPUs | Suite | Case | Metric | Baseline median | Current median | Change | 99% CI | Boot MAD (baseline → current) | Tolerance | Result |\n\
         |---:|---|---|---|---:|---:|---:|---:|---:|---:|---|\n",
        options.title
    );

    let mut regressions = Vec::new();
    let mut keys = base_metrics
        .keys()
        .chain(head_metrics.keys())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    keys.sort_by(compare_metric_keys);
    for key in keys {
        let base_samples = base_metrics.get(&key);
        let head_samples = head_metrics.get(&key);
        let (Some(base_samples), Some(head_samples)) = (base_samples, head_samples) else {
            let samples = head_samples
                .or(base_samples)
                .expect("metric key has samples");
            let median = median(&samples.values);
            let (previous, current, result) = if head_samples.is_some() {
                ("—".to_string(), format!("{median:.3}"), "new metric")
            } else {
                (
                    format!("{median:.3}"),
                    "—".to_string(),
                    "missing from current run",
                )
            };
            let tolerance = samples
                .tolerance_percent
                .map(|value| format!("{value:.2}%"))
                .unwrap_or_else(|| "—".to_string());
            markdown.push_str(&format!(
                "| {} | `{}` | `{}` | `{}` | {} | {} | — | — | — | {} | {} |\n",
                key.cpus, key.suite, key.case, key.metric, previous, current, tolerance, result,
            ));
            continue;
        };
        let base_median = median(&base_samples.boot_medians);
        let head_median = median(&head_samples.boot_medians);
        let relative = relative_change(base_median, head_median).unwrap_or(0.0);
        let tolerance = head_samples.tolerance_percent;
        let regression = match head_samples.direction {
            1 => relative,
            2 => -relative,
            _ => 0.0,
        };
        let confidence = bootstrap_change_interval(base_samples, head_samples);
        let confidence_text = if let Some(confidence) = confidence {
            format!("{:+.2}% to {:+.2}%", confidence.lower, confidence.upper)
        } else if base_samples.boot_medians.len() == 1 && head_samples.boot_medians.len() == 1 {
            "single boot per image".to_string()
        } else {
            "—".to_string()
        };
        let mad_text = format!(
            "{:.2}% → {:.2}%",
            relative_mad(&base_samples.boot_medians),
            relative_mad(&head_samples.boot_medians)
        );
        let regression_confidence_lower = confidence.map(|interval| match head_samples.direction {
            1 => interval.lower,
            2 => -interval.upper,
            _ => 0.0,
        });
        let regression_confidence_upper = confidence.map(|interval| match head_samples.direction {
            1 => interval.upper,
            2 => -interval.lower,
            _ => 0.0,
        });
        let direct_single_boot =
            base_samples.boot_medians.len() == 1 && head_samples.boot_medians.len() == 1;
        let result = match tolerance {
            Some(limit)
                if (direct_single_boot && regression > limit)
                    || regression_confidence_lower.is_some_and(|lower| lower > limit) =>
            {
                regressions.push((key.clone(), regression, limit));
                "🔴 regression"
            }
            Some(limit)
                if (direct_single_boot && regression > limit)
                    || regression_confidence_upper.is_some_and(|upper| upper > limit) =>
            {
                if regression >= 0.0 {
                    "🟡 uncertain regression"
                } else {
                    "🔵 uncertain improvement (regression possible)"
                }
            }
            Some(limit)
                if (direct_single_boot && regression < -limit)
                    || regression_confidence_upper.is_some_and(|upper| upper < -limit) =>
            {
                "🟢 improvement"
            }
            Some(limit)
                if confidence.is_some()
                    && regression_confidence_lower.is_some_and(|lower| lower >= -limit)
                    && regression_confidence_upper.is_some_and(|upper| upper <= limit) =>
            {
                "statistically stable"
            }
            Some(_) if confidence.is_none() && !direct_single_boot => "insufficient boots",
            Some(_) if regression > 0.0 => "🟡 uncertain regression",
            Some(_) if regression < 0.0 => "🔵 uncertain improvement",
            Some(_) => "uncertain change",
            None => "informational",
        };
        let tolerance = tolerance
            .map(|value| format!("{value:.2}%"))
            .unwrap_or_else(|| "—".to_string());
        markdown.push_str(&format!(
            "| {} | `{}` | `{}` | `{}` | {:.3} | {:.3} | {:+.2}% | {} | {} | {} | {} |\n",
            key.cpus,
            key.suite,
            key.case,
            key.metric,
            base_median,
            head_median,
            relative,
            confidence_text,
            mad_text,
            tolerance,
            result,
        ));
    }

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    }
    fs::write(&output_path, markdown)
        .map_err(|err| format!("failed to write {}: {err}", output_path.display()))?;
    print_status!("benchmark comparison: {}", output_path.display());
    if options.annotations {
        for (key, regression, tolerance) in &regressions {
            annotate_error(
                "Performance regression",
                &format!(
                    "{} vCPUs {}/{}/{} regressed by {:.2}% (tolerance {:.2}%)",
                    key.cpus, key.suite, key.case, key.metric, regression, tolerance
                ),
            );
        }
    }
    if regressions.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} benchmark metric(s) exceeded their tolerance",
            regressions.len()
        ))
    }
}

fn compare_metric_keys(left: &MetricKey, right: &MetricKey) -> CmpOrdering {
    left.cpus
        .cmp(&right.cpus)
        .then_with(|| left.suite.cmp(&right.suite))
        .then_with(|| left.case.cmp(&right.case))
        .then_with(|| natural_cmp(&left.metric, &right.metric))
}

fn natural_cmp(left: &str, right: &str) -> CmpOrdering {
    let mut left = left.as_bytes();
    let mut right = right.as_bytes();
    while !left.is_empty() && !right.is_empty() {
        let left_digits = left[0].is_ascii_digit();
        let right_digits = right[0].is_ascii_digit();
        if left_digits && right_digits {
            let left_len = left.iter().take_while(|byte| byte.is_ascii_digit()).count();
            let right_len = right
                .iter()
                .take_while(|byte| byte.is_ascii_digit())
                .count();
            let left_number = left[..left_len].iter().fold(0u64, |value, byte| {
                value.saturating_mul(10) + u64::from(byte - b'0')
            });
            let right_number = right[..right_len].iter().fold(0u64, |value, byte| {
                value.saturating_mul(10) + u64::from(byte - b'0')
            });
            match left_number.cmp(&right_number) {
                CmpOrdering::Equal => {
                    left = &left[left_len..];
                    right = &right[right_len..];
                }
                ordering => return ordering,
            }
        } else {
            match left[0].cmp(&right[0]) {
                CmpOrdering::Equal => {
                    left = &left[1..];
                    right = &right[1..];
                }
                ordering => return ordering,
            }
        }
    }
    left.len().cmp(&right.len())
}

fn resolve(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

fn collect_metrics(report: &BenchReport) -> Result<BTreeMap<MetricKey, MetricSamples>, String> {
    let mut metrics = BTreeMap::new();
    for run in &report.runs {
        let mut boot_values = BTreeMap::<MetricKey, Vec<f64>>::new();
        for event in &run.events {
            if event.kind != "measurement" {
                continue;
            }
            if event.payload.get("suite").and_then(Value::as_str) == Some("executor.runtime")
                && event.payload.get("case").and_then(Value::as_str) == Some("correctness")
            {
                continue;
            }
            let text = |name: &str| {
                event
                    .payload
                    .get(name)
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .ok_or_else(|| format!("measurement missing string field `{name}`"))
            };
            let key = MetricKey {
                cpus: run.cpus,
                suite: text("suite")?,
                case: text("case")?,
                metric: text("metric")?,
            };
            let value = event
                .payload
                .get("value")
                .and_then(Value::as_f64)
                .ok_or_else(|| "measurement missing numeric `value`".to_string())?;
            let unit = event
                .payload
                .get("unit")
                .and_then(Value::as_u64)
                .ok_or_else(|| "measurement missing numeric `unit`".to_string())?;
            let direction = event
                .payload
                .get("direction")
                .and_then(Value::as_u64)
                .ok_or_else(|| "measurement missing numeric `direction`".to_string())?;
            // Keep accepting the legacy field so an old boot image can serve as the transition
            // baseline. New kernels emit only `tolerance_percent`.
            let tolerance_percent = event
                .payload
                .get("tolerance_percent")
                .or_else(|| event.payload.get("regression_threshold_percent"))
                .and_then(Value::as_f64);
            let samples = metrics
                .entry(key.clone())
                .or_insert_with(MetricSamples::default);
            if !samples.values.is_empty()
                && (samples.unit != unit
                    || samples.direction != direction
                    || samples.tolerance_percent != tolerance_percent)
            {
                return Err("measurement metadata changed within a metric".to_string());
            }
            samples.unit = unit;
            samples.direction = direction;
            samples.tolerance_percent = tolerance_percent;
            samples.values.push(value);
            boot_values.entry(key).or_default().push(value);
        }
        for (key, values) in boot_values {
            if let Some(samples) = metrics.get_mut(&key) {
                samples.boot_medians.push(median(&values));
            }
        }
    }
    Ok(metrics)
}

#[derive(Clone, Copy)]
struct ChangeInterval {
    lower: f64,
    upper: f64,
}

fn bootstrap_change_interval(base: &MetricSamples, head: &MetricSamples) -> Option<ChangeInterval> {
    // Independent boots add evidence; resamples only make the estimated interval less granular.
    // Ten boots per image is the recommended minimum for a 99% interval.
    const MIN_BOOT_SAMPLES: usize = 10;
    // More resamples stabilize the reported tail endpoints but cost comparator CPU time.
    // 50,000–200,000 is a useful range at 99%; 100,000 is a balanced default.
    const RESAMPLES: usize = 100_000;
    if base.boot_medians.len() < MIN_BOOT_SAMPLES || head.boot_medians.len() < MIN_BOOT_SAMPLES {
        return None;
    }

    let mut random = XorShift64::new(0x6a09_e667_f3bc_c909);
    let mut base_resample = Vec::with_capacity(base.boot_medians.len());
    let mut head_resample = Vec::with_capacity(head.boot_medians.len());
    let mut changes = Vec::with_capacity(RESAMPLES);
    for _ in 0..RESAMPLES {
        base_resample.clear();
        head_resample.clear();
        for _ in 0..base.boot_medians.len() {
            base_resample.push(base.boot_medians[random.index(base.boot_medians.len())]);
        }
        for _ in 0..head.boot_medians.len() {
            head_resample.push(head.boot_medians[random.index(head.boot_medians.len())]);
        }
        changes.push(relative_change(
            median(&base_resample),
            median(&head_resample),
        )?);
    }
    changes.sort_by(f64::total_cmp);
    // Raising the confidence level widens this interval: false regression alarms
    // become less likely, while more borderline changes become variance warnings.
    // 99% is a useful default for a noisy CI host when each image has 10+ boots.
    Some(ChangeInterval {
        lower: percentile(&changes, 0.005),
        upper: percentile(&changes, 0.995),
    })
}

fn relative_change(base: f64, head: f64) -> Option<f64> {
    if !base.is_finite() || !head.is_finite() || base <= 0.0 || head <= 0.0 {
        return None;
    }
    Some((head / base).mul_add(100.0, -100.0))
}

struct XorShift64(u64);

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn index(&mut self, upper: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 as usize % upper
    }
}

fn relative_mad(values: &[f64]) -> f64 {
    let center = median(values);
    if center == 0.0 {
        return 0.0;
    }
    let deviations = values
        .iter()
        .map(|value| (value - center).abs())
        .collect::<Vec<_>>();
    median(&deviations) * 100.0 / center.abs()
}

fn percentile(sorted_values: &[f64], percentile: f64) -> f64 {
    if sorted_values.is_empty() {
        return 0.0;
    }
    let index = ((sorted_values.len() - 1) as f64 * percentile).round() as usize;
    sorted_values[index]
}

fn median(values: &[f64]) -> f64 {
    let mut values = values.to_vec();
    values.sort_by(f64::total_cmp);
    match values.len() {
        0 => 0.0,
        len if len % 2 == 1 => values[len / 2],
        len => (values[len / 2 - 1] + values[len / 2]) / 2.0,
    }
}

#[cfg(test)]
mod image_tests {
    use super::*;

    #[test]
    fn console_write_errors_do_not_abort_benchmarks() {
        struct FailingOutput(std::io::ErrorKind);
        impl Write for FailingOutput {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(self.0))
            }
            fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
        }
        for kind in [std::io::ErrorKind::BrokenPipe, std::io::ErrorKind::WouldBlock] {
            best_effort_output(&mut FailingOutput(kind), format_args!("benchmark sample {}", 4));
        }
        let mut output = Vec::new();
        best_effort_output(&mut output, format_args!("benchmark sample {}", 4));
        assert_eq!(output, b"benchmark sample 4\n");
    }

    #[test]
    fn benchmark_names_are_optional_and_comma_separated() {
        assert!(BenchOptions::parse(Vec::new(), false).unwrap().suites.is_empty());
        let options = BenchOptions::parse([
            "--suite", "heap.mimalloc, io.iobuffer,heap.mimalloc", "--tag", "io,heap", "--tag", "ci"
        ].map(str::to_string), false).unwrap();
        assert_eq!(options.suites, ["heap.mimalloc", "io.iobuffer"]);
        assert_eq!(options.tags, ["io", "heap", "ci"]);
        for value in ["", "heap.mimalloc,", "bad;name"] {
            assert!(BenchOptions::parse(["--suite", value].map(str::to_string), false).is_err());
        }
    }

    #[test]
    fn benchmark_pgo_collection_is_opt_in() {
        assert!(!BenchOptions::parse(Vec::new(), false).unwrap().pgo);
        assert!(BenchOptions::parse(["--pgo".to_string()], false).unwrap().pgo);
    }

    #[test]
    fn pgo_defaults_to_five_training_boots_and_preserves_overrides() {
        let normal = BenchOptions::parse(Vec::new(), false).unwrap();
        assert_eq!(normal.cpus, [1, 2, 4]);
        assert_eq!(normal.max_repetitions, None);
        let pgo = BenchOptions::parse(["--pgo"].map(str::to_string), false).unwrap();
        assert_eq!(pgo.cpus, [4]);
        assert_eq!(pgo.max_repetitions, Some(5));
        for args in [
            vec!["--pgo", "--cpus", "1,4"],
            vec!["--cpus", "1,4", "--pgo"],
        ] {
            let options = BenchOptions::parse(args.into_iter().map(str::to_string), false).unwrap();
            assert_eq!(options.cpus, [1, 4]);
            assert_eq!(options.max_repetitions, Some(5));
        }
        let options = BenchOptions::parse(
            ["--max-repetitions", "2", "--pgo"].map(str::to_string), false
        ).unwrap();
        assert_eq!(options.max_repetitions, Some(2));
    }

    #[test]
    fn benchmark_accepts_build_and_collection_options() {
        let options = BenchOptions::parse([
            "--all", "--offline", "--pgo", "--merge"
        ].map(str::to_string), false).unwrap();
        assert!(options.offline && options.pgo && options.merge);
        assert!(options.boot_image.is_none());
    }

    #[test]
    fn existing_image_uses_platform_and_profile_without_building() {
        let repository = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap();
        let root = std::env::temp_dir().join(format!("rustos-bench-test-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        for platform in ["aarch64-uefi", "x86_64-uefi"] {
            let plan = config::load_platform(repository, platform).unwrap();
            for release in [false, true] {
                // A missing build must fail without creating any build output.
                assert!(existing_image(&root, &plan, release).is_err());
                let directory = root.join("target/rustos").join(platform).join(crate::profile(release));
                assert!(!directory.exists());
                fs::create_dir_all(&directory).unwrap();
                for name in ["kernel.exe", "boot.img", "kernel.def", "kernel.lib", "stub"] {
                    fs::write(directory.join(name), b"existing artifact").unwrap();
                }
                let manifest = serde_json::json!({
                    "schema": 2, "platform": platform, "profile": crate::profile(release),
                    "kernel": {"image": "kernel.exe", "debug": null},
                    "sdk": {"definition_file": "kernel.def", "import_library": "kernel.lib"},
                    "stub": "stub", "boot_image": "boot.img", "boot_packages": [], "debug_search_paths": []
                });
                fs::write(directory.join("artifacts.json"), serde_json::to_vec(&manifest).unwrap()).unwrap();
                assert_eq!(existing_image(&root, &plan, release).unwrap(), directory.join("boot.img"));
            }
        }
        fs::remove_dir_all(root).unwrap();
    }
}
