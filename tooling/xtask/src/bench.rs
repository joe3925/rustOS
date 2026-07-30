use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    cmp::Ordering as CmpOrdering,
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use crate::{
    QemuOptions, SystemDisk, assert_exists, build_platform, config, find_firmware, find_qemu,
    qemu_args, system_disk,
};

const PROTOCOL_PREFIX: &str = "RUSTOS_BENCH\t";
const MAX_ACTION_ANNOTATIONS: usize = 3;
static ACTION_ANNOTATIONS: AtomicUsize = AtomicUsize::new(0);

pub enum BenchCommand {
    Run(BenchOptions),
    Compare(CompareOptions),
}

pub struct BenchOptions {
    platform: String,
    launch: String,
    host: Option<String>,
    cpus: Vec<usize>,
    suites: Vec<String>,
    tags: Vec<String>,
    output: PathBuf,
    repetitions: usize,
    boot_image: Option<PathBuf>,
    export_boot_image: Option<PathBuf>,
    prepare_only: bool,
    boot_timeout: Duration,
    timeout: Duration,
    offline: bool,
}

pub fn parse<I>(args: I) -> Result<BenchCommand, String>
where
    I: IntoIterator<Item = String>,
{
    let mut args = args.into_iter().peekable();
    if args.peek().map(String::as_str) == Some("compare") {
        args.next();
        CompareOptions::parse(args).map(BenchCommand::Compare)
    } else {
        BenchOptions::parse(args).map(BenchCommand::Run)
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
            annotate_error("Benchmark command failed", err);
        }
    }
    result
}

impl BenchOptions {
    fn parse<I>(args: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = String>,
    {
        let mut platform = "x86_64-uefi".to_string();
        let mut launch = "qemu-x86_64-q35-ci".to_string();
        let mut host = None;
        let mut cpus = vec![1, 2, 4];
        let mut suites = Vec::new();
        let mut tags = Vec::new();
        let mut output = PathBuf::from("target/bench/results.json");
        let mut repetitions = 1;
        let mut boot_image = None;
        let mut export_boot_image = None;
        let mut prepare_only = false;
        let mut boot_timeout = Duration::from_secs(2 * 60);
        let mut timeout = Duration::from_secs(15 * 60);
        let mut offline = false;
        let mut args = args.into_iter();

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--platform" => {
                    platform = next_value(&mut args, "--platform")?;
                }
                "--launch" => {
                    launch = next_value(&mut args, "--launch")?;
                }
                "--host" => host = Some(next_value(&mut args, "--host")?),
                "--cpus" => {
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
                "--suite" => suites.push(next_value(&mut args, "--suite")?),
                "--tag" => tags.push(next_value(&mut args, "--tag")?),
                "--output" => output = PathBuf::from(next_value(&mut args, "--output")?),
                "--repetitions" => {
                    let value = next_value(&mut args, "--repetitions")?;
                    repetitions = value
                        .parse()
                        .map_err(|_| format!("invalid repetition count `{value}`"))?;
                    if repetitions == 0 {
                        return Err("--repetitions must be positive".to_string());
                    }
                }
                "--boot-image" => {
                    boot_image = Some(PathBuf::from(next_value(&mut args, "--boot-image")?))
                }
                "--export-boot-image" => {
                    export_boot_image =
                        Some(PathBuf::from(next_value(&mut args, "--export-boot-image")?))
                }
                "--prepare-only" => prepare_only = true,
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
                other => return Err(format!("unknown bench argument `{other}`")),
            }
        }

        if suites.is_empty() && tags.is_empty() {
            tags.push("ci".to_string());
        }

        Ok(Self {
            platform,
            launch,
            host,
            cpus,
            suites,
            tags,
            output,
            repetitions,
            boot_image,
            export_boot_image,
            prepare_only,
            boot_timeout,
            timeout,
            offline,
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

fn run(root: &Path, options: BenchOptions) -> Result<(), String> {
    let platform = config::load_platform(root, &options.platform)?;
    let launch = config::load_launch(root, &options.launch)?;
    let host = config::load_host(
        root,
        options.host.as_deref().unwrap_or(std::env::consts::OS),
    )?;

    let boot_image = if let Some(path) = &options.boot_image {
        resolve(root, path)
    } else {
        std::env::set_var("RUSTOS_BENCH_SUITES", options.suites.join(","));
        std::env::set_var("RUSTOS_BENCH_TAGS", options.tags.join(","));
        build_platform(
            root,
            &platform,
            true,
            options.offline,
            &["kernel-bench".to_string()],
        )?;
        crate::load_artifact_manifest(root, &platform, true)?.boot_image
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
    if options.prepare_only {
        return Ok(());
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
        for repetition in 1..=options.repetitions {
            println!(
                "==> benchmarking with {cpus} vCPU(s), repetition {repetition}/{}",
                options.repetitions
            );
            let disk_path = bench_dir.join(format!("system-{cpus}cpu-repetition-{repetition}.img"));
            fs::copy(&seed_disk.path, &disk_path).map_err(|err| {
                format!(
                    "failed to clone benchmark disk {} to {}: {err}",
                    seed_disk.path.display(),
                    disk_path.display()
                )
            })?;
            let disk = SystemDisk {
                path: disk_path,
                format: seed_disk.format.clone(),
            };
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
                options.boot_timeout,
                options.timeout,
                serial_log,
            );
            if let Err(err) = fs::remove_file(&disk.path) {
                eprintln!(
                    "warning: failed to remove temporary benchmark disk {}: {err}",
                    disk.path.display()
                );
            }
            runs.push(topology?);
        }
    }

    let report = BenchReport {
        schema: "rustos.bench-run.v1".to_string(),
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
        println!("benchmark results: {}", output.display());
        Ok(())
    } else {
        Err(format!(
            "one or more benchmark topologies failed; partial results: {}",
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
    boot_timeout: Duration,
    timeout: Duration,
    serial_log: PathBuf,
) -> Result<TopologyRun, String> {
    let qemu_options = QemuOptions {
        release: true,
        debug: false,
        detach: false,
        dry_run: false,
        console_serial: false,
        gdb_port: crate::DEFAULT_GDB_PORT,
        lldb_meta: false,
        meta_port: crate::DEFAULT_META_PORT,
        platform: Some(platform.id.clone()),
        launch: Some(launch.id.clone()),
        host: None,
    };
    std::env::set_var("RUSTOS_QEMU_SMP", cpus.to_string());
    std::env::set_var("RUSTOS_QEMU_SERIAL", "stdio");
    let args = qemu_args(root, launch, firmware, boot_image, disk, &qemu_options)?;

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
            if sender.send(line).is_err() {
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

    loop {
        while let Ok(line) = receiver.try_recv() {
            let line = line.map_err(|err| format!("failed reading QEMU serial output: {err}"))?;
            println!("{line}");
            benchmark_started |= record_serial_line(
                &line,
                &mut serial,
                &mut events,
                &mut complete,
                &mut status,
                &mut panic_lines,
                &mut panic_seen_at,
            )?;
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
            &mut serial,
            &mut events,
            &mut complete,
            &mut status,
            &mut panic_lines,
            &mut panic_seen_at,
        )?;
    }
    fs::write(&serial_log, serial)
        .map_err(|err| format!("failed to write {}: {err}", serial_log.display()))?;

    let panic = (!panic_lines.is_empty()).then(|| panic_lines.join("\n"));
    if let Some(details) = &panic {
        report_panic(cpus, details);
        status = "panicked".to_string();
    } else if status == "timeout" {
        annotate_error(
            &format!("Benchmark timed out ({cpus} vCPUs)"),
            &format!("QEMU did not finish within {} seconds", timeout.as_secs()),
        );
    } else if status == "boot_timeout" {
        annotate_error(
            &format!("Kernel boot timed out ({cpus} vCPUs)"),
            &format!(
                "The kernel did not emit benchmark run_start within {} seconds",
                boot_timeout.as_secs()
            ),
        );
    } else if complete && status != "passed" {
        annotate_error(
            &format!("Benchmark failed ({cpus} vCPUs)"),
            &format!("The benchmark runner reported terminal status `{status}`"),
        );
    } else if !complete {
        annotate_error(
            &format!("Incomplete benchmark ({cpus} vCPUs)"),
            "QEMU exited without emitting a benchmark run_end event",
        );
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

#[allow(clippy::too_many_arguments)]
fn record_serial_line(
    line: &str,
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
    if let Some(event) = parse_event(line)? {
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
        ACTION_ANNOTATIONS.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
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

fn parse_event(line: &str) -> Result<Option<ProtocolEvent>, String> {
    let Some(rest) = line.strip_prefix(PROTOCOL_PREFIX) else {
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
    regression_threshold_percent: Option<f64>,
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
         Metrics exceeding their registered regression threshold fail this comparison. \
         Repeated suites use paired boot medians and a 10,000-resample 95% bootstrap confidence interval; \
         single-pair suites apply their practical threshold directly. MAD reports boot-to-boot variability. \
         Positive and negative changes are interpreted according to whether higher or lower values are better.\n\n\
         | CPUs | Suite | Case | Metric | Previous median | Current median | Change | 95% CI | Boot MAD (previous → current) | Threshold | Result |\n\
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
            let threshold = samples
                .regression_threshold_percent
                .map(|value| format!("{value:.2}%"))
                .unwrap_or_else(|| "—".to_string());
            markdown.push_str(&format!(
                "| {} | `{}` | `{}` | `{}` | {} | {} | — | — | — | {} | {} |\n",
                key.cpus, key.suite, key.case, key.metric, previous, current, threshold, result,
            ));
            continue;
        };
        let base_median = median(&base_samples.boot_medians);
        let head_median = median(&head_samples.boot_medians);
        let relative = paired_change(&base_samples.boot_medians, &head_samples.boot_medians)
            .unwrap_or_else(|| {
                if base_median == 0.0 {
                    0.0
                } else {
                    (head_median - base_median) * 100.0 / base_median
                }
            });
        let threshold = head_samples.regression_threshold_percent;
        let regression = match head_samples.direction {
            1 => relative,
            2 => -relative,
            _ => 0.0,
        };
        let confidence = bootstrap_change_interval(base_samples, head_samples);
        let confidence_text = if let Some(confidence) = confidence {
            format!("{:+.2}% to {:+.2}%", confidence.lower, confidence.upper)
        } else if base_samples.boot_medians.len() == 1 && head_samples.boot_medians.len() == 1 {
            "single paired boot".to_string()
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
        let improvement_confidence_upper =
            confidence.map(|interval| match head_samples.direction {
                1 => interval.upper,
                2 => -interval.lower,
                _ => 0.0,
            });
        let direct_single_boot =
            base_samples.boot_medians.len() == 1 && head_samples.boot_medians.len() == 1;
        let result = match threshold {
            Some(limit)
                if regression > limit
                    && (direct_single_boot
                        || regression_confidence_lower.is_some_and(|lower| lower > limit)) =>
            {
                regressions.push((key.clone(), regression, limit));
                "🔴 regression"
            }
            Some(limit) if regression > limit => "🟡 variance warning",
            Some(limit)
                if regression < -limit
                    && (direct_single_boot
                        || improvement_confidence_upper.is_some_and(|upper| upper < -limit)) =>
            {
                "🟢 improvement"
            }
            Some(_) => "within threshold",
            None => "informational",
        };
        let threshold = threshold
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
            threshold,
            result,
        ));
    }

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    }
    fs::write(&output_path, markdown)
        .map_err(|err| format!("failed to write {}: {err}", output_path.display()))?;
    println!("benchmark comparison: {}", output_path.display());
    if options.annotations {
        for (key, regression, threshold) in &regressions {
            annotate_error(
                "Performance regression",
                &format!(
                    "{} vCPUs {}/{}/{} regressed by {:.2}% (threshold {:.2}%)",
                    key.cpus, key.suite, key.case, key.metric, regression, threshold
                ),
            );
        }
    }
    if regressions.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} benchmark metric(s) exceeded their regression threshold",
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
            let regression_threshold_percent = event
                .payload
                .get("regression_threshold_percent")
                .and_then(Value::as_f64);
            let samples = metrics
                .entry(key.clone())
                .or_insert_with(MetricSamples::default);
            if !samples.values.is_empty()
                && (samples.unit != unit
                    || samples.direction != direction
                    || samples.regression_threshold_percent != regression_threshold_percent)
            {
                return Err("measurement metadata changed within a metric".to_string());
            }
            samples.unit = unit;
            samples.direction = direction;
            samples.regression_threshold_percent = regression_threshold_percent;
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
    const MIN_BOOT_SAMPLES: usize = 3;
    const RESAMPLES: usize = 10_000;
    if base.boot_medians.len() < MIN_BOOT_SAMPLES
        || head.boot_medians.len() < MIN_BOOT_SAMPLES
        || base.boot_medians.len() != head.boot_medians.len()
    {
        return None;
    }

    let mut random = XorShift64::new(0x6a09_e667_f3bc_c909);
    let paired_logs = paired_log_ratios(&base.boot_medians, &head.boot_medians)?;
    let mut resample = Vec::with_capacity(paired_logs.len());
    let mut changes = Vec::with_capacity(RESAMPLES);
    for _ in 0..RESAMPLES {
        resample.clear();
        for _ in 0..paired_logs.len() {
            resample.push(paired_logs[random.index(paired_logs.len())]);
        }
        changes.push(median(&resample).exp().mul_add(100.0, -100.0));
    }
    changes.sort_by(f64::total_cmp);
    Some(ChangeInterval {
        lower: percentile(&changes, 0.025),
        upper: percentile(&changes, 0.975),
    })
}

fn paired_change(base: &[f64], head: &[f64]) -> Option<f64> {
    let logs = paired_log_ratios(base, head)?;
    Some(median(&logs).exp().mul_add(100.0, -100.0))
}

fn paired_log_ratios(base: &[f64], head: &[f64]) -> Option<Vec<f64>> {
    if base.is_empty() || base.len() != head.len() {
        return None;
    }
    base.iter()
        .zip(head)
        .map(|(base, head)| (*base > 0.0 && *head > 0.0).then(|| (head / base).ln()))
        .collect()
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
