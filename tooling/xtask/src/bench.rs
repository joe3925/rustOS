use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
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
    assert_exists, build_platform, config, find_firmware, find_qemu, qemu_args, system_disk,
    QemuOptions, SystemDisk,
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
    let result = match command {
        BenchCommand::Run(options) => run(root, options),
        BenchCommand::Compare(options) => compare(root, options),
    };
    if let Err(err) = &result {
        annotate_error("Benchmark command failed", err);
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

    std::env::set_var("RUSTOS_BENCH_SUITES", options.suites.join(","));
    std::env::set_var("RUSTOS_BENCH_TAGS", options.tags.join(","));
    build_platform(
        root,
        &platform,
        true,
        options.offline,
        &["kernel-bench".to_string()],
    )?;

    let artifacts = crate::load_artifact_manifest(root, &platform, true)?;
    let qemu = find_qemu(&launch, &host)?;
    let firmware = find_firmware(&launch, &host, &qemu)?;
    let seed_disk = system_disk(root)?;
    assert_exists(&artifacts.boot_image, "boot image")?;
    assert_exists(&seed_disk.path, "system disk")?;

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
        println!("==> benchmarking with {cpus} vCPU(s)");
        let disk_path = bench_dir.join(format!("system-{cpus}cpu.img"));
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
        let serial_log = bench_dir.join(format!("{cpus}cpu.serial.log"));
        let topology = run_topology(
            root,
            &platform,
            &launch,
            &qemu,
            &firmware,
            &artifacts.boot_image,
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

    let annotation = details
        .lines()
        .take(8)
        .collect::<Vec<_>>()
        .join(" | ");
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
}

impl CompareOptions {
    fn parse<I>(args: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = String>,
    {
        let mut base = None;
        let mut head = None;
        let mut output = PathBuf::from("target/bench/comparison.md");
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--base" => base = Some(PathBuf::from(next_value(&mut args, "--base")?)),
                "--head" => head = Some(PathBuf::from(next_value(&mut args, "--head")?)),
                "--output" => output = PathBuf::from(next_value(&mut args, "--output")?),
                other => return Err(format!("unknown bench compare argument `{other}`")),
            }
        }
        Ok(Self {
            base: base.ok_or_else(|| "bench compare requires --base".to_string())?,
            head: head.ok_or_else(|| "bench compare requires --head".to_string())?,
            output,
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
    let mut markdown = String::from(
        "# Kernel benchmark comparison\n\n\
         Performance changes are informational and do not fail the workflow.\n\n\
         | CPUs | Suite | Case | Metric | Previous median | Current median | Change | Threshold | Result |\n\
         |---:|---|---|---|---:|---:|---:|---:|---|\n",
    );

    let mut regressions = Vec::new();
    for (key, base_samples) in &base_metrics {
        let Some(head_samples) = head_metrics.get(key) else {
            continue;
        };
        let base_median = median(&base_samples.values);
        let head_median = median(&head_samples.values);
        let relative = if base_median == 0.0 {
            0.0
        } else {
            (head_median - base_median) * 100.0 / base_median
        };
        let threshold = head_samples.regression_threshold_percent;
        let regression = match head_samples.direction {
            1 => relative,
            2 => -relative,
            _ => 0.0,
        };
        let result = match threshold {
            Some(limit) if regression > limit => {
                regressions.push((key.clone(), regression, limit));
                "🔴 regression"
            }
            Some(limit) if regression < -limit => "🟢 improvement",
            Some(_) => "within threshold",
            None => "informational",
        };
        let threshold = threshold
            .map(|value| format!("{value:.2}%"))
            .unwrap_or_else(|| "—".to_string());
        markdown.push_str(&format!(
            "| {} | `{}` | `{}` | `{}` | {:.3} | {:.3} | {:+.2}% | {} | {} |\n",
            key.cpus,
            key.suite,
            key.case,
            key.metric,
            base_median,
            head_median,
            relative,
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
    for (key, regression, threshold) in &regressions {
        annotate_error(
            "Performance regression",
            &format!(
                "{} vCPUs {}/{}/{} regressed by {:.2}% (threshold {:.2}%)",
                key.cpus, key.suite, key.case, key.metric, regression, threshold
            ),
        );
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
            let samples = metrics.entry(key).or_insert_with(MetricSamples::default);
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
        }
    }
    Ok(metrics)
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
