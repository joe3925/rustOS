use alloc::{
    collections::btree_map::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};
use core::sync::atomic::{AtomicU32, Ordering};
use kernel_types::benchmark::{
    BenchMetricDirection, BenchMetricUnit, BenchRunHandle, BenchSuiteDescriptor, BenchSuiteStatus,
};
use serde_json::json;
use spin::{Mutex, Once};

use super::{boot_state, suites};
use crate::println;

const PROTOCOL_VERSION: u32 = 1;

#[derive(Default)]
struct RunState {
    suite: String,
    case: Option<String>,
    failed: bool,
    sample_index: BTreeMap<(String, String), u64>,
}

static SUITES: Once<Mutex<BTreeMap<String, BenchSuiteDescriptor>>> = Once::new();
static RUNS: Once<Mutex<BTreeMap<u32, RunState>>> = Once::new();
static NEXT_RUN: AtomicU32 = AtomicU32::new(1);

fn suites() -> &'static Mutex<BTreeMap<String, BenchSuiteDescriptor>> {
    SUITES.call_once(|| Mutex::new(BTreeMap::new()))
}

fn runs() -> &'static Mutex<BTreeMap<u32, RunState>> {
    RUNS.call_once(|| Mutex::new(BTreeMap::new()))
}

fn emit(kind: &str, payload: serde_json::Value) {
    println!("RUSTOS_BENCH\t{}\t{}\t{}", PROTOCOL_VERSION, kind, payload);
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'/'))
}

pub fn register_suite(descriptor: BenchSuiteDescriptor) -> bool {
    if !valid_identifier(&descriptor.name)
        || descriptor.tags.iter().any(|tag| !valid_identifier(tag))
    {
        return false;
    }

    let mut registry = suites().lock();
    if registry.contains_key(&descriptor.name) {
        return false;
    }
    registry.insert(descriptor.name.clone(), descriptor);
    true
}

pub fn register_builtin_suites() {
    for descriptor in suites::descriptors() {
        assert!(
            register_suite(descriptor),
            "duplicate or invalid built-in benchmark suite"
        );
    }
}

pub fn bench_case_start(handle: BenchRunHandle, case: String) -> bool {
    if !valid_identifier(&case) {
        return false;
    }
    let suite = {
        let mut active = runs().lock();
        let Some(run) = active.get_mut(&handle.0) else {
            return false;
        };
        if run.case.is_some() {
            return false;
        }
        run.case = Some(case.clone());
        run.suite.clone()
    };
    emit("case_start", json!({ "suite": suite, "case": case }));
    true
}

pub fn bench_case_fail(handle: BenchRunHandle, reason: String) -> bool {
    let (suite, case) = {
        let mut active = runs().lock();
        let Some(run) = active.get_mut(&handle.0) else {
            return false;
        };
        run.failed = true;
        (run.suite.clone(), run.case.clone().unwrap_or_default())
    };
    emit(
        "case_failure",
        json!({ "suite": suite, "case": case, "reason": reason }),
    );
    true
}

pub fn bench_measure(
    handle: BenchRunHandle,
    metric: String,
    value: f64,
    unit: BenchMetricUnit,
    direction: BenchMetricDirection,
) -> bool {
    bench_measure_with_tolerance(handle, metric, value, unit, direction, None)
}

pub fn bench_measure_with_tolerance(
    handle: BenchRunHandle,
    metric: String,
    value: f64,
    unit: BenchMetricUnit,
    direction: BenchMetricDirection,
    tolerance_percent: Option<f64>,
) -> bool {
    if !valid_identifier(&metric)
        || !value.is_finite()
        || tolerance_percent.is_some_and(|tolerance| !tolerance.is_finite() || tolerance < 0.0)
    {
        return false;
    }

    let (suite, case, sample) = {
        let mut active = runs().lock();
        let Some(run) = active.get_mut(&handle.0) else {
            return false;
        };
        let Some(case) = run.case.clone() else {
            return false;
        };
        let sample = run
            .sample_index
            .entry((case.clone(), metric.clone()))
            .or_insert(0);
        let current = *sample;
        *sample = sample.saturating_add(1);
        (run.suite.clone(), case, current)
    };

    emit(
        "measurement",
        json!({
            "suite": suite,
            "case": case,
            "metric": metric,
            "sample": sample,
            "value": value,
            "unit": unit as u32,
            "direction": direction as u32,
            "tolerance_percent": tolerance_percent,
        }),
    );
    true
}

pub fn bench_case_end(handle: BenchRunHandle) -> bool {
    let finished = {
        let mut active = runs().lock();
        active.get_mut(&handle.0).and_then(|run| {
            run.case
                .take()
                .map(|case| (run.suite.clone(), case, run.failed))
        })
    };
    if let Some((suite, case, failed)) = finished {
        emit(
            "case_end",
            json!({ "suite": suite, "case": case, "status": if failed { "failed" } else { "passed" } }),
        );
        true
    } else {
        false
    }
}

fn matches_selection(descriptor: &BenchSuiteDescriptor, names: &[String], tags: &[String]) -> bool {
    (names.is_empty() && tags.is_empty())
        || names.iter().any(|name| name == &descriptor.name)
        || tags
            .iter()
            .any(|tag| descriptor.tags.iter().any(|candidate| candidate == tag))
}

async fn run_selected_suites_for_repetition(
    names: &[String],
    tags: &[String],
    repetition: usize,
    persist_repetition: bool,
) -> bool {
    let selected: Vec<BenchSuiteDescriptor> = suites()
        .lock()
        .values()
        .filter(|suite| matches_selection(suite, names, tags))
        .filter(|suite| usize::from(suite.independent_boots) >= repetition)
        .cloned()
        .collect();

    emit(
        "run_start",
        json!({
            "suite_count": selected.len(),
            "cpu_count": crate::platform::processor_count(),
            "repetition": repetition,
            "suites": selected.iter().map(|suite| json!({
                "name": suite.name,
                "independent_boots": suite.independent_boots,
            })).collect::<Vec<_>>(),
        }),
    );

    let mut passed = true;
    for suite in selected {
        let handle = BenchRunHandle(NEXT_RUN.fetch_add(1, Ordering::Relaxed));
        runs().lock().insert(
            handle.0,
            RunState {
                suite: suite.name.clone(),
                ..RunState::default()
            },
        );
        emit(
            "suite_start",
            json!({ "suite": suite.name, "tags": suite.tags }),
        );

        let status = (suite.callback)(handle).await;
        bench_case_end(handle);
        let run = runs().lock().remove(&handle.0).unwrap_or_default();
        let suite_passed = status == BenchSuiteStatus::Passed && !run.failed;
        passed &= suite_passed;
        emit(
            "suite_end",
            json!({
                "suite": run.suite,
                "status": if suite_passed { "passed" } else if status == BenchSuiteStatus::Skipped { "skipped" } else { "failed" },
            }),
        );
    }

    if persist_repetition {
        passed &= boot_state::persist_next_repetition(repetition).await;
    }

    emit(
        "run_end",
        json!({ "status": if passed { "passed" } else { "failed" } }),
    );
    passed
}

pub async fn run_selected_suites(names: &[String], tags: &[String]) -> bool {
    run_selected_suites_for_repetition(names, tags, 1, false).await
}

pub async fn run_configured_suites() -> bool {
    let names = option_env!("RUSTOS_BENCH_SUITES")
        .unwrap_or("")
        .split(',')
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let tags = option_env!("RUSTOS_BENCH_TAGS")
        .unwrap_or("")
        .split(',')
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let repetition = boot_state::current_repetition().await;
    run_selected_suites_for_repetition(&names, &tags, repetition, true).await
}
