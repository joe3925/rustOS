import argparse
import ctypes
import json
import os
import platform
import statistics
import subprocess
from collections import defaultdict
from pathlib import Path


TARGET_PERCENT = 90


def pairs_per_second(pairs, wall_ns):
    if pairs <= 0 or wall_ns <= 0:
        raise ValueError("a timing sample must contain completed pairs and positive elapsed time")
    return pairs * 1e9 / wall_ns


parser = argparse.ArgumentParser(description="Compare parallel mimalloc throughput on Windows and rustOS.")
parser.add_argument("--cpus", default="1,2,4", help="worker counts and matching guest CPU counts")
parser.add_argument("--output", type=Path, default=Path("target/heap-bench/run"))
parser.add_argument("--affinity", type=lambda value: int(value, 0),
                    help="Windows processor mask for the runner and its child processes")
parser.add_argument("--kernel-report", type=Path, help="use a completed heap.mimalloc report from this build")
parser.add_argument("--offline", action="store_true", help="build rustOS with the local Cargo cache")
args = parser.parse_args()
if os.name != "nt" or platform.machine().lower() not in ("amd64", "x86_64"):
    parser.error("run this comparison on x64 Windows")
try:
    counts = [int(cpu) for cpu in args.cpus.split(",")]
except ValueError:
    parser.error("--cpus requires positive integers")
if min(counts) < 1 or len(set(counts)) != len(counts):
    parser.error("--cpus requires distinct positive integers")
if args.affinity is not None:
    if not 0 < args.affinity < 1 << 64 or args.affinity.bit_count() < max(counts):
        parser.error("--affinity must include a logical processor for each worker")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    if not kernel32.SetProcessAffinityMask(ctypes.c_void_p(-1), ctypes.c_size_t(args.affinity)):
        raise ctypes.WinError(ctypes.get_last_error())

root = Path(__file__).resolve().parents[2]
out = args.output.resolve()
out.mkdir(exist_ok=True, parents=True)
mi = root / "third_party/mimalloc-v2"
obj = out / "windows-mi.obj"
exe = out / "windows-heap.exe"
subprocess.run(["clang", "-O3", "-DNDEBUG", "-DMI_DEBUG=0", "-DMI_SECURE=0", "-DMI_STAT=0",
                "-I", mi / "include", "-c", mi / "src/static.c", "-o", obj], cwd=root, check=True)
subprocess.run(["rustc", "--edition=2024", "-Copt-level=3", "-Cpanic=abort",
                root / "tooling/heap-bench/windows.rs", "-C", f"link-arg={obj}", "-l", "advapi32",
                "-o", exe], cwd=root, check=True)

kernel_path = args.kernel_report or out / "kernel.json"
if args.kernel_report is None:
    offline = ["--offline"] if args.offline else []
    subprocess.run(["cargo", "run", *offline, "-p", "xtask", "--", "bench", "--launch", "qemu-x86_64-q35-whpx",
                    "--suite", "heap.mimalloc", "--cpus", args.cpus, "--output", kernel_path, *offline],
                   cwd=root, check=True)

report = json.loads(kernel_path.read_text())
if report["schema"] != "rustos.bench-run.v1":
    raise ValueError("unexpected kernel report format")
windows_runs = []
comparison = []
for count in counts:
    runs = [run for run in report["runs"] if run["cpus"] == count]
    repetitions = set()
    rates = defaultdict(lambda: defaultdict(list))
    initial = []
    before = []
    for run in runs:
        if not run["complete"] or run["status"] != "passed":
            raise ValueError(f"incomplete kernel run with {count} workers")
        start, = [event["payload"] for event in run["events"] if event["kind"] == "run_start"]
        suite, = [suite for suite in start["suites"] if suite["name"] == "heap.mimalloc"]
        if start["cpu_count"] != count or start["repetition"] in repetitions:
            raise ValueError(f"inconsistent kernel run with {count} workers")
        repetitions.add(start["repetition"])
        metrics = defaultdict(dict)
        for event in run["events"]:
            p = event["payload"]
            if event["kind"] == "measurement" and p["suite"] == "heap.mimalloc":
                series = metrics[p["case"], p["metric"]]
                if p["sample"] in series:
                    raise ValueError(f"duplicate kernel sample for {p['case']} / {p['metric']}")
                series[p["sample"]] = p["value"]
        initial.append(int(metrics["physical-heap", "at_mimalloc_init"][0]))
        before.append(int(metrics["physical-heap", "before_workers"][0]))
        native = subprocess.check_output([exe, str(count)], text=True)
        samples = []
        native_rates = defaultdict(dict)
        for line in native.splitlines():
            case, trial, pairs, ns, cpus = line.split()
            trial, pairs, ns, cpus = map(int, (trial, pairs, ns, cpus))
            if pairs != metrics[case, "pairs"][0] or trial in native_rates[case]:
                raise ValueError(f"workload mismatch for {case} with {count} workers")
            native_rates[case][trial] = pairs_per_second(pairs, ns)
            samples.append(dict(case=case, trial=trial, pairs=pairs, wall_ns=ns, worker_cpus_at_start=cpus))
        kernel_cases = {case for case, metric in metrics if metric == "wall_ns"}
        if not native_rates or native_rates.keys() != kernel_cases:
            raise ValueError("kernel and Windows workloads differ")
        for case, trials in native_rates.items():
            kernel_trials = metrics[case, "wall_ns"]
            if trials.keys() != kernel_trials.keys():
                raise ValueError(f"sample count mismatch for {case}")
            rates[case]["windows"].append(statistics.median(trials.values()))
            pairs = metrics[case, "pairs"][0]
            rates[case]["kernel"].append(statistics.median(pairs_per_second(pairs, ns) for ns in kernel_trials.values()))
        windows_runs.append(dict(workers=count, repetition=start["repetition"], samples=samples))

    if not runs or repetitions != set(range(1, suite["independent_boots"] + 1)):
        raise ValueError(f"missing kernel repetitions for {count} workers")
    for case, values in rates.items():
        kernel = statistics.median(values["kernel"])
        windows = statistics.median(values["windows"])
        percent = 100 * kernel / windows
        comparison.append(dict(workers=count, case=case, kernel_pairs_per_second=kernel,
                               windows_pairs_per_second=windows, percent_of_windows=percent,
                               initial_heap_bytes=initial, before_workers_heap_bytes=before))
        status = "  below target" if percent < TARGET_PERCENT else ""
        print(f"{count} worker(s)  {case:16}  kernel {kernel/1e6:8.1f}  Windows {windows/1e6:8.1f}"
              f"  M pairs/s  {percent:6.2f}%{status}")
    print(f"  Physical heap at init {max(initial)/2**20:g} MiB, before workers {min(before)/2**20:g}-{max(before)/2**20:g} MiB")

(out / "comparison.json").write_text(json.dumps(dict(kernel_report=str(kernel_path.resolve()),
    windows_version=platform.version(), affinity_mask=args.affinity,
    windows_runs=windows_runs, comparison=comparison), indent=2) + "\n")
raise SystemExit(0 if all(row["percent_of_windows"] >= TARGET_PERCENT for row in comparison) else 1)
