use alloc::{format, string::String, sync::Arc, vec, vec::Vec};
use async_lock::Barrier;
use core::sync::atomic::{AtomicU64, Ordering};
use kernel_executor::runtime::runtime::spawn_join_owned;
use kernel_types::{
    async_ffi::{AbiFuture, FutureExt},
    benchmark::{BenchMetricDirection, BenchMetricUnit, BenchRunHandle, BenchSuiteStatus},
    dma::{IoBufferBacking, IoBufferBackingConfig, IoBufferBackingDesc},
    fs::{OpenFlags, Path},
};

use crate::{file_system::file::File, platform, println, structs::stopwatch::Stopwatch};
use super::{bench_case_end, bench_case_fail, bench_case_start, bench_measure};

const WORKERS: usize = 4;
const FILES_PER_WORKER: usize = 2;
const FILE_BYTES: usize = 64 * 1024 * 1024;
const BUFFER_BYTES: usize = 1024 * 1024;
const VERIFY_BLOCK_BYTES: usize = 4096;
const DURATION_NS: u64 = 10_000_000_000;
const JOBS: [&str; WORKERS] = ["stream-read", "stream-write", "random-mixed", "log-write"];

struct Shared {
    barrier: Barrier,
    start_cycles: AtomicU64,
}

struct WorkerInput {
    id: usize,
    files: Vec<File>,
}

struct WorkerResult {
    read_bytes: u64,
    write_bytes: u64,
    read_ops: u64,
    write_ops: u64,
    flush_ops: u64,
    io_ns: u64,
    drain_ns: u64,
    cpu_mask: u64,
    verified_bytes: u64,
    latencies: [Vec<u64>; 3],
    error: Option<String>,
}

async fn run_worker(mut input: WorkerInput, shared: Arc<Shared>) -> WorkerResult {
    let mut result = WorkerResult {
        read_bytes: 0,
        write_bytes: 0,
        read_ops: 0,
        write_ops: 0,
        flush_ops: 0,
        io_ns: 0,
        drain_ns: 0,
        cpu_mask: 0,
        verified_bytes: 0,
        latencies: core::array::from_fn(|_| Vec::with_capacity(65_536)),
        error: None,
    };
    let mut buffer = vec![0xa5; BUFFER_BYTES];
    let backing = IoBufferBacking::new(
        IoBufferBackingDesc::SliceMut(&mut buffer),
        IoBufferBackingConfig::worst_case_for_len(BUFFER_BYTES),
    );
    let mut generations = vec![vec![0u64; FILE_BYTES / VERIFY_BLOCK_BYTES]; FILES_PER_WORKER];
    let mut random = 0x2026_1106_09ab_cdefu64 ^ input.id as u64;
    let mut cursor = 0usize;

    shared.barrier.wait().await;
    shared.barrier.wait().await;
    let start = shared.start_cycles.load(Ordering::Acquire);
    let io_result: Result<(), String> = async {
        let backing = backing.as_ref().map_err(|error| format!("backing: {error:?}"))?;
        while Stopwatch::from_cycles(platform::cycle_counter() - start).as_nanos()
            < DURATION_NS as u128
        {
            let cpu = platform::current_cpu_id();
            if cpu < 64 {
                result.cpu_mask |= 1u64 << cpu;
            }
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            let size = match input.id {
                0 | 1 => BUFFER_BYTES,
                2 => VERIFY_BLOCK_BYTES,
                _ => 8192,
            };
            let writing = input.id == 1 || input.id == 3 || (input.id == 2 && random % 10 >= 7);
            let file_index = if input.id == 2 {
                ((random >> 8) as usize) % FILES_PER_WORKER
            } else {
                cursor / FILE_BYTES % FILES_PER_WORKER
            };
            let offset = if input.id == 2 {
                ((random >> 16) as usize % (FILE_BYTES / size)) * size
            } else {
                cursor % FILE_BYTES
            };
            let file_id = input.id * FILES_PER_WORKER + file_index + 1;
            let generation = result.write_ops + 1;
            if writing {
                let mut edit = backing.create_bidirectional(0, size)
                    .map_err(|error| format!("write edit: {error:?}"))?;
                let bytes = edit.try_as_mut_slice().ok_or_else(|| format!("write buffer is not contiguous"))?;
                for local in (0..size).step_by(VERIFY_BLOCK_BYTES) {
                    let block = (offset + local) / VERIFY_BLOCK_BYTES;
                    let tag = ((file_id as u64) << 56) | ((block as u64) << 32) | generation;
                    bytes[local..local + 8].copy_from_slice(&tag.to_le_bytes());
                    bytes[local + VERIFY_BLOCK_BYTES - 8..local + VERIFY_BLOCK_BYTES]
                        .copy_from_slice(&(!tag).to_le_bytes());
                }
            }
            let timer = Stopwatch::start();
            if writing {
                let io = backing.create_to_device(0, size)
                    .map_err(|error| format!("write lease: {error:?}"))?;
                let written = input.files[file_index].write_iobuffer_at(offset as u64, io).await
                    .map_err(|error| format!("write: {error:?}"))?;
                result.latencies[1].push(timer.elapsed_nanos());
                if written != size {
                    return Err(format!("short write: {written}/{size}"));
                }
                for block in offset / VERIFY_BLOCK_BYTES..(offset + size) / VERIFY_BLOCK_BYTES {
                    generations[file_index][block] = generation;
                }
                result.write_bytes += size as u64;
                result.write_ops += 1;
            } else {
                let io = backing.create_from_device(0, size)
                    .map_err(|error| format!("read lease: {error:?}"))?;
                let read = input.files[file_index].read_iobuffer_at(offset as u64, io).await
                    .map_err(|error| format!("read: {error:?}"))?;
                result.latencies[0].push(timer.elapsed_nanos());
                if read != size {
                    return Err(format!("short read: {read}/{size}"));
                }
                let inspect = backing.create_to_device(0, size)
                    .map_err(|error| format!("read inspect: {error:?}"))?;
                let bytes = inspect.try_as_slice().ok_or_else(|| format!("read buffer is not contiguous"))?;
                for local in (0..size).step_by(VERIFY_BLOCK_BYTES) {
                    let block = (offset + local) / VERIFY_BLOCK_BYTES;
                    let tag = ((file_id as u64) << 56) | ((block as u64) << 32)
                        | generations[file_index][block];
                    if bytes[local..local + 8] != tag.to_le_bytes()
                        || bytes[local + VERIFY_BLOCK_BYTES - 8..local + VERIFY_BLOCK_BYTES]
                            != (!tag).to_le_bytes()
                    {
                        return Err(format!("read mismatch: file={file_id} block={block}"));
                    }
                }
                result.read_bytes += size as u64;
                result.read_ops += 1;
            }
            if input.id == 3 && result.write_ops % 128 == 0 {
                let timer = Stopwatch::start();
                input.files[file_index].flush().await
                    .map_err(|error| format!("log flush: {error:?}"))?;
                result.latencies[2].push(timer.elapsed_nanos());
                result.flush_ops += 1;
            }
            cursor = (cursor + size) % (FILE_BYTES * FILES_PER_WORKER);
        }
        Ok(())
    }.await;
    result.io_ns = Stopwatch::from_cycles(platform::cycle_counter() - start).as_nanos() as u64;
    result.error = io_result.err();
    let drain = Stopwatch::start();
    for file in &input.files {
        if let Err(error) = file.flush().await {
            result.error.get_or_insert_with(|| format!("final flush: {error:?}"));
        }
    }
    result.drain_ns = drain.elapsed_nanos();
    shared.barrier.wait().await;
    shared.barrier.wait().await;

    let verify_result: Result<(), String> = async {
        let backing = backing.as_ref().map_err(|error| format!("backing: {error:?}"))?;
        for (file_index, file) in input.files.iter().enumerate() {
            let file_id = input.id * FILES_PER_WORKER + file_index + 1;
            for offset in (0..FILE_BYTES).step_by(BUFFER_BYTES) {
                let io = backing.create_from_device(0, BUFFER_BYTES)
                    .map_err(|error| format!("verify lease: {error:?}"))?;
                let read = file.read_iobuffer_at(offset as u64, io).await
                    .map_err(|error| format!("verify read: {error:?}"))?;
                if read != BUFFER_BYTES {
                    return Err(format!("short verify read: {read}"));
                }
                let inspect = backing.create_to_device(0, BUFFER_BYTES)
                    .map_err(|error| format!("verify inspect: {error:?}"))?;
                let bytes = inspect.try_as_slice().ok_or_else(|| format!("verify buffer is not contiguous"))?;
                for local in (0..BUFFER_BYTES).step_by(VERIFY_BLOCK_BYTES) {
                    let block = (offset + local) / VERIFY_BLOCK_BYTES;
                    let tag = ((file_id as u64) << 56) | ((block as u64) << 32)
                        | generations[file_index][block];
                    if bytes[local..local + 8] != tag.to_le_bytes()
                        || bytes[local + VERIFY_BLOCK_BYTES - 8..local + VERIFY_BLOCK_BYTES]
                            != (!tag).to_le_bytes()
                    {
                        return Err(format!("verify mismatch: file={file_id} block={block}"));
                    }
                }
                result.verified_bytes += BUFFER_BYTES as u64;
            }
        }
        Ok(())
    }.await;
    if let Err(error) = verify_result {
        result.error.get_or_insert(error);
    }
    for file in input.files {
        if let Err(error) = file.close().await {
            result.error.get_or_insert_with(|| format!("close: {error:?}"));
        }
    }
    result
}

pub(super) extern "C" fn multi_file_suite(handle: BenchRunHandle) -> AbiFuture<BenchSuiteStatus> {
    async move {
        if !bench_case_start(handle, "mixed-load".into()) {
            return BenchSuiteStatus::Failed;
        }
        let setup: Result<Vec<WorkerInput>, String> = async {
            File::make_dir(&Path::from_string("C:\\bench\\multi-file")).await
                .map_err(|error| format!("directory: {error:?}"))?;
            let mut buffer = vec![0xa5; BUFFER_BYTES];
            let backing = IoBufferBacking::new(
                IoBufferBackingDesc::SliceMut(&mut buffer),
                IoBufferBackingConfig::worst_case_for_len(BUFFER_BYTES),
            ).map_err(|error| format!("setup backing: {error:?}"))?;
            let mut inputs = Vec::with_capacity(WORKERS);
            for worker in 0..WORKERS {
                let mut files = Vec::with_capacity(FILES_PER_WORKER);
                for local_file in 0..FILES_PER_WORKER {
                    let file_id = worker * FILES_PER_WORKER + local_file + 1;
                    let path = Path::from_string(&format!("C:\\bench\\multi-file\\file-{file_id}.bin"));
                    let mut file = File::open(&path, &[OpenFlags::Create, OpenFlags::ReadWrite]).await
                        .map_err(|error| format!("open {file_id}: {error:?}"))?;
                    if file.size != FILE_BYTES as u64 {
                        file.set_len(FILE_BYTES as u64).await
                            .map_err(|error| format!("size {file_id}: {error:?}"))?;
                    }
                    for offset in (0..FILE_BYTES).step_by(BUFFER_BYTES) {
                        let mut edit = backing.create_bidirectional(0, BUFFER_BYTES)
                            .map_err(|error| format!("setup edit: {error:?}"))?;
                        let bytes = edit.try_as_mut_slice().ok_or_else(|| format!("setup buffer is not contiguous"))?;
                        for local in (0..BUFFER_BYTES).step_by(VERIFY_BLOCK_BYTES) {
                            let block = (offset + local) / VERIFY_BLOCK_BYTES;
                            let tag = ((file_id as u64) << 56) | ((block as u64) << 32);
                            bytes[local..local + 8].copy_from_slice(&tag.to_le_bytes());
                            bytes[local + VERIFY_BLOCK_BYTES - 8..local + VERIFY_BLOCK_BYTES]
                                .copy_from_slice(&(!tag).to_le_bytes());
                        }
                        drop(edit);
                        let io = backing.create_to_device(0, BUFFER_BYTES)
                            .map_err(|error| format!("setup lease: {error:?}"))?;
                        let written = file.write_iobuffer_at(offset as u64, io).await
                            .map_err(|error| format!("setup write {file_id}: {error:?}"))?;
                        if written != BUFFER_BYTES {
                            return Err(format!("short setup write: {written}"));
                        }
                    }
                    file.flush().await.map_err(|error| format!("setup flush {file_id}: {error:?}"))?;
                    files.push(file);
                }
                inputs.push(WorkerInput { id: worker, files });
            }
            Ok(inputs)
        }.await;
        let inputs = match setup {
            Ok(inputs) => inputs,
            Err(error) => {
                bench_case_fail(handle, error);
                bench_case_end(handle);
                return BenchSuiteStatus::Failed;
            }
        };
        let shared = Arc::new(Shared {
            barrier: Barrier::new(WORKERS + 1),
            start_cycles: AtomicU64::new(0),
        });
        let mut workers = Vec::with_capacity(WORKERS);
        for input in inputs {
            workers.push(spawn_join_owned(run_worker(input, shared.clone())));
        }
        shared.barrier.wait().await;
        println!("[multi-file-ready] workers={} files={} file_bytes={} duration_ns={}",
            WORKERS, WORKERS * FILES_PER_WORKER, FILE_BYTES, DURATION_NS);
        let timer = Stopwatch::start();
        shared.start_cycles.store(platform::cycle_counter(), Ordering::Release);
        shared.barrier.wait().await;
        shared.barrier.wait().await;
        let elapsed_ns = timer.elapsed_nanos();
        println!("[multi-file-timed-end] elapsed_ns={elapsed_ns}");
        shared.barrier.wait().await;
        let mut results = Vec::with_capacity(WORKERS);
        for worker in workers {
            results.push(worker.await);
        }
        let mut passed = true;
        let mut total_read = 0u64;
        let mut total_write = 0u64;
        let mut total_ops = 0u64;
        let mut cpu_mask = 0u64;
        for (id, result) in results.iter_mut().enumerate() {
            if let Some(error) = result.error.take() {
                bench_case_fail(handle, format!("worker {id}: {error}"));
                passed = false;
            }
            if result.verified_bytes != (FILES_PER_WORKER * FILE_BYTES) as u64
                || result.read_ops + result.write_ops == 0
            {
                bench_case_fail(handle, format!("worker {id} did not complete its work"));
                passed = false;
            }
            println!("[multi-file-worker] id={} job={} read_bytes={} write_bytes={} read_ops={} write_ops={} flush_ops={} io_ns={} drain_ns={} cpu_mask={} verified_bytes={}",
                id, JOBS[id], result.read_bytes, result.write_bytes, result.read_ops,
                result.write_ops, result.flush_ops, result.io_ns, result.drain_ns,
                result.cpu_mask, result.verified_bytes);
            for (kind, samples) in result.latencies.iter_mut().enumerate() {
                if samples.is_empty() {
                    continue;
                }
                samples.sort_unstable();
                let count = samples.len();
                let mean_ns = samples.iter().map(|value| *value as u128).sum::<u128>() / count as u128;
                let p50_ns = samples[(count * 50).div_ceil(100) - 1];
                let p95_ns = samples[(count * 95).div_ceil(100) - 1];
                let p99_ns = samples[(count * 99).div_ceil(100) - 1];
                let operation = ["read", "write", "flush"][kind];
                println!("[multi-file-latency] id={} operation={} count={} mean_ns={} p50_ns={} p95_ns={} p99_ns={} max_ns={}",
                    id, operation, count, mean_ns, p50_ns, p95_ns, p99_ns, samples[count - 1]);
                bench_measure(handle, format!("{}.{}.p95_ns", JOBS[id], operation),
                    p95_ns as f64, BenchMetricUnit::Nanoseconds, BenchMetricDirection::LowerIsBetter);
            }
            let bytes = result.read_bytes + result.write_bytes;
            bench_measure(handle, format!("{}.bytes_per_second", JOBS[id]),
                bytes as f64 * 1e9 / elapsed_ns as f64,
                BenchMetricUnit::BytesPerSecond, BenchMetricDirection::HigherIsBetter);
            total_read += result.read_bytes;
            total_write += result.write_bytes;
            total_ops += result.read_ops + result.write_ops;
            cpu_mask |= result.cpu_mask;
        }
        println!("[multi-file-summary] workers={} files={} read_bytes={} write_bytes={} io_ops={} elapsed_ns={} cpu_mask={} status={}",
            WORKERS, WORKERS * FILES_PER_WORKER, total_read, total_write, total_ops,
            elapsed_ns, cpu_mask, if passed { "passed" } else { "failed" });
        bench_measure(handle, "total.bytes_per_second".into(),
            (total_read + total_write) as f64 * 1e9 / elapsed_ns as f64,
            BenchMetricUnit::BytesPerSecond, BenchMetricDirection::HigherIsBetter);
        bench_measure(handle, "total.io_ops_per_second".into(),
            total_ops as f64 * 1e9 / elapsed_ns as f64,
            BenchMetricUnit::OperationsPerSecond, BenchMetricDirection::HigherIsBetter);
        bench_case_end(handle);
        if passed { BenchSuiteStatus::Passed } else { BenchSuiteStatus::Failed }
    }.into_abi()
}
