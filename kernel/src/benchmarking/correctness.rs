use alloc::string::ToString;
use kernel_types::{
    async_ffi::{AbiFuture, FutureExt},
    benchmark::{BenchRunHandle, BenchSuiteStatus},
};

use super::{bench_case_end, bench_case_fail, bench_case_start, task_batch::run_task_batch};

pub(super) extern "C" fn executor_suite(handle: BenchRunHandle) -> AbiFuture<BenchSuiteStatus> {
    async move {
        if !bench_case_start(handle, "correctness".to_string()) {
            return BenchSuiteStatus::Failed;
        }
        let task_count = 2_048usize.saturating_mul(crate::platform::processor_count().max(1));
        let expected = (0..task_count as u64).fold(0u64, |sum, value| {
            sum.wrapping_add(correctness_value(value))
        });
        for _ in 0..15 {
            let actual = run_task_batch(task_count, correctness_value).await.checksum;
            if actual != expected {
                bench_case_fail(
                    handle,
                    alloc::format!(
                        "executor checksum mismatch: expected={expected:#x}, actual={actual:#x}"
                    ),
                );
                bench_case_end(handle);
                return BenchSuiteStatus::Failed;
            }
        }
        bench_case_end(handle);
        BenchSuiteStatus::Passed
    }
    .into_abi()
}

fn correctness_value(value: u64) -> u64 {
    let mut result = value.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    for round in 0..1_024u64 {
        result = result.rotate_left(13).wrapping_mul(0xbf58_476d_1ce4_e5b9)
            ^ round.wrapping_mul(0x94d0_49bb_1331_11eb);
    }
    result
}
