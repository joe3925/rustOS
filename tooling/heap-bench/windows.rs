#[path = "../../kernel/src/benchmarking/heap/workload.rs"]
mod workload;

use std::{sync::Barrier, thread, time::Instant};
use workload::{CASES, PAIRS_PER_WORKER, SAMPLES, run_worker, sample_window};

unsafe extern "C" {
    fn mi_malloc(size: usize) -> *mut u8;
    fn mi_free(ptr: *mut u8);
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentProcessorNumberEx(processor: *mut ProcessorNumber);
}

#[repr(C)]
#[derive(Default)]
struct ProcessorNumber {
    group: u16,
    number: u8,
    reserved: u8,
}

fn main() {
    let workers: usize = std::env::args()
        .nth(1)
        .expect("supply the worker count")
        .parse()
        .unwrap();
    assert!(workers > 0 && workers <= thread::available_parallelism().unwrap().get());
    let origin = Instant::now();
    for (case, sizes) in CASES {
        let barrier = Barrier::new(workers);
        let samples: Vec<_> = thread::scope(|scope| {
            let handles: Vec<_> = (0..workers)
                .map(|index| {
                    let barrier = &barrier;
                    scope.spawn(move || unsafe {
                        run_worker(
                            index,
                            sizes,
                            |_| {
                                barrier.wait();
                            },
                            |layout| mi_malloc(layout.size()),
                            |ptr, _| mi_free(ptr),
                            || origin.elapsed().as_nanos() as u64,
                            || {
                                let mut cpu = ProcessorNumber::default();
                                GetCurrentProcessorNumberEx(&mut cpu);
                                (u32::from(cpu.group) << 8) | u32::from(cpu.number)
                            },
                        )
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect()
        });
        let pairs = PAIRS_PER_WORKER as u64 * workers as u64;
        for trial in 0..SAMPLES {
            let (ns, cpus) = sample_window(&samples, trial);
            println!("{case}\t{trial}\t{pairs}\t{ns}\t{cpus}");
        }
    }
}
