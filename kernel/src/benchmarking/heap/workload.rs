use core::alloc::Layout;
use core::ptr;

pub const CASES: [(&str, &[usize]); 2] = [
    ("fixed-64", &[64]),
    (
        "mixed-16-4096",
        &[
            16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536, 2048, 4096,
        ],
    ),
];
const BATCH: usize = 128;
const BATCHES: usize = 262_144;
pub const PAIRS_PER_WORKER: usize = BATCH * BATCHES;
pub const SAMPLES: usize = 7;

#[derive(Clone, Copy, Debug, Default)]
pub struct Sample {
    start: u64,
    end: u64,
    cpu: u32,
}

pub unsafe fn run_worker(
    index: usize,
    sizes: &[usize],
    start_round: impl Fn(usize),
    allocate: impl Fn(Layout) -> *mut u8,
    free: impl Fn(*mut u8, Layout),
    now: impl Fn() -> u64,
    cpu: impl Fn() -> u32,
) -> [Sample; SAMPLES] {
    let layouts: [Layout; BATCH] = core::array::from_fn(|slot| {
        Layout::from_size_align(sizes[(slot + index) % sizes.len()], 8).unwrap()
    });
    let mut blocks = [ptr::null_mut(); BATCH];
    let mut samples = [Sample::default(); SAMPLES];
    for trial in 0..=SAMPLES {
        start_round(trial);
        let cpu = cpu();
        let start = now();
        let batches = if trial == 0 { BATCHES / 4 } else { BATCHES };
        for batch in 0..batches {
            for (slot, block) in blocks.iter_mut().enumerate() {
                *block = allocate(layouts[slot]);
                assert!(!block.is_null(), "heap benchmark allocation failed");
                unsafe { (*block).write_volatile(batch as u8) };
            }
            for n in 0..BATCH {
                let slot = (n * 37 + batch) & (BATCH - 1);
                free(blocks[slot], layouts[slot]);
            }
        }
        let end = now();
        if trial > 0 {
            samples[trial - 1] = Sample { start, end, cpu };
        }
    }
    samples
}

pub fn sample_window(workers: &[[Sample; SAMPLES]], trial: usize) -> (u64, usize) {
    let start = workers
        .iter()
        .map(|samples| samples[trial].start)
        .min()
        .unwrap();
    let end = workers
        .iter()
        .map(|samples| samples[trial].end)
        .max()
        .unwrap();
    let distinct_cpus = workers
        .iter()
        .enumerate()
        .filter(|(index, worker)| {
            !workers[..*index]
                .iter()
                .any(|other| other[trial].cpu == worker[trial].cpu)
        })
        .count();
    (end.checked_sub(start).unwrap(), distinct_cpus)
}
