//! Work-stealing thread pool for the async executor.
//!
//! ## Optimizations (Fix #2)
//!
//! 1. **Per-Worker Local Queues**: Each worker has a lock-free ArrayQueue for fast local access.
//! 2. **Work Stealing**: Idle workers steal half the work from busy workers.
//! 3. **Global Overflow**: Only falls back to locked global queue when local queues are full.
//! 4. **Batched Global Drain**: Workers pull multiple jobs from global queue at once.

#![allow(dead_code)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crossbeam_queue::ArrayQueue;

use crate::memory::paging::stack::StackSize;
use crate::scheduling::scheduler::SCHEDULER;
use crate::scheduling::task::Task;
use crate::structs::condvar::Condvar;
use crate::structs::sleep_mutex::SleepMutex;

// =============================================================================
// Constants
// =============================================================================

/// Capacity of each worker's local queue.
/// Small enough to stay hot in L2 cache, large enough to buffer bursts.
const LOCAL_QUEUE_CAPACITY: usize = 256;

/// How many jobs to drain from global queue at once.
const GLOBAL_BATCH_SIZE: usize = 64;

// =============================================================================
// Types
// =============================================================================

pub type JobFn = extern "win64" fn(usize);

#[derive(Clone, Copy)]
pub struct Job {
    pub f: JobFn,
    pub a: usize,
}

impl From<(extern "win64" fn(usize), usize)> for Job {
    fn from(job: (extern "win64" fn(usize), usize)) -> Self {
        Job { f: job.0, a: job.1 }
    }
}

// =============================================================================
// Shared State
// =============================================================================

struct Shared {
    /// Global overflow queue (locked). Used when local queues are full.
    global_queue: SleepMutex<VecDeque<Job>>,

    /// Per-worker local queues (lock-free). Workers primarily work from these.
    local_queues: Vec<Arc<ArrayQueue<Job>>>,

    /// Condition variable for waking sleeping workers.
    not_empty: Condvar,

    /// Shutdown flag.
    shutdown: AtomicBool,

    /// Total pending job count (across all queues).
    job_count: AtomicUsize,

    /// Number of active workers.
    num_workers: AtomicUsize,

    /// Sequence number for notifications.
    seq: AtomicUsize,
}

impl Shared {
    #[inline(always)]
    fn bump_seq(&self) {
        self.seq.fetch_add(1, Ordering::Release);
    }

    #[inline(always)]
    fn wake_one(&self) {
        self.not_empty.notify_one();
    }

    #[inline(always)]
    fn wake_all(&self) {
        self.not_empty.notify_all();
    }

    /// Steal up to half the jobs from a victim's local queue.
    /// Returns the number of jobs stolen.
    fn steal_batch(&self, from_worker: usize, to_queue: &ArrayQueue<Job>) -> usize {
        if from_worker >= self.local_queues.len() {
            return 0;
        }

        let victim_queue = &self.local_queues[from_worker];
        let victim_len = victim_queue.len();

        if victim_len == 0 {
            return 0;
        }

        // Steal half, minimum 1, maximum what fits in our queue
        let steal_count = (victim_len / 2).max(1);
        let mut stolen = 0;

        for _ in 0..steal_count {
            match victim_queue.pop() {
                Some(job) => {
                    if to_queue.push(job).is_err() {
                        // Our queue is full, execute this one directly
                        (job.f)(job.a);
                        self.job_count.fetch_sub(1, Ordering::Relaxed);
                    }
                    stolen += 1;
                }
                None => break, // Victim emptied
            }
        }

        stolen
    }

    /// Drain jobs from global queue into local queue.
    /// Returns the number of jobs drained.
    fn drain_global_to_local(&self, local_queue: &ArrayQueue<Job>) -> usize {
        let mut global = self.global_queue.lock();
        let drain_count = global.len().min(GLOBAL_BATCH_SIZE);

        if drain_count == 0 {
            return 0;
        }

        let mut drained = 0;
        for _ in 0..drain_count {
            if let Some(job) = global.pop_front() {
                if local_queue.push(job).is_err() {
                    // Local full, put back
                    global.push_front(job);
                    break;
                }
                drained += 1;
            } else {
                break;
            }
        }

        drained
    }
}

// =============================================================================
// Worker Context
// =============================================================================

struct WorkerCtx {
    shared: Arc<Shared>,
    worker_id: usize,
    local_queue: Arc<ArrayQueue<Job>>,
}

// =============================================================================
// ThreadPool
// =============================================================================

pub struct ThreadPool {
    shared: Arc<Shared>,
}

impl ThreadPool {
    pub fn new(threads: usize) -> Self {
        assert!(threads > 0);

        // Create per-worker local queues
        let local_queues: Vec<Arc<ArrayQueue<Job>>> = (0..threads)
            .map(|_| Arc::new(ArrayQueue::new(LOCAL_QUEUE_CAPACITY)))
            .collect();

        let shared = Arc::new(Shared {
            global_queue: SleepMutex::new(VecDeque::new()),
            local_queues,
            not_empty: Condvar::new(),
            shutdown: AtomicBool::new(false),
            job_count: AtomicUsize::new(0),
            num_workers: AtomicUsize::new(0),
            seq: AtomicUsize::new(0),
        });

        // Spawn worker threads
        for i in 0..threads {
            shared.num_workers.fetch_add(1, Ordering::Release);

            let ctx = Box::new(WorkerCtx {
                shared: shared.clone(),
                worker_id: i,
                local_queue: shared.local_queues[i].clone(),
            });

            let name: String = alloc::format!("thread_pool_worker_{i}");
            let th = Task::new_kernel_mode(
                worker_entry,
                Box::into_raw(ctx) as usize,
                StackSize::Tiny,
                name,
                0,
            );
            SCHEDULER.spawn_task(th);
        }

        Self { shared }
    }

    /// Submit a job to the thread pool.
    ///
    /// Tries to push to a local queue first (lock-free fast path),
    /// falls back to global queue if local is full.
    pub fn submit(&self, function: JobFn, context: usize) {
        if self.shared.shutdown.load(Ordering::Acquire) {
            return;
        }

        let job = Job {
            f: function,
            a: context,
        };

        // Try submitting to a local queue based on current CPU
        // This provides locality when the submitter is a worker thread
        let num_workers = self.shared.local_queues.len();
        if num_workers > 0 {
            // Use a simple round-robin or CPU-based selection
            let target = self.select_target_queue();

            if self.shared.local_queues[target].push(job).is_ok() {
                self.shared.job_count.fetch_add(1, Ordering::Release);
                self.shared.bump_seq();
                self.shared.wake_one();
                return;
            }
        }

        // Local queue full or no workers, use global queue
        {
            let mut q = self.shared.global_queue.lock();
            q.push_back(job);
            self.shared.job_count.fetch_add(1, Ordering::Release);
        }

        self.shared.bump_seq();
        self.shared.wake_one();
    }

    /// Submit multiple jobs at once.
    pub fn submit_many(&self, jobs: &[Job]) {
        if jobs.is_empty() {
            return;
        }
        if self.shared.shutdown.load(Ordering::Acquire) {
            return;
        }

        let num_workers = self.shared.local_queues.len();

        // Try to distribute across local queues first
        if num_workers > 0 {
            let per_queue = (jobs.len() + num_workers - 1) / num_workers;
            let mut next_idx = 0;

            for local_queue in &self.shared.local_queues {
                if next_idx >= jobs.len() {
                    break;
                }

                let end = (next_idx + per_queue).min(jobs.len());
                for job in &jobs[next_idx..end] {
                    if local_queue.push(*job).is_err() {
                        // Local queue full: put the remaining (including this one) into the global queue once.
                        let mut q = self.shared.global_queue.lock();
                        for &job in &jobs[next_idx..] {
                            q.push_back(job);
                            self.shared.job_count.fetch_add(1, Ordering::Release);
                        }
                        self.shared.bump_seq();
                        self.shared.wake_all();
                        return;
                    }
                    self.shared.job_count.fetch_add(1, Ordering::Release);
                    next_idx += 1;
                }
            }

            // Push any leftover to global queue (only those not already accepted)
            if next_idx < jobs.len() {
                let mut q = self.shared.global_queue.lock();
                for &job in &jobs[next_idx..] {
                    q.push_back(job);
                    self.shared.job_count.fetch_add(1, Ordering::Release);
                }
            }
        } else {
            // No workers yet, push everything to the global queue
            let mut q = self.shared.global_queue.lock();
            for &job in jobs {
                q.push_back(job);
                self.shared.job_count.fetch_add(1, Ordering::Release);
            }
        }

        self.shared.bump_seq();
        self.shared.wake_all();
    }

    /// Submit a job, or execute it directly if the pool is shut down.
    pub fn submit_if_runnable(&self, f: JobFn, a: usize) {
        if self.shared.shutdown.load(Ordering::Acquire) {
            (f)(a);
            return;
        }
        self.submit(f, a);
    }

    /// Try to execute one job from the pool (for external helpers).
    pub fn try_execute_one(&self) -> bool {
        // Try local queues first
        for local_queue in &self.shared.local_queues {
            if let Some(job) = local_queue.pop() {
                self.shared.job_count.fetch_sub(1, Ordering::Relaxed);
                (job.f)(job.a);
                return true;
            }
        }

        // Try global queue
        let job = {
            let mut q = self.shared.global_queue.lock();
            q.pop_front()
        };

        if let Some(job) = job {
            self.shared.job_count.fetch_sub(1, Ordering::Relaxed);
            (job.f)(job.a);
            return true;
        }

        false
    }

    /// Shut down the thread pool.
    pub fn shutdown(&self) {
        self.shared.shutdown.store(true, Ordering::Release);
        self.shared.bump_seq();
        self.shared.wake_all();
    }

    /// Check if the pool is shut down.
    pub fn is_shutdown(&self) -> bool {
        self.shared.shutdown.load(Ordering::Acquire)
    }

    /// Get the number of pending jobs.
    pub fn pending_jobs(&self) -> usize {
        self.shared.job_count.load(Ordering::Acquire)
    }

    /// Get the number of active workers.
    pub fn workers(&self) -> usize {
        self.shared.num_workers.load(Ordering::Acquire)
    }

    /// Select which local queue to target for submission.
    #[inline]
    fn select_target_queue(&self) -> usize {
        // Try to use CPU ID for locality
        #[cfg(feature = "smp")]
        {
            crate::scheduling::scheduler::current_cpu_id() % self.shared.local_queues.len()
        }
        #[cfg(not(feature = "smp"))]
        {
            // Simple round-robin
            static COUNTER: AtomicUsize = AtomicUsize::new(0);
            COUNTER.fetch_add(1, Ordering::Relaxed) % self.shared.local_queues.len()
        }
    }
}

impl Drop for ThreadPool {
    fn drop(&mut self) {
        self.shutdown();
    }
}

// =============================================================================
// Worker Entry Point
// =============================================================================

extern "win64" fn worker_entry(ctx_ptr: usize) {
    let ctx = unsafe { Box::from_raw(ctx_ptr as *mut WorkerCtx) };
    let shared = ctx.shared.clone();
    let worker_id = ctx.worker_id;
    let local_queue = ctx.local_queue.clone();
    drop(ctx);

    let num_workers = shared.local_queues.len();

    'outer: loop {
        // Phase 1: Drain local queue (lock-free hot path)
        while let Some(job) = local_queue.pop() {
            shared.job_count.fetch_sub(1, Ordering::Relaxed);
            (job.f)(job.a);
        }

        // Phase 2: Try stealing from other workers
        if num_workers > 1 {
            for offset in 1..num_workers {
                let victim = (worker_id + offset) % num_workers;
                if shared.steal_batch(victim, &local_queue) > 0 {
                    continue 'outer; // Got work, go back to local drain
                }
            }
        }

        // Phase 3: Try global queue (batched drain)
        if shared.drain_global_to_local(&local_queue) > 0 {
            continue 'outer; // Got work from global
        }

        // Phase 4: Wait for work
        {
            let mut global = shared.global_queue.lock();

            // Double-check after acquiring lock
            if let Some(job) = global.pop_front() {
                drop(global);
                shared.job_count.fetch_sub(1, Ordering::Relaxed);
                (job.f)(job.a);
                continue 'outer;
            }

            // Check local queue again (someone might have pushed while we waited for lock)
            if let Some(job) = local_queue.pop() {
                drop(global);
                shared.job_count.fetch_sub(1, Ordering::Relaxed);
                (job.f)(job.a);
                continue 'outer;
            }

            // Check shutdown
            if shared.shutdown.load(Ordering::Acquire) {
                break;
            }

            // Actually wait
            global = shared.not_empty.wait(global);

            // After waking, try to get work from global before releasing lock
            if let Some(job) = global.pop_front() {
                drop(global);
                shared.job_count.fetch_sub(1, Ordering::Relaxed);
                (job.f)(job.a);
                continue 'outer;
            }
        }
    }

    shared.num_workers.fetch_sub(1, Ordering::AcqRel);
}
