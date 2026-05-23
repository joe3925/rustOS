use crate::drivers::interrupt_index::current_is_in_interrupt_atomic;
use crate::memory::heap::buddylocked::BuddyLocked;

use crate::memory::heap::HEAP_SIZE;
use crate::memory::paging::stack::StackSize;
use crate::println;
use crate::scheduling::runtime::runtime::yield_now;
use crate::scheduling::scheduler::SCHEDULER;
use crate::scheduling::task::Task;
use crate::structs::stopwatch::Stopwatch;
use alloc::boxed::Box;
use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::mem::size_of;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

cfg_if::cfg_if! {
    if #[cfg(feature = "allocator-mimalloc")] {
        use crate::memory::heap::mimalloc as mi;

        pub struct KernelAllocator {
            bootstrap: BuddyLocked,
            mimalloc_enabled: AtomicBool,
            enable_lock: spin::Mutex<()>,
        }

        impl KernelAllocator {
            pub const fn new() -> Self {
                Self {
                    bootstrap: BuddyLocked::new(),
                    mimalloc_enabled: AtomicBool::new(false),
                    enable_lock: spin::Mutex::new(()),
                }
            }

            pub fn enable_mimalloc(&self) {
                if self.mimalloc_enabled.load(Ordering::Acquire) {
                    return;
                }

                let _guard = self.enable_lock.lock();
                if !self.mimalloc_enabled.load(Ordering::Acquire) {
                    unsafe { mi::enable_mimalloc_impl(); }
                    self.mimalloc_enabled.store(true, Ordering::Release);
                }
            }

            #[inline(always)]
            pub fn mimalloc_enabled(&self) -> bool {
                self.mimalloc_enabled.load(Ordering::Acquire)
            }

            pub fn mimalloc_thread_done(&self) {

                if self.mimalloc_enabled() {
                    if current_is_in_interrupt_atomic().load(Ordering::Acquire){
                        panic!("mimalloc_thread_done called from interrupt, this shouldn't happen");
                    }
                    unsafe { mi::mimalloc_thread_done_impl(); }
                }
            }

            pub fn free_memory(&self) -> usize {
                self.bootstrap.free_memory() + mi::get_mimalloc_free_memory()
            }
        }

        unsafe impl GlobalAlloc for KernelAllocator {
            unsafe fn alloc(&self, layout: Layout) -> *mut u8 {

                if self.mimalloc_enabled() {
                    if current_is_in_interrupt_atomic().load(Ordering::Acquire){
                        panic!("Cannot accses allocator from interrupt");
                    }
                    mi::mimalloc_alloc(layout)
                } else {
                    self.bootstrap.alloc(layout)
                }
            }

            unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {

                if self.mimalloc_enabled() {
                    if current_is_in_interrupt_atomic().load(Ordering::Acquire){
                        panic!("Cannot accses allocator from interrupt");
                    }
                    mi::mimalloc_alloc_zeroed(layout)
                } else {
                    let ptr = self.bootstrap.alloc(layout);
                    if !ptr.is_null() {
                        core::ptr::write_bytes(ptr, 0, layout.size());
                    }
                    ptr
                }
            }

            unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {

                if ptr.is_null() {
                    return;
                }

                if mi::ptr_is_mimalloc(ptr) {
                    if current_is_in_interrupt_atomic().load(Ordering::Acquire){
                        panic!("Cannot accses allocator from interrupt");
                    }
                    mi::mimalloc_dealloc(ptr, layout)
                } else {
                    self.bootstrap.dealloc(ptr, layout)
                }
            }

            unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
                if ptr.is_null() {
                    return self.alloc(Layout::from_size_align_unchecked(new_size, layout.align()));
                }

                if mi::ptr_is_mimalloc(ptr) {
                    if current_is_in_interrupt_atomic().load(Ordering::Acquire){
                        panic!("Cannot accses allocator from interrupt");
                    }
                    mi::mimalloc_realloc(ptr, layout, new_size)
                } else {
                    let new_layout = Layout::from_size_align_unchecked(new_size, layout.align());
                    let new_ptr = self.alloc(new_layout);
                    if !new_ptr.is_null() {
                        core::ptr::copy_nonoverlapping(
                            ptr,
                            new_ptr,
                            core::cmp::min(layout.size(), new_size),
                        );
                        self.bootstrap.dealloc(ptr, layout);
                    }
                    new_ptr
                }
            }
        }

    } else if #[cfg(feature = "allocator-buddy")] {
        pub struct KernelAllocator {
            inner: BuddyLocked,
        }

        impl KernelAllocator {
            pub const fn new() -> Self {
                Self {
                    inner: BuddyLocked::new(),
                }
            }

            pub fn enable_mimalloc(&self) {
                // No-op for buddy allocator
            }

            pub fn mimalloc_thread_done(&self) {
                // No-op
            }

            pub fn free_memory(&self) -> usize {
                self.inner.free_memory()
            }
        }

        unsafe impl GlobalAlloc for KernelAllocator {
            unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
                self.inner.alloc(layout)
            }

            unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
                self.inner.alloc_zeroed(layout)
            }

            unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
                self.inner.dealloc(ptr, layout)
            }
        }
    } else {
        compile_error!("Must enable either 'allocator-mimalloc' or 'allocator-buddy' feature.");
    }
}

struct ParallelCtx {
    gate: Arc<AtomicBool>,
    element_count_per_thread: usize,
    finished: Arc<AtomicUsize>,
    push_total_ms: Arc<AtomicUsize>,
    push_max_ms: Arc<AtomicUsize>,
    verify_total_ms: Arc<AtomicUsize>,
    verify_max_ms: Arc<AtomicUsize>,
}

extern "win64" fn parallel_worker(ctx: usize) {
    let ctx = unsafe { Box::from_raw(ctx as *mut ParallelCtx) };
    while !ctx.gate.load(Ordering::Acquire) {
        yield_now();
    }

    {
        let mut vec: Vec<u64> = Vec::with_capacity(1);
        let push_sw = Stopwatch::start();
        for i in 0..ctx.element_count_per_thread {
            vec.push(i as u64);
        }
        let push_ms = push_sw.elapsed_millis() as usize;
        ctx.push_total_ms.fetch_add(push_ms, Ordering::Relaxed);
        atomic_max(&ctx.push_max_ms, push_ms);

        let verify_sw = Stopwatch::start();
        for i in 0..ctx.element_count_per_thread {
            if i != vec[i] as usize {
                println!("Heap data verification failed at index {}", i);
            }
        }
        let verify_ms = verify_sw.elapsed_millis() as usize;
        ctx.verify_total_ms.fetch_add(verify_ms, Ordering::Relaxed);
        atomic_max(&ctx.verify_max_ms, verify_ms);
    }

    ctx.finished.fetch_add(1, Ordering::Release);
}

pub fn test_full_heap_parallel() {
    let threads_to_test = [2, 4, 16];

    for &num_threads in &threads_to_test {
        let element_count_per_thread = ((HEAP_SIZE as usize / 4) / size_of::<u64>()) / num_threads;

        let gate = Arc::new(AtomicBool::new(false));
        let finished = Arc::new(AtomicUsize::new(0));
        let push_total_ms = Arc::new(AtomicUsize::new(0));
        let push_max_ms = Arc::new(AtomicUsize::new(0));
        let verify_total_ms = Arc::new(AtomicUsize::new(0));
        let verify_max_ms = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::with_capacity(num_threads);

        for i in 0..num_threads {
            let ctx = Box::new(ParallelCtx {
                gate: gate.clone(),
                element_count_per_thread,
                finished: finished.clone(),
                push_total_ms: push_total_ms.clone(),
                push_max_ms: push_max_ms.clone(),
                verify_total_ms: verify_total_ms.clone(),
                verify_max_ms: verify_max_ms.clone(),
            });

            let name = format!("heap_test_worker_{}", i);
            let task = Task::new_kernel_mode(
                parallel_worker,
                Box::into_raw(ctx) as usize,
                StackSize::Large,
                name,
                0,
            );
            tasks.push(task.clone());
            SCHEDULER.add_task(task);
        }

        reset_parallel_heap_test_stats();
        let sw = Stopwatch::start();
        gate.store(true, Ordering::Release);

        while finished.load(Ordering::Acquire) < num_threads {
            yield_now();
        }

        while tasks.iter().any(|task| !task.is_terminated()) {
            yield_now();
        }

        print_parallel_heap_test_result(
            num_threads,
            sw.elapsed().as_millis(),
            push_max_ms.load(Ordering::Relaxed),
            push_total_ms.load(Ordering::Relaxed),
            verify_max_ms.load(Ordering::Relaxed),
            verify_total_ms.load(Ordering::Relaxed),
        );
    }
}

cfg_if::cfg_if! {
    if #[cfg(feature = "allocator-mimalloc")] {
        fn reset_parallel_heap_test_stats() {
            crate::memory::heap::mimalloc::mimalloc_commit_stats_reset();
            crate::memory::heap::mimalloc::mimalloc_alloc_stats_reset();
        }

        fn print_parallel_heap_test_result(
            num_threads: usize,
            elapsed_ms: u128,
            push_max_ms: usize,
            push_total_ms: usize,
            verify_max_ms: usize,
            verify_total_ms: usize,
        ) {
            let commit_stats = crate::memory::heap::mimalloc::mimalloc_commit_stats();
            let alloc_stats = crate::memory::heap::mimalloc::mimalloc_alloc_stats();
            let commit_ms = Stopwatch::from_cycles(commit_stats.cycles).as_millis();
            let alloc_ms = Stopwatch::from_cycles(alloc_stats.alloc_cycles).as_millis();
            let realloc_ms = Stopwatch::from_cycles(alloc_stats.realloc_cycles).as_millis();
            let dealloc_ms = Stopwatch::from_cycles(alloc_stats.dealloc_cycles).as_millis();
            println!(
                "Heap test parallel ({} threads) passed: took {} ms (push max/sum {} / {} ms, verify max/sum {} / {} ms, commits calls/maps {} / {}, req/map {} / {} MiB, commit {} ms, alloc/realloc/free calls {} / {} / {}, MiB {} / {} / {}, ms {} / {} / {})",
                num_threads,
                elapsed_ms,
                push_max_ms,
                push_total_ms,
                verify_max_ms,
                verify_total_ms,
                commit_stats.calls,
                commit_stats.map_calls,
                commit_stats.requested / (1024 * 1024),
                commit_stats.mapped / (1024 * 1024),
                commit_ms,
                alloc_stats.alloc_calls,
                alloc_stats.realloc_calls,
                alloc_stats.dealloc_calls,
                alloc_stats.alloc_bytes / (1024 * 1024),
                alloc_stats.realloc_new_bytes / (1024 * 1024),
                alloc_stats.dealloc_bytes / (1024 * 1024),
                alloc_ms,
                realloc_ms,
                dealloc_ms
            );
        }
    } else if #[cfg(feature = "allocator-buddy")] {
        fn reset_parallel_heap_test_stats() {}

        fn print_parallel_heap_test_result(
            num_threads: usize,
            elapsed_ms: u128,
            push_max_ms: usize,
            push_total_ms: usize,
            verify_max_ms: usize,
            verify_total_ms: usize,
        ) {
            println!(
                "Heap test parallel ({} threads) passed: took {} ms (push max/sum {} / {} ms, verify max/sum {} / {} ms)",
                num_threads,
                elapsed_ms,
                push_max_ms,
                push_total_ms,
                verify_max_ms,
                verify_total_ms,
            );
        }
    }
}

fn atomic_max(target: &AtomicUsize, value: usize) {
    let mut current = target.load(Ordering::Relaxed);
    while value > current {
        match target.compare_exchange_weak(current, value, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(next) => current = next,
        }
    }
}
