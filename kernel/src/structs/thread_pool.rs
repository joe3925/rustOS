use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::MaybeUninit;
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
use spin::RwLock;
use x86_64::instructions::interrupts::without_interrupts;

use crate::drivers::interrupt_index::current_cpu_id;
use crate::memory::paging::constants::KERNEL_STACK_SIZE;
use crate::scheduling::scheduler::{TaskHandle, SCHEDULER};
use crate::scheduling::task::Task;
use crate::static_handlers::task_yield;

pub type JobFn = extern "C" fn(usize);

#[derive(Clone, Copy)]
struct Job {
    f: JobFn,
    a: usize,
}

struct Node {
    job: MaybeUninit<Job>,
    next: AtomicPtr<Node>,
}

struct JobQueue {
    head: AtomicPtr<Node>,
    tail: AtomicPtr<Node>,
}

impl JobQueue {
    fn new() -> Self {
        let dummy = Box::into_raw(Box::new(Node {
            job: MaybeUninit::uninit(),
            next: AtomicPtr::new(ptr::null_mut()),
        }));

        JobQueue {
            head: AtomicPtr::new(dummy),
            tail: AtomicPtr::new(dummy),
        }
    }

    fn push(&self, job: Job) {
        let node = Box::into_raw(Box::new(Node {
            job: MaybeUninit::new(job),
            next: AtomicPtr::new(ptr::null_mut()),
        }));

        loop {
            let tail = self.tail.load(Ordering::Acquire);
            let next = unsafe { (*tail).next.load(Ordering::Acquire) };

            if tail == self.tail.load(Ordering::Acquire) {
                if next.is_null() {
                    if unsafe {
                        (*tail).next.compare_exchange(
                            next,
                            node,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                    }
                    .is_ok()
                    {
                        let _ = self.tail.compare_exchange(
                            tail,
                            node,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        );
                        break;
                    }
                } else {
                    let _ =
                        self.tail
                            .compare_exchange(tail, next, Ordering::AcqRel, Ordering::Acquire);
                }
            }
        }
    }

    fn pop(&self) -> Option<Job> {
        loop {
            let head = self.head.load(Ordering::Acquire);
            let tail = self.tail.load(Ordering::Acquire);
            let next = unsafe { (*head).next.load(Ordering::Acquire) };

            if head == self.head.load(Ordering::Acquire) {
                if head == tail {
                    if next.is_null() {
                        return None;
                    }

                    let _ =
                        self.tail
                            .compare_exchange(tail, next, Ordering::AcqRel, Ordering::Acquire);
                } else {
                    if next.is_null() {
                        continue;
                    }

                    let job = unsafe { (*next).job.as_ptr().read() };

                    if self
                        .head
                        .compare_exchange(head, next, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    {
                        unsafe {
                            let _ = Box::from_raw(head);
                        }
                        return Some(job);
                    }
                }
            }
        }
    }
}

pub struct ThreadPool {
    queue: JobQueue,
    sleepers: Box<[AtomicUsize]>,
    last_worker_idx: AtomicUsize,
    worker_count: usize,
}

struct WorkerArgs {
    pool: Arc<ThreadPool>,
    index: usize,
}

impl ThreadPool {
    pub fn new(threads: usize) -> Arc<Self> {
        let mut sleepers = Vec::with_capacity(threads);
        for _ in 0..threads {
            sleepers.push(AtomicUsize::new(0));
        }

        let pool = Arc::new(Self {
            queue: JobQueue::new(),
            sleepers: sleepers.into_boxed_slice(),
            last_worker_idx: AtomicUsize::new(0),
            worker_count: threads,
        });

        pool.start(threads);
        pool
    }

    fn start(self: &Arc<Self>, threads: usize) {
        for i in 0..threads {
            let t = Task::new_kernel_mode(worker as usize, KERNEL_STACK_SIZE, "".into(), 0);

            let args = Box::new(WorkerArgs {
                pool: self.clone(),
                index: i,
            });
            let args_ptr = Box::into_raw(args) as usize;

            without_interrupts(|| {
                t.write().context.rdi = args_ptr as u64;
            });

            SCHEDULER.add_task(t);
        }
    }

    pub fn submit(&self, function: JobFn, context: usize) {
        self.queue.push(Job {
            f: function,
            a: context,
        });

        let idx = self.last_worker_idx.fetch_add(1, Ordering::Relaxed) % self.worker_count;

        let sleeper_ptr = self.sleepers[idx].swap(0, Ordering::AcqRel);
        if sleeper_ptr != 0 {
            unsafe {
                let task: Arc<RwLock<Task>> = Arc::from_raw(sleeper_ptr as *const _);
                without_interrupts(|| {
                    task.write().wake();
                });
            }
        }
    }

    pub fn submit_if_runnable(&self, f: JobFn, a: usize) -> bool {
        self.queue.push(Job { f, a });

        for sleeper in self.sleepers.iter() {
            let sleeper_ptr = sleeper.swap(0, Ordering::AcqRel);
            if sleeper_ptr != 0 {
                unsafe {
                    let task: Arc<RwLock<Task>> = Arc::from_raw(sleeper_ptr as *const _);
                    without_interrupts(|| {
                        task.write().wake();
                    });
                }
                return true;
            }
        }

        false
    }

    pub fn try_execute_one(&self) -> bool {
        if let Some(j) = self.queue.pop() {
            (j.f)(j.a);
            return true;
        }
        false
    }
}

extern "C" fn worker(args_ptr: usize) {
    let args = unsafe { Box::from_raw(args_ptr as *mut WorkerArgs) };
    let pool = args.pool;
    let my_idx = args.index;

    let me = SCHEDULER
        .get_current_task(current_cpu_id())
        .expect("worker task missing");

    loop {
        if let Some(j) = pool.queue.pop() {
            (j.f)(j.a);
            continue;
        }

        let raw = Arc::into_raw(me.clone()) as usize;

        match pool.sleepers[my_idx].compare_exchange(0, raw, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => {
                without_interrupts(|| {
                    me.write().is_sleeping = true;
                });

                unsafe {
                    task_yield();
                }

                continue;
            }
            Err(existing) => {
                unsafe {
                    let _ = TaskHandle::from_raw(raw as *const _);
                }

                if existing != 0 {
                    unsafe {
                        let task: TaskHandle = Arc::from_raw(existing as *const _);
                        without_interrupts(|| {
                            task.write().wake();
                        });
                    }
                }
            }
        }
    }
}
