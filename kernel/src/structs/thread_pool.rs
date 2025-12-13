use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::hint::spin_loop;
use spin::Mutex;
use spin::RwLock;

use crate::memory::paging::constants::KERNEL_STACK_SIZE;
use crate::scheduling::scheduler::SCHEDULER;
use crate::scheduling::task::Task;

pub type JobFn = extern "win64" fn(usize);

#[derive(Clone, Copy)]
struct Job {
    f: JobFn,
    a: usize,
}

pub struct ThreadPool {
    queue: Mutex<VecDeque<Job>>,
    workers: RwLock<Vec<()>>,
}

struct WorkerArgs {
    pool: Arc<ThreadPool>,
}

impl ThreadPool {
    pub fn new(threads: usize) -> Arc<Self> {
        let pool = Arc::new(Self {
            queue: Mutex::new(VecDeque::new()),
            workers: RwLock::new(Vec::new()),
        });

        {
            let mut w = pool.workers.write();
            w.reserve(threads);
            for _ in 0..threads {
                w.push(());
            }
        }

        for _ in 0..threads {
            pool.spawn_worker();
        }

        pool
    }

    fn spawn_worker(self: &Arc<Self>) {
        let args = Box::new(WorkerArgs { pool: self.clone() });
        let args_ptr = Box::into_raw(args) as usize;
        let t = Task::new_kernel_mode(worker, args_ptr, KERNEL_STACK_SIZE, "".into(), 0);
        SCHEDULER.add_task(t);
    }

    pub fn enable_dynamic(&self, _max_threads: usize) {}

    pub fn submit(&self, function: JobFn, context: usize) {
        let job = Job {
            f: function,
            a: context,
        };
        self.queue.lock().push_back(job);
    }

    pub fn submit_if_runnable(&self, f: JobFn, a: usize) -> bool {
        self.submit(f, a);
        true
    }

    pub fn try_execute_one(&self) -> bool {
        let job = self.queue.lock().pop_front();
        if let Some(j) = job {
            (j.f)(j.a);
            return true;
        }
        false
    }
}

extern "win64" fn worker(args_ptr: usize) {
    let args = unsafe { Box::from_raw(args_ptr as *mut WorkerArgs) };
    let pool = args.pool;

    loop {
        let job = pool.queue.lock().pop_front();
        if let Some(j) = job {
            (j.f)(j.a);
        } else {
            spin_loop();
        }
    }
}
