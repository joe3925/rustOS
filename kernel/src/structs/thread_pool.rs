use alloc::boxed::Box;
use alloc::collections::vec_deque::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

use crate::drivers::interrupt_index::current_cpu_id;
use crate::memory::paging::constants::KERNEL_STACK_SIZE;
use crate::scheduling::scheduler::{TaskHandle, SCHEDULER};
use crate::scheduling::task::Task;

pub type JobFn = extern "win64" fn(usize);

#[derive(Clone, Copy)]
struct Job {
    f: JobFn,
    a: usize,
}

struct Inner {
    q: VecDeque<Job>,
    sleepers: Vec<TaskHandle>,
}

pub struct ThreadPool {
    inner: Mutex<Inner>,
}

impl ThreadPool {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner {
                q: VecDeque::new(),
                sleepers: Vec::new(),
            }),
        })
    }

    pub fn start(self: &Arc<Self>, n: usize) {
        for _ in 0..n {
            let t = Task::new_kernel_mode(worker as usize, KERNEL_STACK_SIZE, "".into(), 0);
            t.write().context.rdi = Arc::as_ptr(self) as u64;
            SCHEDULER.add_task(t);
        }
    }

    pub fn submit(&self, f: JobFn, a: usize) {
        let mut g = self.inner.lock();
        g.q.push_back(Job { f, a });
        if let Some(t) = g.sleepers.pop() {
            t.write().wake();
        }
    }

    pub fn submit_if_runnable(&self, f: JobFn, a: usize) -> bool {
        let started = Arc::new(AtomicBool::new(false));

        let mut g = self.inner.lock();
        let sleeper = match g.sleepers.pop() {
            Some(t) => t,
            None => return false,
        };

        let payload = Box::new(TrampPayload {
            f,
            a,
            started: started.clone(),
        });

        g.q.push_front(Job {
            f: job_start_trampoline,
            a: Box::into_raw(payload) as usize,
        });

        sleeper.write().wake();
        drop(g);

        while !started.load(Ordering::Acquire) {
            core::hint::spin_loop();
        }
        true
    }
}

struct TrampPayload {
    f: JobFn,
    a: usize,
    started: Arc<AtomicBool>,
}

extern "win64" fn job_start_trampoline(p: usize) {
    let b: Box<TrampPayload> = unsafe { Box::from_raw(p as *mut TrampPayload) };
    b.started.store(true, Ordering::Release);
    let f = b.f;
    let a = b.a;
    (f)(a);
}

extern "C" fn worker(pool_ptr: usize) {
    let pool: &ThreadPool = unsafe { &*(pool_ptr as *const ThreadPool) };
    let me = SCHEDULER.get_current_task(current_cpu_id()).unwrap();

    loop {
        let job = {
            let mut g = pool.inner.lock();
            if let Some(j) = g.q.pop_front() {
                Some(j)
            } else {
                g.sleepers.push(me.clone());
                me.write().sleep();
                None
            }
        };

        if let Some(j) = job {
            (j.f)(j.a);
            continue;
        }

        loop {
            if !me.read().is_sleeping {
                break;
            }
            unsafe { core::arch::asm!("hlt", options(nomem, nostack, preserves_flags)) };
        }
    }
}
