use alloc::collections::vec_deque::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

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
            SCHEDULER.lock().add_task(t);
        }
    }

    pub fn submit(&self, f: JobFn, a: usize) {
        let mut g = self.inner.lock();
        g.q.push_back(Job { f, a });
        if let Some(t) = g.sleepers.pop() {
            t.write().wake();
        }
    }
}

extern "C" fn worker(pool_ptr: usize) {
    let pool: &ThreadPool = unsafe { &*(pool_ptr as *const ThreadPool) };
    let me = SCHEDULER.lock().get_current_task();

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
