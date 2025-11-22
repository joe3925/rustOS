use alloc::boxed::Box;
use alloc::collections::vec_deque::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;
use x86_64::instructions::interrupts::without_interrupts;

use crate::drivers::interrupt_index::current_cpu_id;
use crate::memory::paging::constants::KERNEL_STACK_SIZE;
use crate::println;
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
            without_interrupts(|| {
                t.write().context.rdi = Arc::as_ptr(self) as u64;
            });
            SCHEDULER.add_task(t);
        }
    }

    pub fn submit(&self, f: JobFn, a: usize) {
        let to_wake = {
            let mut g = self.inner.lock();
            g.q.push_back(Job { f, a });
            g.sleepers.pop()
        };
        if let Some(t) = to_wake {
            without_interrupts(|| {
                t.write().wake();
            });
        }
    }

    // Best-effort: only queue if there is a sleeping worker to run it.
    pub fn submit_if_runnable(&self, f: JobFn, a: usize) -> bool {
        let to_wake = {
            let mut g = self.inner.lock();
            match g.sleepers.pop() {
                Some(t) => {
                    g.q.push_back(Job { f, a });
                    Some(t)
                }
                None => None,
            }
        };

        if let Some(t) = to_wake {
            without_interrupts(|| {
                t.write().wake();
            });
            true
        } else {
            false
        }
    }
    pub fn try_execute_one(&self) -> bool {
        let job = {
            let mut g = self.inner.lock();
            g.q.pop_front()
        };

        if let Some(j) = job {
            (j.f)(j.a);
            return true;
        }

        false
    }
}

extern "C" fn worker(pool_ptr: usize) {
    let pool: &ThreadPool = unsafe { &*(pool_ptr as *const ThreadPool) };
    let me = SCHEDULER
        .get_current_task(current_cpu_id())
        .expect("worker task missing");

    loop {
        let mut guard = pool.inner.lock();

        loop {
            if let Some(j) = guard.q.pop_front() {
                if let Some(idx) = guard.sleepers.iter().position(|t| Arc::ptr_eq(t, &me)) {
                    guard.sleepers.swap_remove(idx);
                }

                drop(guard);
                (j.f)(j.a);
                break;
            }

            if !guard.sleepers.iter().any(|t| Arc::ptr_eq(t, &me)) {
                guard.sleepers.push(me.clone());
            }

            drop(guard);

            without_interrupts(|| {
                me.write().sleep();
            });

            while me.read().is_sleeping {
                unsafe { core::arch::asm!("hlt", options(nomem, nostack, preserves_flags)) };
            }

            guard = pool.inner.lock();
        }
    }
}
