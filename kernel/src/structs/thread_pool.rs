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

    pub fn submit_if_runnable(&self, f: JobFn, a: usize) -> bool {
        let started = Arc::new(AtomicBool::new(false));

        let sleeper = {
            let mut g = self.inner.lock();
            match g.sleepers.pop() {
                Some(t) => {
                    let payload = Box::new(TrampPayload {
                        f,
                        a,
                        started: started.clone(),
                    });
                    g.q.push_front(Job {
                        f: job_start_trampoline,
                        a: Box::into_raw(payload) as usize,
                    });
                    t
                }
                None => return false,
            }
        };
        without_interrupts(|| {
            sleeper.write().wake();
        });

        let mut spins = 0usize;
        while !started.load(Ordering::Acquire) {
            core::hint::spin_loop();
            spins = spins.wrapping_add(1);
            if spins > 1_000_000 {
                println!("Timeout");
                return false;
            }
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
    (b.f)(b.a);
}

extern "C" fn worker(pool_ptr: usize) {
    let pool: &ThreadPool = unsafe { &*(pool_ptr as *const ThreadPool) };
    let me = SCHEDULER.get_current_task(current_cpu_id()).unwrap();

    loop {
        // Fast path: try get a job.
        if let Some(j) = {
            let mut g = pool.inner.lock();
            g.q.pop_front()
        } {
            (j.f)(j.a);
            continue;
        }

        without_interrupts(|| {
            let should_sleep = {
                let mut g = pool.inner.lock();

                if let Some(j) = g.q.pop_front() {
                    drop(g);

                    (j.f)(j.a);
                    false
                } else {
                    me.write().sleep();
                    g.sleepers.push(me.clone());
                    true
                }
            };

            if should_sleep {
                me.write().sleep();
            }
        });

        loop {
            if !me.read().is_sleeping {
                break;
            }
            unsafe { core::arch::asm!("hlt", options(nomem, nostack, preserves_flags)) };
        }
    }
}
