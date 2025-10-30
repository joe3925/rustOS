use crate::drivers::interrupt_index::current_cpu_id;
use crate::drivers::timer_driver::PER_CORE_SWITCHES;
use crate::executable::program::PROGRAM_MANAGER;
use crate::memory::paging::constants::KERNEL_STACK_SIZE;
use crate::scheduling::state::State;
use crate::scheduling::task::{idle_task, Task};
use crate::util::{kernel_main, KERNEL_INITIALIZED, TOTAL_TIME};
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::arch::asm;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use hashbrown::HashMap;
use lazy_static::lazy_static;
use spin::Mutex;
use spin::RwLock;
use x86_64::instructions::interrupts::{self, without_interrupts};
use x86_64::registers::control::Cr3;

#[derive(Debug)]
#[repr(u32)]
pub enum TaskError {
    NotFound(u64),
}

pub type TaskHandle = Arc<RwLock<Task>>;

#[derive(Debug)]
pub struct CoreScheduler {
    run_queue: Mutex<VecDeque<TaskHandle>>,
    current: RwLock<Option<TaskHandle>>,
    idle_task: TaskHandle,
}

pub struct Scheduler {
    all_tasks: Mutex<HashMap<u64, TaskHandle>>,
    cores: Box<[CoreScheduler]>,
    next_task_id: AtomicU64,
    num_cores: AtomicUsize,
}

lazy_static! {
    pub static ref SCHEDULER: Scheduler = Scheduler::new();
}

impl Scheduler {
    fn new() -> Self {
        Self {
            all_tasks: Mutex::new(HashMap::new()),
            cores: Vec::new().into_boxed_slice(),
            next_task_id: AtomicU64::new(1),
            num_cores: AtomicUsize::new(0),
        }
    }

    pub fn init(&self, num_cores: usize) {
        self.num_cores.store(num_cores, Ordering::Relaxed);

        let mut cores_vec: Vec<CoreScheduler> = Vec::with_capacity(num_cores);
        for _ in 0..num_cores {
            let idle = Task::new_kernel_mode(idle_task as usize, KERNEL_STACK_SIZE, "".into(), 0);
            let idle_handle = idle;
            let idle_id = self.add_task_internal(idle_handle.clone());
            {
                let mut t = idle_handle.write();
                t.id = idle_id;
            }
            cores_vec.push(CoreScheduler {
                run_queue: Mutex::new(VecDeque::new()),
                current: RwLock::new(None),
                idle_task: self.get_task_by_id(idle_id).expect("idle missing"),
            });
        }
        // SAFETY: replace empty slice once
        let cores_box = cores_vec.into_boxed_slice();
        let ptr = &self.cores as *const _ as *mut Box<[CoreScheduler]>;
        unsafe { ptr.write(cores_box) };

        let kernel =
            Task::new_kernel_mode(kernel_main as usize, KERNEL_STACK_SIZE, "kernel".into(), 0);
        self.add_task(kernel);
    }

    pub fn add_task(&self, task: TaskHandle) -> u64 {
        without_interrupts(|| {
            let n = self.num_cores.load(Ordering::Relaxed);
            let mut best = 0usize;
            let mut best_len = usize::MAX;
            for i in 0..n {
                let len = self.cores[i].run_queue.lock().len();
                if len < best_len {
                    best_len = len;
                    best = i;
                }
            }
            let id = self.add_task_internal(task.clone());
            {
                task.write().id = id;
                self.cores[best].run_queue.lock().push_back(task);
            }
            id
        })
    }

    fn add_task_internal(&self, task: TaskHandle) -> u64 {
        let id = self.next_task_id.fetch_add(1, Ordering::Relaxed);
        task.write().id = id;
        self.all_tasks.lock().insert(id, task);
        id
    }

    #[inline(always)]
    pub fn on_timer_tick(&self, state: *mut State, cpu_id: usize) {
        if !KERNEL_INITIALIZED.load(Ordering::Acquire) {
            return;
        }

        if let Some(cur) = self.get_current_task(cpu_id) {
            cur.write().update_from_context(state);
        }

        if ((TOTAL_TIME.get().unwrap().elapsed_millis() % 500) == 0) {
            self.reap_tasks(cpu_id);
            self.balance();
        }
        let next = self.schedule_next(cpu_id);

        let (needs_restore, ctx_ptr) = {
            let t = next.read();
            (t.parent_pid != 0, &t.context as *const _ as *mut State)
        };

        if needs_restore {
            self.restore_page_table(&next);
        }

        PER_CORE_SWITCHES
            .get(cpu_id)
            .unwrap()
            .fetch_add(1, Ordering::Relaxed);
        unsafe { (*ctx_ptr).restore(state) };
    }

    fn schedule_next(&self, cpu_id: usize) -> TaskHandle {
        let core = &self.cores[cpu_id];

        if let Some(previous_task) = core.current.write().take() {
            if !Arc::ptr_eq(&previous_task, &core.idle_task) {
                core.run_queue.lock().push_back(previous_task);
            }
        }

        let next_task = {
            let mut run_queue_guard = core.run_queue.lock();
            let queue_len = run_queue_guard.len();
            for _ in 0..queue_len {
                if let Some(task_handle) = run_queue_guard.pop_front() {
                    let is_runnable = {
                        let task = task_handle.read();
                        !task.is_sleeping && !task.terminated
                    };
                    if is_runnable {
                        drop(run_queue_guard);
                        *core.current.write() = Some(task_handle.clone());
                        return task_handle;
                    } else {
                        run_queue_guard.push_back(task_handle);
                    }
                } else {
                    break;
                }
            }
            core.idle_task.clone()
        };

        *core.current.write() = Some(next_task.clone());
        next_task
    }

    pub fn get_current_task(&self, cpu_id: usize) -> Option<TaskHandle> {
        x86_64::instructions::interrupts::without_interrupts(|| {
            self.cores[cpu_id].current.read().clone()
        })
    }

    fn reap_tasks(&self, cpu_id: usize) {
        let core = &self.cores[cpu_id];
        let mut q = core.run_queue.lock();
        q.retain(|h| !h.read().terminated);
        if let Some(cur) = core.current.read().as_ref() {
            if cur.read().terminated {
                *core.current.write() = None;
            }
        }
    }

    pub fn balance(&self) {
        let n = self.num_cores.load(Ordering::Relaxed);
        if n < 2 {
            return;
        }
        let mut busiest = 0usize;
        let mut least = 0usize;
        let mut max_len = 0usize;
        let mut min_len = usize::MAX;
        for i in 0..n {
            let len = self.cores[i].run_queue.lock().len();
            if len > max_len {
                max_len = len;
                busiest = i;
            }
            if len < min_len {
                min_len = len;
                least = i;
            }
        }
        if busiest != least && max_len > min_len + 1 {
            if let Some(task) = self.cores[busiest].run_queue.lock().pop_back() {
                self.cores[least].run_queue.lock().push_front(task);
            }
        }
    }

    pub fn get_task_by_id(&self, id: u64) -> Option<TaskHandle> {
        self.all_tasks.lock().get(&id).cloned()
    }

    pub fn delete_task(&self, id: u64) -> Result<(), TaskError> {
        if let Some(h) = self.get_task_by_id(id) {
            h.write().terminated = true;
            Ok(())
        } else {
            Err(TaskError::NotFound(id))
        }
    }

    pub fn restore_page_table(&self, task_handle: &TaskHandle) {
        let t = task_handle.read();
        if t.parent_pid == 0 {
            return;
        }
        if let Some(program) = PROGRAM_MANAGER.get(t.parent_pid) {
            unsafe { Cr3::write(program.read().cr3, Cr3::read().1) };
        } else {
            let id = t.id;
            drop(t);
            let _ = self.delete_task(id);
        }
    }
}

pub fn kernel_task_yield() {
    unsafe { asm!("int 0x20") };
}

pub fn kernel_task_end() -> ! {
    // TODO: need a better pattern then this
    interrupts::without_interrupts(|| {
        let id = SCHEDULER
            .get_current_task(current_cpu_id() as usize)
            .unwrap()
            .read()
            .id;
        SCHEDULER.delete_task(id);
    });
    loop {}
}
