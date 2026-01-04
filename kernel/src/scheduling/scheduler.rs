// scheduling/scheduler.rs

use crate::cpu;
use crate::drivers::interrupt_index::current_cpu_id;
use crate::drivers::timer_driver::PER_CORE_SWITCHES;
use crate::executable::program::PROGRAM_MANAGER;
use crate::memory::paging::stack::StackSize;
use crate::println;
use crate::scheduling::state::State;
use crate::scheduling::task::{idle_task, ParkState, Task};
use crate::static_handlers::task_yield;
use crate::util::{kernel_main, KERNEL_INITIALIZED, TOTAL_TIME};
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::arch::naked_asm;
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
    sleep_queue: Mutex<Vec<TaskHandle>>,
    current: RwLock<Option<TaskHandle>>,
    idle_task: TaskHandle,
}

pub struct Scheduler {
    all_tasks: Mutex<HashMap<u64, TaskHandle>>,
    cores: Box<[CoreScheduler]>,
    next_task_id: AtomicU64,
    num_cores: AtomicUsize,
    balance_lock: Mutex<()>,
}

lazy_static! {
    pub static ref SCHEDULER: Scheduler = Scheduler::new();
}

#[inline(always)]
fn derive_tsc_hz() -> u64 {
    let sw = TOTAL_TIME.get().unwrap();
    let us = sw.elapsed_micros();
    if us == 0 {
        return 0;
    }
    let c = sw.elapsed_cycles();
    ((c as u128) * 1_000_000u128 / (us as u128)) as u64
}

#[inline(always)]
fn cycles_to_micros(cycles: u64, hz: u64) -> u64 {
    if hz == 0 {
        return 0;
    }
    ((cycles as u128) * 1_000_000u128 / (hz as u128)) as u64
}

#[inline(always)]
fn cycles_to_millis(cycles: u64, hz: u64) -> u64 {
    if hz == 0 {
        return 0;
    }
    ((cycles as u128) * 1_000u128 / (hz as u128)) as u64
}

impl Scheduler {
    fn new() -> Self {
        Self {
            all_tasks: Mutex::new(HashMap::new()),
            cores: Vec::new().into_boxed_slice(),
            next_task_id: AtomicU64::new(1),
            num_cores: AtomicUsize::new(0),
            balance_lock: Mutex::new(()),
        }
    }

    pub fn init(&self, num_cores: usize) {
        self.num_cores.store(num_cores, Ordering::Relaxed);

        let mut cores_vec: Vec<CoreScheduler> = Vec::with_capacity(num_cores);
        for _ in 0..num_cores {
            let idle = Task::new_kernel_mode(idle_task, 0, StackSize::Tiny, "".into(), 0);
            let idle_handle = idle;
            let idle_id = self.add_task_internal(idle_handle.clone());
            {
                let mut t = idle_handle.write();
                t.id = idle_id;
            }
            cores_vec.push(CoreScheduler {
                run_queue: Mutex::new(VecDeque::new()),
                sleep_queue: Mutex::new(Vec::new()),
                current: RwLock::new(None),
                idle_task: self.get_task_by_id(idle_id).expect("idle missing"),
            });
        }

        let cores_box = cores_vec.into_boxed_slice();
        let ptr = &self.cores as *const _ as *mut Box<[CoreScheduler]>;
        unsafe { ptr.write(cores_box) };
    }

    pub fn add_task(&self, task: TaskHandle) -> u64 {
        without_interrupts(|| {
            let n = self.num_cores.load(Ordering::Relaxed);
            if n == 0 {
                return 0;
            }

            let start = (self.next_task_id.load(Ordering::Relaxed) as usize) % n;
            let mut best = start;
            let mut best_load = usize::MAX;

            for k in 0..n {
                let i = (start + k) % n;
                let load = self.core_effective_load(i);
                if load < best_load {
                    best_load = load;
                    best = i;
                    if best_load == 0 {
                        break;
                    }
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

        let now_cycles = cpu::get_cycles();
        let now_ms = TOTAL_TIME.get().unwrap().elapsed_millis();

        if let Some(cur) = self.get_current_task(cpu_id) {
            if let Some(mut guard) = cur.try_write() {
                guard.update_from_context(state);
            } else {
                return;
            }
        }

        // Periodic load balancing
        if (now_ms % 500) == 0 {
            if let Some(_guard) = self.balance_lock.try_lock() {
                // self.balance();
            }
        }

        // Schedule next task
        let next = match self.schedule_next(cpu_id, now_cycles) {
            Some(task) => task,
            None => return,
        };

        let (needs_restore, ctx_ptr) = {
            if let Some(t) = next.try_read() {
                (t.parent_pid != 0, &t.context as *const _ as *mut State)
            } else {
                return;
            }
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

    #[inline(always)]
    fn core_effective_load(&self, i: usize) -> usize {
        let core = &self.cores[i];
        let rq_len = core.run_queue.lock().len();
        let running = {
            let g = core.current.read();
            match g.as_ref() {
                Some(t) if !Arc::ptr_eq(t, &core.idle_task) => 1,
                _ => 0,
            }
        };
        rq_len + running
    }

    fn schedule_next(&self, cpu_id: usize, now_cycles: u64) -> Option<TaskHandle> {
        let core = &self.cores[cpu_id];
        let mut current_guard = core.current.write();

        let previous = current_guard.take();
        let mut previous_for_fallback = previous.clone();

        if let Some(ref previous_task) = previous {
            if !Arc::ptr_eq(previous_task, &core.idle_task) {
                if let Some(t) = previous_task.try_read() {
                    t.account_switched_out(now_cycles);
                    let terminated = t.terminated;
                    let park_state = t.park_state();

                    drop(t);

                    if terminated {
                        previous_for_fallback = None;
                    } else if park_state == ParkState::ParkRequested
                        || park_state == ParkState::UnparkPending
                    {
                        let actually_park = previous_task.read().park_commit();

                        if actually_park {
                            core.sleep_queue.lock().push(previous_task.clone());
                            previous_for_fallback = None;
                        } else {
                            core.run_queue.lock().push_back(previous_task.clone());
                        }
                    } else {
                        core.run_queue.lock().push_back(previous_task.clone());
                    }
                } else {
                    *current_guard = previous.clone();
                    return None;
                }
            }
        }

        // Try to find a runnable task from the run queue
        let mut run_queue_guard = core.run_queue.lock();
        let len = run_queue_guard.len();
        let mut next: Option<TaskHandle> = None;

        for _ in 0..len {
            if let Some(candidate) = run_queue_guard.pop_front() {
                if candidate.try_read().is_some() {
                    next = Some(candidate.clone());
                    break;
                } else {
                    run_queue_guard.push_back(candidate);
                }
            }
        }
        drop(run_queue_guard);

        // If we found a task, schedule it
        if let Some(n) = next {
            if let Some(t) = n.try_read() {
                t.mark_scheduled_in(cpu_id, now_cycles);
            } else {
                return None;
            }
            *current_guard = Some(n.clone());
            return Some(n);
        }

        // No task in run queue - try to continue with previous if it's still runnable
        if let Some(prev) = previous_for_fallback {
            if let Some(t) = prev.try_read() {
                if t.park_state() == ParkState::Running {
                    t.mark_scheduled_in(cpu_id, now_cycles);
                    drop(t);
                    *current_guard = Some(prev.clone());
                    return Some(prev.clone());
                }
            }
        }

        // Fall back to idle task
        if let Some(t) = core.idle_task.try_read() {
            t.mark_scheduled_in(cpu_id, now_cycles);
        } else {
            return None;
        }

        *current_guard = Some(core.idle_task.clone());
        Some(core.idle_task.clone())
    }

    pub fn wake_task(&self, task_handle: &TaskHandle) {
        without_interrupts(|| {
            let needs_queue_move = task_handle.read().unpark();

            if needs_queue_move {
                let n = self.num_cores.load(Ordering::Relaxed);
                for i in 0..n {
                    let mut sleep_lock = self.cores[i].sleep_queue.lock();
                    if let Some(idx) = sleep_lock.iter().position(|t| Arc::ptr_eq(t, task_handle)) {
                        sleep_lock.swap_remove(idx);
                        drop(sleep_lock);
                        self.cores[i]
                            .run_queue
                            .lock()
                            .push_back(task_handle.clone());
                        return;
                    }
                }

                self.cores[0]
                    .run_queue
                    .lock()
                    .push_back(task_handle.clone());
            }
        });
    }

    /// Wake a task by its ID.
    pub fn wake_task_by_id(&self, task_id: u64) -> Result<(), TaskError> {
        if let Some(handle) = self.get_task_by_id(task_id) {
            self.wake_task(&handle);
            Ok(())
        } else {
            Err(TaskError::NotFound(task_id))
        }
    }

    pub fn get_current_task(&self, cpu_id: usize) -> Option<TaskHandle> {
        without_interrupts(|| self.cores[cpu_id].current.read().clone())
    }

    pub fn balance(&self) {
        let n = self.num_cores.load(Ordering::Relaxed);
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

        if n >= 2 && busiest != least && max_len > min_len + 1 {
            let moved = { self.cores[busiest].run_queue.lock().pop_back() };
            if let Some(task) = moved {
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
            let is_parked = h.read().is_parked();
            if is_parked {
                self.wake_task(&h);
            }
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

    pub fn park_and_yield(&self) {
        let should_yield = without_interrupts(|| {
            let cpu_id = current_cpu_id() as usize;
            if let Some(task) = self.get_current_task(cpu_id) {
                // park_begin() returns false if an unpark is already pending
                task.read().park_begin()
            } else {
                false
            }
        });

        if should_yield {
            unsafe { task_yield() };
        }
    }

    /// Park with a condition check. Only parks if the condition is true.
    ///
    /// This is useful for patterns like:
    /// ```
    /// while !condition_met() {
    ///     scheduler.park_while(|| !condition_met());
    /// }
    /// ```
    ///
    /// The condition is checked with interrupts disabled, preventing races.
    pub fn park_while<F>(&self, should_park: F)
    where
        F: FnOnce() -> bool,
    {
        let should_yield = without_interrupts(|| {
            // Check condition first
            if !should_park() {
                return false;
            }

            let cpu_id = current_cpu_id() as usize;
            if let Some(task) = self.get_current_task(cpu_id) {
                task.read().park_begin()
            } else {
                false
            }
        });

        if should_yield {
            unsafe { task_yield() };
        }
    }
}

#[no_mangle]
pub extern "win64" fn yield_handler_win64(state: *mut State) {
    if !KERNEL_INITIALIZED.load(Ordering::Relaxed) {
        return;
    }
    let cpu_id = current_cpu_id() as usize;
    SCHEDULER.on_timer_tick(state, cpu_id);
}

#[unsafe(naked)]
pub extern "win64" fn yield_interrupt_entry() -> ! {
    naked_asm!(
        "cli",
        "push r15",
        "push r14",
        "push r13",
        "push r12",
        "push r11",
        "push r10",
        "push r9",
        "push r8",
        "push rdi",
        "push rsi",
        "push rbp",
        "push rbx",
        "push rdx",
        "push rcx",
        "push rax",
        "mov rcx, rsp",
        "cld",
        "sub rsp, 40",
        "call {handler}",
        "add rsp, 40",
        "pop rax",
        "pop rcx",
        "pop rdx",
        "pop rbx",
        "pop rbp",
        "pop rsi",
        "pop rdi",
        "pop r8",
        "pop r9",
        "pop r10",
        "pop r11",
        "pop r12",
        "pop r13",
        "pop r14",
        "pop r15",
        "sti",
        "iretq",
        handler = sym yield_handler_win64,
    );
}

pub fn kernel_task_end() -> ! {
    interrupts::without_interrupts(|| {
        let id = SCHEDULER
            .get_current_task(current_cpu_id() as usize)
            .unwrap()
            .read()
            .id;
        SCHEDULER.delete_task(id).ok();
    });
    loop {}
}
