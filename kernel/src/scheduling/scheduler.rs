use crate::drivers::interrupt_index::get_current_logical_id;
use crate::executable::program::PROGRAM_MANAGER;
use crate::memory::paging::constants::KERNEL_STACK_SIZE;
use crate::scheduling::task::{idle_task, Task};
use crate::structs::per_core_storage::PCS;
use crate::util::kernel_main;
use alloc::collections::vec_deque::VecDeque;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use core::arch::asm;
use lazy_static::lazy_static;
use spin::{Mutex, RwLock};
use x86_64::registers::control::Cr3;

#[derive(Debug)]
#[repr(u32)]
pub enum TaskError {
    NotFound(u64),
    BadName,
}
lazy_static! {
    pub static ref SCHEDULER: Mutex<Scheduler> = Mutex::new(Scheduler::new());
}
pub type TaskHandle = Arc<RwLock<Task>>;
pub struct Scheduler {
    tasks: VecDeque<TaskHandle>,
    current_task: PCS<u64>,
    id: u64,
}

impl Scheduler {
    pub fn new() -> Self {
        Self {
            tasks: VecDeque::new(),
            current_task: PCS::new(),
            id: 1,
        }
    }

    #[inline]
    pub fn add_task(&mut self, task: TaskHandle) -> u64 {
        {
            // mutate via write-lock
            let mut t = task.write();
            t.id = self.id;
        }
        self.id += 1;
        self.tasks.push_back(task);
        self.id - 1
    }
    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }
    pub fn restore_page_table(&mut self) {
        if let Some(program) = PROGRAM_MANAGER.get(self.get_current_task().read().parent_pid) {
            unsafe { Cr3::write(program.read().cr3, Cr3::read().1) };
        } else {
            // Attempt to recover
            // Worst case we spin through all the tasks and end up with only the idle task
            if (self.tasks.len() > 1) {
                let task_id = self.get_current_task().read().id;
                self.delete_task(task_id)
                    .expect("This should not be possible");
                self.reap_task();
                self.schedule_next();
                self.restore_page_table();
            }
        }
    }
    pub fn has_core_init(&self) -> bool {
        if let Some(task) = self.current_task.get(get_current_logical_id() as usize) {
            if *task == 0 {
                return false;
            }
            true
        } else {
            false
        }
    }
    pub fn runnable_task(&self) -> usize {
        let mut runnable_task = 0;
        for task in &self.tasks {
            if task.read().executer_id.is_none() {
                runnable_task += 1;
            }
        }
        runnable_task
    }
    pub fn should_idle(&self) -> bool {
        for task in &self.tasks {
            if task.read().name != "" && task.read().executer_id.is_none() {
                return false;
            }
        }
        return true;
    }

    // round-robin
    #[inline]
    pub fn schedule_next(&mut self) {
        let logical_id = get_current_logical_id() as usize;

        self.reap_task();

        if self.tasks.is_empty() {
            let kernel_task =
                Task::new_kernel_mode(kernel_main as usize, KERNEL_STACK_SIZE, "kernel".into(), 0);
            self.add_task(kernel_task);
        }

        if self.runnable_task() == 0 && !self.has_core_init() {
            let idle_task =
                Task::new_kernel_mode(idle_task as usize, KERNEL_STACK_SIZE, "".into(), 0);
            self.add_task(idle_task);
        }

        if !self.tasks.is_empty() {
            if self.has_core_init() {
                let id = *self
                    .current_task
                    .get(logical_id)
                    .expect("no current task for core");

                if let Some(handle) = self.get_task_by_id(id) {
                    handle.write().executer_id = None;
                }
                self.reset_task_by_id(id).expect("reset failed");
            }

            let next_task_id = if self.should_idle() {
                self.tasks
                    .iter()
                    .find(|h| {
                        let t = h.read();
                        t.name.is_empty() && t.executer_id.is_none() && !t.is_sleeping
                    })
                    .map(|h| h.read().id)
            } else {
                self.tasks
                    .iter()
                    .find(|h| {
                        let t = h.read();
                        !t.name.is_empty() && t.executer_id.is_none() && !t.is_sleeping
                    })
                    .map(|h| h.read().id)
            };

            if let Some(id) = next_task_id {
                self.current_task.set(logical_id, id);

                if let Some(handle) = self.get_task_by_id(id) {
                    handle.write().executer_id = Some(logical_id as u16);
                }
            }
        }
    }

    pub fn get_current_task(&self) -> TaskHandle {
        let logical_id = get_current_logical_id() as usize;
        let id = *self
            .current_task
            .get(logical_id)
            .expect("no current task for this core");

        self.get_task_by_id(id)
            .expect("scheduler lost current task")
    }

    /// Find a task by ID.  Clones the `Arc`, so the caller gets
    /// its own strong reference.
    pub fn get_task_by_id(&self, id: u64) -> Option<TaskHandle> {
        self.tasks.iter().find(|h| h.read().id == id).cloned()
    }

    /// Move the task to the back of the queue (round-robin reset).
    pub fn reset_task_by_id(&mut self, id: u64) -> Result<(), TaskError> {
        if let Some(idx) = self.tasks.iter().position(|h| h.read().id == id) {
            let handle = self.tasks.remove(idx).expect("index just found");
            self.tasks.push_back(handle);
            Ok(())
        } else {
            Err(TaskError::NotFound(id))
        }
    }

    /// Mark a task for deletion; it will be reaped next cycle.
    pub(crate) fn delete_task(&mut self, id: u64) -> Result<(), TaskError> {
        if let Some(handle) = self.get_task_by_id(id) {
            handle.write().terminated = true;
            Ok(())
        } else {
            Err(TaskError::NotFound(id))
        }
    }

    /// Look up a task by name and return a handle.
    pub(crate) fn get_task_by_name(&self, name: &str) -> Option<TaskHandle> {
        self.tasks.iter().find(|h| h.read().name == name).cloned()
    }
    fn reap_task(&mut self) {
        let core_id = get_current_logical_id() as u16;

        // Iterate from back to front so `remove(i)` is O(1) per removal.
        for i in (0..self.tasks.len()).rev() {
            // First, read-lock just long enough to check the flags.
            let should_reap = {
                let t = self.tasks[i].read();
                t.terminated && t.executer_id == Some(core_id)
            };

            if should_reap {
                // Clear per-core bookkeeping.
                self.current_task.set(core_id as usize, 0);

                // Destroy and drop the task under a write-lock.
                {
                    let mut t = self.tasks[i].write();
                    t.destroy();
                }

                // Remove the handle from the queue.
                self.tasks.remove(i);
            }
        }
    }

    /// Debug helper: print every task in the queue.
    fn print_task(&self) {
        for handle in &self.tasks {
            handle.read().print();
        }
    }
}
pub fn kernel_task_yield() {
    unsafe {
        asm!("int 0x20");
    }
}
pub fn kernel_task_end() -> ! {
    let syscall_number: u64 = 2;
    let arg1: u64;
    {
        let scheduler = SCHEDULER.lock();
        arg1 = scheduler.get_current_task().read().id;
    }
    unsafe {
        asm!(
        "mov rax, {0}",          //move syscall number into rax
        "mov r8, {1}",          //first argument
        "int 0x80",
        "2:",
        "jmp 2b",
        in(reg) syscall_number,
        in(reg) arg1,
        );
    }
    loop {}
}
