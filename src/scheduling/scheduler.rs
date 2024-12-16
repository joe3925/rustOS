use crate::scheduling::task::{idle_task, test_syscall, Task};
use alloc::vec::Vec;
use core::arch::asm;
use core::sync::atomic::{AtomicUsize, Ordering};
use lazy_static::lazy_static;
use spin::Mutex;
use crate::memory::paging::{allocate_infinite_loop_page, allocate_syscall_page};
pub enum TaskError {
    NotFound(u64),
}
// Global scheduler that contains a list of tasks
lazy_static! {
    pub static ref SCHEDULER: Mutex<Scheduler> = Mutex::new(Scheduler::new());
}

pub struct Scheduler {
    tasks: Vec<Task>,
    current_task: AtomicUsize,  // Index of the currently running task
}

impl Scheduler {
    pub fn new() -> Self {
        Self {
            tasks: Vec::with_capacity(150),
            current_task: AtomicUsize::new(0),
        }
    }

    // Add a new task to the scheduler
    #[inline]
    pub fn add_task(&mut self, task: Task) {
        self.tasks.push(task);
    }
    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    // Select the next task to run in a round-robin fashion
    #[inline]
    pub unsafe fn schedule_next(&mut self) {
        while self.tasks.len() < 1{
            //let user_idle_task = Task::new(allocate_syscall_page().expect("failed to alloc syscall page").as_u64() as usize, true); // Example idle task with kernel mode
            //let kernel_idle_task = Task::new(idle_task as usize, false); // Example idle task with kernel mode
            let kernel_idle_task = Task::new(test_syscall as usize, false); // Example idle task with kernel mode

            self.add_task(kernel_idle_task);
        }
        if self.tasks.len() > 0 {
            let next_task = (self.current_task.load(Ordering::SeqCst) + 1) % self.tasks.len();
            self.current_task.store(next_task, Ordering::SeqCst);
        }
    }

    // Get the currently selected task
    pub fn get_current_task(&mut self) -> &mut Task {
        let index = self.current_task.load(Ordering::SeqCst);
        &mut self.tasks[index]
    }

    pub fn end_task(&mut self, id: u64) -> Result<(), TaskError> {
        for i in 0..self.tasks.len() {
            if self.tasks[i].id == id {
                self.tasks[i].destroy();
                self.tasks.remove(i);
                return Ok(());
            }
        }
        Err(TaskError::NotFound(id))
    }
}
pub fn thr_yield() {
    unsafe {
        ;
    }
}
