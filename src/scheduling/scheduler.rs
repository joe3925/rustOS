use crate::scheduling::task::{idle_task, Task};
use alloc::vec::Vec;
use core::arch::asm;
use core::sync::atomic::{AtomicUsize, Ordering};
use lazy_static::lazy_static;
use spin::Mutex;

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
            tasks: Vec::with_capacity(25),
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
        if self.tasks.len() < 1{
            let idle_task = Task::new(idle_task as usize, 1024 * 10, false); // Example idle task with kernel mode
            self.add_task(idle_task);
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
}
pub fn thr_yield() {
    unsafe {
        asm!("int 0x20");
    }
}
