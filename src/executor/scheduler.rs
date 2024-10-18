use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use lazy_static::lazy_static;
use spin::Mutex;
use crate::executor::state::State;
use crate::executor::task::{idle_task, Task};
use crate::println;


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
            tasks: Vec::new(),
            current_task: AtomicUsize::new(0),
        }
    }

    // Add a new task to the scheduler
    pub fn add_task(&mut self, task: Task) {
        self.tasks.push(task);
    }

    // Select the next task to run in a round-robin fashion
    pub fn schedule_next(&mut self) {
        if self.tasks.is_empty() {
            // If there are no tasks, add the idle task to prevent returning
            let idle_task = Task::new(idle_task as usize, 1024 * 10, true); // Example idle task with kernel mode
            self.add_task(idle_task);
        }
        if self.tasks.len() > 0 {
            self.get_current_task().context.update();


            let next_task = (self.current_task.load(Ordering::SeqCst) + 1) % self.tasks.len();
            self.current_task.store(next_task, Ordering::SeqCst);
            println!("State: {:#?}", self.get_current_task().context);
            println!("rsp: {:#?}", self.get_current_task().context.rsp);
            unsafe { self.get_current_task().context.restore(); }
        }

    }

    // Get the currently selected task
    pub fn get_current_task(&mut self) -> &mut Task {
        let index = self.current_task.load(Ordering::SeqCst);
        &mut self.tasks[index]
    }

    // Context switch between tasks
    pub fn context_switch(&mut self) {
        // Save the current task's state
        let current_task_index = self.current_task.load(Ordering::SeqCst);
        let mut current_task = &mut self.tasks[current_task_index];
        current_task.context.update();  // Save CPU context

        // Select the next task to run
        self.schedule_next();

        // Restore the next task's state
        let next_task_index = self.current_task.load(Ordering::SeqCst);
        current_task = &mut self.tasks[next_task_index];
        unsafe {
            current_task.context.restore();  // Restore CPU context for next task
        }
    }
}
