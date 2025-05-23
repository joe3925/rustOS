use crate::scheduling::task::{idle_task, Task};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::arch::asm;
use core::sync::atomic::{AtomicUsize, Ordering};
use lazy_static::lazy_static;
use spin::Mutex;
use crate::println;

pub enum TaskError {
    NotFound(u64),

}
lazy_static! {
    pub static ref SCHEDULER: Mutex<Scheduler> = Mutex::new(Scheduler::new());
}

pub struct Scheduler {
    tasks: Vec<Task>,
    current_task: AtomicUsize,
}

impl Scheduler {
    pub fn new() -> Self {
        Self {
            tasks: Vec::new(),
            current_task: AtomicUsize::new(0),
        }
    }

    #[inline]
    pub fn add_task(&mut self, task: Task) {
        self.tasks.push(task);
    }
    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    // round-robin
    #[inline]
    pub fn schedule_next(&mut self) {
        self.end_task();
        if self.tasks.len() < 1 {
            let kernel_idle_task = Task::new_kernelmode(idle_task as usize, 0x2800, "idle task".to_string());
            self.add_task(kernel_idle_task);
        }

        if self.tasks.len() > 0 {
            let mut next_task = (self.current_task.load(Ordering::SeqCst) + 1) % self.tasks.len();
            if (self.tasks.len() > 1) {
                let next_task_id = self.tasks[next_task].id;
                //don't schedule the idle task if there are other tasks available
                if (next_task_id == 0) {
                    next_task = (self.current_task.load(Ordering::SeqCst) + 2) % self.tasks.len();
                }
            }
            self.current_task.store(next_task, Ordering::SeqCst);
        }
    }

    pub fn get_current_task(&mut self) -> &mut Task {
        let index = self.current_task.load(Ordering::SeqCst);
        &mut self.tasks[index]
    }
    ///marks task for deletion will be deleted next scheduler cycle
    pub(crate) fn delete_task(&mut self, id: u64) -> Result<(), TaskError> {
        for i in 0..self.tasks.len() {
            if self.tasks[i].id == id {
                self.tasks[i].terminated = true;
                return Ok(());
            }
        }
        Err(TaskError::NotFound(id))
    }
    pub(crate) fn get_task_by_name(&mut self, name: String) -> Option<&mut Task> {
        for i in (0..self.tasks.len()) {
            if (self.tasks[i].name == name) {
                return Some(&mut self.tasks[i]);
            }
        }
        None
    }
    fn end_task(&mut self) {
        for i in (0..self.tasks.len()).rev() {
            if self.tasks[i].terminated {
                self.tasks[i].destroy();
                self.tasks.remove(i);
            }
        }
    }
    fn print_task(&self) {
        for task in &self.tasks {
            task.print();
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
        let mut scheduler = SCHEDULER.lock();
        arg1 = scheduler.get_current_task().id;
    }
    unsafe {
        asm!(
        "mov rax, {0}",          //move syscall number into rax
        "mov r8, {1}",          //first argument
        "int 0x80",
        in(reg) syscall_number,
        in(reg) arg1,
        );
    }
    loop {}
}
