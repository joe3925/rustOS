use crate::executable::program::PROGRAM_MANAGER;
use crate::memory::paging::{KERNEL_CR3_U64, KERNEL_STACK_SIZE};
use crate::println;
use crate::scheduling::task::{idle_task, Task};
use crate::util::kernel_main;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::arch::asm;
use core::sync::atomic::{AtomicUsize, Ordering};
use lazy_static::lazy_static;
use spin::Mutex;
use x86_64::registers::control::Cr3;

pub enum TaskError {
    NotFound(u64),
}
lazy_static! {
    pub static ref SCHEDULER: Mutex<Scheduler> = Mutex::new(Scheduler::new());
}

pub struct Scheduler {
    tasks: Vec<Task>,
    current_task: AtomicUsize,
    id: u64,
}

impl Scheduler {
    pub fn new() -> Self {
        Self {
            tasks: Vec::new(),
            current_task: AtomicUsize::new(0),
            id: 0,
        }
    }

    #[inline]
    pub fn add_task(&mut self, mut task: Task) {
        task.id = self.id;
        self.id += 1;
        self.tasks.push(task);
    }
    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }
    pub fn restore_page_table(&mut self) {
        if let Some(prorgam) = PROGRAM_MANAGER
            .read()
            .get(self.get_current_task().parent_pid)
        {
            unsafe { Cr3::write(prorgam.cr3, Cr3::read().1) };
        } else {
            // Attempt to recover
            // Worse case we spin through all the tasks and end up with only the idle task
            if (self.tasks.len() > 1) {
                let task_id = self.get_current_task().id;
                self.delete_task(task_id);
                self.schedule_next();
                self.restore_page_table();
            }
        }
    }

    // round-robin
    #[inline]
    pub fn schedule_next(&mut self) {
        self.end_task();
        if self.tasks.len() < 1 {
            let kernel_task = Task::new_kernelmode(
                kernel_main as usize,
                KERNEL_STACK_SIZE,
                "kernel".to_string(),
                0,
            );
            self.add_task(kernel_task);
        }

        if self.tasks.len() > 0 {
            let next_task = (self.current_task.load(Ordering::SeqCst) + 1) % self.tasks.len();
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
