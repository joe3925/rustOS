use crate::drivers::interrupt_index::get_current_logical_id;
use crate::executable::program::PROGRAM_MANAGER;
use crate::memory::paging::constants::KERNEL_STACK_SIZE;
use crate::scheduling::task::{idle_task, Task};
use crate::structs::per_core_storage::PCS;
use crate::util::kernel_main;
use alloc::collections::vec_deque::VecDeque;
use alloc::string::{String, ToString};
use core::arch::asm;
use lazy_static::lazy_static;
use spin::Mutex;
use x86_64::registers::control::Cr3;

#[derive(Debug)]
pub enum TaskError {
    NotFound(u64),
    BadName,
}
lazy_static! {
    pub static ref SCHEDULER: Mutex<Scheduler> = Mutex::new(Scheduler::new());
}

pub struct Scheduler {
    tasks: VecDeque<Task>,
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
    pub fn add_task(&mut self, mut task: Task) -> Result<(), TaskError> {
        task.id = self.id;
        self.id += 1;
        self.tasks.push_back(task);
        Ok(())
    }
    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }
    pub fn restore_page_table(&mut self) {
        let program_manager = PROGRAM_MANAGER.read();
        let program_option = { program_manager.get(self.get_current_task().parent_pid) };
        if let Some(program) = program_option {
            unsafe { Cr3::write(program.cr3, Cr3::read().1) };
        } else {
            // Attempt to recover
            // Worst case we spin through all the tasks and end up with only the idle task
            if (self.tasks.len() > 1) {
                let task_id = self.get_current_task().id;
                self.delete_task(task_id)
                    .expect("This should not be possible");
                self.reap_task();
                self.schedule_next();
                self.restore_page_table();
            }
        }
    }
    pub fn has_core_init(&self) -> bool{
        if let Some(task) = self.current_task.get(get_current_logical_id() as usize){
            if *task == 0 {
                return false;
            }
            true
        }else{
            false
        }
    }
    pub fn runnable_task(&self) -> usize {
        let mut runnable_task = 0;
        for task in &self.tasks {
            if task.executer_id.is_none() {
                runnable_task += 1;
            }
        }
        runnable_task
    }
    pub fn should_idle(&self) -> bool {
        for task in &self.tasks {
            if task.name != "" && task.executer_id.is_none() {
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
        if self.tasks.len() < 1 {
            let kernel_task = Task::new_kernel_mode(
                kernel_main as usize,
                KERNEL_STACK_SIZE,
                "kernel".to_string(),
                0,
            );
            self.add_task(kernel_task);
        }
        if (self.runnable_task() == 0 && !self.has_core_init()) {
            let idle_task = Task::new_kernel_mode(
                idle_task as usize,
                KERNEL_STACK_SIZE,
                "".to_string(),
                0,
            );
            self.add_task(idle_task);
        }

        if self.tasks.len() > 0 {

            if self.has_core_init() {
                let id = self.current_task.get(logical_id).map(|g| *g).unwrap();
                let current_task = self.get_task_by_id(id).unwrap();
                current_task.executer_id = None;
                self.reset_task_by_id(id).expect("This should not happen");
            }
            let next_task_id: Option<u64> = if self.should_idle() {
                self.tasks
                    .iter()
                    .find(|t| t.name == "" && t.executer_id.is_none())
                    .map(|t| t.id)
            } else {
                self.tasks
                    .iter()
                    .find(|t| t.name != "" && t.executer_id.is_none())
                    .map(|t| t.id)
            };

            if let Some(id) = next_task_id {
                self.current_task.set(logical_id, id);
                self.get_current_task().executer_id = Some(logical_id as u16);
            } else {
                return; 
            }
        }
    }

    pub fn get_current_task(&mut self) -> &mut Task {
        let task_id = {
            let guard = self
                .current_task
                .get(get_current_logical_id() as usize)
                .expect("no current task for this core");
            guard.clone()
        };
        self.get_task_by_id(task_id)
            .expect("scheduler lost current task")
    }
    pub fn get_task_by_id(&mut self, id: u64) -> Option<&mut Task> {
        for task in &mut self.tasks {
            if task.id == id {
                return Some(task);
            }
        }
        None
    }
    pub fn reset_task_by_id(&mut self, id: u64) -> Result<(), TaskError> {
        // Locate the index of the task (O(n))
        if let Some(idx) = self.tasks.iter().position(|t| t.id == id) {
            let task = self.tasks.remove(idx).expect("index just found");
            self.tasks.push_back(task);
            Ok(())
        } else {
            Err(TaskError::NotFound(id))
        }
    }
    ///marks task for deletion will be deleted next scheduler cycle
    pub(crate) fn delete_task(&mut self, id: u64) -> Result<(), TaskError> {
        if let Some(task) = self.get_task_by_id(id) {
            task.terminated = true;
            return Ok(());
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
    fn reap_task(&mut self) {
        for i in (0..self.tasks.len()).rev() {
            if self.tasks[i].terminated {
                if let Some(executer_id) = self.tasks[i].executer_id {
                    if(executer_id == get_current_logical_id() as u16){
                        self.current_task.set(executer_id as usize, 0);
                        self.tasks[i].destroy();
                        self.tasks.remove(i);
                    }
                }
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
        "2:",
        "jmp 2b",
        in(reg) syscall_number,
        in(reg) arg1,
        );
    }
    loop {}
}
