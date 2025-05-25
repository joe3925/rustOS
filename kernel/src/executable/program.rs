use alloc::{string::String, vec::Vec};
use lazy_static::lazy_static;
use spin::{Mutex, RwLock};
use x86_64::PhysAddr;

pub struct Program {
    pub title: String,
    pub pid: u64,
    pub image_base: usize,
    pub main_thread_id: u64,
    pub managed_threads: Mutex<Vec<u64>>,
    pub cr3: PhysAddr,
}

pub struct ProgramManager {
    programs: Vec<Program>,
    next_pid: u64,
}

impl ProgramManager {
    pub const fn new() -> Self {
        Self {
            programs: Vec::new(),
            next_pid: 1,
        }
    }

    pub fn add_program(&mut self, mut program: Program) -> u64 {
        let pid = self.next_pid;
        self.next_pid += 1;
        program.pid = pid;
        self.programs.push(program);
        pid
    }

    pub fn get(&self, pid: u64) -> Option<&Program> {
        self.programs.iter().find(|p| p.pid == pid)
    }

    pub fn get_mut(&mut self, pid: u64) -> Option<&mut Program> {
        self.programs.iter_mut().find(|p| p.pid == pid)
    }

    pub fn all(&self) -> &Vec<Program> {
        &self.programs
    }
}

lazy_static! {
    pub static ref PROGRAM_MANAGER: RwLock<ProgramManager> =
        RwLock::new(ProgramManager::new());
}
