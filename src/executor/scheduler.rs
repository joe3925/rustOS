use alloc::collections::VecDeque;
use core::task::{Context, Poll, Waker};
use lazy_static::lazy_static;
use spin::Mutex;
use crate::executor::task::Task;

pub struct Scheduler {
    tasks: VecDeque<Task>,
    waker: Option<Waker>,  // Optional: to store the waker for future use
}

impl Scheduler {
    pub fn new() -> Scheduler {
        Scheduler {
            tasks: VecDeque::new(),
            waker: None,
        }
    }

    pub fn add_task(&mut self, task: Task) {
        self.tasks.push_back(task);
    }

    pub fn poll_next_task(&mut self, context: &mut Context) {
        if let Some(mut task) = self.tasks.pop_front() {
            match task.poll(context) {
                Poll::Ready(()) => {
                    // Task completed, don't re-add to the queue
                }
                Poll::Pending => {
                    // Task is still pending, re-add it to the queue
                    self.tasks.push_back(task);
                }
            }
        }
    }

    pub fn run(&mut self, context: &mut Context) {
        if !self.tasks.is_empty() {
            self.poll_next_task(context);
        }
    }
}

lazy_static! {
    pub static ref SCHEDULER: Mutex<Scheduler> = Mutex::new(Scheduler::new());
}