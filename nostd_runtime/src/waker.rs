// waker.rs
use alloc::sync::Arc;
use alloc::task::Wake;
use core::task::Waker;

use crate::executor::{ExecutorInner, TaskId};

pub struct TaskWake {
    id: TaskId,
    exec: Arc<ExecutorInner>,
}

impl Wake for TaskWake {
    fn wake(self: Arc<Self>) {
        self.exec.enqueue(self.id);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.exec.enqueue(self.id);
    }
}

pub fn create_waker(id: TaskId, exec: Arc<ExecutorInner>) -> Waker {
    Waker::from(Arc::new(TaskWake { id, exec }))
}
