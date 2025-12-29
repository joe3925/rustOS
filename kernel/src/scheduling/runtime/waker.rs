use alloc::sync::Arc;
use alloc::task::Wake;
use core::task::Waker;

use crate::scheduling::runtime::task::FutureTask;

pub struct TaskWake {
    task: Arc<FutureTask>,
}

impl Wake for TaskWake {
    fn wake(self: Arc<Self>) {
        self.task.enqueue();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.task.enqueue();
    }
}

pub fn create(task: Arc<FutureTask>) -> Waker {
    Waker::from(Arc::new(TaskWake { task }))
}
