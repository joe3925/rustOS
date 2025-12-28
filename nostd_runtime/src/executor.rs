use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll};
use spin::{Mutex, Once};

use crate::submit_pump;
use crate::task::Task;
use crate::waker;

pub type TaskId = usize;

struct Slab {
    tasks: Vec<Option<Arc<Task>>>,
    free: Vec<TaskId>,
}

impl Slab {
    fn new() -> Self {
        Self {
            tasks: Vec::new(),
            free: Vec::new(),
        }
    }

    fn insert(&mut self, task: Arc<Task>) -> TaskId {
        if let Some(id) = self.free.pop() {
            if id >= self.tasks.len() {
                panic!("slab free id out of range");
            }
            if self.tasks[id].is_some() {
                panic!("slab free id points to occupied slot");
            }
            self.tasks[id] = Some(task);
            return id;
        }

        let id = self.tasks.len();
        self.tasks.push(Some(task));
        id
    }

    fn get(&self, id: TaskId) -> Option<Arc<Task>> {
        if id >= self.tasks.len() {
            return None;
        }
        self.tasks[id].as_ref().cloned()
    }

    fn remove(&mut self, id: TaskId) -> bool {
        if id >= self.tasks.len() {
            return false;
        }
        if self.tasks[id].take().is_some() {
            self.free.push(id);
            return true;
        }
        false
    }
}

pub struct ExecutorInner {
    slab: Mutex<Slab>,
    ready: Mutex<VecDeque<TaskId>>,
    pump_scheduled: AtomicBool,
}

impl ExecutorInner {
    pub fn new() -> Self {
        Self {
            slab: Mutex::new(Slab::new()),
            ready: Mutex::new(VecDeque::new()),
            pump_scheduled: AtomicBool::new(false),
        }
    }

    pub fn spawn<F>(self: &Arc<Self>, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let task = Arc::new(Task::new(Box::pin(future)));
        let id = self.insert_task(task);
        self.enqueue(id);
    }

    fn insert_task(self: &Arc<Self>, task: Arc<Task>) -> TaskId {
        let mut slab = self.slab.lock();
        slab.insert(task)
    }

    fn get_task(self: &Arc<Self>, id: TaskId) -> Option<Arc<Task>> {
        let slab = self.slab.lock();
        slab.get(id)
    }

    fn remove_task(self: &Arc<Self>, id: TaskId) {
        let mut slab = self.slab.lock();
        let _ = slab.remove(id);
    }

    pub fn enqueue(self: &Arc<Self>, id: TaskId) {
        let task = self.get_task(id);
        if task.is_none() {
            return;
        }
        let task = task.unwrap();

        if task.queued.swap(true, Ordering::AcqRel) {
            return;
        }

        {
            let mut ready = self.ready.lock();
            ready.push_back(id);
        }

        self.schedule_pump();
    }

    fn schedule_pump(self: &Arc<Self>) {
        if self
            .pump_scheduled
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            submit_pump();
        }
    }

    fn pop_ready(self: &Arc<Self>) -> Option<TaskId> {
        let mut ready = self.ready.lock();
        ready.pop_front()
    }

    fn ready_is_empty(self: &Arc<Self>) -> bool {
        let ready = self.ready.lock();
        ready.is_empty()
    }

    pub fn pump(self: &Arc<Self>) {
        loop {
            let id = match self.pop_ready() {
                Some(x) => x,
                None => break,
            };

            let task = match self.get_task(id) {
                Some(t) => t,
                None => continue,
            };

            task.queued.store(false, Ordering::Release);

            let wk = waker::create_waker(id, self.clone());
            let mut cx = Context::from_waker(&wk);

            let poll_res = {
                let mut fut = task.future.lock();
                fut.as_mut().poll(&mut cx)
            };

            if let Poll::Ready(()) = poll_res {
                self.remove_task(id);
            }
        }

        self.pump_scheduled.store(false, Ordering::Release);

        if !self.ready_is_empty() {
            self.schedule_pump();
        }
    }
}

pub struct Executor {
    inner: Arc<ExecutorInner>,
}

impl Executor {
    fn new() -> Self {
        Self {
            inner: Arc::new(ExecutorInner::new()),
        }
    }

    pub fn global() -> &'static Executor {
        static EXEC: Once<Executor> = Once::new();
        EXEC.call_once(Executor::new)
    }

    pub fn spawn<F>(&self, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.inner.spawn(future);
    }

    pub fn pump(&self) {
        self.inner.pump();
    }
}

#[inline(never)]
pub extern "win64" fn pump_trampoline(_ctx: usize) {
    Executor::global().pump();
}
