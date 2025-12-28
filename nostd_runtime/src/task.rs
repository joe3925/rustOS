// task.rs
use alloc::boxed::Box;
use core::pin::Pin;
use core::sync::atomic::AtomicBool;
use core::task::Poll;
use spin::Mutex;

pub struct Task {
    pub future: Mutex<Pin<Box<dyn core::future::Future<Output = ()> + Send + 'static>>>,
    pub queued: AtomicBool,
}

impl Task {
    pub fn new(fut: Pin<Box<dyn core::future::Future<Output = ()> + Send + 'static>>) -> Self {
        Self {
            future: Mutex::new(fut),
            queued: AtomicBool::new(false),
        }
    }
}
