use std::time::{Duration, Instant};

#[unsafe(no_mangle)]
extern "C" fn kernel_resolve_error_context_module(_instruction_pointer: usize) -> Option<String> {
    None
}

use crate::platform::StdPlatform;

type P = StdPlatform;

const TIMEOUT: Duration = Duration::from_secs(5);

fn recv_timeout<T>(rx: &std::sync::mpsc::Receiver<T>) -> T {
    rx.recv_timeout(TIMEOUT)
        .expect("timed out waiting for test event")
}

fn wait_until(mut pred: impl FnMut() -> bool) {
    let start = Instant::now();
    while !pred() {
        assert!(start.elapsed() < TIMEOUT, "timed out waiting for condition");
        std::thread::yield_now();
    }
}

mod bounded_mpmc;
mod bounded_wait_queue;
mod completion_port;
mod mpmc;
mod thread_pool;
mod wait_queue;
