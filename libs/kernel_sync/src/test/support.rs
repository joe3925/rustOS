use std::time::{Duration, Instant};

#[unsafe(no_mangle)]
extern "C" fn kernel_resolve_error_context_module(_instruction_pointer: usize) -> Option<String> {
    None
}
use crate::platform::StdPlatform;

pub(super) type P = StdPlatform;

const TIMEOUT: Duration = Duration::from_secs(5);

pub(super) fn recv_timeout<T>(rx: &std::sync::mpsc::Receiver<T>) -> T {
    rx.recv_timeout(TIMEOUT)
        .expect("timed out waiting for test event")
}

pub(super) fn wait_until(mut pred: impl FnMut() -> bool) {
    let start = Instant::now();
    while !pred() {
        assert!(start.elapsed() < TIMEOUT, "timed out waiting for condition");
        std::thread::yield_now();
    }
}
