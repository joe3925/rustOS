use std::time::{Duration, Instant};

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
mod channel;
mod mpmc;
mod sleep_mutex;
mod thread_pool;
mod wait_queue;
