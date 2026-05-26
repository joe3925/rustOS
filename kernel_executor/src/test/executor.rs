use alloc::{format, string::ToString, sync::Arc, vec::Vec};
use core::future::Future;
use core::mem::{align_of, size_of, size_of_val};
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::process::exit;
use std::sync::{Condvar, Mutex};
use std::time::Duration;

use crate::runtime::runtime::{block_on, spawn, JoinAll};
use crate::runtime::slab::{INLINE_FUTURE_ALIGN, JOINABLE_STORAGE_SIZE};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener as TokioTcpListener;
use tokio::net::TcpStream as TokioTcpStream;
use tokio::runtime::{Builder, Handle};
use tokio::sync::{Mutex as TokioMutex, Semaphore};

const DEFAULT_HTTP_STRESS_TASKS: usize = 1_000_000;
const REQUESTS_PER_TASK: usize = 3;

// Windows will run out of sockets if this number is too big
const NETWORK_CONCURRENCY_PER_SHARD: usize = 32;

const LARGE_FUTURE_PADDING: usize = JOINABLE_STORAGE_SIZE + 1;
const WATCHDOG_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Clone, Copy)]
enum HttpStressFutureSet {
    InlineOnly,
    LargeOnly,
    MixedInlineAndLarge,
}

impl HttpStressFutureSet {
    fn is_large(self, task_id: usize) -> bool {
        match self {
            Self::InlineOnly => false,
            Self::LargeOnly => true,
            Self::MixedInlineAndLarge => task_id % 2 == 1,
        }
    }

    fn expects_inline(self) -> bool {
        matches!(self, Self::InlineOnly | Self::MixedInlineAndLarge)
    }

    fn expects_large(self) -> bool {
        matches!(self, Self::LargeOnly | Self::MixedInlineAndLarge)
    }

    fn label(self) -> &'static str {
        match self {
            Self::InlineOnly => "inline futures",
            Self::LargeOnly => "large futures",
            Self::MixedInlineAndLarge => "mixed inline and large futures",
        }
    }
}

struct ProgressWatchdog {
    stop: Arc<(Mutex<bool>, Condvar)>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl ProgressWatchdog {
    fn start(label: &'static str, progress: Arc<AtomicUsize>) -> Self {
        let stop = Arc::new((Mutex::new(false), Condvar::new()));
        let stop_for_thread = stop.clone();

        let thread = std::thread::Builder::new()
            .name(format!("executor stress watchdog: {label}"))
            .spawn(move || {
                let mut last_progress = progress.load(Ordering::Acquire);

                loop {
                    let (lock, condvar) = &*stop_for_thread;
                    let guard = lock.lock().expect("executor stress watchdog stop lock");

                    let (guard, timeout) = condvar
                        .wait_timeout(guard, WATCHDOG_INTERVAL)
                        .expect("executor stress watchdog stop condvar");

                    if *guard {
                        break;
                    }

                    if !timeout.timed_out() {
                        continue;
                    }

                    drop(guard);

                    let current_progress = progress.load(Ordering::Acquire);
                    if current_progress == last_progress {
                        std::eprintln!(
                            "executor stress watchdog failed {label}: no progress for {:?}; progress counter stayed at {current_progress}",
                            WATCHDOG_INTERVAL
                        );
                        exit(1);
                    }

                    last_progress = current_progress;
                }
            })
            .expect("spawn executor stress watchdog thread");

        Self {
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for ProgressWatchdog {
    fn drop(&mut self) {
        let (lock, condvar) = &*self.stop;
        *lock.lock().expect("executor stress watchdog stop lock") = true;
        condvar.notify_all();

        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct LargeExecutorHttpTask<F> {
    inner: F,
    _padding: [u8; LARGE_FUTURE_PADDING],
}

impl<F> LargeExecutorHttpTask<F> {
    fn new(inner: F) -> Self {
        Self {
            inner,
            _padding: [0xA5; LARGE_FUTURE_PADDING],
        }
    }
}

impl<F: Future> Future for LargeExecutorHttpTask<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: `inner` is structurally pinned when `Self` is pinned, and this
        // projection does not move it.
        unsafe { self.map_unchecked_mut(|this| &mut this.inner) }.poll(cx)
    }
}

struct AsyncStartGate {
    open: AtomicBool,
    parked: AtomicUsize,
    waiters: Mutex<Vec<Waker>>,
}

impl AsyncStartGate {
    fn new() -> Self {
        Self {
            open: AtomicBool::new(false),
            parked: AtomicUsize::new(0),
            waiters: Mutex::new(Vec::new()),
        }
    }

    fn wait(self: &Arc<Self>) -> AsyncStartGateWait {
        AsyncStartGateWait {
            gate: self.clone(),
            registered: false,
        }
    }

    fn parked_count(&self) -> usize {
        self.parked.load(Ordering::Acquire)
    }

    fn open(&self) {
        let waiters = {
            let mut guard = self.waiters.lock().expect("async start gate waiters lock");
            self.open.store(true, Ordering::Release);
            core::mem::take(&mut *guard)
        };

        for waker in waiters {
            waker.wake();
        }
    }
}

struct AsyncStartGateWait {
    gate: Arc<AsyncStartGate>,
    registered: bool,
}

impl Future for AsyncStartGateWait {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        if this.gate.open.load(Ordering::Acquire) {
            return Poll::Ready(());
        }

        let mut guard = this
            .gate
            .waiters
            .lock()
            .expect("async start gate waiters lock");

        if this.gate.open.load(Ordering::Acquire) {
            return Poll::Ready(());
        }

        if !this.registered {
            guard.push(cx.waker().clone());
            this.registered = true;
            this.gate.parked.fetch_add(1, Ordering::AcqRel);
        }

        Poll::Pending
    }
}

struct YieldRounds {
    remaining: usize,
}

impl Future for YieldRounds {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.remaining == 0 {
            Poll::Ready(())
        } else {
            this.remaining -= 1;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

struct LocalHttpServer {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    accept_task: tokio::task::JoinHandle<()>,
}

impl LocalHttpServer {
    fn start(tokio: &Handle, progress: Arc<AtomicUsize>) -> Self {
        let listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind executor stress HTTP server");
        listener
            .set_nonblocking(true)
            .expect("set executor stress HTTP server nonblocking");

        let addr = listener
            .local_addr()
            .expect("read executor stress HTTP server addr");
        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_task = stop.clone();
        let accept_task = {
            let _guard = tokio.enter();
            let listener =
                TokioTcpListener::from_std(listener).expect("convert executor stress listener");
            tokio.spawn(run_http_server(listener, stop_for_task, progress))
        };

        Self {
            addr,
            stop,
            accept_task,
        }
    }

    fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for LocalHttpServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.addr);
        self.accept_task.abort();
    }
}

async fn run_http_server(
    listener: TokioTcpListener,
    stop: Arc<AtomicBool>,
    progress: Arc<AtomicUsize>,
) {
    while !stop.load(Ordering::Acquire) {
        match listener.accept().await {
            Ok((stream, _)) => {
                progress.fetch_add(1, Ordering::AcqRel);
                tokio::spawn(handle_http_connection(stream, progress.clone()));
            }
            Err(_) if stop.load(Ordering::Acquire) => break,
            Err(err) => panic!("executor stress HTTP accept failed: {err}"),
        }
    }
}

async fn handle_http_connection(mut stream: TokioTcpStream, progress: Arc<AtomicUsize>) {
    loop {
        let Some((task_id, round)) = read_http_request(&mut stream).await else {
            return;
        };
        progress.fetch_add(1, Ordering::AcqRel);

        let value = request_value(task_id, round);
        let body = value.to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{}",
            body.len(),
            body
        );

        stream
            .write_all(response.as_bytes())
            .await
            .expect("write executor stress HTTP response");
        progress.fetch_add(1, Ordering::AcqRel);
    }
}

async fn read_http_request(stream: &mut TokioTcpStream) -> Option<(usize, usize)> {
    let mut request = Vec::with_capacity(1024);
    let mut buf = [0u8; 512];

    loop {
        let n = stream
            .read(&mut buf)
            .await
            .expect("read executor stress HTTP request");
        if n == 0 {
            return None;
        }

        request.extend_from_slice(&buf[..n]);
        if request.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let request = core::str::from_utf8(&request).unwrap_or("");
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");

    Some(parse_work_path(path))
}

fn parse_work_path(path: &str) -> (usize, usize) {
    let mut parts = path.trim_start_matches('/').split('/');
    let kind = parts.next();
    let task_id = parts.next().and_then(|s| s.parse().ok());
    let round = parts.next().and_then(|s| s.parse().ok());

    match (kind, task_id, round) {
        (Some("work"), Some(task_id), Some(round)) => (task_id, round),
        _ => panic!("unexpected executor stress HTTP path: {path}"),
    }
}

fn request_value(task_id: usize, round: usize) -> u64 {
    let mut value = task_id as u64;
    value ^= (round as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    value = value.rotate_left((round as u32) & 31);
    value ^ 0xA5A5_5A5A_D3C3_B4B4
}

async fn http_get_value(
    addr: SocketAddr,
    task_id: usize,
    round: usize,
    permits: Arc<Semaphore>,
    connections: Arc<TokioMutex<Vec<TokioTcpStream>>>,
    progress: Arc<AtomicUsize>,
) -> u64 {
    let _permit = permits
        .acquire_owned()
        .await
        .expect("executor stress HTTP semaphore closed");
    progress.fetch_add(1, Ordering::AcqRel);

    let mut stream = match connections.lock().await.pop() {
        Some(stream) => stream,
        None => TokioTcpStream::connect(addr)
            .await
            .expect("connect executor stress HTTP server"),
    };
    let request = format!(
        "GET /work/{task_id}/{round} HTTP/1.1\r\nHost: {addr}\r\nConnection: keep-alive\r\n\r\n"
    );

    stream
        .write_all(request.as_bytes())
        .await
        .expect("write executor stress HTTP request");
    progress.fetch_add(1, Ordering::AcqRel);

    let body = read_http_body(&mut stream).await;
    progress.fetch_add(1, Ordering::AcqRel);
    connections.lock().await.push(stream);

    let body = core::str::from_utf8(&body).expect("executor stress HTTP response body not UTF-8");

    body.trim()
        .parse()
        .expect("executor stress HTTP response body not u64")
}

async fn read_http_body(stream: &mut TokioTcpStream) -> Vec<u8> {
    let mut response = Vec::with_capacity(256);
    let mut buf = [0u8; 256];
    let header_end = loop {
        let n = stream
            .read(&mut buf)
            .await
            .expect("read executor stress HTTP response");
        if n == 0 {
            panic!("executor stress HTTP server closed connection before response");
        }

        response.extend_from_slice(&buf[..n]);

        if let Some(idx) = response.windows(4).position(|w| w == b"\r\n\r\n") {
            break idx + 4;
        }
    };

    let headers = core::str::from_utf8(&response[..header_end])
        .expect("executor stress HTTP response headers not UTF-8");
    let content_length = headers
        .lines()
        .find_map(|line| {
            line.strip_prefix("Content-Length:")
                .or_else(|| line.strip_prefix("content-length:"))
                .and_then(|value| value.trim().parse::<usize>().ok())
        })
        .expect("executor stress HTTP response missing content length");
    let expected_len = header_end + content_length;

    while response.len() < expected_len {
        let n = stream
            .read(&mut buf)
            .await
            .expect("read executor stress HTTP response body");
        if n == 0 {
            panic!("executor stress HTTP server closed connection during response body");
        }

        response.extend_from_slice(&buf[..n]);
    }

    response[header_end..expected_len].to_vec()
}

async fn run_executor_http_task(
    task_id: usize,
    gate: Arc<AsyncStartGate>,
    tokio: Handle,
    addr: SocketAddr,
    permits: Arc<Semaphore>,
    connections: Arc<TokioMutex<Vec<TokioTcpStream>>>,
    progress: Arc<AtomicUsize>,
) -> u64 {
    progress.fetch_add(1, Ordering::AcqRel);
    gate.wait().await;
    progress.fetch_add(1, Ordering::AcqRel);

    let mut checksum = 0u64;
    let mut round = 0usize;
    while round < REQUESTS_PER_TASK {
        YieldRounds { remaining: 2 }.await;
        progress.fetch_add(1, Ordering::AcqRel);

        let permits = permits.clone();
        let connections = connections.clone();
        let progress_for_request = progress.clone();
        let request = tokio.spawn(http_get_value(
            addr,
            task_id,
            round,
            permits,
            connections,
            progress_for_request,
        ));
        let value = request
            .await
            .expect("executor stress Tokio request task panicked");
        progress.fetch_add(1, Ordering::AcqRel);

        assert_eq!(value, request_value(task_id, round));
        checksum ^= value;
        round += 1;
    }

    progress.fetch_add(1, Ordering::AcqRel);
    checksum
}

fn stress_task_total() -> usize {
    std::env::var("KERNEL_EXECUTOR_HTTP_STRESS_TASKS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_HTTP_STRESS_TASKS)
}

fn stress_network_concurrency() -> usize {
    let default = super::test_shard_count() * NETWORK_CONCURRENCY_PER_SHARD;
    std::env::var("KERNEL_EXECUTOR_HTTP_STRESS_CONCURRENCY")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
        .max(1)
}

fn expected_task_checksum(task_id: usize) -> u64 {
    let mut checksum = 0u64;
    let mut round = 0usize;
    while round < REQUESTS_PER_TASK {
        checksum ^= request_value(task_id, round);
        round += 1;
    }
    checksum
}

fn assert_future_fits_joinable_inline_storage<F>(future: &F)
where
    F: Future,
{
    assert!(
        size_of_val(future) <= JOINABLE_STORAGE_SIZE,
        "expected executor stress future to fit joinable inline storage: size {} > {}",
        size_of_val(future),
        JOINABLE_STORAGE_SIZE
    );
    assert!(
        align_of::<F>() <= INLINE_FUTURE_ALIGN,
        "expected executor stress future alignment to fit joinable inline storage: align {} > {}",
        align_of::<F>(),
        INLINE_FUTURE_ALIGN
    );
    assert!(
        size_of::<F::Output>() <= JOINABLE_STORAGE_SIZE,
        "expected executor stress result to fit joinable inline storage: size {} > {}",
        size_of::<F::Output>(),
        JOINABLE_STORAGE_SIZE
    );
    assert!(
        align_of::<F::Output>() <= INLINE_FUTURE_ALIGN,
        "expected executor stress result alignment to fit joinable inline storage: align {} > {}",
        align_of::<F::Output>(),
        INLINE_FUTURE_ALIGN
    );
}

fn assert_future_exceeds_joinable_inline_storage<F>(future: &F)
where
    F: Future,
{
    assert!(
        size_of_val(future) > JOINABLE_STORAGE_SIZE,
        "expected executor stress future to exceed joinable inline storage: size {} <= {}",
        size_of_val(future),
        JOINABLE_STORAGE_SIZE
    );
    assert!(
        align_of::<F>() <= INLINE_FUTURE_ALIGN,
        "large executor stress future should miss inline storage by size, not alignment: align {} > {}",
        align_of::<F>(),
        INLINE_FUTURE_ALIGN
    );
    assert!(
        size_of::<F::Output>() <= JOINABLE_STORAGE_SIZE,
        "expected executor stress result to fit joinable inline storage: size {} > {}",
        size_of::<F::Output>(),
        JOINABLE_STORAGE_SIZE
    );
    assert!(
        align_of::<F::Output>() <= INLINE_FUTURE_ALIGN,
        "expected executor stress result alignment to fit joinable inline storage: align {} > {}",
        align_of::<F::Output>(),
        INLINE_FUTURE_ALIGN
    );
}

fn run_saturated_executor_http_test(future_set: HttpStressFutureSet) {
    let _guard = super::global_runtime_lock();
    super::init_threaded_runtime();

    let task_count = stress_task_total();
    let progress = Arc::new(AtomicUsize::new(0));
    let tokio = Arc::new(
        Builder::new_multi_thread()
            .worker_threads(super::test_shard_count().max(2))
            .enable_io()
            .build()
            .expect("build executor stress Tokio runtime"),
    );
    let server = LocalHttpServer::start(tokio.handle(), progress.clone());
    let permits = Arc::new(Semaphore::new(stress_network_concurrency()));
    let connections = Arc::new(TokioMutex::new(Vec::with_capacity(
        stress_network_concurrency(),
    )));
    let gate = Arc::new(AsyncStartGate::new());

    let mut saw_inline = false;
    let mut saw_large = false;
    let mut handles = Vec::with_capacity(task_count);
    for task_id in 0..task_count {
        let future = run_executor_http_task(
            task_id,
            gate.clone(),
            tokio.handle().clone(),
            server.addr(),
            permits.clone(),
            connections.clone(),
            progress.clone(),
        );

        if future_set.is_large(task_id) {
            let future = LargeExecutorHttpTask::new(future);
            if !saw_large {
                assert_future_exceeds_joinable_inline_storage(&future);
                saw_large = true;
            }
            handles.push(spawn(future));
        } else {
            if !saw_inline {
                assert_future_fits_joinable_inline_storage(&future);
                saw_inline = true;
            }
            handles.push(spawn(future));
        }

        progress.fetch_add(1, Ordering::AcqRel);
    }

    assert_eq!(saw_inline, future_set.expects_inline());
    assert_eq!(saw_large, future_set.expects_large());

    super::wait_until(Duration::from_secs(60), || {
        gate.parked_count() == task_count
    });
    gate.open();
    progress.fetch_add(1, Ordering::AcqRel);

    let watchdog = ProgressWatchdog::start(future_set.label(), progress.clone());
    let results = block_on(async { JoinAll::new(handles).await });
    drop(watchdog);

    assert_eq!(results.len(), task_count);
    for (task_id, value) in results.into_iter().enumerate() {
        assert_eq!(value, expected_task_checksum(task_id));
    }
}

// This test exists to saturate the executor with 1,000,000 resident async
// loopback HTTP tasks whose future type is small enough for joinable inline
// storage. It protects the executor path used by compact request futures.
#[test]
fn saturated_executor_handles_1m_async_loopback_http_tasks_inline_futures() {
    run_saturated_executor_http_test(HttpStressFutureSet::InlineOnly);
}

// This test exists to saturate the executor with 1,000,000 resident async
// loopback HTTP tasks whose future type is too large for joinable inline
// storage. It forces the oversized future path while keeping the same network,
// yielding, wake, and JoinAll behavior as the inline-sized stress case.
#[test]
fn saturated_executor_handles_1m_async_loopback_http_tasks_large_futures() {
    run_saturated_executor_http_test(HttpStressFutureSet::LargeOnly);
}

// This test exists to keep inline-sized and oversized async loopback HTTP
// futures resident in the executor at the same time. The submission loop
// alternates both future sizes and every task parks behind one start gate before
// the gate opens, so the large futures cannot start only after the small futures
// have completed.
#[test]
fn saturated_executor_handles_1m_async_loopback_http_tasks_mixed_inline_and_large_futures() {
    run_saturated_executor_http_test(HttpStressFutureSet::MixedInlineAndLarge);
}
