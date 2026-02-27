use alloc::sync::Arc;
use alloc::vec;
use crossbeam_queue::ArrayQueue;
use kernel_api::kernel_types::request::RequestData;
use kernel_api::request::{RequestHandle, RequestType, TraversalPolicy};
use kernel_api::status::DriverStatus;

/// Lock-free pool of reusable RequestHandle instances backed by a SegQueue.
/// Requests are created once (with BLOCK_SIZE backing storage) and recycled,
/// keeping steady-state I/O paths allocation-free.
pub struct RequestPool<const BLOCK_SIZE: usize> {
    queue: ArrayQueue<RequestHandle<'static>>,
}

impl<const BLOCK_SIZE: usize> RequestPool<BLOCK_SIZE> {
    pub fn new() -> Self {
        // Choose a fixed pool size large enough for expected parallelism; no resizing.
        // Default to 256 entries; tweak as needed.
        const DEFAULT_CAP: usize = 256;
        let queue = ArrayQueue::new(DEFAULT_CAP);
        let pool = Self { queue };
        // Pre-fill the pool; ignore push errors (would mean capacity miscalc).
        for _ in 0..DEFAULT_CAP {
            let _ = pool.queue.push(Self::make_request());
        }
        pool
    }

    fn make_request() -> RequestHandle<'static> {
        let data = vec![0u8; BLOCK_SIZE].into_boxed_slice();
        RequestHandle::new(
            RequestType::Write {
                offset: 0,
                len: BLOCK_SIZE,
                flush_write_through: false,
            },
            RequestData::from_boxed_bytes(data),
        )
    }

    fn pop_or_new(&self) -> RequestHandle<'static> {
        self.queue.pop().unwrap_or_else(Self::make_request)
    }

    fn push(&self, mut req: RequestHandle<'static>) {
        // Reset minimal per-call state; callers will overwrite the rest.
        if let RequestHandle::Owned(ref mut r) = req {
            r.completed = false;
            r.status = DriverStatus::ContinueStep;
            r.traversal_policy = TraversalPolicy::FailIfUnhandled;
            r.completion_routine = None;
            r.completion_context = 0;
            r.waker = None;
        }
        // If queue is full, drop the request (pool stays bounded and non-resizing).
        let _ = self.queue.push(req);
    }

    pub fn acquire(self: &Arc<Self>) -> PooledRequest<BLOCK_SIZE> {
        let handle = self.pop_or_new();
        PooledRequest {
            pool: Arc::clone(self),
            handle: Some(handle),
        }
    }
}

pub struct PooledRequest<const BLOCK_SIZE: usize> {
    pool: Arc<RequestPool<BLOCK_SIZE>>,
    handle: Option<RequestHandle<'static>>,
}

impl<const BLOCK_SIZE: usize> PooledRequest<BLOCK_SIZE> {
    #[inline]
    pub fn handle_mut(&mut self) -> &mut RequestHandle<'static> {
        self.handle.as_mut().expect("pooled request missing handle")
    }
}

impl<const BLOCK_SIZE: usize> Drop for PooledRequest<BLOCK_SIZE> {
    fn drop(&mut self) {
        if let Some(req) = self.handle.take() {
            self.pool.push(req);
        }
    }
}
