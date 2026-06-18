use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::{Context, Poll};

use kernel_executor::global_async::{ExecutorDomainId, KERNEL_NORMAL_EXECUTOR_DOMAIN};
use kernel_executor::runtime::runtime::spawn_detached_in_executor_domain;
use kernel_sync::bounded_mpmc::BoundedSendError;
use kernel_sync::mpmc::TryRecvError;

use crate::sync_platform::{
    bounded_mpmc_channel, BoundedMpmcReceiver as BoundedReceiver,
    BoundedMpmcSender as BoundedSender,
};

use super::io_request::{
    CompleteTransition, IoOpcode, IoRequestFuture, IoRequestOutput, IoRequestTable, KernelIoOp,
    RequestId, RequestTableError, UserIoCompletion, IO_STATUS_CANCELLED,
};

pub struct CompletionQueue {
    pub owner_pid: u64,
    pub bound_executor_domain: ExecutorDomainId,
    pub request_capacity: usize,
    pub completion_capacity: usize,
    pub flags: u64,

    request_table: IoRequestTable,
    completion_sender: BoundedSender<UserIoCompletion>,
    completion_receiver: BoundedReceiver<UserIoCompletion>,
    completion_permits: AtomicUsize,
}

impl core::fmt::Debug for CompletionQueue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CompletionQueue")
            .field("owner_pid", &self.owner_pid)
            .field("bound_executor_domain", &self.bound_executor_domain)
            .field("request_capacity", &self.request_capacity)
            .field("completion_capacity", &self.completion_capacity)
            .field("flags", &self.flags)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletionQueueError {
    InvalidCapacity,
    RequestTableFull,
    CompletionQueueFull,
    RequestNotFound,
    RequestAlreadyComplete,
}

impl CompletionQueue {
    pub fn new(
        owner_pid: u64,
        request_capacity: usize,
        completion_capacity: usize,
        flags: u64,
    ) -> Result<Arc<Self>, CompletionQueueError> {
        if request_capacity == 0 || completion_capacity == 0 {
            return Err(CompletionQueueError::InvalidCapacity);
        }

        let max_waiters = request_capacity.max(1);
        let (completion_sender, completion_receiver) =
            bounded_mpmc_channel(completion_capacity, max_waiters);

        Ok(Arc::new(Self {
            owner_pid,
            bound_executor_domain: KERNEL_NORMAL_EXECUTOR_DOMAIN,
            request_capacity,
            completion_capacity,
            flags,
            request_table: IoRequestTable::new(request_capacity),
            completion_sender,
            completion_receiver,
            completion_permits: AtomicUsize::new(completion_capacity),
        }))
    }

    pub fn enqueue(self: &Arc<Self>, op: KernelIoOp) -> Result<RequestId, CompletionQueueError> {
        self.reserve_completion_permit()?;

        let request_id = match self.request_table.allocate() {
            Ok(request_id) => request_id,
            Err(RequestTableError::Full) => {
                self.release_completion_permit();
                return Err(CompletionQueueError::RequestTableFull);
            }
            Err(_) => {
                self.release_completion_permit();
                return Err(CompletionQueueError::RequestTableFull);
            }
        };

        let opcode = op.opcode();
        let user_token = op.user_token();
        let future = IoRequestDriverFuture {
            queue: self.clone(),
            request_id,
            opcode,
            user_token,
            inner: op.into_future(),
        };

        spawn_detached_in_executor_domain(self.bound_executor_domain, future);
        Ok(request_id)
    }

    pub fn enqueue_many(
        self: &Arc<Self>,
        ops: impl IntoIterator<Item = KernelIoOp>,
        out_ids: &mut [RequestId],
    ) -> usize {
        let mut submitted = 0usize;

        for (idx, op) in ops.into_iter().enumerate() {
            if idx >= out_ids.len() {
                break;
            }

            match self.enqueue(op) {
                Ok(request_id) => {
                    out_ids[idx] = request_id;
                    submitted += 1;
                }
                Err(_) => break,
            }
        }

        submitted
    }

    pub fn poll_completions(&self, out: &mut [UserIoCompletion]) -> usize {
        let mut count = 0usize;

        while count < out.len() {
            let completion = match self.completion_receiver.try_recv() {
                Ok(completion) => completion,
                Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => break,
            };

            self.request_table.reap(completion.request_id);
            self.release_completion_permit();
            out[count] = completion;
            count += 1;
        }

        count
    }

    pub fn wait_completions(&self, out: &mut [UserIoCompletion], timeout_ns: u64) -> usize {
        if out.is_empty() {
            return 0;
        }

        let count = self.poll_completions(out);
        if count != 0 || timeout_ns == 0 {
            return count;
        }

        if timeout_ns == u64::MAX {
            let first = match self.completion_receiver.recv() {
                Ok(completion) => completion,
                Err(_) => return 0,
            };

            self.request_table.reap(first.request_id);
            self.release_completion_permit();
            out[0] = first;
            return 1 + self.poll_completions(&mut out[1..]);
        }

        let timer = crate::structs::stopwatch::Stopwatch::start();
        loop {
            let count = self.poll_completions(out);
            if count != 0 {
                return count;
            }
            if timer.elapsed_nanos() >= timeout_ns {
                return 0;
            }

            crate::scheduling::runtime::runtime::yield_now();
        }
    }

    pub fn cancel(&self, request_id: RequestId) -> Result<(), CompletionQueueError> {
        self.request_table
            .cancel(request_id)
            .map_err(|err| match err {
                RequestTableError::NotFound => CompletionQueueError::RequestNotFound,
                RequestTableError::AlreadyComplete => CompletionQueueError::RequestAlreadyComplete,
                RequestTableError::Full => CompletionQueueError::RequestTableFull,
            })
    }

    fn reserve_completion_permit(&self) -> Result<(), CompletionQueueError> {
        self.completion_permits
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |available| {
                (available != 0).then_some(available - 1)
            })
            .map(|_| ())
            .map_err(|_| CompletionQueueError::CompletionQueueFull)
    }

    fn release_completion_permit(&self) {
        self.completion_permits.fetch_add(1, Ordering::Release);
    }

    fn complete_request(
        &self,
        request_id: RequestId,
        opcode: IoOpcode,
        user_token: u64,
        output: IoRequestOutput,
    ) {
        let transition = match self.request_table.complete(request_id) {
            Ok(transition) => transition,
            Err(_) => return,
        };

        let output = match transition {
            CompleteTransition::Normal => output,
            CompleteTransition::Cancelled => IoRequestOutput::error(IO_STATUS_CANCELLED),
        };

        let completion = UserIoCompletion {
            request_id,
            user_token,
            opcode: opcode as u32,
            reserved: 0,
            status: output.status,
            result: output.result,
            extra: output.extra,
        };

        match self.completion_sender.try_send(completion) {
            Ok(()) => {}
            Err(BoundedSendError::Full(_)) => {
                panic!("completion queue invariant broken: reserved completion slot was full");
            }
            Err(BoundedSendError::Disconnected(_)) => {
                panic!("completion queue invariant broken: completion receiver disconnected");
            }
        }
    }
}

struct IoRequestDriverFuture {
    queue: Arc<CompletionQueue>,
    request_id: RequestId,
    opcode: IoOpcode,
    user_token: u64,
    inner: IoRequestFuture,
}

impl Future for IoRequestDriverFuture {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };
        this.queue
            .request_table
            .set_waker(this.request_id, cx.waker());

        match this
            .queue
            .request_table
            .mark_running_or_cancelled(this.request_id)
        {
            Ok(CompleteTransition::Normal) => {}
            Ok(CompleteTransition::Cancelled) => {
                this.queue.complete_request(
                    this.request_id,
                    this.opcode,
                    this.user_token,
                    IoRequestOutput::error(IO_STATUS_CANCELLED),
                );
                return Poll::Ready(());
            }
            Err(_) => return Poll::Ready(()),
        }

        match this.inner.as_mut().poll(cx) {
            Poll::Ready(output) => {
                this.queue
                    .complete_request(this.request_id, this.opcode, this.user_token, output);
                Poll::Ready(())
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
