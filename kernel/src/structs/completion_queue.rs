use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

use kernel_executor::global_async::ExecutorDomainId;
use kernel_executor::runtime::runtime::try_spawn_to_port_in_executor_domain;
use kernel_sync::{PortReserveError, mpmc::TryRecvError};
use kernel_types::completion::{CompletionPermit, TaskCompletion, TaskOutcome};

use crate::sync_platform::{CompletionPort as KernelCompletionPort, CompletionPortPermit};
use crate::structs::executor_domain::UserExecutorDomain;

use super::io_request::{
    CompleteTransition, IO_STATUS_CANCELLED, IoOpcode, IoRequestOutput, IoRequestTable, KernelIoOp,
    RequestId, RequestTableError, UserIoCompletion,
};

pub struct CompletionQueue {
    pub owner_pid: u64,
    pub bound_executor_domain: ExecutorDomainId,
    executor_domain: Arc<UserExecutorDomain>,
    pub request_capacity: usize,
    pub completion_capacity: usize,
    pub flags: u64,

    request_table: IoRequestTable,
    completion_port: Arc<KernelCompletionPort<UserIoCompletion>>,
    completion_chunk_capacity: usize,
    resizing_completion_port: AtomicBool,
    closed: AtomicBool,
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
    Closed,
    DomainUnavailable,
}

impl CompletionQueue {
    pub fn new(
        owner_pid: u64,
        executor_domain: Arc<UserExecutorDomain>,
        request_capacity: usize,
        completion_capacity: usize,
        flags: u64,
    ) -> Result<Arc<Self>, CompletionQueueError> {
        if request_capacity == 0 || completion_capacity == 0 {
            return Err(CompletionQueueError::InvalidCapacity);
        }

        let completion_chunk_capacity = completion_capacity.div_ceil(4).max(1);
        Ok(Arc::new(Self {
            owner_pid,
            bound_executor_domain: executor_domain.id(),
            executor_domain,
            request_capacity,
            completion_capacity,
            flags,
            request_table: IoRequestTable::new(request_capacity),
            completion_port: KernelCompletionPort::new(
                completion_capacity,
                completion_chunk_capacity,
            ),
            completion_chunk_capacity,
            resizing_completion_port: AtomicBool::new(false),
            closed: AtomicBool::new(false),
        }))
    }

    pub fn enqueue(self: &Arc<Self>, op: KernelIoOp) -> Result<RequestId, CompletionQueueError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(CompletionQueueError::Closed);
        }
        if self.executor_domain.is_draining() {
            return Err(CompletionQueueError::DomainUnavailable);
        }
        let port_permit = self.reserve_completion_slot()?;

        let request_id = match self.request_table.allocate() {
            Ok(request_id) => request_id,
            Err(RequestTableError::Full) => {
                return Err(CompletionQueueError::RequestTableFull);
            }
            Err(_) => {
                return Err(CompletionQueueError::RequestTableFull);
            }
        };

        let opcode = op.opcode();
        let user_token = op.user_token();
        let permit = IoCompletionPermit {
            queue: self.clone(),
            port_permit: Some(port_permit),
            opcode,
            user_token,
            consumed: false,
        };
        let task = match try_spawn_to_port_in_executor_domain(
            self.bound_executor_domain,
            async move { op.execute().await },
            request_id,
            permit,
        ) {
            Ok(task) => task,
            Err(_) => {
                self.request_table.reap_submitted(request_id);
                return Err(CompletionQueueError::RequestTableFull);
            }
        };
        self.request_table.install_task(request_id, task);
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
            let completion = match self.completion_port.try_recv() {
                Ok(completion) => match completion.outcome {
                    TaskOutcome::Completed(completion) => completion,
                    TaskOutcome::Cancelled => {
                        unreachable!("mapped I/O permit emitted cancellation")
                    }
                },
                Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => break,
            };

            self.request_table.reap(completion.request_id);
            self.reclaim_completion_capacity();
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
            let first = match self.completion_port.recv() {
                Ok(completion) => match completion.outcome {
                    TaskOutcome::Completed(completion) => completion,
                    TaskOutcome::Cancelled => {
                        unreachable!("mapped I/O permit emitted cancellation")
                    }
                },
                Err(_) => return 0,
            };

            self.request_table.reap(first.request_id);
            self.reclaim_completion_capacity();
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

    pub fn shutdown(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.request_table.cancel_all();
        }
    }

    fn reserve_completion_slot(
        self: &Arc<Self>,
    ) -> Result<CompletionPortPermit<UserIoCompletion>, CompletionQueueError> {
        loop {
            match self.completion_port.try_reserve() {
                Ok(permit) => return Ok(permit),
                Err(PortReserveError::Closed) => return Err(CompletionQueueError::Closed),
                Err(PortReserveError::Full) => {}
            }

            if self
                .resizing_completion_port
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                let current = self.completion_port.capacity();
                let requested = current.div_ceil(2).max(self.completion_chunk_capacity);
                let additional = requested
                    .div_ceil(self.completion_chunk_capacity)
                    .saturating_mul(self.completion_chunk_capacity);
                let result = self.completion_port.try_grow(additional);
                self.resizing_completion_port
                    .store(false, Ordering::Release);
                result.map_err(|_| CompletionQueueError::CompletionQueueFull)?;
            } else {
                core::hint::spin_loop();
            }
        }
    }

    fn reclaim_completion_capacity(&self) {
        let capacity = self.completion_port.capacity();
        let outstanding = self.completion_port.outstanding();
        if capacity <= self.completion_capacity || outstanding.saturating_mul(2) > capacity {
            return;
        }
        if self
            .resizing_completion_port
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }

        let capacity = self.completion_port.capacity();
        let outstanding = self.completion_port.outstanding();
        if capacity > self.completion_capacity && outstanding.saturating_mul(2) <= capacity {
            let lower_bound = self.completion_capacity.max(outstanding);
            let desired_removal = capacity.div_ceil(4);
            let removable = desired_removal.min(capacity.saturating_sub(lower_bound))
                / self.completion_chunk_capacity
                * self.completion_chunk_capacity;
            let target = capacity.saturating_sub(removable);
            // Reclamation is opportunistic. A busy or non-representable chunk
            // layout is left intact and reconsidered after a later reap.
            if removable != 0 {
                let _ = self.completion_port.try_shrink_to(target);
            }
        }
        self.resizing_completion_port
            .store(false, Ordering::Release);
    }
}

struct IoCompletionPermit {
    queue: Arc<CompletionQueue>,
    port_permit: Option<CompletionPortPermit<UserIoCompletion>>,
    opcode: IoOpcode,
    user_token: u64,
    consumed: bool,
}

impl CompletionPermit<IoRequestOutput> for IoCompletionPermit {
    fn complete(mut self, completion: TaskCompletion<IoRequestOutput>) {
        self.consumed = true;
        let output = match completion.outcome {
            TaskOutcome::Completed(output) => output,
            TaskOutcome::Cancelled => IoRequestOutput::error(IO_STATUS_CANCELLED),
        };
        let transition = self
            .queue
            .request_table
            .complete(completion.key)
            .unwrap_or(CompleteTransition::Cancelled);
        let output = match transition {
            CompleteTransition::Normal => output,
            CompleteTransition::Cancelled => IoRequestOutput::error(IO_STATUS_CANCELLED),
        };
        let user = UserIoCompletion {
            request_id: completion.key,
            user_token: self.user_token,
            opcode: self.opcode as u32,
            reserved: 0,
            status: output.status,
            result: output.result,
            extra: output.extra,
        };
        self.port_permit
            .take()
            .expect("I/O port permit missing")
            .complete(TaskCompletion {
                task: completion.task,
                key: completion.key,
                outcome: TaskOutcome::Completed(user),
            });
    }
}

impl Drop for IoCompletionPermit {
    fn drop(&mut self) {
        if !self.consumed {
            self.port_permit.take();
        }
    }
}
