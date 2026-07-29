use alloc::string::String;

use kernel_types::completion::{CompletionPermit, TaskCompletion, TaskOutcome, TaskToken};
use loom::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use loom::sync::Arc;
use loom::thread;

use crate::bounded_mpmc::{bounded_mpmc_channel, BoundedSendError};
use crate::bounded_wait_queue::{BoundedWaitQueue, BoundedWaitQueueEnqueue};
use crate::completion_port::CompletionPort;
use crate::mpmc::{mpmc_channel, SendError as MpmcSendError, TryRecvError};
use crate::platform::{Platform, ThreadEntry};
use crate::sleep_mutex::SleepMutex;
use crate::sync::model;
use crate::wait_queue::WaitQueue;

#[unsafe(no_mangle)]
extern "C" fn kernel_resolve_error_context_module(_instruction_pointer: usize) -> Option<String> {
    None
}

#[derive(Clone)]
struct ModelTask {
    inner: Arc<ModelTaskInner>,
}

struct ModelTaskInner {
    id: u64,
    waiting_on: AtomicU64,
    unparks: AtomicUsize,
}

impl ModelTask {
    fn new(id: u64) -> Self {
        Self {
            inner: Arc::new(ModelTaskInner {
                id,
                waiting_on: AtomicU64::new(0),
                unparks: AtomicUsize::new(0),
            }),
        }
    }
}

struct ModelPlatform;

impl Platform for ModelPlatform {
    type Task = ModelTask;

    fn current_task() -> Option<Self::Task> {
        None
    }

    fn task_id(task: &Self::Task) -> u64 {
        task.inner.id
    }

    fn same_task(a: &Self::Task, b: &Self::Task) -> bool {
        Arc::ptr_eq(&a.inner, &b.inner)
    }

    fn mark_waiting(task: &Self::Task, wait_queue_id: u64) -> bool {
        task.inner
            .waiting_on
            .compare_exchange(0, wait_queue_id, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn clear_waiting(task: &Self::Task, wait_queue_id: u64) -> bool {
        task.inner
            .waiting_on
            .compare_exchange(wait_queue_id, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn is_waiting(task: &Self::Task, wait_queue_id: u64) -> bool {
        task.inner.waiting_on.load(Ordering::Acquire) == wait_queue_id
    }

    fn unpark(task: &Self::Task) {
        task.inner.unparks.fetch_add(1, Ordering::AcqRel);
    }

    fn park_current() {
        thread::yield_now();
    }

    fn spawn_thread(_name: String, _entry: ThreadEntry, _context: usize) {
        panic!("thread-pool spawning is not used by primitive loom models")
    }

    fn spin_loop() {
        thread::yield_now();
    }
}

#[test]
fn bounded_wait_slot_enqueue_and_wake_do_not_lose_ownership() {
    model(|| {
        let queue = Arc::new(BoundedWaitQueue::<ModelPlatform>::new(1));
        let task = ModelTask::new(1);

        let enqueue_queue = queue.clone();
        let enqueue_task = task.clone();
        let enqueue = thread::spawn(move || enqueue_queue.enqueue(&enqueue_task));

        let wake_queue = queue.clone();
        let wake = thread::spawn(move || wake_queue.wake_one());

        let enqueue_result = enqueue.join().unwrap().unwrap();
        let _ = wake.join().unwrap();

        let len = queue.len();
        let waiting = task.inner.waiting_on.load(Ordering::Acquire);
        assert!(len <= 1);
        assert_eq!(waiting == queue.id(), len == 1);
        if enqueue_result == BoundedWaitQueueEnqueue::Woken {
            assert_eq!(len, 0);
        }
    });
}

#[test]
fn bounded_wait_wakers_claim_each_task_at_most_once() {
    model(|| {
        let queue = Arc::new(BoundedWaitQueue::<ModelPlatform>::new(2));
        let first = ModelTask::new(1);
        let second = ModelTask::new(2);
        assert_eq!(
            queue.enqueue(&first).unwrap(),
            BoundedWaitQueueEnqueue::Queued
        );
        assert_eq!(
            queue.enqueue(&second).unwrap(),
            BoundedWaitQueueEnqueue::Queued
        );

        let one = queue.clone();
        let wake_one = thread::spawn(move || one.wake_one());
        let all = queue.clone();
        let wake_all = thread::spawn(move || all.wake_all());
        wake_one.join().unwrap();
        wake_all.join().unwrap();

        assert_eq!(queue.len(), 0);
        assert_eq!(first.inner.waiting_on.load(Ordering::Acquire), 0);
        assert_eq!(second.inner.waiting_on.load(Ordering::Acquire), 0);
        assert!(first.inner.unparks.load(Ordering::Acquire) <= 1);
        assert!(second.inner.unparks.load(Ordering::Acquire) <= 1);
    });
}

#[test]
fn wait_queue_dequeue_and_clear_preserve_length() {
    model(|| {
        let queue = Arc::new(WaitQueue::<ModelPlatform>::new());
        let task = ModelTask::new(1);
        assert!(queue.enqueue(&task));

        let first = queue.clone();
        let a = thread::spawn(move || first.dequeue_one());
        let second = queue.clone();
        let b = thread::spawn(move || second.dequeue_one());

        let claimed =
            usize::from(a.join().unwrap().is_some()) + usize::from(b.join().unwrap().is_some());
        assert_eq!(claimed, 1);
        assert_eq!(queue.len(), 0);
        assert_eq!(task.inner.waiting_on.load(Ordering::Acquire), 0);
    });
}

#[test]
fn sleep_mutex_allows_only_one_mutator() {
    model(|| {
        let mutex = Arc::new(SleepMutex::<ModelPlatform, usize>::new(0));
        let left = mutex.clone();
        let a = thread::spawn(move || loop {
            if let Some(mut guard) = left.try_lock() {
                *guard += 1;
                break;
            }
            thread::yield_now();
        });
        let right = mutex.clone();
        let b = thread::spawn(move || loop {
            if let Some(mut guard) = right.try_lock() {
                *guard += 1;
                break;
            }
            thread::yield_now();
        });
        a.join().unwrap();
        b.join().unwrap();
        assert_eq!(*mutex.try_lock().expect("mutex left locked"), 2);
    });
}

#[test]
fn completion_port_permit_survives_close_and_completes_once() {
    model(|| {
        let port = CompletionPort::<ModelPlatform, usize>::new(1, 1);
        let permit = port.try_reserve().unwrap();
        assert_eq!(port.outstanding(), 1);

        let close_port = port.clone();
        let close = thread::spawn(move || close_port.close());
        let complete = thread::spawn(move || {
            permit.complete(TaskCompletion {
                task: TaskToken::from_raw(1).unwrap(),
                key: 7,
                outcome: TaskOutcome::Completed(9),
            });
        });
        close.join().unwrap();
        complete.join().unwrap();

        let completion = port.try_recv().expect("reserved completion was lost");
        assert_eq!(completion.key, 7);
        assert_eq!(completion.outcome, TaskOutcome::Completed(9));
        assert_eq!(port.outstanding(), 0);
    });
}

#[test]
fn completion_port_dropped_permit_returns_capacity_once() {
    model(|| {
        let port = CompletionPort::<ModelPlatform, usize>::new(1, 1);
        let permit = port.try_reserve().unwrap();
        let close_port = port.clone();
        let close = thread::spawn(move || close_port.close());
        let dropper = thread::spawn(move || drop(permit));
        close.join().unwrap();
        dropper.join().unwrap();
        assert_eq!(port.outstanding(), 0);
    });
}

#[test]
fn mpmc_receiver_close_and_send_have_consistent_outcome() {
    model(|| {
        let (sender, receiver) = mpmc_channel::<ModelPlatform, usize>();
        let send = thread::spawn(move || sender.send(1));
        let close = thread::spawn(move || drop(receiver));
        let result = send.join().unwrap();
        close.join().unwrap();
        assert!(matches!(result, Ok(()) | Err(MpmcSendError(1))));
    });
}

#[test]
fn mpmc_competing_senders_are_drained_exactly_once() {
    model(|| {
        let (sender, receiver) = mpmc_channel::<ModelPlatform, usize>();
        let other_sender = sender.clone();
        let first = thread::spawn(move || sender.send(1));
        let second = thread::spawn(move || other_sender.send(2));

        first.join().unwrap().unwrap();
        second.join().unwrap().unwrap();

        let left = receiver.try_recv().expect("first value was lost");
        let right = receiver.try_recv().expect("second value was lost");
        assert_ne!(left, right);
        assert!(matches!(left, 1 | 2));
        assert!(matches!(right, 1 | 2));
        assert!(matches!(
            receiver.try_recv(),
            Err(TryRecvError::Empty | TryRecvError::Disconnected)
        ));
    });
}

#[test]
fn bounded_mpmc_receiver_close_and_send_have_consistent_outcome() {
    model(|| {
        let (sender, receiver) = bounded_mpmc_channel::<ModelPlatform, usize>(1, 1);
        let send = thread::spawn(move || sender.try_send(1));
        let close = thread::spawn(move || drop(receiver));
        let result = send.join().unwrap();
        close.join().unwrap();
        assert!(matches!(
            result,
            Ok(()) | Err(BoundedSendError::Disconnected(1))
        ));
    });
}
