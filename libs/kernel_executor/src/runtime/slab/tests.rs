#[cfg(not(any(loom, feature = "loom")))]
mod threaded {
    use crate::runtime::slab::{
        decode_joinable_slab_ptr, decode_slab_ptr, encode_joinable_slab_ptr, encode_slab_ptr,
        enqueue_joinable_slab_task, enqueue_slab_task, get_task_slab, is_joinable_slab_ptr,
        is_slab_ptr, slab_stats, SlabConfigBuilder,
    };
    use alloc::{sync::Arc, vec::Vec};
    use core::future::Future;
    use core::pin::Pin;
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use core::task::{Context, Poll};
    use std::sync::Mutex;
    use std::time::Duration;

    use crate::runtime::runtime::spawn_detached;

    struct GatedDetachedFuture {
        gate: Arc<AtomicBool>,
        wakers: Arc<Mutex<Vec<core::task::Waker>>>,
        completed: Arc<AtomicUsize>,
    }

    impl Future for GatedDetachedFuture {
        type Output = ();

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            if self.gate.load(Ordering::Acquire) {
                self.completed.fetch_add(1, Ordering::AcqRel);
                Poll::Ready(())
            } else {
                self.wakers
                    .lock()
                    .expect("gated detached future waker lock")
                    .push(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    // This test exists to verify that caller-provided slab configuration is clamped
    // to supported bounds without losing the fallback policy bit.
    #[test]
    fn slab_config_builder_clamps_capacity_and_preserves_fallback_policy() {
        let config = SlabConfigBuilder::new().capacity(1).fallback(false).build();

        assert!(config.slots_per_shard >= 64);
        assert!(!config.allow_fallback);

        let config = SlabConfigBuilder::new().slots_per_shard(usize::MAX).build();
        assert!(config.slots_per_shard <= 4096);
    }

    // This test exists to protect the compact slab pointer encoding. Detached and
    // joinable slots share the same integer space, so their tags must stay distinct.
    #[test]
    fn slab_pointer_encoding_keeps_detached_and_joinable_namespaces_separate() {
        let detached = encode_slab_ptr(3, 0x0FFE, 0x1_2345);
        assert!(is_slab_ptr(detached));
        assert!(!is_joinable_slab_ptr(detached));
        assert_eq!(decode_slab_ptr(detached), Some((3, 0x0FFE, 0x2345)));
        assert_eq!(decode_joinable_slab_ptr(detached), None);

        let joinable = encode_joinable_slab_ptr(7, 0x0ABC, 0xCAFE);
        assert!(is_slab_ptr(joinable));
        assert!(is_joinable_slab_ptr(joinable));
        assert_eq!(
            decode_joinable_slab_ptr(joinable),
            Some((7, 0x0ABC, 0xCAFE))
        );
        assert_eq!(decode_slab_ptr(joinable), None);
    }

    // This test covers cached waker initialization on joinable slab slots. Many
    // threads racing to fetch the cached waker must all get equivalent wakers for
    // the same slot, with no partially initialized waker visible.
    #[test]
    fn joinable_slot_cached_waker_initializes_once_under_thread_contention() {
        let _guard = crate::test::global_runtime_lock();
        crate::test::init_threaded_runtime();

        let slab = get_task_slab();
        let handle = slab
            .allocate_joinable()
            .expect("expected a joinable slab slot");
        let (shard_idx, local_idx, generation) = handle.indices();
        let slot = slab
            .get_joinable_slot(shard_idx, local_idx, generation)
            .expect("allocated joinable slot missing");
        let wakers = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

        std::thread::scope(|scope| {
            for _ in 0..32 {
                let wakers = wakers.clone();
                scope.spawn(move || {
                    let waker = slot.get_cached_waker(shard_idx, local_idx, generation);
                    wakers.lock().expect("cached waker result lock").push(waker);
                });
            }
        });

        let wakers = wakers.lock().expect("cached waker result lock");
        assert_eq!(wakers.len(), 32);
        for waker in wakers.iter().skip(1) {
            assert!(wakers[0].will_wake(waker));
        }
        drop(wakers);

        slab.decrement_joinable_ref(shard_idx, local_idx, generation);
    }

    // This test covers stale generation protection for joinable slab slots. Once a
    // slot's refcount reaches zero, an old generation must not be resurrected by a
    // stale waker or by a direct stale refcount increment.
    #[test]
    fn stale_joinable_generation_cannot_reacquire_freed_slot() {
        let _guard = crate::test::global_runtime_lock();
        crate::test::init_threaded_runtime();

        let slab = get_task_slab();
        let handle = slab
            .allocate_joinable()
            .expect("expected a joinable slab slot");
        let (shard_idx, local_idx, generation) = handle.indices();

        assert!(slab.increment_joinable_ref(shard_idx, local_idx, generation));
        slab.decrement_joinable_ref(shard_idx, local_idx, generation);
        slab.decrement_joinable_ref(shard_idx, local_idx, generation);

        assert!(
            !slab.increment_joinable_ref(shard_idx, local_idx, generation),
            "stale joinable generation reacquired a freed slot"
        );
        enqueue_joinable_slab_task(shard_idx, local_idx, generation);
        assert!(
            !slab.increment_joinable_ref(shard_idx, local_idx, generation),
            "stale joinable wake resurrected a freed slot"
        );
    }

    // This test covers the same stale generation/refcount contract for detached
    // slab slots. A stale detached waker must not be able to put a freed slot back
    // into the executor.
    #[test]
    fn stale_detached_generation_cannot_reacquire_freed_slot() {
        let _guard = crate::test::global_runtime_lock();
        crate::test::init_threaded_runtime();

        let slab = get_task_slab();
        let handle = slab.allocate().expect("expected a detached slab slot");
        let (shard_idx, local_idx, generation) = handle.indices();

        assert!(slab.increment_ref(shard_idx, local_idx, generation));
        slab.decrement_ref(shard_idx, local_idx, generation);
        slab.decrement_ref(shard_idx, local_idx, generation);

        assert!(
            !slab.increment_ref(shard_idx, local_idx, generation),
            "stale detached generation reacquired a freed slot"
        );
        enqueue_slab_task(shard_idx, local_idx, generation);
        assert!(
            !slab.increment_ref(shard_idx, local_idx, generation),
            "stale detached wake resurrected a freed slot"
        );
    }

    // This test exists to make sure the global slab initializes under the threaded
    // runtime and reports sane capacity/allocation counters after startup.
    #[test]
    fn global_slab_stats_are_readable_after_default_initialization() {
        let _guard = crate::test::global_runtime_lock();
        crate::test::init_threaded_runtime();

        let stats = slab_stats();
        assert!(stats.total_capacity >= 64);
        assert!(stats.currently_allocated <= stats.total_capacity);
    }

    // This test exists to verify the detached slab exhaustion path. It holds every
    // slab slot pending, submits extra detached work through the Arc fallback path,
    // then wakes all tasks to prove both storage paths still complete.
    #[test]
    fn slab_stats_record_detached_slot_exhaustion_fallbacks() {
        let _guard = crate::test::global_runtime_lock();
        crate::test::init_threaded_runtime();

        let stats = slab_stats();
        let before = stats.fallback_allocations;
        let tasks = stats.total_capacity + 64;
        let gate = Arc::new(AtomicBool::new(false));
        let completed = Arc::new(AtomicUsize::new(0));
        let wakers = Arc::new(Mutex::new(Vec::with_capacity(tasks)));

        for _ in 0..tasks {
            spawn_detached(GatedDetachedFuture {
                gate: gate.clone(),
                wakers: wakers.clone(),
                completed: completed.clone(),
            });
        }

        crate::test::wait_until(Duration::from_secs(10), || {
            wakers
                .lock()
                .expect("gated detached future waker lock")
                .len()
                == tasks
        });

        let after = slab_stats().fallback_allocations;
        assert!(after > before);

        gate.store(true, Ordering::Release);
        let stored_wakers = {
            let mut guard = wakers.lock().expect("gated detached future waker lock");
            core::mem::take(&mut *guard)
        };

        for waker in stored_wakers {
            waker.wake();
        }

        crate::test::wait_until(Duration::from_secs(10), || {
            completed.load(Ordering::Acquire) == tasks
        });
    }
}

#[cfg(any(loom, feature = "loom"))]
mod loom {
    use super::super::slot::{
        JoinableSlot, NotifyResult, TaskSlot, WAKER_SET, WAKER_TAKEN, WAKER_UPDATING,
    };
    use crate::sync::exhaustive_model;
    use core::mem::ManuallyDrop;
    use core::task::{RawWaker, RawWakerVTable, Waker};

    struct ModelWakeCounter {
        wakes: crate::sync::atomic::AtomicUsize,
    }

    unsafe fn clone_model_waker(ptr: *const ()) -> RawWaker {
        let arc =
            ManuallyDrop::new(unsafe { std::sync::Arc::from_raw(ptr.cast::<ModelWakeCounter>()) });
        let cloned = std::sync::Arc::clone(&arc);
        RawWaker::new(
            std::sync::Arc::into_raw(cloned).cast::<()>(),
            &MODEL_WAKER_VTABLE,
        )
    }

    unsafe fn wake_model_waker(ptr: *const ()) {
        let arc = unsafe { std::sync::Arc::from_raw(ptr.cast::<ModelWakeCounter>()) };
        arc.wakes
            .fetch_add(1, crate::sync::atomic::Ordering::AcqRel);
    }

    unsafe fn wake_model_waker_by_ref(ptr: *const ()) {
        let arc =
            ManuallyDrop::new(unsafe { std::sync::Arc::from_raw(ptr.cast::<ModelWakeCounter>()) });
        arc.wakes
            .fetch_add(1, crate::sync::atomic::Ordering::AcqRel);
    }

    unsafe fn drop_model_waker(ptr: *const ()) {
        drop(unsafe { std::sync::Arc::from_raw(ptr.cast::<ModelWakeCounter>()) });
    }

    static MODEL_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
        clone_model_waker,
        wake_model_waker,
        wake_model_waker_by_ref,
        drop_model_waker,
    );

    fn model_waker(counter: std::sync::Arc<ModelWakeCounter>) -> Waker {
        let raw = RawWaker::new(
            std::sync::Arc::into_raw(counter).cast::<()>(),
            &MODEL_WAKER_VTABLE,
        );
        unsafe { Waker::from_raw(raw) }
    }

    // Models the exact JoinableSlot lost-wakeup protocol with Loom-controlled
    // atomics. wake_join_handle must not return while another thread is between
    // WAKER_UPDATING and WAKER_SET.
    #[test]
    fn loom_joinable_wake_waits_for_in_progress_waker_update() {
        exhaustive_model(|| {
            let slot = crate::sync::Arc::new(JoinableSlot::new());
            let counter = std::sync::Arc::new(ModelWakeCounter {
                wakes: crate::sync::atomic::AtomicUsize::new(0),
            });
            let waker = model_waker(counter.clone());

            slot.waker_state
                .store(WAKER_UPDATING, crate::sync::atomic::Ordering::Release);

            let wake_slot = slot.clone();
            let wake_thread = loom::thread::spawn(move || {
                wake_slot.wake_join_handle();
            });

            let finish_slot = slot.clone();
            let finish_thread = loom::thread::spawn(move || {
                unsafe {
                    (*finish_slot.join_waker.get()).write(waker);
                }
                finish_slot
                    .waker_state
                    .store(WAKER_SET, crate::sync::atomic::Ordering::Release);
            });

            finish_thread.join().expect("waker install thread panicked");
            wake_thread.join().expect("wake thread panicked");

            assert_eq!(
                counter.wakes.load(crate::sync::atomic::Ordering::Acquire),
                1
            );
            assert_eq!(
                slot.waker_state
                    .load(crate::sync::atomic::Ordering::Acquire),
                WAKER_TAKEN
            );
        });
    }

    // Models the production JoinHandle poll race: the handle registers a waker
    // while task completion stores crate::runtime::task::STATE_COMPLETED and wakes the handle. If the
    // poll path can still return Pending, exactly one completion wake is required.
    #[test]
    fn loom_joinable_pending_poll_gets_completion_wake() {
        exhaustive_model(|| {
            let slot = crate::sync::Arc::new(JoinableSlot::new());
            let counter = std::sync::Arc::new(ModelWakeCounter {
                wakes: crate::sync::atomic::AtomicUsize::new(0),
            });
            let returned_pending =
                crate::sync::Arc::new(crate::sync::atomic::AtomicBool::new(false));
            let waker = model_waker(counter.clone());

            let waiter_slot = slot.clone();
            let waiter_pending = returned_pending.clone();
            let waiter = loom::thread::spawn(move || {
                if !waiter_slot.is_completed() {
                    loom::thread::yield_now();
                    waiter_slot.update_join_waker(&waker);
                    loom::thread::yield_now();

                    if !waiter_slot.is_completed() {
                        waiter_pending.store(true, crate::sync::atomic::Ordering::Release);
                    }
                }
            });

            let complete_slot = slot.clone();
            let completer = loom::thread::spawn(move || {
                loom::thread::yield_now();
                complete_slot.state.store(
                    crate::runtime::task::STATE_COMPLETED,
                    crate::sync::atomic::Ordering::Release,
                );
                loom::thread::yield_now();
                complete_slot.wake_join_handle();
            });

            waiter.join().expect("join handle poll thread panicked");
            completer.join().expect("completion thread panicked");

            if returned_pending.load(crate::sync::atomic::Ordering::Acquire) {
                assert_eq!(
                    counter.wakes.load(crate::sync::atomic::Ordering::Acquire),
                    1
                );
                assert_eq!(
                    slot.waker_state
                        .load(crate::sync::atomic::Ordering::Acquire),
                    WAKER_TAKEN
                );
            }
        });
    }

    // Models the detached slab task wake-vs-pending-poll race. The caller's
    // IdleRace retry must convert a just-idled task into QUEUED instead of
    // losing the wake.
    #[test]
    fn loom_task_slot_notify_idle_race_requeues() {
        exhaustive_model(|| {
            let slot = crate::sync::Arc::new(TaskSlot::new());
            slot.state.store(
                crate::runtime::task::STATE_POLLING,
                crate::sync::atomic::Ordering::Release,
            );

            let poll_slot = slot.clone();
            let poller = loom::thread::spawn(move || {
                let prev = poll_slot.state.compare_exchange(
                    crate::runtime::task::STATE_POLLING,
                    crate::runtime::task::STATE_IDLE,
                    crate::sync::atomic::Ordering::AcqRel,
                    crate::sync::atomic::Ordering::Acquire,
                );

                if let Err(crate::runtime::task::STATE_NOTIFIED) = prev {
                    poll_slot.state.store(
                        crate::runtime::task::STATE_QUEUED,
                        crate::sync::atomic::Ordering::Release,
                    );
                }
            });

            let notify_slot = slot.clone();
            let notifier = loom::thread::spawn(move || loop {
                match notify_slot.try_notify_result() {
                    NotifyResult::Notified
                    | NotifyResult::AlreadyQueued
                    | NotifyResult::Completed => return,
                    NotifyResult::IdleRace => {
                        if notify_slot.try_enqueue() {
                            return;
                        }
                    }
                }
            });

            poller.join().expect("poller thread panicked");
            notifier.join().expect("notifier thread panicked");

            assert_eq!(
                slot.state.load(crate::sync::atomic::Ordering::Acquire),
                crate::runtime::task::STATE_QUEUED
            );
        });
    }

    // Models the same wake-vs-pending-poll race for joinable slab slots, which
    // have their own slot type but must preserve the same no-lost-wake contract.
    #[test]
    fn loom_joinable_slot_notify_idle_race_requeues() {
        exhaustive_model(|| {
            let slot = crate::sync::Arc::new(JoinableSlot::new());
            slot.state.store(
                crate::runtime::task::STATE_POLLING,
                crate::sync::atomic::Ordering::Release,
            );

            let poll_slot = slot.clone();
            let poller = loom::thread::spawn(move || {
                let prev = poll_slot.state.compare_exchange(
                    crate::runtime::task::STATE_POLLING,
                    crate::runtime::task::STATE_IDLE,
                    crate::sync::atomic::Ordering::AcqRel,
                    crate::sync::atomic::Ordering::Acquire,
                );

                if let Err(crate::runtime::task::STATE_NOTIFIED) = prev {
                    poll_slot.state.store(
                        crate::runtime::task::STATE_QUEUED,
                        crate::sync::atomic::Ordering::Release,
                    );
                }
            });

            let notify_slot = slot.clone();
            let notifier = loom::thread::spawn(move || loop {
                match notify_slot.try_notify_result() {
                    NotifyResult::Notified
                    | NotifyResult::AlreadyQueued
                    | NotifyResult::Completed => return,
                    NotifyResult::IdleRace => {
                        if notify_slot.try_enqueue() {
                            return;
                        }
                    }
                }
            });

            poller.join().expect("poller thread panicked");
            notifier.join().expect("notifier thread panicked");

            assert_eq!(
                slot.state.load(crate::sync::atomic::Ordering::Acquire),
                crate::runtime::task::STATE_QUEUED
            );
        });
    }
}
