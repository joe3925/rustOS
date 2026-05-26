use crate::runtime::slab::{
    decode_joinable_slab_ptr, decode_slab_ptr, encode_joinable_slab_ptr, encode_slab_ptr,
    is_joinable_slab_ptr, is_slab_ptr, slab_stats, SlabConfigBuilder,
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

// This test exists to make sure the global slab initializes under the threaded
// runtime and reports sane capacity/allocation counters after startup.
#[test]
fn global_slab_stats_are_readable_after_default_initialization() {
    let _guard = super::global_runtime_lock();
    super::init_threaded_runtime();

    let stats = slab_stats();
    assert!(stats.total_capacity >= 64);
    assert!(stats.currently_allocated <= stats.total_capacity);
}

// This test exists to verify the detached slab exhaustion path. It holds every
// slab slot pending, submits extra detached work through the Arc fallback path,
// then wakes all tasks to prove both storage paths still complete.
#[test]
fn slab_stats_record_detached_slot_exhaustion_fallbacks() {
    let _guard = super::global_runtime_lock();
    super::init_threaded_runtime();

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

    super::wait_until(Duration::from_secs(10), || {
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

    super::wait_until(Duration::from_secs(10), || {
        completed.load(Ordering::Acquire) == tasks
    });
}
