use super::slot::{PollResult, TaskSlot, WakeAction};
use super::task_slab::{TaskTable, get_task_table};
use crate::platform::ExecutorPlatform;
use crate::platform::POLL_NOTIFIED;

const PTR_SHARD_BITS: usize = 3;
const PTR_LOCAL_BITS: usize = 32;
const PTR_GEN_BITS: usize = 16;

const PTR_SHARD_SHIFT: usize = 0;
const PTR_LOCAL_SHIFT: usize = PTR_SHARD_SHIFT + PTR_SHARD_BITS;
const PTR_GEN_SHIFT: usize = PTR_LOCAL_SHIFT + PTR_LOCAL_BITS;

const PTR_SHARD_MASK: usize = (1usize << PTR_SHARD_BITS) - 1;
const PTR_LOCAL_MASK: usize = (1usize << PTR_LOCAL_BITS) - 1;
const PTR_GEN_MASK: usize = (1usize << PTR_GEN_BITS) - 1;

const _: () = assert!(usize::BITS as usize > PTR_GEN_SHIFT + PTR_GEN_BITS);
const _: () = assert!(POLL_NOTIFIED > 1usize << (PTR_GEN_SHIFT + PTR_GEN_BITS));

#[inline]
pub fn encode_slab_task_ptr(shard_idx: u8, local_idx: u32, generation: u32) -> usize {
    let shard_bits = ((shard_idx as usize) & PTR_SHARD_MASK) << PTR_SHARD_SHIFT;
    let local_bits = ((local_idx as usize) & PTR_LOCAL_MASK) << PTR_LOCAL_SHIFT;
    let gen_bits = ((generation as usize) & PTR_GEN_MASK) << PTR_GEN_SHIFT;
    (gen_bits | local_bits | shard_bits) + 1
}

#[inline]
pub fn decode_slab_task_ptr(ptrv: usize) -> Option<(usize, usize, u32)> {
    let ptrv = ptrv.checked_sub(1)?;
    let shard_idx = (ptrv >> PTR_SHARD_SHIFT) & PTR_SHARD_MASK;
    let local_idx = (ptrv >> PTR_LOCAL_SHIFT) & PTR_LOCAL_MASK;
    let generation = ((ptrv >> PTR_GEN_SHIFT) & PTR_GEN_MASK) as u32;

    Some((shard_idx, local_idx, generation))
}

#[inline(never)]
pub(crate) extern "C" fn poll_slab_task<E: ExecutorPlatform>(
    slab: &'static TaskTable<E>,
    ctx: usize,
    cached_slot: Option<&'static TaskSlot>,
) {
    let Some((shard_idx, local_idx, generation)) = decode_slab_task_ptr(ctx) else {
        return;
    };

    let Some(slot) = cached_slot.or_else(|| slab.get_slot(shard_idx, local_idx, generation)) else {
        return;
    };

    let waker = super::super::waker::create_slab_task_waker::<E>(shard_idx, local_idx, generation);

    let refs = match slot.poll_once::<E>(&waker, shard_idx, local_idx, generation) {
        PollResult::Pending => 1,
        PollResult::Completed => 2,
        PollResult::Requeued => return,
    };
    unsafe { slab.decrement_owned_refs(slot, shard_idx, local_idx, generation, refs) };
}

#[inline(never)]
pub fn enqueue_slab_task<E: ExecutorPlatform>(shard_idx: usize, local_idx: usize, generation: u32) {
    let slab = get_task_table::<E>();

    let Some(slot) = slab.get_slot(shard_idx, local_idx, generation) else {
        return;
    };
    if !slab.increment_slot_ref(slot, generation) {
        return;
    }
    if slot.record_wake() == WakeAction::Enqueue {
        if let Some(domain_id) = slot.executor_domain_id() {
            let task_id = encode_slab_task_ptr(shard_idx as u8, local_idx as u32, generation);
            let executor = crate::global_async::GlobalAsyncExecutor::<E>::global();
            let accepted = executor.with_executor_domain(domain_id, |domain, tls| {
                executor.enqueue_task::<false, false, false>(domain, tls, task_id, slot);
                true
            }).unwrap_or(false);
            if accepted {
                return;
            }
        }
    }
    slab.decrement_ref::<false>(shard_idx, local_idx, generation);
}

#[inline(never)]
pub extern "C" fn slab_task_poll_trampoline<E: ExecutorPlatform>(ctx: usize) {
    poll_slab_task::<E>(get_task_table::<E>(), ctx, None);
}

#[cfg(test)]
mod tests {
    use super::{decode_slab_task_ptr, encode_slab_task_ptr};

    #[test]
    fn task_pointer_round_trips_u32_local_index() {
        let encoded = encode_slab_task_ptr(7, 0xFEDC_BA98, 0x7654_3210);
        assert_eq!(
            decode_slab_task_ptr(encoded),
            Some((7, 0xFEDC_BA98, 0x3210))
        );
    }
}
