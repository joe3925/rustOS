use crate::sync::spin_loop;

use super::super::runtime::submit_global;
use super::slot::NotifyResult;
use super::task_slab::get_task_table;

const PTR_SHARD_BITS: usize = 3;
const PTR_LOCAL_BITS: usize = 16;
const PTR_GEN_BITS: usize = 16;

const PTR_SHARD_SHIFT: usize = 0;
const PTR_LOCAL_SHIFT: usize = PTR_SHARD_SHIFT + PTR_SHARD_BITS;
const PTR_GEN_SHIFT: usize = PTR_LOCAL_SHIFT + PTR_LOCAL_BITS;

const PTR_SHARD_MASK: usize = (1usize << PTR_SHARD_BITS) - 1;
const PTR_LOCAL_MASK: usize = (1usize << PTR_LOCAL_BITS) - 1;
const PTR_GEN_MASK: usize = (1usize << PTR_GEN_BITS) - 1;

#[inline]
pub fn encode_slab_task_ptr(shard_idx: u8, local_idx: u16, generation: u32) -> usize {
    let shard_bits = ((shard_idx as usize) & PTR_SHARD_MASK) << PTR_SHARD_SHIFT;
    let local_bits = ((local_idx as usize) & PTR_LOCAL_MASK) << PTR_LOCAL_SHIFT;
    let gen_bits = ((generation as usize) & PTR_GEN_MASK) << PTR_GEN_SHIFT;
    gen_bits | local_bits | shard_bits
}

#[inline]
pub fn decode_slab_task_ptr(ptrv: usize) -> Option<(usize, usize, u32)> {
    let shard_idx = (ptrv >> PTR_SHARD_SHIFT) & PTR_SHARD_MASK;
    let local_idx = (ptrv >> PTR_LOCAL_SHIFT) & PTR_LOCAL_MASK;
    let generation = ((ptrv >> PTR_GEN_SHIFT) & PTR_GEN_MASK) as u32;

    Some((shard_idx, local_idx, generation))
}

#[inline(always)]
fn poll_slab_task(ctx: usize) {
    let Some((shard_idx, local_idx, generation)) = decode_slab_task_ptr(ctx) else {
        return;
    };

    let slab = get_task_table();
    let Some(slot) = slab.get_slot(shard_idx, local_idx, generation) else {
        return;
    };

    let waker = slot.get_cached_waker(shard_idx, local_idx, generation);

    let completed = slot.poll_once(&waker, shard_idx, local_idx, generation);

    slab.decrement_ref(shard_idx, local_idx, generation);

    if completed {
        slab.decrement_ref(shard_idx, local_idx, generation);
    }
}

#[inline(always)]
pub fn enqueue_slab_task(shard_idx: usize, local_idx: usize, generation: u32) {
    let slab = get_task_table();

    if !slab.increment_ref(shard_idx, local_idx, generation) {
        return;
    }

    let Some(slot) = slab.get_slot(shard_idx, local_idx, generation) else {
        slab.decrement_ref(shard_idx, local_idx, generation);
        return;
    };

    loop {
        if slot.try_enqueue() {
            let encoded = encode_slab_task_ptr(shard_idx as u8, local_idx as u16, generation);
            submit_global(slab_task_poll_trampoline, encoded);
            return;
        }

        match slot.try_notify_result() {
            NotifyResult::Notified | NotifyResult::AlreadyQueued | NotifyResult::Completed => {
                slab.decrement_ref(shard_idx, local_idx, generation);
                return;
            }
            NotifyResult::IdleRace => {
                spin_loop();
            }
        }
    }
}

#[inline(never)]
pub extern "C" fn slab_task_poll_trampoline(ctx: usize) {
    poll_slab_task(ctx);
}
