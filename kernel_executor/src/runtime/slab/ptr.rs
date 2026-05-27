use core::task::Waker;

use crate::sync::spin_loop;

use super::super::runtime::submit_global;
use super::slot::{JoinableSlot, NotifyResult, SlabSlot, TaskSlot};
use super::task_slab::{get_task_slab, TaskSlab};

const PTR_TAG_DETACHED: usize = 0b01;
const PTR_TAG_JOINABLE: usize = 0b11;

const PTR_SHARD_BITS: usize = 3;
const PTR_LOCAL_BITS: usize = 12;
const PTR_GEN_BITS: usize = 16;

const PTR_SHARD_SHIFT: usize = 2;
const PTR_LOCAL_SHIFT: usize = PTR_SHARD_SHIFT + PTR_SHARD_BITS;
const PTR_GEN_SHIFT: usize = PTR_LOCAL_SHIFT + PTR_LOCAL_BITS;

const PTR_SHARD_MASK: usize = (1usize << PTR_SHARD_BITS) - 1;
const PTR_LOCAL_MASK: usize = (1usize << PTR_LOCAL_BITS) - 1;
const PTR_GEN_MASK: usize = (1usize << PTR_GEN_BITS) - 1;

#[inline]
fn encode_slab_ptr_tag<const TAG: usize>(shard_idx: u8, local_idx: u16, generation: u32) -> usize {
    let shard_bits = ((shard_idx as usize) & PTR_SHARD_MASK) << PTR_SHARD_SHIFT;
    let local_bits = ((local_idx as usize) & PTR_LOCAL_MASK) << PTR_LOCAL_SHIFT;
    let gen_bits = ((generation as usize) & PTR_GEN_MASK) << PTR_GEN_SHIFT;
    gen_bits | local_bits | shard_bits | TAG
}

#[inline]
fn decode_slab_ptr_tag<const TAG: usize>(ptrv: usize) -> Option<(usize, usize, u32)> {
    if (ptrv & 0b11) != TAG {
        return None;
    }
    let shard_idx = (ptrv >> PTR_SHARD_SHIFT) & PTR_SHARD_MASK;
    let local_idx = (ptrv >> PTR_LOCAL_SHIFT) & PTR_LOCAL_MASK;
    let generation = ((ptrv >> PTR_GEN_SHIFT) & PTR_GEN_MASK) as u32;

    Some((shard_idx, local_idx, generation))
}

#[inline]
pub fn encode_slab_ptr(shard_idx: u8, local_idx: u16, generation: u32) -> usize {
    encode_slab_ptr_tag::<PTR_TAG_DETACHED>(shard_idx, local_idx, generation)
}

#[inline]
pub fn decode_slab_ptr(ptrv: usize) -> Option<(usize, usize, u32)> {
    decode_slab_ptr_tag::<PTR_TAG_DETACHED>(ptrv)
}

#[inline]
pub fn encode_joinable_slab_ptr(shard_idx: u8, local_idx: u16, generation: u32) -> usize {
    encode_slab_ptr_tag::<PTR_TAG_JOINABLE>(shard_idx, local_idx, generation)
}

#[inline]
pub fn decode_joinable_slab_ptr(ptrv: usize) -> Option<(usize, usize, u32)> {
    decode_slab_ptr_tag::<PTR_TAG_JOINABLE>(ptrv)
}

#[inline]
#[allow(dead_code)]
pub fn is_slab_ptr(ptrv: usize) -> bool {
    (ptrv & 0b01) != 0
}

#[inline]
#[allow(dead_code)]
pub fn is_joinable_slab_ptr(ptrv: usize) -> bool {
    (ptrv & 0b11) == PTR_TAG_JOINABLE
}

trait SlabTaskKind {
    type Slot: SlabSlot;

    const TRAMPOLINE: extern "win64" fn(usize);

    fn encode(shard_idx: u8, local_idx: u16, generation: u32) -> usize;
    fn decode(ctx: usize) -> Option<(usize, usize, u32)>;
    fn get_slot(
        slab: &TaskSlab,
        shard_idx: usize,
        local_idx: usize,
        generation: u32,
    ) -> Option<&Self::Slot>;
    fn increment_ref(slab: &TaskSlab, shard_idx: usize, local_idx: usize, generation: u32) -> bool;
    fn decrement_ref(slab: &TaskSlab, shard_idx: usize, local_idx: usize, generation: u32);
    fn poll_once(
        slot: &Self::Slot,
        waker: &Waker,
        shard_idx: usize,
        local_idx: usize,
        generation: u32,
    ) -> bool;
}

struct DetachedSlabTask;

impl SlabTaskKind for DetachedSlabTask {
    type Slot = TaskSlot;

    const TRAMPOLINE: extern "win64" fn(usize) = slab_poll_trampoline;

    #[inline]
    fn encode(shard_idx: u8, local_idx: u16, generation: u32) -> usize {
        encode_slab_ptr(shard_idx, local_idx, generation)
    }

    #[inline]
    fn decode(ctx: usize) -> Option<(usize, usize, u32)> {
        decode_slab_ptr(ctx)
    }

    #[inline]
    fn get_slot(
        slab: &TaskSlab,
        shard_idx: usize,
        local_idx: usize,
        generation: u32,
    ) -> Option<&TaskSlot> {
        slab.get_slot(shard_idx, local_idx, generation)
    }

    #[inline]
    fn increment_ref(slab: &TaskSlab, shard_idx: usize, local_idx: usize, generation: u32) -> bool {
        slab.increment_ref(shard_idx, local_idx, generation)
    }

    #[inline]
    fn decrement_ref(slab: &TaskSlab, shard_idx: usize, local_idx: usize, generation: u32) {
        slab.decrement_ref(shard_idx, local_idx, generation);
    }

    #[inline]
    fn poll_once(
        slot: &TaskSlot,
        waker: &Waker,
        shard_idx: usize,
        local_idx: usize,
        generation: u32,
    ) -> bool {
        slot.poll_once(waker, shard_idx, local_idx, generation)
    }
}

struct JoinableSlabTask;

impl SlabTaskKind for JoinableSlabTask {
    type Slot = JoinableSlot;

    const TRAMPOLINE: extern "win64" fn(usize) = joinable_slab_poll_trampoline;

    #[inline]
    fn encode(shard_idx: u8, local_idx: u16, generation: u32) -> usize {
        encode_joinable_slab_ptr(shard_idx, local_idx, generation)
    }

    #[inline]
    fn decode(ctx: usize) -> Option<(usize, usize, u32)> {
        decode_joinable_slab_ptr(ctx)
    }

    #[inline]
    fn get_slot(
        slab: &TaskSlab,
        shard_idx: usize,
        local_idx: usize,
        generation: u32,
    ) -> Option<&JoinableSlot> {
        slab.get_joinable_slot(shard_idx, local_idx, generation)
    }

    #[inline]
    fn increment_ref(slab: &TaskSlab, shard_idx: usize, local_idx: usize, generation: u32) -> bool {
        slab.increment_joinable_ref(shard_idx, local_idx, generation)
    }

    #[inline]
    fn decrement_ref(slab: &TaskSlab, shard_idx: usize, local_idx: usize, generation: u32) {
        slab.decrement_joinable_ref(shard_idx, local_idx, generation);
    }

    #[inline]
    fn poll_once(
        slot: &JoinableSlot,
        waker: &Waker,
        shard_idx: usize,
        local_idx: usize,
        generation: u32,
    ) -> bool {
        slot.poll_once_joinable(waker, shard_idx, local_idx, generation)
    }
}

#[inline(always)]
fn poll_slab_task<K>(ctx: usize)
where
    K: SlabTaskKind,
{
    let Some((shard_idx, local_idx, generation)) = K::decode(ctx) else {
        return;
    };

    let slab = get_task_slab();
    let Some(slot) = K::get_slot(slab, shard_idx, local_idx, generation) else {
        return;
    };

    let waker = slot.get_cached_waker(shard_idx, local_idx, generation);

    let completed = K::poll_once(slot, &waker, shard_idx, local_idx, generation);

    K::decrement_ref(slab, shard_idx, local_idx, generation);

    if completed {
        K::decrement_ref(slab, shard_idx, local_idx, generation);
    }
}

#[inline(always)]
fn enqueue_slab_task_inner<K>(shard_idx: usize, local_idx: usize, generation: u32)
where
    K: SlabTaskKind,
{
    let slab = get_task_slab();

    if !K::increment_ref(slab, shard_idx, local_idx, generation) {
        return;
    }

    let Some(slot) = K::get_slot(slab, shard_idx, local_idx, generation) else {
        K::decrement_ref(slab, shard_idx, local_idx, generation);
        return;
    };

    loop {
        if slot.try_enqueue() {
            let encoded = K::encode(shard_idx as u8, local_idx as u16, generation);
            submit_global(K::TRAMPOLINE, encoded);
            return;
        }

        match slot.try_notify_result() {
            NotifyResult::Notified | NotifyResult::AlreadyQueued | NotifyResult::Completed => {
                K::decrement_ref(slab, shard_idx, local_idx, generation);
                return;
            }
            NotifyResult::IdleRace => {
                spin_loop();
            }
        }
    }
}

#[inline(never)]
pub extern "win64" fn slab_poll_trampoline(ctx: usize) {
    poll_slab_task::<DetachedSlabTask>(ctx);
}

pub fn enqueue_slab_task(shard_idx: usize, local_idx: usize, generation: u32) {
    enqueue_slab_task_inner::<DetachedSlabTask>(shard_idx, local_idx, generation);
}

#[inline(never)]
pub extern "win64" fn joinable_slab_poll_trampoline(ctx: usize) {
    poll_slab_task::<JoinableSlabTask>(ctx);
}

pub fn enqueue_joinable_slab_task(shard_idx: usize, local_idx: usize, generation: u32) {
    enqueue_slab_task_inner::<JoinableSlabTask>(shard_idx, local_idx, generation);
}
