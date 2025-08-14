use core::sync::atomic::{AtomicUsize, Ordering};

use bootloader_api::info::{MemoryRegion, MemoryRegionKind};
use spin::Mutex;
use x86_64::{
    structures::paging::{FrameAllocator, PageSize, PhysFrame, Size1GiB, Size2MiB, Size4KiB},
    PhysAddr,
};

use crate::{
    memory::paging::{
        constants::{
            BOOT_MEMORY_SIZE, FRAMES_PER_1G, FRAMES_PER_2M, LOW_FRAMES, WORDS_PER_1G, WORDS_PER_2M,
        },
        paging::num_frames_4k,
    },
    util::boot_info,
};

pub static MEMORY_BITMAP: Mutex<[u64; num_frames_4k(BOOT_MEMORY_SIZE) / 64]> =
    Mutex::new([0; num_frames_4k(BOOT_MEMORY_SIZE) / 64]);

pub static USED_MEMORY: AtomicUsize = AtomicUsize::new(0);

pub fn total_usable_bytes() -> u64 {
    boot_info()
        .memory_regions
        .iter()
        .filter(|r| r.kind == MemoryRegionKind::Usable)
        .map(|r| r.end - r.start)
        .sum()
}
#[derive(Clone)]

// This struct doesnt do anything anymore but remains so old code still works
pub struct BootInfoFrameAllocator {}

impl BootInfoFrameAllocator {
    pub fn init_start(memory_regions: &'static [MemoryRegion]) {
        let mut memory_map = MEMORY_BITMAP.lock();

        let words = (LOW_FRAMES + 63) / 64;
        for w in 0..words.min(memory_map.len()) {
            memory_map[w] = !0u64; // mark every bit in the word
        }

        /* ── 2. Tag all non‑Usable regions from the firmware/bootloader map ───── */
        for region in memory_regions {
            if region.kind == MemoryRegionKind::Usable {
                continue;
            }

            let start_frame = (region.start >> 12) as usize;
            let end_frame = ((region.end + 0xFFF) >> 12) as usize - 1;

            if start_frame / 64 >= memory_map.len() {
                continue; // outside our bitmap
            }

            let first_word = start_frame / 64;
            let last_word = end_frame / 64;

            let first_mask = !0u64 << (start_frame & 63);
            let last_mask = !0u64 >> (63 - (end_frame & 63));

            if first_word == last_word {
                memory_map[first_word] |= first_mask & last_mask;
                continue;
            }

            memory_map[first_word] |= first_mask; // partial first word

            for w in (first_word + 1)..last_word {
                // full words in the middle
                memory_map[w] = !0u64;
            }

            memory_map[last_word] |= last_mask; // partial last word
        }
    }
    pub fn init(memory_regions: &'static [MemoryRegion]) -> Self {
        BootInfoFrameAllocator {}
    }
    pub fn deallocate_frame<S: PageSize>(&self, frame: PhysFrame<S>) {
        let base_idx = (frame.start_address().as_u64() >> 12) as usize;
        let (len, bytes) = match S::SIZE {
            Size4KiB::SIZE => (1, 0x1000),
            Size2MiB::SIZE => (FRAMES_PER_2M, 0x20_0000),
            Size1GiB::SIZE => (FRAMES_PER_1G, 0x4000_0000),
            _ => return,
        };

        let mut bm = MEMORY_BITMAP.lock();
        clear_range(bm.as_mut_slice(), base_idx, len);
        USED_MEMORY.fetch_sub(bytes, Ordering::SeqCst);
    }
}

unsafe impl FrameAllocator<Size4KiB> for BootInfoFrameAllocator {
    #[inline]
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        let mut bm = MEMORY_BITMAP.lock();

        for (word_idx, word) in bm.iter_mut().enumerate() {
            if *word == u64::MAX {
                continue;
            }

            let free_bit = (!*word).trailing_zeros() as usize;
            *word |= 1u64 << free_bit;

            let frame_idx = word_idx * 64 + free_bit;
            let phys = (frame_idx as u64) << 12;
            return Some(PhysFrame::containing_address(PhysAddr::new(phys)));
        }
        None
    }
}

unsafe impl FrameAllocator<Size2MiB> for BootInfoFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size2MiB>> {
        let mut bm = MEMORY_BITMAP.lock();
        let words = bm.len();

        for (word_idx, word) in bm.iter().enumerate() {
            if *word == u64::MAX {
                continue; // no free bit here
            }

            // any zero‑bit in this word gives us a candidate index
            let bit = (!*word).trailing_zeros() as usize;
            let idx = word_idx * 64 + bit; // frame index
            let base = idx & !(FRAMES_PER_2M - 1); // align down to 512

            // check whole 2 MiB block
            let start_w = base / 64;
            if start_w + WORDS_PER_2M > words {
                break; // out of bitmap
            }
            let all_free = bm[start_w..start_w + WORDS_PER_2M].iter().all(|w| *w == 0);
            if !all_free {
                continue;
            }

            // mark 512 bits allocated
            for w in &mut bm[start_w..start_w + WORDS_PER_2M] {
                *w = u64::MAX;
            }

            let phys = (base as u64) << 12;
            USED_MEMORY.fetch_add(FRAMES_PER_2M * 4 * 1024, Ordering::SeqCst);
            return Some(PhysFrame::containing_address(PhysAddr::new(phys)));
        }
        None
    }
}

unsafe impl FrameAllocator<Size1GiB> for BootInfoFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size1GiB>> {
        let mut bm = MEMORY_BITMAP.lock();
        let words = bm.len();

        for (word_idx, word) in bm.iter().enumerate() {
            if *word == u64::MAX {
                continue;
            }

            let bit = (!*word).trailing_zeros() as usize;
            let idx = word_idx * 64 + bit;
            let base = idx & !(FRAMES_PER_1G - 1); // align 1 GiB

            let start_w = base / 64;
            if start_w + WORDS_PER_1G > words {
                break;
            }
            let all_free = bm[start_w..start_w + WORDS_PER_1G].iter().all(|w| *w == 0);
            if !all_free {
                continue;
            }

            for w in &mut bm[start_w..start_w + WORDS_PER_1G] {
                *w = u64::MAX;
            }
            let phys = (base as u64) << 12;
            USED_MEMORY.fetch_add(FRAMES_PER_1G * 4 * 1024, Ordering::SeqCst);
            return Some(PhysFrame::containing_address(PhysAddr::new(phys)));
        }
        None
    }
}
fn clear_range(bitmap: &mut [u64], start: usize, len: usize) {
    if len == 0 {
        return;
    }

    let end = start + len - 1;
    let words = bitmap.len();
    if start / 64 >= words {
        return;
    }

    let end = core::cmp::min(end, words * 64 - 1);

    let first_word = start / 64;
    let last_word = end / 64;

    if first_word == last_word {
        let mask = ((!0u64) << (start & 63)) & ((!0u64) >> (63 - (end & 63)));
        bitmap[first_word] &= !mask;
        return;
    }

    bitmap[first_word] &= !(!0u64 << (start & 63));

    for w in (first_word + 1)..last_word {
        bitmap[w] = 0;
    }

    bitmap[last_word] &= !(!0u64 >> (63 - (end & 63)));
}
