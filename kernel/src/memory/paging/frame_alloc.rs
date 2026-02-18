use core::sync::atomic::{AtomicUsize, Ordering};

use bootloader_api::info::{MemoryRegion, MemoryRegionKind};
use kernel_types::irq::IrqSafeMutex;
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

pub static MEMORY_BITMAP: IrqSafeMutex<[u64; num_frames_4k(BOOT_MEMORY_SIZE) / 64]> =
    IrqSafeMutex::new([0; num_frames_4k(BOOT_MEMORY_SIZE) / 64]);

pub static USED_MEMORY: AtomicUsize = AtomicUsize::new(0);

static NEXT_WORD_4K: AtomicUsize = AtomicUsize::new(0);
static NEXT_WORD_2M: AtomicUsize = AtomicUsize::new(0);
static NEXT_WORD_1G: AtomicUsize = AtomicUsize::new(0);

pub fn total_usable_bytes() -> u64 {
    boot_info()
        .memory_regions
        .iter()
        .filter(|r| r.kind == MemoryRegionKind::Usable)
        .map(|r| r.end - r.start)
        .sum()
}

#[derive(Clone)]
pub struct BootInfoFrameAllocator {}

impl BootInfoFrameAllocator {
    pub fn init_start(_memory_regions: &'static [MemoryRegion]) {
        let mut bm = MEMORY_BITMAP.lock();

        for w in bm.iter_mut() {
            *w = 0;
        }

        if LOW_FRAMES != 0 {
            set_range(bm.as_mut_slice(), 0, LOW_FRAMES);
        }

        NEXT_WORD_4K.store(0, Ordering::Release);
        NEXT_WORD_2M.store(0, Ordering::Release);
        NEXT_WORD_1G.store(0, Ordering::Release);
    }

    pub fn init(_memory_regions: &'static [MemoryRegion]) -> Self {
        BootInfoFrameAllocator {}
    }

    /// Allocate `num_frames` physically contiguous 4KiB frames, aligned to
    /// `align_frames` frame boundary (e.g. 512 for 2MiB, 1 for no extra alignment).
    pub fn allocate_contiguous_frames_aligned(
        num_frames: usize,
        align_frames: usize,
    ) -> Option<PhysAddr> {
        if num_frames == 0 || align_frames == 0 {
            return None;
        }
        debug_assert!(align_frames.is_power_of_two());

        let mut bm = MEMORY_BITMAP.lock();
        let total_frames = bm.len() * 64;
        if num_frames > total_frames {
            return None;
        }

        let boot = boot_info();

        for region in boot
            .memory_regions
            .iter()
            .filter(|r| r.kind == MemoryRegionKind::Usable)
        {
            let region_start = usize::max((region.start >> 12) as usize, LOW_FRAMES);
            let end_frame = (region.end >> 12) as usize;

            if region_start >= end_frame {
                continue;
            }

            // Round up to alignment boundary
            let mut start_frame = (region_start + align_frames - 1) & !(align_frames - 1);

            while start_frame + num_frames <= end_frame {
                if range_is_free(&*bm, start_frame, num_frames) {
                    set_range(bm.as_mut_slice(), start_frame, num_frames);
                    USED_MEMORY.fetch_add(num_frames * 0x1000, Ordering::SeqCst);
                    NEXT_WORD_4K.store(start_frame / 64, Ordering::Relaxed);

                    let phys = (start_frame as u64) << 12;
                    return Some(PhysAddr::new(phys));
                }

                // Skip to next aligned position
                start_frame += align_frames;
            }
        }

        None
    }

    pub fn allocate_contiguous_frames(num_frames: usize) -> Option<PhysAddr> {
        Self::allocate_contiguous_frames_aligned(num_frames, 1)
    }

    pub fn deallocate_frame<S: PageSize>(&self, frame: PhysFrame<S>) {
        let base_idx = (frame.start_address().as_u64() >> 12) as usize;
        let (len, bytes_u64) = match S::SIZE {
            Size4KiB::SIZE => (1usize, 0x1000u64),
            Size2MiB::SIZE => (FRAMES_PER_2M, 0x20_0000u64),
            Size1GiB::SIZE => (FRAMES_PER_1G, 0x4000_0000u64),
            _ => return,
        };

        let mut bm = MEMORY_BITMAP.lock();
        clear_range(bm.as_mut_slice(), base_idx, len);

        USED_MEMORY.fetch_sub(bytes_u64 as usize, Ordering::SeqCst);
    }
}

unsafe impl FrameAllocator<Size4KiB> for BootInfoFrameAllocator {
    #[inline]
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        let mut bm = MEMORY_BITMAP.lock();
        let words = bm.len();
        if words == 0 {
            return None;
        }

        let start = NEXT_WORD_4K.load(Ordering::Relaxed) % words;
        for step in 0..words {
            let word_idx = (start + step) % words;
            let word = bm[word_idx];
            if word == u64::MAX {
                continue;
            }

            let free_bit = (!word).trailing_zeros() as usize;
            let frame_idx = word_idx * 64 + free_bit;

            if frame_idx < LOW_FRAMES {
                set_bit(bm.as_mut_slice(), frame_idx);
                continue;
            }

            if !frame_range_is_usable(frame_idx, 1) {
                set_bit(bm.as_mut_slice(), frame_idx);
                continue;
            }

            set_bit(bm.as_mut_slice(), frame_idx);
            NEXT_WORD_4K.store(word_idx, Ordering::Relaxed);

            USED_MEMORY.fetch_add(0x1000, Ordering::SeqCst);
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
        if words == 0 {
            return None;
        }

        let start = NEXT_WORD_2M.load(Ordering::Relaxed) % words;
        for step in 0..words {
            let word_idx = (start + step) % words;
            let word = bm[word_idx];
            if word == u64::MAX {
                continue;
            }

            let bit = (!word).trailing_zeros() as usize;
            let idx = word_idx * 64 + bit;
            let base = idx & !(FRAMES_PER_2M - 1);

            if base < LOW_FRAMES {
                set_bit(bm.as_mut_slice(), idx);
                continue;
            }

            if !frame_range_is_usable(base, FRAMES_PER_2M) {
                set_bit(bm.as_mut_slice(), idx);
                continue;
            }

            let start_w = base / 64;
            if start_w + WORDS_PER_2M > words {
                break;
            }

            let mut all_free = true;
            for w in &bm[start_w..start_w + WORDS_PER_2M] {
                if *w != 0 {
                    all_free = false;
                    break;
                }
            }
            if !all_free {
                continue;
            }

            for w in &mut bm[start_w..start_w + WORDS_PER_2M] {
                *w = u64::MAX;
            }

            NEXT_WORD_2M.store(word_idx, Ordering::Relaxed);

            USED_MEMORY.fetch_add(0x20_0000, Ordering::SeqCst);
            let phys = (base as u64) << 12;
            return Some(PhysFrame::containing_address(PhysAddr::new(phys)));
        }
        None
    }
}

unsafe impl FrameAllocator<Size1GiB> for BootInfoFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size1GiB>> {
        let mut bm = MEMORY_BITMAP.lock();
        let words = bm.len();
        if words == 0 {
            return None;
        }

        let start = NEXT_WORD_1G.load(Ordering::Relaxed) % words;
        for step in 0..words {
            let word_idx = (start + step) % words;
            let word = bm[word_idx];
            if word == u64::MAX {
                continue;
            }

            let bit = (!word).trailing_zeros() as usize;
            let idx = word_idx * 64 + bit;
            let base = idx & !(FRAMES_PER_1G - 1);

            if base < LOW_FRAMES {
                set_bit(bm.as_mut_slice(), idx);
                continue;
            }

            if !frame_range_is_usable(base, FRAMES_PER_1G) {
                set_bit(bm.as_mut_slice(), idx);
                continue;
            }

            let start_w = base / 64;
            if start_w + WORDS_PER_1G > words {
                break;
            }

            let mut all_free = true;
            for w in &bm[start_w..start_w + WORDS_PER_1G] {
                if *w != 0 {
                    all_free = false;
                    break;
                }
            }
            if !all_free {
                continue;
            }

            for w in &mut bm[start_w..start_w + WORDS_PER_1G] {
                *w = u64::MAX;
            }

            NEXT_WORD_1G.store(word_idx, Ordering::Relaxed);

            USED_MEMORY.fetch_add(0x4000_0000, Ordering::SeqCst);
            let phys = (base as u64) << 12;
            return Some(PhysFrame::containing_address(PhysAddr::new(phys)));
        }
        None
    }
}

fn frame_range_is_usable(base_idx: usize, len: usize) -> bool {
    let base = (base_idx as u64) << 12;
    let end_excl = ((base_idx.saturating_add(len) as u64) << 12);

    boot_info().memory_regions.iter().any(|r| {
        if r.kind != MemoryRegionKind::Usable {
            return false;
        }
        let rs = r.start;
        let re = r.end;
        base >= rs && end_excl <= re
    })
}

fn set_bit(bitmap: &mut [u64], idx: usize) {
    let w = idx / 64;
    let b = idx & 63;
    if w >= bitmap.len() {
        return;
    }
    bitmap[w] |= 1u64 << b;
}

fn set_range(bitmap: &mut [u64], start: usize, len: usize) {
    if len == 0 {
        return;
    }

    let words = bitmap.len();
    if words == 0 {
        return;
    }

    if start / 64 >= words {
        return;
    }

    let end_incl = start + len - 1;
    let max_bit = words * 64 - 1;
    let end_incl = core::cmp::min(end_incl, max_bit);

    let first_word = start / 64;
    let last_word = end_incl / 64;

    if first_word == last_word {
        let mask = ((!0u64) << (start & 63)) & ((!0u64) >> (63 - (end_incl & 63)));
        bitmap[first_word] |= mask;
        return;
    }

    bitmap[first_word] |= !0u64 << (start & 63);

    for w in (first_word + 1)..last_word {
        bitmap[w] = !0u64;
    }

    bitmap[last_word] |= !0u64 >> (63 - (end_incl & 63));
}

fn clear_range(bitmap: &mut [u64], start: usize, len: usize) {
    if len == 0 {
        return;
    }

    let words = bitmap.len();
    if words == 0 {
        return;
    }

    if start / 64 >= words {
        return;
    }

    let end_incl = start + len - 1;
    let max_bit = words * 64 - 1;
    let end_incl = core::cmp::min(end_incl, max_bit);

    let first_word = start / 64;
    let last_word = end_incl / 64;

    if first_word == last_word {
        let mask = ((!0u64) << (start & 63)) & ((!0u64) >> (63 - (end_incl & 63)));
        bitmap[first_word] &= !mask;
        return;
    }

    bitmap[first_word] &= !(!0u64 << (start & 63));

    for w in (first_word + 1)..last_word {
        bitmap[w] = 0;
    }

    bitmap[last_word] &= !(!0u64 >> (63 - (end_incl & 63)));
}

fn range_is_free(bitmap: &[u64], start: usize, len: usize) -> bool {
    if len == 0 {
        return false;
    }

    let end = match start.checked_add(len) {
        Some(v) => v,
        None => return false,
    };

    let total_bits = bitmap.len() * 64;
    if end > total_bits {
        return false;
    }

    let first_word = start / 64;
    let last_word = (end - 1) / 64;

    if first_word == last_word {
        let mask = ((!0u64) << (start & 63)) & ((!0u64) >> (63 - ((end - 1) & 63)));
        return (bitmap[first_word] & mask) == 0;
    }

    let first_mask = !0u64 << (start & 63);
    if (bitmap[first_word] & first_mask) != 0 {
        return false;
    }

    for w in (first_word + 1)..last_word {
        if bitmap[w] != 0 {
            return false;
        }
    }

    let last_mask = !0u64 >> (63 - ((end - 1) & 63));
    (bitmap[last_word] & last_mask) == 0
}
