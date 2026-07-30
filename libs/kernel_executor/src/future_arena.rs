use alloc::alloc::{alloc, dealloc, Layout};
use core::ptr::NonNull;

use crate::growable_slab::{GrowableSlab, SlabHandle, DEFAULT_SLAB_SHARDS};
use crate::sync::atomic::{AtomicUsize, Ordering};
use kernel_types::async_ffi::AbiFutureAllocation;

#[derive(Clone, Copy, Debug)]
pub struct FutureArenaConfig {
    pub slots_per_chunk: usize,
    pub max_chunks_per_class: usize,
    pub max_live_futures: usize,
    pub max_bytes: usize,
}

impl Default for FutureArenaConfig {
    fn default() -> Self {
        Self {
            slots_per_chunk: 64,
            max_chunks_per_class: usize::MAX,
            max_live_futures: usize::MAX,
            max_bytes: usize::MAX,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FutureSizeClass {
    Bytes64,
    Bytes128,
    Bytes256,
    Bytes512,
    Bytes1024,
    Bytes2048,
    Bytes4096,
}

impl FutureSizeClass {
    pub const fn capacity(self) -> usize {
        match self {
            Self::Bytes64 => 64,
            Self::Bytes128 => 128,
            Self::Bytes256 => 256,
            Self::Bytes512 => 512,
            Self::Bytes1024 => 1024,
            Self::Bytes2048 => 2048,
            Self::Bytes4096 => 4096,
        }
    }

    fn select(size: usize, align: usize) -> Option<Self> {
        if align > 64 {
            return None;
        }
        match size.max(1) {
            0..=64 => Some(Self::Bytes64),
            65..=128 => Some(Self::Bytes128),
            129..=256 => Some(Self::Bytes256),
            257..=512 => Some(Self::Bytes512),
            513..=1024 => Some(Self::Bytes1024),
            1025..=2048 => Some(Self::Bytes2048),
            2049..=4096 => Some(Self::Bytes4096),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum FutureBacking {
    Slab {
        class: FutureSizeClass,
        handle: SlabHandle,
    },
    Large,
}

#[derive(Debug)]
pub struct FutureAllocation {
    pub ptr: NonNull<u8>,
    pub owner_domain: crate::domain::ExecutorDomainId,
    pub backing: FutureBacking,
    pub capacity: usize,
    pub align: usize,
}

unsafe impl Send for FutureAllocation {}

#[repr(C, align(64))]
struct Block<const N: usize>([u8; N]);

fn block64() -> Block<64> {
    Block([0; 64])
}
fn block128() -> Block<128> {
    Block([0; 128])
}
fn block256() -> Block<256> {
    Block([0; 256])
}
fn block512() -> Block<512> {
    Block([0; 512])
}
fn block1024() -> Block<1024> {
    Block([0; 1024])
}
fn block2048() -> Block<2048> {
    Block([0; 2048])
}
fn block4096() -> Block<4096> {
    Block([0; 4096])
}

pub struct FutureArena {
    owner: crate::domain::ExecutorDomainId,
    config: FutureArenaConfig,
    c64: GrowableSlab<Block<64>>,
    c128: GrowableSlab<Block<128>>,
    c256: GrowableSlab<Block<256>>,
    c512: GrowableSlab<Block<512>>,
    c1024: GrowableSlab<Block<1024>>,
    c2048: GrowableSlab<Block<2048>>,
    c4096: GrowableSlab<Block<4096>>,
    live: AtomicUsize,
    bytes: AtomicUsize,
    class_live: [AtomicUsize; 7],
}

impl FutureArena {
    pub fn new(owner: crate::domain::ExecutorDomainId, config: FutureArenaConfig) -> Self {
        let slots = config.slots_per_chunk.max(1);
        let chunks = config
            .max_chunks_per_class
            .max(1)
            .div_ceil(DEFAULT_SLAB_SHARDS);
        Self {
            owner,
            config,
            c64: GrowableSlab::new(DEFAULT_SLAB_SHARDS, slots, chunks, block64),
            c128: GrowableSlab::new(DEFAULT_SLAB_SHARDS, slots, chunks, block128),
            c256: GrowableSlab::new(DEFAULT_SLAB_SHARDS, slots, chunks, block256),
            c512: GrowableSlab::new(DEFAULT_SLAB_SHARDS, slots, chunks, block512),
            c1024: GrowableSlab::new(DEFAULT_SLAB_SHARDS, slots, chunks, block1024),
            c2048: GrowableSlab::new(DEFAULT_SLAB_SHARDS, slots, chunks, block2048),
            c4096: GrowableSlab::new(DEFAULT_SLAB_SHARDS, slots, chunks, block4096),
            live: AtomicUsize::new(0),
            bytes: AtomicUsize::new(0),
            class_live: core::array::from_fn(|_| AtomicUsize::new(0)),
        }
    }

    fn reserve_accounting(&self, capacity: usize) -> bool {
        if self
            .live
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| {
                (v < self.config.max_live_futures).then_some(v + 1)
            })
            .is_err()
        {
            return false;
        }
        if self
            .bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| {
                v.checked_add(capacity)
                    .filter(|next| *next <= self.config.max_bytes)
            })
            .is_err()
        {
            self.live.fetch_sub(1, Ordering::AcqRel);
            return false;
        }
        true
    }

    fn rollback_accounting(&self, capacity: usize) {
        self.bytes.fetch_sub(capacity, Ordering::AcqRel);
        self.live.fetch_sub(1, Ordering::AcqRel);
    }

    pub fn allocate(&self, size: usize, align: usize) -> Option<FutureAllocation> {
        let class = FutureSizeClass::select(size, align);
        let capacity = class.map(FutureSizeClass::capacity).unwrap_or(size.max(1));
        if let Some(class) = class {
            let limit = self
                .config
                .slots_per_chunk
                .saturating_mul(self.config.max_chunks_per_class);
            if self.class_live[class as usize]
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |live| {
                    (live < limit).then_some(live + 1)
                })
                .is_err()
            {
                return None;
            }
        }
        if !self.reserve_accounting(capacity) {
            if let Some(class) = class {
                self.class_live[class as usize].fetch_sub(1, Ordering::AcqRel);
            }
            return None;
        }

        let result = if let Some(class) = class {
            let reserved = match class {
                FutureSizeClass::Bytes64 => reserve_block(&self.c64),
                FutureSizeClass::Bytes128 => reserve_block(&self.c128),
                FutureSizeClass::Bytes256 => reserve_block(&self.c256),
                FutureSizeClass::Bytes512 => reserve_block(&self.c512),
                FutureSizeClass::Bytes1024 => reserve_block(&self.c1024),
                FutureSizeClass::Bytes2048 => reserve_block(&self.c2048),
                FutureSizeClass::Bytes4096 => reserve_block(&self.c4096),
            };
            reserved.map(|(handle, ptr)| FutureAllocation {
                ptr,
                owner_domain: self.owner,
                backing: FutureBacking::Slab { class, handle },
                capacity,
                align,
            })
        } else {
            Layout::from_size_align(size.max(1), align.max(1))
                .ok()
                .and_then(|layout| NonNull::new(unsafe { alloc(layout) }))
                .map(|ptr| FutureAllocation {
                    ptr,
                    owner_domain: self.owner,
                    backing: FutureBacking::Large,
                    capacity,
                    align,
                })
        };
        if result.is_none() {
            self.rollback_accounting(capacity);
            if let Some(class) = class {
                self.class_live[class as usize].fetch_sub(1, Ordering::AcqRel);
            }
        }
        result
    }

    pub unsafe fn release(&self, allocation: FutureAllocation) -> bool {
        if allocation.owner_domain != self.owner {
            return false;
        }
        let released = match allocation.backing {
            FutureBacking::Slab { class, handle } => match class {
                FutureSizeClass::Bytes64 => self.c64.release(handle),
                FutureSizeClass::Bytes128 => self.c128.release(handle),
                FutureSizeClass::Bytes256 => self.c256.release(handle),
                FutureSizeClass::Bytes512 => self.c512.release(handle),
                FutureSizeClass::Bytes1024 => self.c1024.release(handle),
                FutureSizeClass::Bytes2048 => self.c2048.release(handle),
                FutureSizeClass::Bytes4096 => self.c4096.release(handle),
            },
            FutureBacking::Large => {
                if let Ok(layout) = Layout::from_size_align(allocation.capacity, allocation.align) {
                    dealloc(allocation.ptr.as_ptr(), layout);
                    true
                } else {
                    false
                }
            }
        };
        if released {
            self.rollback_accounting(allocation.capacity);
            if let FutureBacking::Slab { class, .. } = allocation.backing {
                self.class_live[class as usize].fetch_sub(1, Ordering::AcqRel);
            }
        }
        released
    }

    pub fn live_futures(&self) -> usize {
        self.live.load(Ordering::Acquire)
    }
    pub fn live_bytes(&self) -> usize {
        self.bytes.load(Ordering::Acquire)
    }

    pub fn into_abi(allocation: FutureAllocation) -> AbiFutureAllocation {
        let token = match allocation.backing {
            FutureBacking::Slab { class, handle } => {
                (1u64 << 63)
                    | ((class as u64) << 56)
                    | ((handle.shard as u64) << 48)
                    | ((handle.local_index as u64) << 32)
                    | handle.generation as u64
            }
            FutureBacking::Large => large_token(
                allocation.ptr,
                allocation.owner_domain,
                allocation.capacity,
                allocation.align,
            ),
        };
        AbiFutureAllocation {
            ptr: allocation.ptr.as_ptr().cast(),
            owner_domain: allocation.owner_domain.raw(),
            token,
            capacity: allocation
                .capacity
                .try_into()
                .expect("ABI future allocation too large"),
            align: allocation
                .align
                .try_into()
                .expect("ABI future alignment too large"),
        }
    }

    pub unsafe fn release_abi(&self, allocation: AbiFutureAllocation) -> bool {
        let Some(ptr) = NonNull::new(allocation.ptr.cast::<u8>()) else {
            return false;
        };
        let owner = crate::domain::ExecutorDomainId::from_raw(allocation.owner_domain);
        if owner != self.owner {
            return false;
        }
        let capacity = allocation.capacity as usize;
        let align = allocation.align as usize;
        let backing = if allocation.token >> 63 == 1 {
            let class = match ((allocation.token >> 56) & 0x7) as u8 {
                0 => FutureSizeClass::Bytes64,
                1 => FutureSizeClass::Bytes128,
                2 => FutureSizeClass::Bytes256,
                3 => FutureSizeClass::Bytes512,
                4 => FutureSizeClass::Bytes1024,
                5 => FutureSizeClass::Bytes2048,
                6 => FutureSizeClass::Bytes4096,
                _ => return false,
            };
            if capacity != class.capacity() {
                return false;
            }
            let handle = SlabHandle {
                shard: ((allocation.token >> 48) & 0xff) as u8,
                local_index: ((allocation.token >> 32) & 0xffff) as u16,
                generation: allocation.token as u32,
            };
            let expected = match class {
                FutureSizeClass::Bytes64 => block_ptr(&self.c64, handle),
                FutureSizeClass::Bytes128 => block_ptr(&self.c128, handle),
                FutureSizeClass::Bytes256 => block_ptr(&self.c256, handle),
                FutureSizeClass::Bytes512 => block_ptr(&self.c512, handle),
                FutureSizeClass::Bytes1024 => block_ptr(&self.c1024, handle),
                FutureSizeClass::Bytes2048 => block_ptr(&self.c2048, handle),
                FutureSizeClass::Bytes4096 => block_ptr(&self.c4096, handle),
            };
            if expected != Some(ptr) {
                return false;
            }
            FutureBacking::Slab { class, handle }
        } else {
            if allocation.token != large_token(ptr, owner, capacity, align) {
                return false;
            }
            FutureBacking::Large
        };
        self.release(FutureAllocation {
            ptr,
            owner_domain: owner,
            backing,
            capacity,
            align,
        })
    }
}

fn large_token(
    ptr: NonNull<u8>,
    owner: crate::domain::ExecutorDomainId,
    capacity: usize,
    align: usize,
) -> u64 {
    let token = (ptr.as_ptr() as usize as u64)
        ^ owner.raw().rotate_left(17)
        ^ (capacity as u64).rotate_left(31)
        ^ (align as u64).rotate_left(47);
    token & !(1u64 << 63)
}

fn reserve_block<const N: usize>(
    slab: &GrowableSlab<Block<N>>,
) -> Option<(SlabHandle, NonNull<u8>)> {
    let handle = slab.reserve()?;
    let ptr = unsafe { slab.get_mut_ptr(handle)? };
    Some((handle, NonNull::new(ptr.cast::<u8>())?))
}

fn block_ptr<const N: usize>(
    slab: &GrowableSlab<Block<N>>,
    handle: SlabHandle,
) -> Option<NonNull<u8>> {
    let ptr = unsafe { slab.get_mut_ptr(handle)? };
    NonNull::new(ptr.cast::<u8>())
}

#[cfg(all(test, not(any(loom, feature = "loom"))))]
mod tests {
    use super::*;
    use crate::global_async::ExecutorDomainId;

    fn arena(config: FutureArenaConfig) -> FutureArena {
        FutureArena::new(ExecutorDomainId::from_parts(100, 1), config)
    }

    #[test]
    fn selects_classes_accounts_and_reuses() {
        let arena = arena(FutureArenaConfig {
            slots_per_chunk: 2,
            max_chunks_per_class: 2,
            max_live_futures: 16,
            max_bytes: 4096,
        });
        let allocation = arena.allocate(200, 8).unwrap();
        assert!(matches!(
            allocation.backing,
            FutureBacking::Slab {
                class: FutureSizeClass::Bytes256,
                ..
            }
        ));
        assert_eq!(allocation.capacity, 256);
        let ptr = allocation.ptr;
        unsafe {
            assert!(arena.release(allocation));
        }
        assert_eq!(arena.live_futures(), 0);
        assert_eq!(arena.live_bytes(), 0);
        let mut observed_reuse = false;
        for _ in 0..8 {
            let reused = arena.allocate(200, 8).unwrap();
            observed_reuse |= reused.ptr == ptr;
            unsafe {
                assert!(arena.release(reused));
            }
        }
        assert!(observed_reuse);
    }

    #[test]
    fn enforces_count_byte_and_class_limits() {
        let arena = arena(FutureArenaConfig {
            slots_per_chunk: 1,
            max_chunks_per_class: 1,
            max_live_futures: 2,
            max_bytes: 128,
        });
        let first = arena.allocate(1, 1).unwrap();
        assert!(arena.allocate(1, 1).is_none());
        assert!(arena.allocate(65, 1).is_none());
        unsafe {
            assert!(arena.release(first));
        }
    }

    #[test]
    fn large_and_overaligned_allocations_use_direct_backing() {
        let arena = arena(FutureArenaConfig::default());
        for (size, align) in [(4097, 8), (32, 128)] {
            let allocation = arena.allocate(size, align).unwrap();
            assert!(matches!(allocation.backing, FutureBacking::Large));
            assert_eq!((allocation.ptr.as_ptr() as usize) % align, 0);
            unsafe {
                assert!(arena.release(allocation));
            }
        }
    }

    #[test]
    fn domains_have_physically_distinct_arenas() {
        let first = FutureArena::new(
            ExecutorDomainId::from_parts(101, 1),
            FutureArenaConfig::default(),
        );
        let second = FutureArena::new(
            ExecutorDomainId::from_parts(102, 1),
            FutureArenaConfig::default(),
        );
        let a = first.allocate(64, 8).unwrap();
        let b = second.allocate(64, 8).unwrap();
        assert_ne!(a.ptr, b.ptr);
        unsafe {
            assert!(first.release(a));
            assert!(second.release(b));
        }
    }
}
