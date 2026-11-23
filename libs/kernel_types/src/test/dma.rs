use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::device::{DeviceInit, DeviceObject};
use crate::dma::{
    Bidirectional, IoBuffer, IoBufferBacking, IoBufferBackingConfig, IoBufferBackingDesc,
    IoBufferDmaMappingLayout, IoBufferDmaSegment, IoBufferError, PhysicalFrameExtent,
};

const TEST_FRAME_SIZE: u64 = 512 * 8;
const TEST_GRANULE: usize = TEST_FRAME_SIZE as usize;

static UNMAP_COOKIE_SUM: AtomicUsize = AtomicUsize::new(0);

extern "C" fn record_unmap(_dev: &Arc<DeviceObject>, cookie: usize) {
    UNMAP_COOKIE_SUM.fetch_add(cookie, Ordering::AcqRel);
}

extern "C" fn count_unmap(_dev: &Arc<DeviceObject>, cookie: usize) {
    // Tests keep the counter alive until every buffer with this mapping is dropped.
    let count = unsafe { &*(cookie as *const AtomicUsize) };
    count.fetch_add(1, Ordering::AcqRel);
}

fn device() -> Arc<DeviceObject> {
    DeviceObject::new(DeviceInit::new())
}

fn frame(phys_addr: u64) -> PhysicalFrameExtent {
    unsafe { PhysicalFrameExtent::new(phys_addr, TEST_FRAME_SIZE, crate::arch::VirtAddr::new(0)) }
}

fn backing_from_frames<'a>(
    frame_offset: usize,
    byte_len: usize,
    frames: &'a [PhysicalFrameExtent],
) -> Result<IoBufferBacking<'a>, IoBufferError> {
    IoBufferBacking::new(
        IoBufferBackingDesc::Frames {
            frame_offset,
            byte_len,
            frames,
        },
        IoBufferBackingConfig::default(),
    )
}

fn backing_from_frames_err(
    frame_offset: usize,
    byte_len: usize,
    frames: &[PhysicalFrameExtent],
) -> IoBufferError {
    match backing_from_frames(frame_offset, byte_len, frames) {
        Ok(_) => panic!("expected IoBufferBacking::new to fail"),
        Err(err) => err,
    }
}

#[test]
fn physical_iobuffer_validates_frame_layout_and_iterates_regions() {
    let frames = [frame(0x2000), frame(0x3000), frame(0x9000)];

    let backing = backing_from_frames(128, 6000, &frames).unwrap();
    let buffer = backing.create_phys_to_device(0, 6000).unwrap();
    assert_eq!(buffer.len(), 6000);

    let regions: alloc::vec::Vec<_> = buffer.regions().collect();
    assert_eq!(regions.len(), 1);
    assert_eq!(regions[0].frame_offset(), 128);
    assert_eq!(regions[0].len(), 6000);
    assert_eq!(regions[0].page_frames().len(), 2);
}

#[test]
fn physical_iobuffer_rejects_invalid_frame_descriptions() {
    assert_eq!(
        backing_from_frames_err(0, 1, &[]),
        IoBufferError::InvalidFrameLayout {
            frame_offset: 0,
            byte_len: 1
        }
    );

    assert_eq!(
        backing_from_frames_err(0, TEST_GRANULE, &[frame(0x2100)]),
        IoBufferError::InvalidFrameAlignment {
            phys_addr: 0x2100,
            byte_len: TEST_FRAME_SIZE
        }
    );

    assert_eq!(
        backing_from_frames_err(TEST_GRANULE, 1, &[frame(0x2000)]),
        IoBufferError::InvalidFrameLayout {
            frame_offset: TEST_GRANULE,
            byte_len: 1
        }
    );
}

#[test]
fn dma_mapping_contiguous_layout_unmaps_once() {
    let frames = [frame(0x4000)];
    let backing = backing_from_frames(0, TEST_GRANULE, &frames).unwrap();
    let buffer = backing.create_phys_bidirectional(0, TEST_GRANULE).unwrap();
    let layout = IoBufferDmaMappingLayout::Contiguous {
        dma_addr: 0x8000,
        byte_len: buffer.len(),
    };

    let before = UNMAP_COOKIE_SUM.load(Ordering::Acquire);
    let mapped: IoBuffer<'_, '_, Bidirectional> = buffer
        .apply_dma_mapping(layout, device(), record_unmap, 7)
        .unwrap();

    assert_eq!(mapped.dma_segments().count(), 1);
    assert_eq!(
        mapped.dma_segments().next(),
        Some(IoBufferDmaSegment {
            dma_addr: 0x8000,
            byte_len: TEST_GRANULE as u32,
            reserved: 0
        })
    );

    let unmapped = mapped.remove_dma_mapping().unwrap();
    assert!(unmapped.dma_segments().next().is_none());
    assert_eq!(UNMAP_COOKIE_SUM.load(Ordering::Acquire), before + 7);
}

#[test]
fn dma_mapping_rejects_invalid_layout_without_unmapping() {
    let frames = [frame(0x4000)];
    let backing = backing_from_frames(0, TEST_GRANULE, &frames).unwrap();
    let buffer = backing.create_phys_from_device(0, TEST_GRANULE).unwrap();
    let before = UNMAP_COOKIE_SUM.load(Ordering::Acquire);

    let err = buffer
        .apply_dma_mapping(
            IoBufferDmaMappingLayout::FixedChunks {
                dma_addr: 0x1000,
                chunk_len: 0,
                count: 5,
            },
            device(),
            record_unmap,
            11,
        )
        .unwrap_err()
        .1;

    assert_eq!(
        err,
        IoBufferError::InvalidFrameLayout {
            frame_offset: 0,
            byte_len: 0
        }
    );
    assert_eq!(UNMAP_COOKIE_SUM.load(Ordering::Acquire), before);
}

#[test]
fn virtual_iobuffer_copies_without_physical_description() {
    let mut bytes = [1u8, 2, 3, 4, 5, 6];
    let mut buffer =
        unsafe { IoBuffer::from_virt_bidirectional(bytes.as_mut_ptr() as usize, bytes.len()) };

    assert!(buffer.backing().is_none());
    assert_eq!(buffer.regions().count(), 0);

    let mut copied = [0u8; 3];
    buffer.copy_to_slice(2, &mut copied).unwrap();
    assert_eq!(copied, [3, 4, 5]);

    buffer.copy_from_slice(1, &[9, 8]).unwrap();
    assert_eq!(bytes, [1, 9, 8, 4, 5, 6]);
    assert_eq!(buffer.regions().count(), 0);
}

#[test]
fn factory_mapping_unmaps_after_last_split_without_releasing_anchor_lease() {
    let unmaps = AtomicUsize::new(0);
    let frames = [frame(0x4000)];
    let backing = backing_from_frames(0, TEST_GRANULE, &frames).unwrap();
    let factory = backing
        .create_phys_to_device(0, TEST_GRANULE)
        .unwrap()
        .into_to_device_factory()
        .unwrap();
    let mapped = factory
        .create(0, TEST_GRANULE)
        .unwrap()
        .apply_dma_mapping(
            IoBufferDmaMappingLayout::Contiguous {
                dma_addr: 0x8000,
                byte_len: TEST_GRANULE,
            },
            device(),
            count_unmap,
            &unmaps as *const AtomicUsize as usize,
        )
        .unwrap();

    let (left, right) = mapped.split_at(TEST_GRANULE / 2).unwrap();
    drop(left);
    assert_eq!(unmaps.load(Ordering::Acquire), 0);
    drop(right);
    assert_eq!(unmaps.load(Ordering::Acquire), 1);
    assert!(matches!(
        backing.create_phys_to_device(0, TEST_GRANULE),
        Err(IoBufferError::LeaseConflict { .. })
    ));

    drop(factory);
    drop(backing.create_phys_to_device(0, TEST_GRANULE).unwrap());
    assert_eq!(unmaps.load(Ordering::Acquire), 1);
}

#[test]
fn factory_mapping_replacement_and_removal_preserve_other_owners() {
    let unmaps = [const { AtomicUsize::new(0) }; 3];
    let frames = [frame(0x4000)];
    let backing = backing_from_frames(0, TEST_GRANULE, &frames).unwrap();
    let factory = backing
        .create_phys_to_device(0, TEST_GRANULE)
        .unwrap()
        .apply_dma_mapping(
            IoBufferDmaMappingLayout::Contiguous {
                dma_addr: 0x8000,
                byte_len: TEST_GRANULE,
            },
            device(),
            count_unmap,
            &unmaps[0] as *const AtomicUsize as usize,
        )
        .unwrap()
        .into_to_device_factory()
        .unwrap();
    let child = factory.create(0, TEST_GRANULE).unwrap();
    assert_eq!(child.dma_segments().next().unwrap().dma_addr, 0x8000);
    let mapped = child
        .apply_dma_mapping(
            IoBufferDmaMappingLayout::Contiguous {
                dma_addr: 0xa000,
                byte_len: TEST_GRANULE,
            },
            device(),
            count_unmap,
            &unmaps[1] as *const AtomicUsize as usize,
        )
        .unwrap();
    let (left, right) = mapped.split_at(TEST_GRANULE / 2).unwrap();
    let left = left
        .apply_dma_mapping(
            IoBufferDmaMappingLayout::Contiguous {
                dma_addr: 0xc000,
                byte_len: TEST_GRANULE / 2,
            },
            device(),
            count_unmap,
            &unmaps[2] as *const AtomicUsize as usize,
        )
        .unwrap();
    assert_eq!(unmaps[1].load(Ordering::Acquire), 0);
    assert_eq!(left.dma_segments().next().unwrap().dma_addr, 0xc000);
    assert_eq!(right.dma_segments().next().unwrap().dma_addr, 0xa800);

    let left = left.remove_dma_mapping().unwrap();
    assert!(!left.is_dma_mapped());
    assert_eq!(unmaps[2].load(Ordering::Acquire), 1);
    drop(left);
    drop(right);
    assert_eq!(unmaps[1].load(Ordering::Acquire), 1);
    assert_eq!(unmaps[0].load(Ordering::Acquire), 0);
    let inherited = factory.create(0, TEST_GRANULE).unwrap();
    assert_eq!(inherited.dma_segments().next().unwrap().dma_addr, 0x8000);
    let inherited = inherited.remove_dma_mapping().unwrap();
    assert!(!inherited.is_dma_mapped());
    drop(inherited);
    assert_eq!(unmaps[0].load(Ordering::Acquire), 0);

    drop(factory);
    for count in unmaps {
        assert_eq!(count.load(Ordering::Acquire), 1);
    }
}

#[test]
fn virtual_iobuffer_requires_explicit_physical_description() {
    let mut bytes = [0u8; 8];
    let mut buffer =
        unsafe { IoBuffer::from_virt_bidirectional(bytes.as_mut_ptr() as usize, bytes.len()) };

    assert!(matches!(
        buffer.dma_buffer_view(),
        Err(IoBufferError::PhysicalDescriptionMissing)
    ));

    buffer.ensure_phys_described().unwrap();
    assert_eq!(buffer.dma_buffer_view().unwrap().len(), bytes.len());
}

#[test]
fn virtual_iobuffer_split_preserves_ranges() {
    let mut bytes = [0u8; 8];
    let buffer =
        unsafe { IoBuffer::from_virt_bidirectional(bytes.as_mut_ptr() as usize, bytes.len()) };
    let (mut left, mut right) = buffer.split_at(3).unwrap();

    assert_eq!(left.len(), 3);
    assert_eq!(right.len(), 5);
    left.copy_from_slice(0, &[1, 2, 3]).unwrap();
    right.copy_from_slice(0, &[4, 5, 6, 7, 8]).unwrap();
    assert_eq!(bytes, [1, 2, 3, 4, 5, 6, 7, 8]);
}

#[test]
fn backing_leases_enforce_chunk_overlap_and_release() {
    let bytes = [0u8; 1024];
    let backing = IoBufferBacking::new(
        IoBufferBackingDesc::Slice(&bytes),
        IoBufferBackingConfig::default(),
    )
    .unwrap();
    let first = backing.create_to_device(0, 256).unwrap();
    assert_eq!(
        backing.create_to_device(128, 128).unwrap_err(),
        IoBufferError::LeaseConflict {
            start: 128,
            len: 128
        }
    );
    let adjacent = backing.create_to_device(256, 128).unwrap();
    drop(first);
    let reused = backing.create_to_device(0, 256).unwrap();
    drop(reused);
    drop(adjacent);
}

#[test]
fn backing_split_materializes_coarse_claims() {
    let bytes = [0u8; 32768];
    let backing = IoBufferBacking::new(
        IoBufferBackingDesc::Slice(&bytes),
        IoBufferBackingConfig::default(),
    )
    .unwrap();
    let whole = backing.create_to_device(0, bytes.len()).unwrap();
    let (left, right) = whole.split_at(16384).unwrap();
    let (first, left_rest) = left.split_at(128).unwrap();
    drop(first);
    let reclaimed = backing.create_to_device(0, 128).unwrap();
    assert!(matches!(
        backing.create_to_device(128, 128),
        Err(IoBufferError::LeaseConflict { .. })
    ));
    drop(reclaimed);
    drop(right);
    assert!(matches!(
        backing.create_to_device(128, 16256),
        Err(IoBufferError::LeaseConflict { .. })
    ));
    drop(left_rest);
    let restored = backing.create_to_device(0, bytes.len()).unwrap();
    drop(restored);
}

#[test]
fn backing_validates_and_applies_overlap_granularity() {
    for granularity in [16, 64, 128, 512, 4096] {
        let bytes = [0u8; 8192];
        let config =
            IoBufferBackingConfig::worst_case_for_len_with_granularity(bytes.len(), granularity);
        let backing = IoBufferBacking::new(IoBufferBackingDesc::Slice(&bytes), config).unwrap();
        let first = backing.create_to_device(0, granularity).unwrap();
        assert!(matches!(
            backing.create_to_device(0, granularity),
            Err(IoBufferError::LeaseConflict { .. })
        ));
        let adjacent = backing.create_to_device(granularity, granularity).unwrap();
        drop(first);
        drop(adjacent);
    }

    let bytes = [0u8; 64];
    let mut config = IoBufferBackingConfig::default();
    config.overlap_granularity = 3;
    assert!(matches!(
        IoBufferBacking::new(IoBufferBackingDesc::Slice(&bytes), config),
        Err(IoBufferError::InvalidOverlapGranularity)
    ));
    let backing = IoBufferBacking::new(
        IoBufferBackingDesc::Slice(&bytes),
        IoBufferBackingConfig::default(),
    )
    .unwrap();
    let full = backing.create_to_device(0, bytes.len()).unwrap();
    drop(full);
}

#[test]
fn exhausted_lease_table_does_not_retain_overlap() {
    let bytes = [0u8; 512];
    let mut config = IoBufferBackingConfig::default();
    config.lease_capacity = 1;
    let backing = IoBufferBacking::new(IoBufferBackingDesc::Slice(&bytes), config).unwrap();
    let first = backing.create_to_device(0, 128).unwrap();
    assert!(matches!(
        backing.create_to_device(128, 128),
        Err(IoBufferError::LeaseCapacityExceeded { capacity: 1 })
    ));
    drop(first);
    let second = backing.create_to_device(128, 128).unwrap();
    drop(second);
}

#[test]
fn redescribe_replaces_overlap_state_with_an_empty_map() {
    let first_bytes = [0u8; 512];
    let second_bytes = [0u8; 1024];
    let mut backing = IoBufferBacking::new(
        IoBufferBackingDesc::Slice(&first_bytes),
        IoBufferBackingConfig::default(),
    )
    .unwrap();
    let lease = backing.create_to_device(0, 512).unwrap();
    drop(lease);
    backing
        .redescribe(IoBufferBackingDesc::Slice(&second_bytes))
        .unwrap();
    let lease = backing.create_to_device(0, 1024).unwrap();
    drop(lease);
}

#[test]
fn concurrent_overlap_and_disjoint_claims_are_exclusive() {
    use std::sync::{Arc, Barrier};
    use std::thread;

    let bytes = [0u8; 2048];
    let backing = IoBufferBacking::new(
        IoBufferBackingDesc::Slice(&bytes),
        IoBufferBackingConfig::default(),
    )
    .unwrap();
    let barrier = Arc::new(Barrier::new(8));
    let successes = AtomicUsize::new(0);
    thread::scope(|scope| {
        for _ in 0..8 {
            let barrier = barrier.clone();
            let successes = &successes;
            let backing = &backing;
            scope.spawn(move || {
                barrier.wait();
                let lease = backing.create_to_device(0, 128).ok();
                if lease.is_some() {
                    successes.fetch_add(1, Ordering::AcqRel);
                }
                barrier.wait();
                drop(lease);
            });
        }
    });
    assert_eq!(successes.load(Ordering::Acquire), 1);

    thread::scope(|scope| {
        for index in 0..8 {
            let backing = &backing;
            scope.spawn(move || {
                let lease = backing.create_to_device(index * 128, 128).unwrap();
                std::thread::yield_now();
                drop(lease);
            });
        }
    });
}
