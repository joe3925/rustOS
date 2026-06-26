use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::device::{DeviceInit, DeviceObject};
use crate::dma::{
    Bidirectional, IoBuffer, IoBufferBacking, IoBufferBackingConfig, IoBufferBackingDesc,
    IoBufferDmaMappingLayout, IoBufferDmaSegment, IoBufferError, IoBufferPageFrame,
};

const TEST_FRAME_SIZE: u64 = 512 * 8;
const TEST_GRANULE: usize = TEST_FRAME_SIZE as usize;

static UNMAP_COOKIE_SUM: AtomicUsize = AtomicUsize::new(0);

extern "C" fn record_unmap(_dev: &Arc<DeviceObject>, cookie: usize) {
    UNMAP_COOKIE_SUM.fetch_add(cookie, Ordering::AcqRel);
}

fn device() -> Arc<DeviceObject> {
    DeviceObject::new(DeviceInit::new())
}

fn frame(phys_addr: u64) -> IoBufferPageFrame {
    IoBufferPageFrame::new(phys_addr, TEST_FRAME_SIZE, crate::arch::VirtAddr::new(0))
}

fn backing_from_frames<'a>(
    frame_offset: usize,
    byte_len: usize,
    frames: &'a [IoBufferPageFrame],
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
    frames: &[IoBufferPageFrame],
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
    assert_eq!(regions[0].physical_frames().len(), 3);
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

    assert_eq!(mapped.dma_segments().len(), 1);
    assert_eq!(
        mapped.dma_segments().first(),
        Some(IoBufferDmaSegment {
            dma_addr: 0x8000,
            byte_len: TEST_GRANULE as u32,
            reserved: 0
        })
    );

    let unmapped = mapped.remove_dma_mapping().unwrap();
    assert!(unmapped.dma_segments().is_empty());
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
