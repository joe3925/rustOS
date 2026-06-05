use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::device::{DeviceInit, DeviceObject};
use crate::dma::{
    Bidirectional, DmaMapped, FromDevice, IOBUFFER_FRAME_SIZE_4KIB, IOBUFFER_PAGE_SIZE, IoBuffer,
    IoBufferDmaSegment, IoBufferError, IoBufferPageFrame, PhysFramed, ToDevice,
};

static UNMAP_COOKIE_SUM: AtomicUsize = AtomicUsize::new(0);

extern "win64" fn record_unmap(_dev: &Arc<DeviceObject>, cookie: usize) {
    UNMAP_COOKIE_SUM.fetch_add(cookie, Ordering::AcqRel);
}

fn device() -> Arc<DeviceObject> {
    DeviceObject::new(DeviceInit::new())
}

#[test]
fn physical_iobuffer_validates_frame_layout_and_iterates_regions() {
    let frames = [
        IoBufferPageFrame::new(0x2000, IOBUFFER_FRAME_SIZE_4KIB),
        IoBufferPageFrame::new(0x3000, IOBUFFER_FRAME_SIZE_4KIB),
        IoBufferPageFrame::new(0x9000, IOBUFFER_FRAME_SIZE_4KIB),
    ];

    let buffer = IoBuffer::<PhysFramed, ToDevice>::from_frames(128, 6000, &frames).unwrap();
    assert_eq!(buffer.len(), 6000);
    assert_eq!(buffer.frame_offset(), 128);
    assert_eq!(buffer.frame_count(), 3);

    let regions: alloc::vec::Vec<_> = buffer.iter().collect();
    assert_eq!(regions.len(), 1);
    assert!(!regions[0].has_virtual_backing());
    assert_eq!(regions[0].frame_offset(), 128);
    assert_eq!(regions[0].len(), 6000);
    assert_eq!(regions[0].physical_frames().len(), 2);
}

#[test]
fn physical_iobuffer_rejects_invalid_frame_descriptions() {
    assert_eq!(
        IoBuffer::<PhysFramed, ToDevice>::from_frames(0, 1, &[]).unwrap_err(),
        IoBufferError::InvalidFrameLayout {
            frame_offset: 0,
            byte_len: 1
        }
    );

    assert_eq!(
        IoBuffer::<PhysFramed, ToDevice>::from_frames(
            0,
            IOBUFFER_PAGE_SIZE,
            &[IoBufferPageFrame::new(0x2100, IOBUFFER_FRAME_SIZE_4KIB)]
        )
        .unwrap_err(),
        IoBufferError::InvalidFrameAlignment {
            phys_addr: 0x2100,
            byte_len: IOBUFFER_FRAME_SIZE_4KIB
        }
    );

    assert_eq!(
        IoBuffer::<PhysFramed, ToDevice>::from_frames(
            4096,
            1,
            &[IoBufferPageFrame::new(0x2000, IOBUFFER_FRAME_SIZE_4KIB)]
        )
        .unwrap_err(),
        IoBufferError::InvalidFrameLayout {
            frame_offset: 4096,
            byte_len: 1
        }
    );
}

#[test]
fn dma_mapping_compresses_contiguous_segments_and_unmaps_once() {
    let frames = [IoBufferPageFrame::new(0x4000, IOBUFFER_FRAME_SIZE_4KIB)];
    let buffer =
        IoBuffer::<PhysFramed, Bidirectional>::from_frames(0, IOBUFFER_PAGE_SIZE, &frames).unwrap();
    let segments = [
        IoBufferDmaSegment {
            dma_addr: 0x8000,
            byte_len: 1024,
            reserved: 0,
        },
        IoBufferDmaSegment {
            dma_addr: 0x8400,
            byte_len: 1024,
            reserved: 0,
        },
        IoBufferDmaSegment {
            dma_addr: 0x8800,
            byte_len: 1024,
            reserved: 0,
        },
        IoBufferDmaSegment {
            dma_addr: 0x8C00,
            byte_len: 1024,
            reserved: 0,
        },
        IoBufferDmaSegment {
            dma_addr: 0x9000,
            byte_len: 1024,
            reserved: 0,
        },
    ];

    let before = UNMAP_COOKIE_SUM.load(Ordering::Acquire);
    let mapped: IoBuffer<'_, DmaMapped<PhysFramed>, Bidirectional> = buffer
        .apply_dma_mapping(&segments, device(), record_unmap, 7)
        .unwrap();

    assert_eq!(mapped.dma_segments().len(), 1);
    assert_eq!(
        mapped.dma_segments().first(),
        Some(IoBufferDmaSegment {
            dma_addr: 0x8000,
            byte_len: 5120,
            reserved: 0
        })
    );

    let unmapped = mapped.remove_dma_mapping();
    assert!(unmapped.dma_segments().is_empty());
    assert_eq!(UNMAP_COOKIE_SUM.load(Ordering::Acquire), before + 7);
}

#[test]
fn dma_mapping_rejects_too_many_noncompressible_segments_without_unmapping() {
    let frames = [IoBufferPageFrame::new(0x4000, IOBUFFER_FRAME_SIZE_4KIB)];
    let buffer =
        IoBuffer::<PhysFramed, FromDevice>::from_frames(0, IOBUFFER_PAGE_SIZE, &frames).unwrap();
    let segments = [
        IoBufferDmaSegment {
            dma_addr: 0x1000,
            byte_len: 1,
            reserved: 0,
        },
        IoBufferDmaSegment {
            dma_addr: 0x3000,
            byte_len: 2,
            reserved: 0,
        },
        IoBufferDmaSegment {
            dma_addr: 0x6000,
            byte_len: 3,
            reserved: 0,
        },
        IoBufferDmaSegment {
            dma_addr: 0xA000,
            byte_len: 4,
            reserved: 0,
        },
        IoBufferDmaSegment {
            dma_addr: 0xF000,
            byte_len: 5,
            reserved: 0,
        },
    ];

    let err = buffer
        .apply_dma_mapping(&segments, device(), record_unmap, 11)
        .unwrap_err()
        .1;

    assert_eq!(
        err,
        IoBufferError::SegmentCapacityExceeded {
            required: 5,
            capacity: 4
        }
    );
}
