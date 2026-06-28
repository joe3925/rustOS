struct VirtualFrameTranslation {
    phys_addr: u64,
    byte_len: u64,
    offset: u64,
}

#[inline]
fn is_valid_frame_size(byte_len: u64) -> bool {
    byte_len != 0 && byte_len.is_power_of_two()
}

fn translate_virtual_frame(virt_addr: usize) -> Option<VirtualFrameTranslation> {
    let (frame_size, phys_addr) = resolve_virtual_range_frame(VirtAddr::new(virt_addr as u64))?;

    if !is_valid_frame_size(frame_size) {
        return None;
    }

    let offset = virt_addr as u64 & (frame_size - 1);
    let phys_addr = phys_addr.as_u64();
    let phys_base = phys_addr.checked_sub(offset)?;

    if phys_base & (frame_size - 1) != 0 {
        return None;
    }

    Some(VirtualFrameTranslation {
        phys_addr: phys_base,
        byte_len: frame_size,
        offset,
    })
}

#[cfg(any(test, feature = "hosted-tests"))]
fn resolve_virtual_range_frame(addr: VirtAddr) -> Option<(u64, PhysAddr)> {
    Some((4096, PhysAddr::new(addr.as_u64())))
}

#[cfg(not(any(test, feature = "hosted-tests")))]
fn resolve_virtual_range_frame(addr: VirtAddr) -> Option<(u64, PhysAddr)> {
    let block = <Platform as PagingPlatform>::translate_addr(addr)?;
    Some((block.block_size, block.phys_addr))
}

fn build_backing_into<'data>(
    desc: IoBufferBackingDesc<'data>,
    extents: &mut Vec<IoBufferExtent>,
    frames: &mut Vec<IoBufferPageFrame>,
) -> Result<(BackingMemory<'data>, usize), IoBufferError> {
    extents.clear();
    frames.clear();

    match desc {
        IoBufferBackingDesc::Slice(bytes) => {
            let memory = BackingMemory::SingleRead {
                ptr: bytes.as_ptr() as usize,
                len: bytes.len(),
                _data: PhantomData,
            };

            let byte_len = build_virtual_backing_from_iter(
                core::iter::once((bytes.as_ptr() as usize, bytes.len())),
                extents,
                frames,
            )?;

            Ok((memory, byte_len))
        }
        IoBufferBackingDesc::SliceMut(bytes) => {
            let memory = BackingMemory::SingleWrite {
                ptr: bytes.as_mut_ptr() as usize,
                len: bytes.len(),
                _data: PhantomData,
            };

            let byte_len = build_virtual_backing_from_iter(
                core::iter::once((bytes.as_mut_ptr() as usize, bytes.len())),
                extents,
                frames,
            )?;

            Ok((memory, byte_len))
        }
        IoBufferBackingDesc::Segments(segments) => {
            let memory = BackingMemory::SegmentedRead(PhantomData);

            let byte_len = build_virtual_backing_from_iter(
                segments
                    .iter()
                    .map(|segment| (segment.as_ptr() as usize, segment.len())),
                extents,
                frames,
            )?;

            Ok((memory, byte_len))
        }
        IoBufferBackingDesc::SegmentsMut(segments) => {
            validate_mut_segments_disjoint(&segments)?;

            let memory = BackingMemory::SegmentedWrite(PhantomData);

            let byte_len = build_virtual_backing_from_iter(
                segments
                    .iter()
                    .map(|segment| (segment.as_ptr() as usize, segment.len())),
                extents,
                frames,
            )?;

            Ok((memory, byte_len))
        }
        IoBufferBackingDesc::Frames {
            frame_offset,
            byte_len,
            frames: source_frames,
        } => {
            let byte_len = build_physical_backing_into(
                frame_offset,
                byte_len,
                source_frames,
                extents,
                frames,
            )?;

            Ok((BackingMemory::None, byte_len))
        }
        IoBufferBackingDesc::PhysicalExtents {
            frames: source_frames,
            extents: source_extents,
        } => {
            let byte_len =
                build_physical_extent_backing_into(source_frames, source_extents, extents, frames)?;

            Ok((BackingMemory::None, byte_len))
        }
    }
}

fn build_virtual_backing_from_iter<I>(
    regions: I,
    extents: &mut Vec<IoBufferExtent>,
    frames: &mut Vec<IoBufferPageFrame>,
) -> Result<usize, IoBufferError>
where
    I: IntoIterator<Item = (usize, usize)>,
{
    let mut byte_len = 0usize;

    for (virt_addr, len) in regions {
        let first_frame = frames.len();

        let (frame_count, frame_offset) =
            describe_virtual_buffer_to_frames(virt_addr, len, frames)?;

        extents
            .try_reserve_exact(1)
            .map_err(|_| IoBufferError::AllocationFailed)?;

        extents.push(unsafe {
            IoBufferExtent::new(
                Some(virt_addr),
                frame_offset,
                len,
                first_frame,
                frame_count,
            )
        });

        byte_len = byte_len
            .checked_add(len)
            .ok_or(IoBufferError::LengthOverflow)?;
    }

    Ok(byte_len)
}

fn build_physical_backing_into(
    frame_offset: usize,
    byte_len: usize,
    source_frames: &[IoBufferPageFrame],
    extents: &mut Vec<IoBufferExtent>,
    frames: &mut Vec<IoBufferPageFrame>,
) -> Result<usize, IoBufferError> {
    validate_physical_frames(frame_offset, byte_len, source_frames)?;

    let virtual_addr = source_frames.first().and_then(|frame| {
        let base = frame.cpu_address().as_u64() as usize;
        if base == 0 {
            None
        } else {
            base.checked_add(frame_offset)
        }
    });

    extents
        .try_reserve_exact(1)
        .map_err(|_| IoBufferError::AllocationFailed)?;

    frames
        .try_reserve_exact(source_frames.len())
        .map_err(|_| IoBufferError::AllocationFailed)?;

    extents.push(unsafe {
        IoBufferExtent::new(
            virtual_addr,
            frame_offset,
            byte_len,
            0,
            source_frames.len(),
        )
    });

    frames.extend_from_slice(source_frames);

    Ok(byte_len)
}

fn build_physical_extent_backing_into(
    source_frames: &[IoBufferPageFrame],
    source_extents: &[IoBufferExtent],
    extents: &mut Vec<IoBufferExtent>,
    frames: &mut Vec<IoBufferPageFrame>,
) -> Result<usize, IoBufferError> {
    let byte_len = validate_physical_extents(source_frames, source_extents)?;

    extents
        .try_reserve_exact(source_extents.len())
        .map_err(|_| IoBufferError::AllocationFailed)?;

    frames
        .try_reserve_exact(source_frames.len())
        .map_err(|_| IoBufferError::AllocationFailed)?;

    extents.extend_from_slice(source_extents);
    frames.extend_from_slice(source_frames);

    Ok(byte_len)
}

fn describe_virtual_buffer_to_frames(
    virt_addr: usize,
    byte_len: usize,
    frames: &mut Vec<IoBufferPageFrame>,
) -> Result<(usize, usize), IoBufferError> {
    if byte_len == 0 {
        return Ok((0, 0));
    }

    let mut consumed = 0usize;
    let mut frame_count = 0usize;
    let mut first_frame_offset = 0usize;

    while consumed < byte_len {
        let current = virt_addr
            .checked_add(consumed)
            .ok_or(IoBufferError::TranslationFailed { virt_addr })?;
        let translated = translate_virtual_frame(current)
            .ok_or(IoBufferError::TranslationFailed { virt_addr: current })?;
        let offset = usize::try_from(translated.offset)
            .map_err(|_| IoBufferError::TranslationFailed { virt_addr: current })?;
        let frame_len = usize::try_from(translated.byte_len)
            .map_err(|_| IoBufferError::TranslationFailed { virt_addr: current })?;

        if frame_len <= offset {
            return Err(IoBufferError::TranslationFailed { virt_addr: current });
        }

        if frame_count == 0 {
            first_frame_offset = offset;
        }

        let current_base_va = current
            .checked_sub(offset)
            .ok_or(IoBufferError::TranslationFailed { virt_addr: current })?;

        frames
            .try_reserve_exact(1)
            .map_err(|_| IoBufferError::AllocationFailed)?;

        frames.push(unsafe {
            IoBufferPageFrame::new(
                translated.phys_addr,
                translated.byte_len,
                VirtAddr::new(current_base_va as u64),
            )
        });

        frame_count += 1;
        let bytes = (byte_len - consumed).min(frame_len - offset);
        consumed = consumed
            .checked_add(bytes)
            .ok_or(IoBufferError::LengthOverflow)?;
    }

    Ok((frame_count, first_frame_offset))
}

fn validate_mut_segments_disjoint(segments: &[&mut [u8]]) -> Result<(), IoBufferError> {
    for first in 0..segments.len() {
        let first_addr = segments[first].as_ptr() as usize;
        let first_len = segments[first].len();
        let first_end =
            first_addr
                .checked_add(first_len)
                .ok_or(IoBufferError::TranslationFailed {
                    virt_addr: first_addr,
                })?;

        for second in first + 1..segments.len() {
            let second_addr = segments[second].as_ptr() as usize;
            let second_len = segments[second].len();
            let second_end =
                second_addr
                    .checked_add(second_len)
                    .ok_or(IoBufferError::TranslationFailed {
                        virt_addr: second_addr,
                    })?;

            if first_len != 0
                && second_len != 0
                && first_addr < second_end
                && second_addr < first_end
            {
                return Err(IoBufferError::OverlappingMutableExtents { first, second });
            }
        }
    }

    Ok(())
}

fn validate_physical_frames(
    frame_offset: usize,
    byte_len: usize,
    frames: &[IoBufferPageFrame],
) -> Result<(), IoBufferError> {
    if byte_len == 0 {
        return Ok(());
    }

    let Some(first) = frames.first() else {
        return Err(IoBufferError::InvalidFrameLayout {
            frame_offset,
            byte_len,
        });
    };

    for frame in frames {
        if !is_valid_frame_size(frame.byte_len) {
            return Err(IoBufferError::InvalidFrameSize {
                byte_len: frame.byte_len,
            });
        }
        if frame.phys_addr & (frame.byte_len - 1) != 0 {
            return Err(IoBufferError::InvalidFrameAlignment {
                phys_addr: frame.phys_addr,
                byte_len: frame.byte_len,
            });
        }
    }

    if frame_offset >= first.byte_len as usize {
        return Err(IoBufferError::InvalidFrameLayout {
            frame_offset,
            byte_len,
        });
    }

    let mut available = (first.byte_len as usize).saturating_sub(frame_offset);
    for frame in &frames[1..] {
        if available >= byte_len {
            return Ok(());
        }
        available = available.saturating_add(frame.byte_len as usize);
    }

    if available < byte_len {
        Err(IoBufferError::InvalidFrameLayout {
            frame_offset,
            byte_len,
        })
    } else {
        Ok(())
    }
}

fn validate_physical_extents(
    frames: &[IoBufferPageFrame],
    extents: &[IoBufferExtent],
) -> Result<usize, IoBufferError> {
    let mut total_len = 0usize;

    for (idx, extent) in extents.iter().copied().enumerate() {
        let end_frame = extent
            .first_frame
            .checked_add(extent.frame_count)
            .ok_or(IoBufferError::InvalidExtentLayout { extent_index: idx })?;
        if end_frame > frames.len() {
            return Err(IoBufferError::InvalidExtentLayout { extent_index: idx });
        }

        validate_physical_frames(
            extent.frame_offset,
            extent.byte_len,
            &frames[extent.first_frame..end_frame],
        )?;
        total_len = total_len
            .checked_add(extent.byte_len)
            .ok_or(IoBufferError::LengthOverflow)?;
    }

    Ok(total_len)
}

fn validate_dma_mapping_layout(layout: &IoBufferDmaMappingLayout) -> Result<(), IoBufferError> {
    match layout {
        IoBufferDmaMappingLayout::None => Ok(()),
        IoBufferDmaMappingLayout::Contiguous { byte_len, .. } => {
            if *byte_len > u32::MAX as usize {
                Err(IoBufferError::SegmentCapacityExceeded {
                    required: *byte_len,
                    capacity: u32::MAX as usize,
                })
            } else {
                Ok(())
            }
        }
        IoBufferDmaMappingLayout::PageChunks {
            page_offset,
            page_size,
            ..
        } => {
            if *page_size == 0 || *page_size > u32::MAX as usize || *page_offset >= *page_size {
                Err(IoBufferError::InvalidFrameLayout {
                    frame_offset: *page_offset,
                    byte_len: *page_size,
                })
            } else {
                Ok(())
            }
        }
        IoBufferDmaMappingLayout::ScatterGather { page_size, .. } => {
            if *page_size == 0 || *page_size > u32::MAX as usize {
                Err(IoBufferError::InvalidFrameLayout {
                    frame_offset: 0,
                    byte_len: *page_size,
                })
            } else {
                Ok(())
            }
        }
        IoBufferDmaMappingLayout::FixedChunks { chunk_len, .. } => {
            if *chunk_len == 0 {
                Err(IoBufferError::InvalidFrameLayout {
                    frame_offset: 0,
                    byte_len: 0,
                })
            } else {
                Ok(())
            }
        }
        IoBufferDmaMappingLayout::IdentityExtents => Ok(()),
    }
}

fn validate_snapshot(
    slot: &LeaseSlot,
    handle: LeaseHandle,
) -> Result<LeaseSnapshot, IoBufferError> {
    let snapshot = slot.snapshot().ok_or(IoBufferError::InvalidLease)?;
    if snapshot.generation == handle.generation {
        Ok(snapshot)
    } else {
        Err(IoBufferError::InvalidLease)
    }
}

fn checked_slice<'a>(
    ptr: *const u8,
    backing_len: usize,
    offset: usize,
    len: usize,
) -> Option<&'a [u8]> {
    let end = offset.checked_add(len)?;
    if end > backing_len {
        return None;
    }
    Some(unsafe { slice::from_raw_parts(ptr.add(offset), len) })
}

fn checked_slice_mut<'a>(
    ptr: *mut u8,
    backing_len: usize,
    offset: usize,
    len: usize,
) -> Option<&'a mut [u8]> {
    let end = offset.checked_add(len)?;
    if end > backing_len {
        return None;
    }
    Some(unsafe { slice::from_raw_parts_mut(ptr.add(offset), len) })
}

