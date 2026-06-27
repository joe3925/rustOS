pub struct IoBufferRegion<'a> {
    virtual_addr: Option<usize>,
    frame_offset: usize,
    byte_len: usize,
    page_frames: &'a [IoBufferPageFrame],
}

impl<'a> IoBufferRegion<'a> {
    pub fn virtual_address(&self) -> Option<usize> {
        self.virtual_addr
    }

    pub fn frame_offset(&self) -> usize {
        self.frame_offset
    }

    pub fn page_offset(&self) -> usize {
        self.frame_offset
    }

    pub fn len(&self) -> usize {
        self.byte_len
    }

    pub fn is_empty(&self) -> bool {
        self.byte_len == 0
    }

    pub fn page_frames(&self) -> &'a [IoBufferPageFrame] {
        self.page_frames
    }

}

pub struct IoBufferRegionIter<'a> {
    extents: &'a [IoBufferExtent],
    frames: &'a [IoBufferPageFrame],
    next_extent: usize,
    logical_cursor: usize,
    view_start: usize,
    view_end: usize,
}

impl<'a> IoBufferRegionIter<'a> {
    fn new(
        extents: &'a [IoBufferExtent],
        frames: &'a [IoBufferPageFrame],
        view_start: usize,
        view_len: usize,
    ) -> Self {
        Self {
            extents,
            frames,
            next_extent: 0,
            logical_cursor: 0,
            view_start,
            view_end: view_start.saturating_add(view_len),
        }
    }
}

impl<'a> Iterator for IoBufferRegionIter<'a> {
    type Item = IoBufferRegion<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.next_extent < self.extents.len() {
            let extent = self.extents[self.next_extent];
            let extent_start = self.logical_cursor;
            let extent_end = extent_start.checked_add(extent.byte_len)?;
            self.logical_cursor = extent_end;
            self.next_extent += 1;

            let start = max(extent_start, self.view_start);
            let end = min(extent_end, self.view_end);
            if start >= end {
                continue;
            }

            let offset_in_extent = start - extent_start;
            let len = end - start;
            let (first_frame, frame_count, frame_offset) =
                extent_subrange_frames(extent, self.frames, offset_in_extent, len)?;
            let frame_end = first_frame.checked_add(frame_count)?;
            let virtual_addr = extent
                .virtual_addr
                .and_then(|addr| addr.checked_add(offset_in_extent));

            return Some(IoBufferRegion {
                virtual_addr,
                frame_offset,
                byte_len: len,
                page_frames: self.frames.get(first_frame..frame_end)?,
            });
        }

        None
    }
}

#[derive(Clone)]
pub struct IoBufferDmaSegmentIter<'a> {
    layout: DmaSegmentLayout,
    extents: &'a [IoBufferExtent],
    frames: &'a [IoBufferPageFrame],
    mapped_start: usize,
    mapped_end: usize,
    skip: usize,
    remaining: usize,
    index: usize,
    initialized: bool,
    page_offset: usize,
    page_size: usize,
    iova_cursor: u64,
    page_index: usize,
    page_count: usize,
    extent_index: usize,
    logical_cursor: usize,
    frame_index: usize,
    frame_end: usize,
    frame_offset: usize,
    identity_remaining: usize,
}

impl<'a> IoBufferDmaSegmentIter<'a> {
    fn empty(extents: &'a [IoBufferExtent], frames: &'a [IoBufferPageFrame]) -> Self {
        Self::new(DmaSegmentLayout::None, 0, 0, 0, 0, extents, frames)
    }

    fn new(
        layout: DmaSegmentLayout,
        mapped_start: usize,
        mapped_len: usize,
        lease_start: usize,
        lease_len: usize,
        extents: &'a [IoBufferExtent],
        frames: &'a [IoBufferPageFrame],
    ) -> Self {
        Self {
            layout,
            extents,
            frames,
            mapped_start,
            mapped_end: mapped_start.saturating_add(mapped_len),
            skip: lease_start.saturating_sub(mapped_start),
            remaining: lease_len,
            index: 0,
            initialized: false,
            page_offset: 0,
            page_size: 0,
            iova_cursor: 0,
            page_index: 0,
            page_count: 0,
            extent_index: 0,
            logical_cursor: 0,
            frame_index: 0,
            frame_end: 0,
            frame_offset: 0,
            identity_remaining: 0,
        }
    }
}

impl<'a> Iterator for IoBufferDmaSegmentIter<'a> {
    type Item = IoBufferDmaSegment;

    fn next(&mut self) -> Option<Self::Item> {
        while self.remaining != 0 {
            let mut segment = self.next_uncropped()?;
            let segment_len = segment.byte_len as usize;

            if self.skip >= segment_len {
                self.skip -= segment_len;
                continue;
            }

            if self.skip != 0 {
                segment.dma_addr = segment.dma_addr.checked_add(self.skip as u64)?;
                segment.byte_len = segment.byte_len.checked_sub(self.skip as u32)?;
                self.skip = 0;
            }

            let take = min(segment.byte_len as usize, self.remaining);
            segment.byte_len = take as u32;
            self.remaining -= take;
            return Some(segment);
        }

        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.remaining == 0 {
            return (0, Some(0));
        }

        let upper = match self.layout {
            DmaSegmentLayout::None => Some(0),
            DmaSegmentLayout::Contiguous { .. } => Some(1),
            DmaSegmentLayout::FixedChunks { count, .. } => Some(count.saturating_sub(self.index)),
            _ => None,
        };

        (0, upper)
    }
}

impl core::iter::FusedIterator for IoBufferDmaSegmentIter<'_> {}

impl<'a> IoBufferDmaSegmentIter<'a> {
    fn next_uncropped(&mut self) -> Option<IoBufferDmaSegment> {
        match self.layout {
            DmaSegmentLayout::None => None,
            DmaSegmentLayout::Contiguous { segment } => {
                if self.index != 0 {
                    return None;
                }
                self.index = 1;
                Some(segment)
            }
            DmaSegmentLayout::PageChunks {
                iova_base,
                page_offset,
                byte_len,
                page_size,
            } => {
                if !self.initialized {
                    self.page_offset = page_offset;
                    self.page_size = page_size;
                    self.iova_cursor = iova_base;
                    self.identity_remaining = byte_len;
                    self.initialized = true;
                }
                next_page_chunk_segment(
                    self.iova_cursor,
                    self.page_offset,
                    self.page_size,
                    &mut self.index,
                    &mut self.identity_remaining,
                )
            }
            DmaSegmentLayout::ScatterGather {
                iova_base,
                page_size,
            } => {
                if !self.initialized {
                    self.iova_cursor = iova_base;
                    self.page_size = page_size;
                    self.initialized = true;
                }
                next_scatter_gather_segment(
                    self.extents,
                    self.mapped_start,
                    self.mapped_end,
                    self.page_size,
                    &mut self.extent_index,
                    &mut self.logical_cursor,
                    &mut self.iova_cursor,
                    &mut self.page_index,
                    &mut self.page_count,
                    &mut self.page_offset,
                    &mut self.identity_remaining,
                )
            }
            DmaSegmentLayout::FixedChunks {
                dma_addr,
                chunk_len,
                count,
            } => {
                if self.index >= count {
                    return None;
                }
                let segment = IoBufferDmaSegment {
                    dma_addr: dma_addr.checked_add(self.index as u64 * chunk_len as u64)?,
                    byte_len: chunk_len,
                    reserved: 0,
                };
                self.index += 1;
                Some(segment)
            }
            DmaSegmentLayout::IdentityExtents => next_identity_extent_segment_view(
                self.extents,
                self.frames,
                self.mapped_start,
                self.mapped_end,
                &mut self.extent_index,
                &mut self.logical_cursor,
                &mut self.frame_index,
                &mut self.frame_end,
                &mut self.frame_offset,
                &mut self.identity_remaining,
            ),
        }
    }
}

fn extent_subrange_frames(
    extent: IoBufferExtent,
    frames: &[IoBufferPageFrame],
    offset_in_extent: usize,
    len: usize,
) -> Option<(usize, usize, usize)> {
    let mut frame_index = extent.first_frame;
    let frame_end = extent.first_frame.checked_add(extent.frame_count)?;
    let mut frame_offset = extent.frame_offset.checked_add(offset_in_extent)?;

    while frame_index < frame_end {
        let frame_len = frames.get(frame_index)?.byte_len as usize;
        if frame_offset < frame_len {
            break;
        }
        frame_offset -= frame_len;
        frame_index += 1;
    }

    if frame_index >= frame_end {
        return None;
    }

    let first_frame = frame_index;
    let first_offset = frame_offset;
    let mut remaining = len;

    while frame_index < frame_end && remaining != 0 {
        let frame_len = frames.get(frame_index)?.byte_len as usize;
        let available = frame_len.saturating_sub(frame_offset);
        let take = min(available, remaining);
        remaining -= take;
        frame_index += 1;
        frame_offset = 0;
    }

    if remaining == 0 {
        Some((first_frame, frame_index - first_frame, first_offset))
    } else {
        None
    }
}

fn page_chunk_segment_count(page_offset: usize, byte_len: usize, page_size: usize) -> usize {
    if byte_len == 0 || page_size == 0 {
        0
    } else {
        page_offset.saturating_add(byte_len).div_ceil(page_size)
    }
}

fn next_page_chunk_segment(
    iova_base: u64,
    page_offset: usize,
    page_size: usize,
    index: &mut usize,
    remaining: &mut usize,
) -> Option<IoBufferDmaSegment> {
    if *remaining == 0 || page_size == 0 {
        return None;
    }

    let start_in_page = if *index == 0 { page_offset } else { 0 };
    if start_in_page >= page_size {
        return None;
    }

    let bytes = (*remaining)
        .min(page_size - start_in_page)
        .min(u32::MAX as usize);
    let dma_addr = iova_base.checked_add((*index * page_size + start_in_page) as u64)?;
    *remaining -= bytes;
    *index += 1;

    Some(IoBufferDmaSegment {
        dma_addr,
        byte_len: bytes as u32,
        reserved: 0,
    })
}

fn next_scatter_gather_segment(
    extents: &[IoBufferExtent],
    mapped_start: usize,
    mapped_end: usize,
    page_size: usize,
    extent_index: &mut usize,
    logical_cursor: &mut usize,
    iova_cursor: &mut u64,
    page_index: &mut usize,
    page_count: &mut usize,
    page_offset: &mut usize,
    remaining: &mut usize,
) -> Option<IoBufferDmaSegment> {
    if page_size == 0 {
        return None;
    }

    loop {
        if *remaining != 0 {
            let segment = next_page_chunk_segment(
                *iova_cursor,
                *page_offset,
                page_size,
                page_index,
                remaining,
            );
            if *remaining == 0 {
                let advance = (*page_count).checked_mul(page_size)? as u64;
                *iova_cursor = iova_cursor.checked_add(advance)?;
                *page_index = 0;
                *page_count = 0;
                *page_offset = 0;
            }
            return segment;
        }

        while *extent_index < extents.len() {
            let extent = extents[*extent_index];
            let extent_start = *logical_cursor;
            let extent_end = extent_start.checked_add(extent.byte_len)?;
            *extent_index += 1;
            *logical_cursor = extent_end;

            let start = max(extent_start, mapped_start);
            let end = min(extent_end, mapped_end);
            if start >= end {
                continue;
            }

            let offset_in_extent = start - extent_start;
            *page_offset = (extent.frame_offset + offset_in_extent) % page_size;
            *remaining = end - start;
            *page_count = page_chunk_segment_count(*page_offset, *remaining, page_size);
            *page_index = 0;
            break;
        }

        if *remaining == 0 {
            return None;
        }
    }
}

fn next_identity_extent_segment_view(
    extents: &[IoBufferExtent],
    frames: &[IoBufferPageFrame],
    view_start: usize,
    view_end: usize,
    extent_index: &mut usize,
    logical_cursor: &mut usize,
    frame_index: &mut usize,
    frame_end: &mut usize,
    frame_offset: &mut usize,
    remaining: &mut usize,
) -> Option<IoBufferDmaSegment> {
    loop {
        if *remaining != 0 {
            return next_identity_segment_limited(
                frames,
                *frame_end,
                frame_index,
                frame_offset,
                remaining,
            );
        }

        while *extent_index < extents.len() {
            let extent = extents[*extent_index];
            let extent_start = *logical_cursor;
            let extent_end = extent_start.checked_add(extent.byte_len)?;
            *extent_index += 1;
            *logical_cursor = extent_end;

            let start = max(extent_start, view_start);
            let end = min(extent_end, view_end);
            if start >= end {
                continue;
            }

            let end_frame = extent.first_frame.checked_add(extent.frame_count)?;
            if end_frame > frames.len() {
                return None;
            }

            *frame_index = extent.first_frame;
            *frame_end = end_frame;
            *frame_offset = extent.frame_offset.checked_add(start - extent_start)?;
            *remaining = end - start;
            break;
        }

        if *remaining == 0 {
            return None;
        }
    }
}

fn next_identity_segment_limited(
    frames: &[IoBufferPageFrame],
    frame_end: usize,
    frame_index: &mut usize,
    frame_offset: &mut usize,
    remaining: &mut usize,
) -> Option<IoBufferDmaSegment> {
    if *remaining == 0 {
        return None;
    }

    while *frame_index < frame_end && *frame_offset >= frames[*frame_index].byte_len as usize {
        *frame_offset -= frames[*frame_index].byte_len as usize;
        *frame_index += 1;
    }

    if *frame_index >= frame_end {
        return None;
    }

    let first = frames[*frame_index];
    let start_offset = *frame_offset;
    let dma_addr = first.phys_addr.checked_add(start_offset as u64)?;
    let first_available = first.byte_len as usize - start_offset;
    let mut byte_len = (*remaining).min(first_available).min(u32::MAX as usize);

    *remaining -= byte_len;

    if byte_len == first_available {
        *frame_index += 1;
        *frame_offset = 0;
    } else {
        *frame_offset += byte_len;
    }

    while *remaining > 0 && *frame_index < frame_end {
        let next = frames[*frame_index];
        let expected = dma_addr.checked_add(byte_len as u64)?;
        if next.phys_addr != expected {
            break;
        }

        let add_len = (*remaining).min(next.byte_len as usize);
        let merged_len = byte_len.checked_add(add_len)?;
        if merged_len > u32::MAX as usize {
            break;
        }

        byte_len = merged_len;
        *remaining -= add_len;
        *frame_index += 1;
    }

    Some(IoBufferDmaSegment {
        dma_addr,
        byte_len: byte_len as u32,
        reserved: 0,
    })
}


#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DmaBufferRegion<'frames> {
    frame_offset: usize,
    byte_len: usize,
    frames: &'frames [IoBufferPageFrame],
}

impl<'frames> DmaBufferRegion<'frames> {
    const fn new(
        frame_offset: usize,
        byte_len: usize,
        frames: &'frames [IoBufferPageFrame],
    ) -> Self {
        Self {
            frame_offset,
            byte_len,
            frames,
        }
    }
    #[inline]
    pub const fn frame_offset(&self) -> usize {
        self.frame_offset
    }

    #[inline]
    pub const fn len(&self) -> usize {
        self.byte_len
    }

    #[inline]
    pub const fn page_frames(&self) -> &'frames [IoBufferPageFrame] {
        self.frames
    }
    pub const fn is_empty(&self) -> bool {
        self.byte_len == 0
    }
}

enum DmaBufferRegionSource<'a> {
    IoBuffer {
        extents: &'a [IoBufferExtent],
        frames: &'a [IoBufferPageFrame],
        start: usize,
        len: usize,
    },
}

pub struct DmaBufferView<'a> {
    byte_len: usize,
    source: DmaBufferRegionSource<'a>,
}

impl<'a> DmaBufferView<'a> {
    const fn from_iobuffer_parts(
        byte_len: usize,
        extents: &'a [IoBufferExtent],
        frames: &'a [IoBufferPageFrame],
        start: usize,
        len: usize,
    ) -> Self {
        Self {
            byte_len,
            source: DmaBufferRegionSource::IoBuffer {
                extents,
                frames,
                start,
                len,
            },
        }
    }

    pub const fn len(&self) -> usize {
        self.byte_len
    }

    pub const fn is_empty(&self) -> bool {
        self.byte_len == 0
    }

    pub fn regions(&self) -> DmaBufferRegionIter<'a, '_> {
        DmaBufferRegionIter::new(&self.source)
    }
}

pub struct DmaBufferRegionIter<'a, 'view> {
    source: &'view DmaBufferRegionSource<'a>,
    extent_index: usize,
    logical_cursor: usize,
    view_start: usize,
    view_end: usize,
}

impl<'a, 'view> DmaBufferRegionIter<'a, 'view> {
    fn new(source: &'view DmaBufferRegionSource<'a>) -> Self {
        let (view_start, view_end) = match *source {
            DmaBufferRegionSource::IoBuffer { start, len, .. } => {
                (start, start.saturating_add(len))
            }
        };

        Self {
            source,
            extent_index: 0,
            logical_cursor: 0,
            view_start,
            view_end,
        }
    }
}

impl<'a, 'view> Iterator for DmaBufferRegionIter<'a, 'view> {
    type Item = DmaBufferRegion<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        match *self.source {
            DmaBufferRegionSource::IoBuffer {
                extents, frames, ..
            } => self.next_iobuffer_region(extents, frames),
        }
    }
}

impl<'a, 'view> DmaBufferRegionIter<'a, 'view> {
    fn next_iobuffer_region(
        &mut self,
        extents: &'a [IoBufferExtent],
        frames: &'a [IoBufferPageFrame],
    ) -> Option<DmaBufferRegion<'a>> {
        while self.extent_index < extents.len() {
            let extent = extents[self.extent_index];

            let extent_start = self.logical_cursor;
            let extent_end = extent_start.checked_add(extent.byte_len)?;

            self.logical_cursor = extent_end;
            self.extent_index += 1;

            let start = core::cmp::max(extent_start, self.view_start);
            let end = core::cmp::min(extent_end, self.view_end);

            if start >= end {
                continue;
            }

            let offset_in_extent = start.checked_sub(extent_start)?;
            let region_len = end.checked_sub(start)?;

            let (first_frame, frame_count, frame_offset) = extent_subrange_frames_for_dma_region(
                extent,
                frames,
                offset_in_extent,
                region_len,
            )?;

            let frame_end = first_frame.checked_add(frame_count)?;
            let region_frames = frames.get(first_frame..frame_end)?;

            return Some(DmaBufferRegion::new(
                frame_offset,
                region_len,
                region_frames,
            ));
        }

        None
    }
}

fn extent_subrange_frames_for_dma_region(
    extent: IoBufferExtent,
    frames: &[IoBufferPageFrame],
    offset_in_extent: usize,
    len: usize,
) -> Option<(usize, usize, usize)> {
    let mut frame_index = extent.first_frame;
    let frame_end = extent.first_frame.checked_add(extent.frame_count)?;
    let mut frame_offset = extent.frame_offset.checked_add(offset_in_extent)?;

    while frame_index < frame_end {
        let frame_len = frames.get(frame_index)?.byte_len as usize;

        if frame_offset < frame_len {
            break;
        }

        frame_offset -= frame_len;
        frame_index += 1;
    }

    if frame_index >= frame_end {
        return None;
    }

    let first_frame = frame_index;
    let first_offset = frame_offset;
    let mut remaining = len;

    while frame_index < frame_end && remaining != 0 {
        let frame_len = frames.get(frame_index)?.byte_len as usize;
        let available = frame_len.saturating_sub(frame_offset);
        let take = core::cmp::min(available, remaining);

        remaining -= take;
        frame_index += 1;
        frame_offset = 0;
    }

    if remaining == 0 {
        Some((first_frame, frame_index - first_frame, first_offset))
    } else {
        None
    }
}
