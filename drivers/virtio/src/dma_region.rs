use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::ptr::NonNull;

use kernel_api::device::DeviceObject;
use kernel_api::dma::{self, dma_base_page_size};
use kernel_api::kernel_types::dma::{
    Bidirectional, DmaMappingStrategy, IoBuffer, IoBufferBacking, IoBufferBackingConfig,
    IoBufferBackingDesc, PhysFramed,
};
use kernel_api::memory::{
    PageTableFlags, VirtAddr, allocate_auto_kernel_range_mapped_contiguous,
    deallocate_kernel_range, unmap_range,
};

struct DmaChunk {
    byte_offset: usize,
    byte_len: usize,
    dma_addr: u64,
    backing: Option<NonNull<IoBufferBacking<'static>>>,
    buffer: Option<IoBuffer<'static, 'static, PhysFramed, Bidirectional>>,
}

pub struct ContiguousDmaRegion {
    base_va: VirtAddr,
    alloc_bytes: usize,
    mapped_bytes: usize,
    chunks: Vec<DmaChunk>,
}

unsafe impl Send for ContiguousDmaRegion {}
unsafe impl Sync for ContiguousDmaRegion {}

impl ContiguousDmaRegion {
    pub fn new(
        device: &Arc<DeviceObject>,
        mapped_bytes: usize,
        chunk_multiple: usize,
    ) -> Option<Self> {
        let page_size = dma_base_page_size();
        let alloc_bytes = mapped_bytes.div_ceil(page_size) * page_size;

        Self::new_with_alloc(device, mapped_bytes, alloc_bytes, chunk_multiple)
    }

    pub fn new_with_alloc(
        device: &Arc<DeviceObject>,
        mapped_bytes: usize,
        alloc_bytes: usize,
        chunk_multiple: usize,
    ) -> Option<Self> {
        if mapped_bytes == 0 || mapped_bytes > alloc_bytes {
            return None;
        }

        let chunk_multiple = chunk_multiple.max(1);
        let max_segment_bytes = u32::MAX as usize;

        if chunk_multiple > max_segment_bytes {
            return None;
        }

        let max_chunk_bytes = (max_segment_bytes / chunk_multiple) * chunk_multiple;
        if max_chunk_bytes == 0 {
            return None;
        }

        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        let base_va =
            allocate_auto_kernel_range_mapped_contiguous(alloc_bytes as u64, flags).ok()?;

        unsafe {
            core::ptr::write_bytes(base_va.as_u64() as *mut u8, 0, alloc_bytes);
        }

        let mut region = Self {
            base_va,
            alloc_bytes,
            mapped_bytes,
            chunks: Vec::new(),
        };

        let mut byte_offset = 0usize;

        while byte_offset < mapped_bytes {
            let remaining = mapped_bytes - byte_offset;
            let mut byte_len = remaining.min(max_chunk_bytes);

            if remaining > max_chunk_bytes && chunk_multiple > 1 {
                byte_len -= byte_len % chunk_multiple;
                if byte_len == 0 {
                    region.destroy();
                    return None;
                }
            }

            let buf_ptr = (base_va.as_u64() as *mut u8).wrapping_add(byte_offset);
            let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr, byte_len) };

            let backing = match IoBufferBacking::new(
                IoBufferBackingDesc::SliceMut(buf),
                IoBufferBackingConfig::worst_case_for_len(byte_len),
            ) {
                Ok(backing) => backing,
                Err(_) => {
                    region.destroy();
                    return None;
                }
            };

            let backing_ptr = NonNull::from(Box::leak(Box::new(backing)));
            let backing_ref = unsafe { backing_ptr.as_ref() };

            let buffer = match backing_ref.create_bidirectional(0, byte_len) {
                Ok(buffer) => buffer,
                Err(_) => {
                    unsafe {
                        drop(Box::from_raw(backing_ptr.as_ptr()));
                    }

                    region.destroy();
                    return None;
                }
            };

            let buffer = match buffer.into_phys_framed() {
                Ok(buffer) => buffer,
                Err((buffer, _)) => {
                    drop(buffer);

                    unsafe {
                        drop(Box::from_raw(backing_ptr.as_ptr()));
                    }

                    region.destroy();
                    return None;
                }
            };

            let mapped = match dma::map_buffer(device, buffer, DmaMappingStrategy::SingleContiguous)
            {
                Ok(mapped) => mapped,
                Err((buffer, _)) => {
                    drop(buffer);

                    unsafe {
                        drop(Box::from_raw(backing_ptr.as_ptr()));
                    }

                    region.destroy();
                    return None;
                }
            };

            let segments = mapped.dma_segments();
            let Some(segment) = segments.first() else {
                drop(mapped);

                unsafe {
                    drop(Box::from_raw(backing_ptr.as_ptr()));
                }

                region.destroy();
                return None;
            };

            if segments.len() != 1 || segment.byte_len as usize != byte_len {
                drop(mapped);

                unsafe {
                    drop(Box::from_raw(backing_ptr.as_ptr()));
                }

                region.destroy();
                return None;
            }

            region.chunks.push(DmaChunk {
                byte_offset,
                byte_len,
                dma_addr: segment.dma_addr,
                backing: Some(backing_ptr),
                buffer: Some(mapped),
            });

            byte_offset += byte_len;
        }

        Some(region)
    }

    #[inline]
    pub fn base_va(&self) -> VirtAddr {
        self.base_va
    }

    #[inline]
    pub fn as_ptr<T>(&self) -> *mut T {
        self.base_va.as_u64() as *mut T
    }

    pub fn dma_addr_at(&self, byte_offset: usize) -> Option<u64> {
        if byte_offset >= self.mapped_bytes {
            return None;
        }

        self.chunks.iter().find_map(|chunk| {
            let chunk_end = chunk.byte_offset.checked_add(chunk.byte_len)?;

            if byte_offset < chunk.byte_offset || byte_offset >= chunk_end {
                return None;
            }

            Some(chunk.dma_addr + (byte_offset - chunk.byte_offset) as u64)
        })
    }

    pub fn destroy(&mut self) {
        for chunk in &mut self.chunks {
            drop(chunk.buffer.take());

            if let Some(backing) = chunk.backing.take() {
                unsafe {
                    drop(Box::from_raw(backing.as_ptr()));
                }
            }
        }

        self.chunks.clear();

        if self.alloc_bytes == 0 {
            return;
        }

        unsafe {
            unmap_range(self.base_va, self.alloc_bytes as u64);
        }

        deallocate_kernel_range(self.base_va, self.alloc_bytes as u64);

        self.base_va = VirtAddr::new(0);
        self.alloc_bytes = 0;
        self.mapped_bytes = 0;
    }
}

impl Drop for ContiguousDmaRegion {
    fn drop(&mut self) {
        self.destroy();
    }
}
