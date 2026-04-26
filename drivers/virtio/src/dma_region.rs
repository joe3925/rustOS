use alloc::{sync::Arc, vec::Vec};

use kernel_api::device::DeviceObject;
use kernel_api::dma;
use kernel_api::kernel_types::dma::{
    Bidirectional, Described, DmaMapped, DmaMappingStrategy, IoBuffer,
    IOBUFFER_INLINE_PAGE_CAPACITY, IOBUFFER_PAGE_SIZE,
};
use kernel_api::memory::{
    PageTableFlags, allocate_auto_kernel_range_mapped_contiguous, deallocate_kernel_range,
    unmap_range,
};
use kernel_api::x86_64::VirtAddr;

const MAX_DMA_MAP_BYTES: usize = IOBUFFER_INLINE_PAGE_CAPACITY * IOBUFFER_PAGE_SIZE;

struct DmaChunk {
    byte_offset: usize,
    byte_len: usize,
    dma_addr: u64,
    buffer: Option<IoBuffer<'static, DmaMapped, Bidirectional>>,
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
        let alloc_bytes = mapped_bytes.div_ceil(IOBUFFER_PAGE_SIZE) * IOBUFFER_PAGE_SIZE;
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
        if chunk_multiple > MAX_DMA_MAP_BYTES {
            return None;
        }

        let max_chunk_bytes = (MAX_DMA_MAP_BYTES / chunk_multiple) * chunk_multiple;
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

            // Each chunk maps a disjoint sub-slice of the same contiguous allocation.
            let buf_ptr = (base_va.as_u64() as *mut u8).wrapping_add(byte_offset);
            let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr, byte_len) };
            let mapped = match dma::map_buffer(
                device,
                IoBuffer::<Described, Bidirectional>::new(buf),
                DmaMappingStrategy::SingleContiguous,
            ) {
                Ok(mapped) => mapped,
                Err(_) => {
                    region.destroy();
                    return None;
                }
            };

            let segments = mapped.dma_segments();
            if segments.len() != 1 || segments[0].byte_len as usize != byte_len {
                let _ = dma::unmap_buffer(mapped);
                region.destroy();
                return None;
            }

            region.chunks.push(DmaChunk {
                byte_offset,
                byte_len,
                dma_addr: segments[0].dma_addr,
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
            let chunk_end = chunk.byte_offset + chunk.byte_len;
            if byte_offset < chunk.byte_offset || byte_offset >= chunk_end {
                return None;
            }

            Some(chunk.dma_addr + (byte_offset - chunk.byte_offset) as u64)
        })
    }

    pub fn destroy(&mut self) {
        for chunk in &mut self.chunks {
            if let Some(buffer) = chunk.buffer.take() {
                let _ = dma::unmap_buffer(buffer);
            }
        }
        self.chunks.clear();

        if self.alloc_bytes == 0 {
            return;
        }

        unsafe { unmap_range(self.base_va, self.alloc_bytes as u64) };
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
