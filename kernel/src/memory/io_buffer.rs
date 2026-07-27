use alloc::sync::Arc;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::mem::ManuallyDrop;

use kernel_types::arch::{PageFlags, PhysAddr, VirtAddr};
use kernel_types::dma::{
    FromDevice, IoBuffer, IoBufferAccess, IoBufferBacking, IoBufferBackingConfig,
    IoBufferBackingDesc, IoBufferError, IoBufferExtent, IoBufferPageFrame, ToDevice,
};
use kernel_types::memory::PhysicalMappingCache;
use kernel_types::status::PageMapError;

use crate::memory::paging::{
    KernelPageTableFrameAllocator, LocalTlbFlush, MappingSize, UnmapFrameDisposition,
    allocate_auto_kernel_range, base_page_size, deallocate_kernel_range,
};
use crate::platform::{ActivePlatform, PagingPlatform};

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserBufferAccess {
    Read = 0,
    ReadWrite = 1,
}

impl UserBufferAccess {
    pub fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            0 => Some(Self::Read),
            1 => Some(Self::ReadWrite),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct KernelIoMapping {
    base: VirtAddr,
    mapped_len: u64,
}

impl KernelIoMapping {
    fn map_pages(physical_pages: &[PhysAddr]) -> Result<Self, PageMapError> {
        let page_size = base_page_size();
        let mapped_len = (physical_pages.len() as u64)
            .checked_mul(page_size)
            .ok_or(PageMapError::NoMemory())?;
        let base = allocate_auto_kernel_range(mapped_len).ok_or(PageMapError::NoMemory())?;
        let mut allocator = KernelPageTableFrameAllocator;
        let flags = PageFlags::PRESENT | PageFlags::WRITABLE | PageFlags::GLOBAL;

        for (index, physical) in physical_pages.iter().copied().enumerate() {
            let virt = base + (index as u64 * page_size);
            if let Err(error) = unsafe {
                <ActivePlatform as PagingPlatform>::map_leaf(
                    &mut allocator,
                    virt,
                    physical,
                    MappingSize { bytes: page_size },
                    flags,
                    Some(PhysicalMappingCache::Cached),
                    LocalTlbFlush::Flush,
                )
            } {
                let mut rollback_offset = 0;
                while rollback_offset < index as u64 * page_size {
                    let _ = unsafe {
                        <ActivePlatform as PagingPlatform>::unmap_leaf(
                            &mut allocator,
                            base + rollback_offset,
                            MappingSize { bytes: page_size },
                            UnmapFrameDisposition::KeepFrame,
                            LocalTlbFlush::Flush,
                        )
                    };
                    rollback_offset += page_size;
                }
                unsafe { deallocate_kernel_range(base, mapped_len) };
                return Err(error);
            }
        }

        Ok(Self { base, mapped_len })
    }
}

impl Drop for KernelIoMapping {
    fn drop(&mut self) {
        let page_size = base_page_size();
        let mut allocator = KernelPageTableFrameAllocator;
        let mut offset = 0;
        while offset < self.mapped_len {
            let _ = unsafe {
                <ActivePlatform as PagingPlatform>::unmap_leaf(
                    &mut allocator,
                    self.base + offset,
                    MappingSize { bytes: page_size },
                    UnmapFrameDisposition::KeepFrame,
                    LocalTlbFlush::Flush,
                )
            };
            offset += page_size;
        }
        if self.mapped_len != 0 {
            unsafe { deallocate_kernel_range(self.base, self.mapped_len) };
        }
    }
}

pub struct MappedIoBufferBacking {
    backing: ManuallyDrop<IoBufferBacking<'static>>,
    mapping: KernelIoMapping,
    access: UserBufferAccess,
}

impl core::fmt::Debug for MappedIoBufferBacking {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("MappedIoBufferBacking")
            .field("length", &self.backing.len())
            .field("mapping", &self.mapping)
            .field("access", &self.access)
            .finish()
    }
}

impl MappedIoBufferBacking {
    pub fn new(
        physical_pages: Vec<PhysAddr>,
        first_page_offset: usize,
        length: usize,
        access: UserBufferAccess,
    ) -> Result<Self, IoBufferError> {
        let mapping = KernelIoMapping::map_pages(&physical_pages)
            .map_err(|_| IoBufferError::AllocationFailed)?;
        let page_size = base_page_size();
        let mut frames = Vec::new();
        frames
            .try_reserve_exact(physical_pages.len())
            .map_err(|_| IoBufferError::AllocationFailed)?;
        for (index, physical) in physical_pages.into_iter().enumerate() {
            frames.push(unsafe {
                IoBufferPageFrame::new(
                    physical.as_u64(),
                    page_size,
                    mapping.base + index as u64 * page_size,
                )
            });
        }
        let extents = [unsafe {
            IoBufferExtent::new(
                Some(mapping.base.as_u64() as usize + first_page_offset),
                first_page_offset,
                length,
                0,
                frames.len(),
            )
        }];
        let backing = IoBufferBacking::new(
            IoBufferBackingDesc::PhysicalExtents {
                frames: &frames,
                extents: &extents,
            },
            IoBufferBackingConfig::worst_case_for_len(length),
        )?;
        Ok(Self {
            backing: ManuallyDrop::new(unsafe {
                core::mem::transmute::<IoBufferBacking<'_>, IoBufferBacking<'static>>(backing)
            }),
            mapping,
            access,
        })
    }

    pub fn create_to_device(
        self: &Arc<Self>,
        offset: usize,
        len: usize,
    ) -> Result<OwnedIoBuffer<ToDevice>, IoBufferError> {
        OwnedIoBuffer::new(self.clone(), offset, len, false)
    }

    pub fn create_from_device(
        self: &Arc<Self>,
        offset: usize,
        len: usize,
    ) -> Result<OwnedIoBuffer<FromDevice>, IoBufferError> {
        if self.access != UserBufferAccess::ReadWrite {
            return Err(IoBufferError::InvalidBackingKind);
        }
        OwnedIoBuffer::new(self.clone(), offset, len, true)
    }
}

impl Drop for MappedIoBufferBacking {
    fn drop(&mut self) {
        unsafe { ManuallyDrop::drop(&mut self.backing) };
    }
}

pub struct OwnedIoBuffer<Access: IoBufferAccess> {
    buffer: Option<IoBuffer<'static, 'static, Access>>,
    backing: Arc<MappedIoBufferBacking>,
    _access: PhantomData<Access>,
}

impl<Access: IoBufferAccess> OwnedIoBuffer<Access> {
    fn new(
        backing: Arc<MappedIoBufferBacking>,
        offset: usize,
        len: usize,
        writable: bool,
    ) -> Result<Self, IoBufferError> {
        let reference: &'static IoBufferBacking<'static> =
            unsafe { &*(&*backing.backing as *const IoBufferBacking<'static>) };
        let buffer = if writable {
            // Access is fixed by the public typed constructors above.
            let typed = reference.create_phys_from_device(offset, len)?;
            unsafe {
                core::mem::transmute::<
                    IoBuffer<'_, '_, FromDevice>,
                    IoBuffer<'static, 'static, Access>,
                >(typed)
            }
        } else {
            let typed = reference.create_phys_to_device(offset, len)?;
            unsafe {
                core::mem::transmute::<IoBuffer<'_, '_, ToDevice>, IoBuffer<'static, 'static, Access>>(
                    typed,
                )
            }
        };
        Ok(Self {
            buffer: Some(buffer),
            backing,
            _access: PhantomData,
        })
    }

    pub fn len(&self) -> usize {
        self.buffer.as_ref().map_or(0, IoBuffer::len)
    }

    pub(crate) fn take(&mut self) -> IoBuffer<'static, 'static, Access> {
        self.buffer.take().expect("owned I/O buffer already taken")
    }
}

impl OwnedIoBuffer<ToDevice> {
    pub(crate) fn copy_to_slice(&self, destination: &mut [u8]) -> Result<(), IoBufferError> {
        self.buffer
            .as_ref()
            .ok_or(IoBufferError::InvalidLease)?
            .copy_to_slice(0, destination)
    }
}

impl OwnedIoBuffer<FromDevice> {
    pub(crate) fn copy_from_slice(&mut self, source: &[u8]) -> Result<(), IoBufferError> {
        self.buffer
            .as_mut()
            .ok_or(IoBufferError::InvalidLease)?
            .copy_from_slice(0, source)
    }
}

unsafe impl<Access: IoBufferAccess> Send for OwnedIoBuffer<Access> {}
