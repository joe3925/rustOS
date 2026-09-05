use alloc::sync::Arc;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::mem::ManuallyDrop;

use kernel_types::arch::{PageFlags, PhysAddr, VirtAddr};
use kernel_types::dma::implementation::{
    FromDevice, IoBuffer, IoBufferAccess, IoBufferBacking, IoBufferBackingConfig,
    IoBufferBackingDesc, IoBufferError, IoBufferExtent, PhysicalFrameExtent, ToDevice,
};
use kernel_types::memory::PhysicalMappingCache;
use kernel_types::status::PageMapError;

use crate::memory::paging::frame_alloc::KernelPageTableFrameAllocator;

use crate::memory::paging::layout::base_page_size;

use crate::memory::paging::types::{
    LocalTlbFlush, MappingSize, PhysicalMemoryIter, UnmapFrameDisposition,
};

use crate::memory::paging::virt_tracker::{allocate_auto_kernel_range, deallocate_kernel_range};
use crate::memory::user_pins::UserRangePin;
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
    /// This will map the Physical Memory Range to a contiguous virtual region from the kernels dynamic range.
    /// The mappings will be writable.
    fn map_pages(mut physical_memory: PhysicalMemoryIter) -> Result<Self, PageMapError> {
        let mapped_len = physical_memory.len();
        if mapped_len == 0 {
            return Err(PageMapError::NoMemory());
        }

        let base = allocate_auto_kernel_range(mapped_len).ok_or(PageMapError::NoMemory())?;
        let flags = PageFlags::PRESENT | PageFlags::WRITABLE | PageFlags::GLOBAL;
        let mut mapped = 0u64;

        for extent in &mut physical_memory {
            let extent_len = extent.len();

            let Some(next_mapped) = mapped.checked_add(extent_len) else {
                if mapped != 0 {
                    unsafe {
                        crate::memory::paging::map::unmap_range_keep_frames_unchecked(base, mapped);
                    }
                }

                unsafe {
                    deallocate_kernel_range(base, mapped_len);
                }

                return Err(PageMapError::NoMemory());
            };

            if next_mapped > mapped_len {
                if mapped != 0 {
                    unsafe {
                        crate::memory::paging::map::unmap_range_keep_frames_unchecked(base, mapped);
                    }
                }

                unsafe {
                    deallocate_kernel_range(base, mapped_len);
                }

                return Err(PageMapError::TranslationFailed());
            }

            if let Err(error) = unsafe {
                crate::memory::paging::map::map_contiguous_physical_range(
                    base + mapped,
                    PhysAddr::new(extent.physical_address()),
                    extent_len,
                    flags,
                    Some(PhysicalMappingCache::Cached),
                    LocalTlbFlush::Flush,
                )
            } {
                if mapped != 0 {
                    unsafe {
                        crate::memory::paging::map::unmap_range_keep_frames_unchecked(base, mapped);
                    }
                }

                unsafe {
                    deallocate_kernel_range(base, mapped_len);
                }

                return Err(error);
            }

            mapped = next_mapped;
        }

        if mapped != mapped_len {
            if mapped != 0 {
                unsafe {
                    crate::memory::paging::map::unmap_range_keep_frames_unchecked(base, mapped);
                }
            }

            unsafe {
                deallocate_kernel_range(base, mapped_len);
            }

            return Err(PageMapError::TranslationFailed());
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
    _user_pin: UserRangePin,
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
    /// Maps a pinned user address range into kernel space, returns a backing io buffer
    /// Saftey: The pinned range must live as long as the returned backing
    pub unsafe fn new(
        pinned_memory: UserRangePin,
        length: usize,
        access: UserBufferAccess,
    ) -> Result<Self, IoBufferError> {
        if length == 0 || length as u64 > pinned_memory.len() {
            return Err(IoBufferError::InvalidRange);
        }

        let page_size = base_page_size();
        let page_offset = pinned_memory.base_address().as_u64() & (page_size - 1);

        let mapping = KernelIoMapping::map_pages((&pinned_memory).into_iter())
            .map_err(|_| IoBufferError::InvalidRange)?;

        let mapped_offset =
            usize::try_from(page_offset).map_err(|_| IoBufferError::InvalidRange)?;
        let mapped_len =
            usize::try_from(mapping.mapped_len).map_err(|_| IoBufferError::InvalidRange)?;

        let end = mapped_offset
            .checked_add(length)
            .ok_or(IoBufferError::InvalidRange)?;

        if end > mapped_len {
            return Err(IoBufferError::InvalidRange);
        }

        let data = mapping.base + page_offset;

        let backing = match access {
            UserBufferAccess::Read => {
                let slice = unsafe { core::slice::from_raw_parts(data.as_ptr::<u8>(), length) };

                IoBufferBacking::new(
                    IoBufferBackingDesc::Slice(slice),
                    IoBufferBackingConfig::worst_case_for_len(length),
                )?
            }
            UserBufferAccess::ReadWrite => {
                let slice =
                    unsafe { core::slice::from_raw_parts_mut(data.as_mut_ptr::<u8>(), length) };

                IoBufferBacking::new(
                    IoBufferBackingDesc::SliceMut(slice),
                    IoBufferBackingConfig::worst_case_for_len(length),
                )?
            }
        };

        Ok(Self {
            backing: ManuallyDrop::new(unsafe {
                core::mem::transmute::<IoBufferBacking<'_>, IoBufferBacking<'static>>(backing)
            }),
            mapping,
            access,
            _user_pin: pinned_memory,
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

    pub fn len(&self) -> usize {
        self.backing.len()
    }

    pub fn access(&self) -> UserBufferAccess {
        self.access
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
