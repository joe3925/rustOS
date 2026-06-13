use crate::structs::range_tracker::RangeTracker;
use alloc::sync::Arc;
use kernel_types::dma::DeviceMmuPlatformDeviceIdentity;
use kernel_types::dma::DmaPciDeviceIdentity;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceMmuError {
    NoBackingFrame,
    IovaSpaceExhausted,
    NotMapped,
    HardwareError,
    Unsupported,
    InvalidDevice,
    InvalidDomain,
    InvalidRange,
}

pub type DeviceMmuResult<T> = Result<T, DeviceMmuError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceMmuMapPermissions {
    Read,
    Write,
    ReadWrite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceMmuCapabilities {
    pub dma_page_size: u64,
    pub dma_address_bits: u8,
    pub supports_range_invalidation: bool,
    pub supports_domain_invalidation: bool,
    pub reserved: u32,
}

impl DeviceMmuCapabilities {
    pub const fn empty() -> Self {
        Self {
            dma_page_size: 4096,
            dma_address_bits: 0,
            supports_range_invalidation: false,
            supports_domain_invalidation: false,
            reserved: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceMmuBackendInfo {
    pub public_vendor_code: u8,
    pub name: &'static str,
    pub capabilities: DeviceMmuCapabilities,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceMmuDeviceIdentity {
    Pci(DmaPciDeviceIdentity),
    Platform(DeviceMmuPlatformDeviceIdentity),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceMmuDomainInfo {
    pub domain_id: u64,
    pub translation_unit_index: u32,
    pub iova_start: u64,
    pub iova_end: u64,
    pub dma_page_size: u64,
}

#[derive(Debug)]
pub struct DeviceMmuDomain {
    domain_id: u64,
    translation_unit_index: u32,
    dma_page_size: u64,
    iova_tracker: RangeTracker,
}

impl DeviceMmuDomain {
    pub fn new(info: DeviceMmuDomainInfo) -> Self {
        Self {
            domain_id: info.domain_id,
            translation_unit_index: info.translation_unit_index,
            dma_page_size: info.dma_page_size,
            iova_tracker: RangeTracker::new(info.iova_start, info.iova_end),
        }
    }

    #[inline]
    pub fn domain_id(&self) -> u64 {
        self.domain_id
    }

    #[inline]
    pub fn translation_unit_index(&self) -> u32 {
        self.translation_unit_index
    }

    #[inline]
    pub fn dma_page_size(&self) -> u64 {
        self.dma_page_size
    }

    #[inline]
    pub fn alloc_iova(&self, size: u64) -> Option<u64> {
        self.iova_tracker.alloc_auto(size).map(|addr| addr.as_u64())
    }

    #[inline]
    pub fn free_iova(&self, base: u64, size: u64) {
        self.iova_tracker.dealloc(base, size);
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeviceMmuAttachment {
    pub attachment_id: u64,
    pub domain_id: u64,
    pub translation_unit_index: u32,
    pub reserved: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappingRecord {
    pub iova_base: u64,
    pub page_count: u32,
    pub is_identity: bool,
}

pub trait DeviceMmuBackend: Send + Sync {
    fn info(&self) -> DeviceMmuBackendInfo;

    fn create_domain(
        &self,
        identity: DeviceMmuDeviceIdentity,
    ) -> DeviceMmuResult<DeviceMmuDomainInfo>;

    fn destroy_domain(&self, domain: &DeviceMmuDomain);

    fn attach_device(
        &self,
        domain: &DeviceMmuDomain,
        identity: DeviceMmuDeviceIdentity,
    ) -> DeviceMmuResult<DeviceMmuAttachment>;

    fn detach_device(&self, domain: &DeviceMmuDomain, attachment: DeviceMmuAttachment);

    fn map_range(
        &self,
        domain: &DeviceMmuDomain,
        iova: u64,
        phys: u64,
        len: u64,
        permissions: DeviceMmuMapPermissions,
    ) -> DeviceMmuResult<()>;

    fn unmap_range(
        &self,
        domain: &DeviceMmuDomain,
        iova: u64,
        page_count: u32,
    ) -> DeviceMmuResult<()>;

    fn invalidate_range(
        &self,
        domain: &DeviceMmuDomain,
        iova: u64,
        len: u64,
    ) -> DeviceMmuResult<()>;

    fn invalidate_domain(&self, domain: &DeviceMmuDomain) -> DeviceMmuResult<()>;
}

#[derive(Clone)]
pub struct DeviceMmuSystem {
    backend: Arc<dyn DeviceMmuBackend>,
}

impl DeviceMmuSystem {
    pub fn new(backend: Arc<dyn DeviceMmuBackend>) -> Self {
        Self { backend }
    }

    pub fn from_backend<B>(backend: B) -> Self
    where
        B: DeviceMmuBackend + 'static,
    {
        Self {
            backend: Arc::new(backend),
        }
    }

    #[inline]
    pub fn info(&self) -> DeviceMmuBackendInfo {
        self.backend.info()
    }

    #[inline]
    pub fn public_vendor_code(&self) -> u8 {
        self.backend.info().public_vendor_code
    }

    pub fn create_domain(
        &self,
        identity: DeviceMmuDeviceIdentity,
    ) -> DeviceMmuResult<Arc<DeviceMmuDomain>> {
        let info = self.backend.create_domain(identity)?;
        Ok(Arc::new(DeviceMmuDomain::new(info)))
    }

    pub fn destroy_domain(&self, domain: &DeviceMmuDomain) {
        self.backend.destroy_domain(domain);
    }

    pub fn attach_device(
        &self,
        domain: &DeviceMmuDomain,
        identity: DeviceMmuDeviceIdentity,
    ) -> DeviceMmuResult<DeviceMmuAttachment> {
        self.backend.attach_device(domain, identity)
    }

    pub fn detach_device(&self, domain: &DeviceMmuDomain, attachment: DeviceMmuAttachment) {
        self.backend.detach_device(domain, attachment);
    }

    pub fn map_range(
        &self,
        domain: &DeviceMmuDomain,
        iova: u64,
        phys: u64,
        len: u64,
        permissions: DeviceMmuMapPermissions,
    ) -> DeviceMmuResult<()> {
        if len == 0 {
            return Ok(());
        }

        let page_size = domain.dma_page_size();

        if page_size == 0 {
            return Err(DeviceMmuError::InvalidDomain);
        }

        if (iova % page_size) != 0 || (phys % page_size) != 0 || (len % page_size) != 0 {
            return Err(DeviceMmuError::InvalidRange);
        }

        self.backend.map_range(domain, iova, phys, len, permissions)
    }

    pub fn unmap_range(
        &self,
        domain: &DeviceMmuDomain,
        iova: u64,
        page_count: u32,
    ) -> DeviceMmuResult<()> {
        if page_count == 0 {
            return Ok(());
        }

        let page_size = domain.dma_page_size();

        if page_size == 0 {
            return Err(DeviceMmuError::InvalidDomain);
        }

        if (iova % page_size) != 0 {
            return Err(DeviceMmuError::InvalidRange);
        }

        self.backend.unmap_range(domain, iova, page_count)
    }

    pub fn unmap_record(
        &self,
        domain: &DeviceMmuDomain,
        rec: MappingRecord,
    ) -> DeviceMmuResult<()> {
        self.unmap_range(domain, rec.iova_base, rec.page_count)?;

        let len = rec.page_count as u64 * domain.dma_page_size();

        if !rec.is_identity {
            domain.free_iova(rec.iova_base, len);
        }

        self.invalidate_range(domain, rec.iova_base, len)
    }

    pub fn invalidate_range(
        &self,
        domain: &DeviceMmuDomain,
        iova: u64,
        len: u64,
    ) -> DeviceMmuResult<()> {
        if len == 0 {
            return self.invalidate_domain(domain);
        }

        let page_size = domain.dma_page_size();

        if page_size == 0 {
            return Err(DeviceMmuError::InvalidDomain);
        }

        if (iova % page_size) != 0 || (len % page_size) != 0 {
            return Err(DeviceMmuError::InvalidRange);
        }

        self.backend.invalidate_range(domain, iova, len)
    }

    pub fn invalidate_domain(&self, domain: &DeviceMmuDomain) -> DeviceMmuResult<()> {
        self.backend.invalidate_domain(domain)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceMmuDiscoveryError {
    FirmwareUnavailable,
    NotPresent,
    Unsupported,
    MalformedFirmware,
    Backend(DeviceMmuError),
}

pub type DeviceMmuDiscoveryResult<T> = Result<T, DeviceMmuDiscoveryError>;

impl From<DeviceMmuError> for DeviceMmuDiscoveryError {
    fn from(value: DeviceMmuError) -> Self {
        Self::Backend(value)
    }
}
