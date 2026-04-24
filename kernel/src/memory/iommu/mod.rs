use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use kernel_types::dma::DmaPciDeviceIdentity;
use spin::{Mutex, Once};
use x86_64::structures::paging::PageTableFlags;
use x86_64::{PhysAddr, VirtAddr};

use crate::memory::dma::{platform_iommu_info, PlatformIommuInfo};
use crate::memory::paging::tables::virt_to_phys;
use crate::memory::paging::virt_tracker::{
    allocate_auto_kernel_range_mapped, allocate_auto_kernel_range_mapped_contiguous,
};
use crate::println;

use self::amd::AmdViBackend;
use self::intel::IntelVtdBackend;

pub mod amd;
pub mod domain;
pub mod intel;
pub mod page_table;

pub use domain::{IommuDomain, IommuError, MappingRecord};

const PAGE_SIZE: usize = 4096;

/// Allocate `num_pages` zeroed kernel pages. Physical frames are not
/// guaranteed to be contiguous; the mapper picks huge pages when the
/// allocation is large enough.
pub(crate) fn alloc_zeroed_pages(num_pages: usize) -> Result<VirtAddr, IommuError> {
    let size = (num_pages * PAGE_SIZE) as u64;
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
    let va = allocate_auto_kernel_range_mapped(size, flags)
        .map_err(|_| IommuError::NoBackingFrame)?;
    unsafe {
        core::ptr::write_bytes(va.as_mut_ptr::<u8>(), 0, size as usize);
    }
    Ok(va)
}

/// Allocate `num_pages` zeroed kernel pages backed by a physically
/// contiguous range, aligned for huge-page mapping when possible.
/// Returns `(phys_base, virt)`.
pub(crate) fn alloc_zeroed_pages_contiguous(
    num_pages: usize,
) -> Result<(PhysAddr, VirtAddr), IommuError> {
    let size = (num_pages * PAGE_SIZE) as u64;
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
    let va = allocate_auto_kernel_range_mapped_contiguous(size, flags)
        .map_err(|_| IommuError::NoBackingFrame)?;
    unsafe {
        core::ptr::write_bytes(va.as_mut_ptr::<u8>(), 0, size as usize);
    }
    let phys = virt_to_phys(va).ok_or(IommuError::NoBackingFrame)?;
    Ok((phys, va))
}

pub enum IommuBackend {
    Intel(IntelVtdBackend),
    Amd(AmdViBackend),
}

static IOMMU_BACKEND: Once<Option<IommuBackend>> = Once::new();
static IOMMU_DOMAINS: Once<Mutex<BTreeMap<usize, Arc<IommuDomain>>>> = Once::new();

#[inline]
fn domains() -> &'static Mutex<BTreeMap<usize, Arc<IommuDomain>>> {
    IOMMU_DOMAINS.call_once(|| Mutex::new(BTreeMap::new()))
}

#[inline]
fn backend() -> Option<&'static IommuBackend> {
    IOMMU_BACKEND.get().and_then(|b| b.as_ref())
}

pub fn init_iommu() {
    let _ = IOMMU_BACKEND.call_once(|| match platform_iommu_info() {
        PlatformIommuInfo::Intel(info) => match IntelVtdBackend::init(info) {
            Ok(backend) => Some(IommuBackend::Intel(backend)),
            Err(err) => {
                println!("iommu: Intel VT-d init failed: {:?}", err);
                None
            }
        },
        PlatformIommuInfo::Amd(info) => match AmdViBackend::init(info) {
            Ok(backend) => Some(IommuBackend::Amd(backend)),
            Err(err) => {
                println!("iommu: AMD-Vi init failed: {:?}", err);
                None
            }
        },
    });
}

pub fn get_or_create_domain(
    device_key: usize,
    identity: DmaPciDeviceIdentity,
) -> Option<Arc<IommuDomain>> {
    let backend = backend()?;
    let mut all = domains().lock();
    if let Some(domain) = all.get(&device_key) {
        return Some(domain.clone());
    }

    let domain = match backend {
        IommuBackend::Intel(vtd) => vtd.create_domain(identity).ok()?,
        IommuBackend::Amd(vi) => vi.create_domain(identity).ok()?,
    };
    let domain = Arc::new(domain);

    let attached = match backend {
        IommuBackend::Intel(vtd) => vtd.attach(&domain),
        IommuBackend::Amd(vi) => vi.attach(&domain),
    };
    if attached.is_err() {
        return None;
    }

    all.insert(device_key, domain.clone());
    Some(domain)
}

pub fn map_pages(domain: &IommuDomain, iova: u64, pfns: &[u64]) -> Result<(), IommuError> {
    match backend() {
        Some(IommuBackend::Intel(vtd)) => vtd.map_pages(domain, iova, pfns),
        Some(IommuBackend::Amd(vi)) => vi.map_pages(domain, iova, pfns),
        None => Err(IommuError::Unsupported),
    }
}

pub fn unmap_pages(domain: &IommuDomain, iova: u64, page_count: u32) {
    match backend() {
        Some(IommuBackend::Intel(vtd)) => vtd.unmap_pages(domain, iova, page_count),
        Some(IommuBackend::Amd(vi)) => vi.unmap_pages(domain, iova, page_count),
        None => {}
    }
}

pub fn invalidate(domain: &IommuDomain) {
    match backend() {
        Some(IommuBackend::Intel(vtd)) => vtd.invalidate(domain, 0, 0),
        Some(IommuBackend::Amd(vi)) => vi.invalidate(domain, 0, 0),
        None => {}
    }
}
