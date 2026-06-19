//! Intel VT-d (DMA remapping) backend. Register offsets and field
//! layouts follow Intel VT-d Architecture Specification rev 4.1.
//!
//! This implementation uses legacy root/context tables, 4-level
//! second-level paging, and register-based invalidation.

use alloc::vec::Vec;

use kernel_types::dma::{DeviceMmuPlatformDeviceIdentity, DmaPciDeviceIdentity};
use spin::Mutex;
use x86_64::{PhysAddr, VirtAddr};

use super::domain::{IommuDomain, IommuError};
use super::page_table::{self, PTE_ADDR_MASK, PTE_P, PTE_RW};
use super::{IntelDeviceScope, IntelPciPath, IntelPlatformIommuInfo, X86PlatformDeviceRoute};
use crate::memory::paging::{map_physical_pages, unmap_physical_pages};
use crate::println;

const VER_REG: usize = 0x00;
const CAP_REG: usize = 0x08;
const ECAP_REG: usize = 0x10;
const GCMD_REG: usize = 0x18;
const GSTS_REG: usize = 0x1C;
const RTADDR_REG: usize = 0x20;
const CCMD_REG: usize = 0x28;
const FSTS_REG: usize = 0x34;

const GCMD_TE: u32 = 1 << 31;
const GCMD_SRTP: u32 = 1 << 30;
const GSTS_TES: u32 = 1 << 31;
const GSTS_RTPS: u32 = 1 << 30;

const GSTS_ENABLE_MASK: u32 = (1 << 31) | (1 << 26) | (1 << 25) | (1 << 23);

const CCMD_ICC: u64 = 1 << 63;
const CCMD_CIRG_GLOBAL: u64 = 1 << 61;
const CCMD_CIRG_DOMAIN: u64 = 2 << 61;

const IOTLB_IVT: u64 = 1 << 63;
const IOTLB_IIRG_GLOBAL: u64 = 1 << 60;
const IOTLB_IIRG_DOMAIN: u64 = 2 << 60;
const IOTLB_DW: u64 = 1 << 48;
const IOTLB_DR: u64 = 1 << 49;

const AGAW_48: u64 = 0b010;

pub struct IntelVtdBackend {
    inner: Mutex<VtdInner>,
}

struct VtdInner {
    units: Vec<VtdUnit>,
}

struct VtdUnit {
    register_base: u64,
    reg_base_va: *mut u8,
    root_table_phys: u64,
    context_table_phys: [u64; 256],
    iotlb_reg_off: usize,
    iova_end: u64,
    segment: u16,
    include_all: bool,
    device_scopes: Vec<IntelDeviceScope>,
    platform_routes: Vec<X86PlatformDeviceRoute>,
    domain_id_count: u32,
    next_domain_id: u32,
}

unsafe impl Send for VtdInner {}
unsafe impl Sync for VtdInner {}

impl IntelVtdBackend {
    pub fn init(info: &IntelPlatformIommuInfo) -> Result<Self, IommuError> {
        let mut units = Vec::with_capacity(info.remapper_units.len());
        for unit in &info.remapper_units {
            let reg_va = map_physical_pages(
                PhysAddr::new(unit.register_base).into(),
                0x1000,
                kernel_types::memory::PhysicalMappingCache::Uncached,
            )
            .map_err(|_| IommuError::HardwareError)?
            .as_mut_ptr::<u8>();

            let cap = unsafe { read_reg64(reg_va, CAP_REG) };
            let ecap = unsafe { read_reg64(reg_va, ECAP_REG) };
            let ver = unsafe { read_reg32(reg_va, VER_REG) };

            let iro = ((ecap >> 8) & 0x3ff) as usize;
            let iotlb_reg_off = iro * 16 + 0x08;

            let sagaw = ((cap >> 8) & 0x1f) as u32;
            if (sagaw & (1 << 2)) == 0 {
                return Err(IommuError::Unsupported);
            }

            let mgaw = ((cap >> 16) & 0x3f) as u32;
            let iova_end = 1u64 << core::cmp::min(mgaw + 1, 48);

            let nd = (cap & 0x7) as u32;
            let domain_id_count = domain_id_count_from_nd(nd).ok_or(IommuError::Unsupported)?;

            let root_phys = page_table::alloc_root_table()?;

            unsafe {
                write_reg32(reg_va, FSTS_REG, 0xffff_ffff);

                write_reg64(reg_va, RTADDR_REG, root_phys);
                gcmd_issue(reg_va, GCMD_SRTP);
                wait_bit_set32(reg_va, GSTS_REG, GSTS_RTPS);

                write_reg64(reg_va, CCMD_REG, CCMD_ICC | CCMD_CIRG_GLOBAL);
                wait_bit_clear64(reg_va, CCMD_REG, CCMD_ICC);

                write_reg64(
                    reg_va,
                    iotlb_reg_off,
                    IOTLB_IVT | IOTLB_IIRG_GLOBAL | IOTLB_DW | IOTLB_DR,
                );
                wait_bit_clear64(reg_va, iotlb_reg_off, IOTLB_IVT);

                gcmd_issue(reg_va, GCMD_TE);
                wait_bit_set32(reg_va, GSTS_REG, GSTS_TES);
            }

            let fsts = unsafe { read_reg32(reg_va, FSTS_REG) };
            println!(
                "iommu: Intel VT-d up at {:#x}, segment={}, ver={:#x} cap={:#x} ecap={:#x} iro={:#x} mgaw={} nd={} fsts={:#x}",
                unit.register_base, unit.segment, ver, cap, ecap, iro, mgaw, nd, fsts
            );

            units.push(VtdUnit {
                register_base: unit.register_base,
                reg_base_va: reg_va,
                root_table_phys: root_phys,
                context_table_phys: [0u64; 256],
                iotlb_reg_off,
                iova_end,
                segment: unit.segment,
                include_all: unit.include_all,
                device_scopes: unit.device_scopes.clone(),
                platform_routes: unit.platform_routes.clone(),
                domain_id_count,
                next_domain_id: 1,
            });
        }

        if units.is_empty() {
            return Err(IommuError::Unsupported);
        }

        Ok(Self {
            inner: Mutex::new(VtdInner { units }),
        })
    }

    pub fn create_domain(&self, identity: DmaPciDeviceIdentity) -> Result<IommuDomain, IommuError> {
        let (unit_index, domain_id, iova_end) = {
            let mut inner = self.inner.lock();
            let unit_index = inner.select_unit_index(identity)?;
            let unit = &mut inner.units[unit_index];
            let domain_id = allocate_domain_id(unit)?;
            (unit_index, domain_id, unit.iova_end)
        };

        let root_phys = page_table::alloc_root_table()?;
        Ok(IommuDomain::new(
            root_phys,
            domain_id,
            identity.segment,
            identity.requester_id,
            unit_index as u32,
            iova_end,
        ))
    }

    pub fn create_platform_domain(
        &self,
        identity: DeviceMmuPlatformDeviceIdentity,
    ) -> Result<IommuDomain, IommuError> {
        let (unit_index, segment, source_id, domain_id, iova_end) = {
            let mut inner = self.inner.lock();
            let (unit_index, source_id) = inner.select_platform_route(identity)?;
            let unit = &mut inner.units[unit_index];
            let domain_id = allocate_domain_id(unit)?;
            (
                unit_index,
                unit.segment,
                source_id,
                domain_id,
                unit.iova_end,
            )
        };

        let root_phys = page_table::alloc_root_table()?;
        Ok(IommuDomain::new(
            root_phys,
            domain_id,
            segment,
            source_id,
            unit_index as u32,
            iova_end,
        ))
    }

    pub fn attach(&self, domain: &IommuDomain) -> Result<(), IommuError> {
        let mut inner = self.inner.lock();
        let unit = inner
            .units
            .get_mut(domain.remapper_index as usize)
            .ok_or(IommuError::HardwareError)?;
        if unit.segment != domain.segment {
            return Err(IommuError::HardwareError);
        }

        attach_source_id(unit, domain, domain.requester_id)?;
        invalidate_context_domain(unit, domain.domain_id);
        invalidate_domain_iotlb(unit, domain.domain_id);
        Ok(())
    }

    pub fn attach_platform(
        &self,
        domain: &IommuDomain,
        identity: DeviceMmuPlatformDeviceIdentity,
    ) -> Result<(), IommuError> {
        let mut inner = self.inner.lock();
        let unit = inner
            .units
            .get_mut(domain.remapper_index as usize)
            .ok_or(IommuError::HardwareError)?;
        if unit.segment != domain.segment || !unit_has_platform_route(unit, identity) {
            return Err(IommuError::Unsupported);
        }

        let end = platform_translation_id_end(identity)?;
        for source_id in identity.iommu_id_base..end {
            attach_source_id(unit, domain, source_id as u16)?;
        }

        invalidate_context_domain(unit, domain.domain_id);
        invalidate_domain_iotlb(unit, domain.domain_id);
        Ok(())
    }

    #[inline]
    pub fn unmap_pages(&self, domain: &IommuDomain, iova: u64, page_count: u32) {
        let mut cur = iova;
        for _ in 0..page_count {
            let _ = page_table::unmap_4k(domain.root_phys, cur, PTE_P | PTE_RW);
            cur += 0x1000;
        }
        self.invalidate(domain, 0, 0);
    }

    pub fn invalidate(&self, domain: &IommuDomain, _iova: u64, _len: u64) {
        let inner = self.inner.lock();
        let Some(unit) = inner.units.get(domain.remapper_index as usize) else {
            return;
        };
        invalidate_domain_iotlb(unit, domain.domain_id);
    }
}

impl VtdInner {
    fn select_unit_index(&self, identity: DmaPciDeviceIdentity) -> Result<usize, IommuError> {
        let mut segment_matches = 0usize;
        let mut only_segment_match = None;
        let mut scope_matches = 0usize;
        let mut scope_match = None;
        let mut include_all_matches = 0usize;
        let mut include_all_match = None;

        for (idx, unit) in self.units.iter().enumerate() {
            if unit.segment != identity.segment {
                continue;
            }

            segment_matches += 1;
            only_segment_match = Some(idx);

            if unit
                .device_scopes
                .iter()
                .any(|scope| scope_matches_device(scope, identity))
            {
                scope_matches += 1;
                scope_match = Some(idx);
            }

            if unit.include_all {
                include_all_matches += 1;
                include_all_match = Some(idx);
            }
        }

        if scope_matches == 1 {
            return Ok(scope_match.expect("missing VT-d scope match"));
        }
        if segment_matches == 1 {
            return Ok(only_segment_match.expect("missing VT-d segment match"));
        }
        if include_all_matches == 1 {
            return Ok(include_all_match.expect("missing VT-d include-all match"));
        }

        Err(IommuError::Unsupported)
    }

    fn select_platform_route(
        &self,
        identity: DeviceMmuPlatformDeviceIdentity,
    ) -> Result<(usize, u16), IommuError> {
        validate_platform_identity(identity)?;

        let mut found = None;
        for (idx, unit) in self.units.iter().enumerate() {
            for route in &unit.platform_routes {
                if !platform_route_matches(route, identity) {
                    continue;
                }

                let source_id = route.translation_id_base as u16;
                if found.replace((idx, source_id)).is_some() {
                    return Err(IommuError::Unsupported);
                }
            }
        }

        found.ok_or(IommuError::Unsupported)
    }
}

fn allocate_domain_id(unit: &mut VtdUnit) -> Result<u16, IommuError> {
    if unit.next_domain_id >= unit.domain_id_count {
        return Err(IommuError::HardwareError);
    }

    let domain_id = unit.next_domain_id as u16;
    unit.next_domain_id += 1;
    Ok(domain_id)
}

fn attach_source_id(
    unit: &mut VtdUnit,
    domain: &IommuDomain,
    source_id: u16,
) -> Result<(), IommuError> {
    let bus = (source_id >> 8) as u8;
    let devfn = (source_id & 0xff) as u8;
    let ctx_phys = ensure_context_table(unit, bus)?;
    let qw0 = (domain.root_phys & PTE_ADDR_MASK) | 1;
    let qw1 = AGAW_48 | ((domain.domain_id as u64) << 8);
    write_table_pair(ctx_phys, (devfn as usize) * 2, qw0, qw1)
}

fn ensure_context_table(unit: &mut VtdUnit, bus: u8) -> Result<u64, IommuError> {
    if unit.context_table_phys[bus as usize] != 0 {
        return Ok(unit.context_table_phys[bus as usize]);
    }

    let new_ctx = page_table::alloc_root_table()?;
    unit.context_table_phys[bus as usize] = new_ctx;

    write_table_pair(
        unit.root_table_phys,
        (bus as usize) * 2,
        (new_ctx & PTE_ADDR_MASK) | 1,
        0,
    )?;

    Ok(new_ctx)
}

fn invalidate_context_domain(unit: &VtdUnit, domain_id: u16) {
    let ccmd = CCMD_ICC | CCMD_CIRG_DOMAIN | ((domain_id as u64) << 16);
    unsafe {
        write_reg64(unit.reg_base_va, CCMD_REG, ccmd);
        wait_bit_clear64(unit.reg_base_va, CCMD_REG, CCMD_ICC);
    }
}

fn validate_platform_identity(identity: DeviceMmuPlatformDeviceIdentity) -> Result<(), IommuError> {
    if identity.iommu_id_count == 0 {
        return Err(IommuError::Unsupported);
    }

    let Some(last) = identity
        .iommu_id_base
        .checked_add(identity.iommu_id_count - 1)
    else {
        return Err(IommuError::Unsupported);
    };

    if last > u16::MAX as u32 {
        return Err(IommuError::Unsupported);
    }

    Ok(())
}

fn platform_translation_id_end(
    identity: DeviceMmuPlatformDeviceIdentity,
) -> Result<u32, IommuError> {
    validate_platform_identity(identity)?;
    identity
        .iommu_id_base
        .checked_add(identity.iommu_id_count)
        .ok_or(IommuError::Unsupported)
}

fn unit_has_platform_route(unit: &VtdUnit, identity: DeviceMmuPlatformDeviceIdentity) -> bool {
    unit.platform_routes
        .iter()
        .any(|route| platform_route_matches(route, identity))
}

fn platform_route_matches(
    route: &X86PlatformDeviceRoute,
    identity: DeviceMmuPlatformDeviceIdentity,
) -> bool {
    route.firmware_node == identity.firmware_node
        && route.translation_id_base == identity.iommu_id_base
        && route.translation_id_count == identity.iommu_id_count
}

#[inline]
fn invalidate_domain_iotlb(unit: &VtdUnit, domain_id: u16) {
    let iotlb = IOTLB_IVT | IOTLB_IIRG_DOMAIN | IOTLB_DW | IOTLB_DR | ((domain_id as u64) << 32);
    unsafe {
        write_reg64(unit.reg_base_va, unit.iotlb_reg_off, iotlb);
        wait_bit_clear64(unit.reg_base_va, unit.iotlb_reg_off, IOTLB_IVT);
    }
}

fn scope_matches_device(scope: &IntelDeviceScope, identity: DmaPciDeviceIdentity) -> bool {
    if let Some(path) = build_scope_path(identity, scope.start_bus) {
        return pci_paths_match(scope.path.as_slice(), path.as_slice());
    }

    if scope.start_bus != identity.bus || scope.path.len() != 1 {
        return false;
    }

    let Some(last) = scope.path.last() else {
        return false;
    };
    last.device == identity.device && last.function == identity.function
}

fn pci_paths_match(expected: &[IntelPciPath], actual: &[IntelPciPath]) -> bool {
    expected.len() == actual.len()
        && expected
            .iter()
            .zip(actual.iter())
            .all(|(lhs, rhs)| lhs.device == rhs.device && lhs.function == rhs.function)
}

fn build_scope_path(identity: DmaPciDeviceIdentity, start_bus: u8) -> Option<Vec<IntelPciPath>> {
    if identity.config_space_phys == 0 || start_bus > identity.bus {
        return None;
    }

    let ecam_base = identity
        .config_space_phys
        .checked_sub((identity.bus as u64) << 20)?
        .checked_sub((identity.device as u64) << 15)?
        .checked_sub((identity.function as u64) << 12)?;

    let mut path = Vec::new();
    path.push(IntelPciPath {
        device: identity.device,
        function: identity.function,
    });

    let mut current_bus = identity.bus;
    let mut hops = 0usize;
    while current_bus != start_bus {
        let parent = find_parent_bridge(ecam_base, start_bus, current_bus)?;
        if parent.primary_bus >= current_bus {
            return None;
        }

        path.push(IntelPciPath {
            device: parent.device,
            function: parent.function,
        });
        current_bus = parent.primary_bus;
        hops += 1;
        if hops > 255 {
            return None;
        }
    }

    path.reverse();
    Some(path)
}

#[derive(Clone, Copy)]
struct ParentBridge {
    primary_bus: u8,
    device: u8,
    function: u8,
}

fn find_parent_bridge(ecam_base: u64, start_bus: u8, target_bus: u8) -> Option<ParentBridge> {
    if target_bus <= start_bus {
        return None;
    }

    let mut found = None;
    for bus in start_bus..target_bus {
        let bus_pa = PhysAddr::new(ecam_base + ((bus as u64) << 20));
        let Ok(bus_va) = map_physical_pages(
            bus_pa.into(),
            1 << 20,
            kernel_types::memory::PhysicalMappingCache::Uncached,
        ) else {
            continue;
        };

        let candidate = scan_bus_for_parent_bridge(bus_va.into(), target_bus);
        let _ = unmap_physical_pages(bus_va, 1 << 20);

        if let Some(parent) = candidate {
            if found.is_some() {
                return None;
            }
            found = Some(parent);
        }
    }

    found
}

fn scan_bus_for_parent_bridge(bus_va: VirtAddr, target_bus: u8) -> Option<ParentBridge> {
    let mut found = None;
    let bus_base = bus_va.as_ptr::<u8>();

    for device in 0u8..32 {
        let func0 = cfg_function_base(bus_base, device, 0);
        let vendor = unsafe { read_cfg32(func0, 0x00) } & 0xffff;
        if vendor == 0xffff {
            continue;
        }

        let header_type = ((unsafe { read_cfg32(func0, 0x0c) } >> 16) & 0xff) as u8;
        let function_count = if (header_type & 0x80) != 0 { 8 } else { 1 };
        for function in 0u8..function_count {
            let func_base = cfg_function_base(bus_base, device, function);
            let vendor = unsafe { read_cfg32(func_base, 0x00) } & 0xffff;
            if vendor == 0xffff {
                continue;
            }

            let header_type = ((unsafe { read_cfg32(func_base, 0x0c) } >> 16) & 0x7f) as u8;
            if header_type != 0x01 {
                continue;
            }

            let buses = unsafe { read_cfg32(func_base, 0x18) };
            let primary_bus = (buses & 0xff) as u8;
            let secondary_bus = ((buses >> 8) & 0xff) as u8;
            if secondary_bus != target_bus {
                continue;
            }

            if found.is_some() {
                return None;
            }
            found = Some(ParentBridge {
                primary_bus,
                device,
                function,
            });
        }
    }

    found
}

#[inline]
fn cfg_function_base(bus_base: *const u8, device: u8, function: u8) -> *const u8 {
    unsafe { bus_base.add(((device as usize) << 15) | ((function as usize) << 12)) }
}

#[inline]
unsafe fn read_cfg32(base: *const u8, off: usize) -> u32 {
    unsafe { core::ptr::read_volatile(base.add(off) as *const u32) }
}

#[inline]
fn domain_id_count_from_nd(nd: u32) -> Option<u32> {
    match nd {
        0 => Some(16),
        1 => Some(64),
        2 => Some(256),
        3 => Some(1024),
        4 => Some(4096),
        5 => Some(16384),
        6 => Some(65536),
        _ => None,
    }
}

#[inline]
unsafe fn read_reg32(base: *mut u8, off: usize) -> u32 {
    unsafe { core::ptr::read_volatile(base.add(off) as *const u32) }
}

#[inline]
unsafe fn write_reg32(base: *mut u8, off: usize, v: u32) {
    unsafe { core::ptr::write_volatile(base.add(off) as *mut u32, v) }
}

#[inline]
unsafe fn read_reg64(base: *mut u8, off: usize) -> u64 {
    unsafe { core::ptr::read_volatile(base.add(off) as *const u64) }
}

#[inline]
unsafe fn write_reg64(base: *mut u8, off: usize, v: u64) {
    unsafe { core::ptr::write_volatile(base.add(off) as *mut u64, v) }
}

#[inline]
unsafe fn wait_bit_set32(base: *mut u8, off: usize, bit: u32) {
    while unsafe { read_reg32(base, off) } & bit == 0 {
        core::hint::spin_loop();
    }
}

#[inline]
unsafe fn gcmd_issue(base: *mut u8, cmd_bit: u32) {
    let enabled = unsafe { read_reg32(base, GSTS_REG) } & GSTS_ENABLE_MASK;
    unsafe { write_reg32(base, GCMD_REG, enabled | cmd_bit) };
}

#[inline]
unsafe fn wait_bit_clear64(base: *mut u8, off: usize, bit: u64) {
    while unsafe { read_reg64(base, off) } & bit != 0 {
        core::hint::spin_loop();
    }
}

fn write_table_pair(
    table_phys: u64,
    index: usize,
    first: u64,
    second: u64,
) -> Result<(), IommuError> {
    unsafe {
        let ptr = page_table::phys_to_mut::<u64>(table_phys).add(index);
        ptr.write_volatile(first);
        ptr.add(1).write_volatile(second);
    }
    Ok(())
}
