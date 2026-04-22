//! Intel VT-d (DMA remapping) backend. Register offsets and field
//! layouts follow Intel VT-d Architecture Specification rev 4.1, §10.4.
//!
//! This implementation is deliberately minimal: legacy root table,
//! second-level 4-level paging (AGAW = 48-bit), register-based
//! invalidation. Queued invalidation and interrupt remapping are
//! TODOs.

use core::sync::atomic::{AtomicU16, Ordering};

use spin::Mutex;
use x86_64::PhysAddr;

use crate::memory::dma::IntelPlatformIommuInfo;
use crate::memory::iommu::domain::{IommuDomain, IommuError};
use crate::memory::iommu::page_table::{self, PTE_ADDR_MASK};
use crate::memory::paging::mmio::map_mmio_region;
use crate::println;

// --- Register offsets (VT-d §10.4) -----------------------------------------
const VER_REG: usize = 0x00;
const CAP_REG: usize = 0x08;
const ECAP_REG: usize = 0x10;
const GCMD_REG: usize = 0x18;
const GSTS_REG: usize = 0x1C;
const RTADDR_REG: usize = 0x20;
const CCMD_REG: usize = 0x28;
const FSTS_REG: usize = 0x34;

// Global Command / Status bits
const GCMD_TE: u32 = 1 << 31;
const GCMD_SRTP: u32 = 1 << 30;
const GSTS_TES: u32 = 1 << 31;
const GSTS_RTPS: u32 = 1 << 30;

// Context Command bits (CCMD_REG)
const CCMD_ICC: u64 = 1 << 63;
const CCMD_CIRG_GLOBAL: u64 = 1 << 61;   // Global Invalidation Request
const CCMD_CIRG_DOMAIN: u64 = 2 << 61;   // Domain-selective

// IOTLB register bits (at CAP.IRO * 16 + 0x08, high qword)
const IOTLB_IVT: u64 = 1 << 63;
const IOTLB_IIRG_GLOBAL: u64 = 1 << 60;
const IOTLB_IIRG_DOMAIN: u64 = 2 << 60;

// --- Register / structure layouts ------------------------------------------
//
// Legacy Root Entry (16 bytes):
//   qw[0]: [0]=P, [11:1]=rsvd, [63:12]=CTP pfn (shifted)
//   qw[1]: reserved
//
// Legacy Context Entry (16 bytes):
//   qw[0]: [0]=P, [1]=FPD, [3:2]=T, [11:4]=rsvd, [63:12]=SLPTPTR
//   qw[1]: [2:0]=AW, [6:3]=rsvd, [7]=0, [23:8]=DID, [63:24]=rsvd

const AGAW_48: u64 = 0b010; // 4-level second-level paging

static NEXT_DOMAIN_ID: AtomicU16 = AtomicU16::new(1);

pub struct IntelVtdBackend {
    inner: Mutex<VtdInner>,
}

struct VtdInner {
    reg_base_va: *mut u8,
    root_table_phys: u64,
    /// Indexed by PCI bus (0..=255). Zero means no context table allocated yet.
    context_table_phys: [u64; 256],
    iotlb_reg_off: usize,
    iova_end: u64,
}

// The register pointer is a device-MMIO mapping. We access it only under the
// `inner` mutex, so it's safe to send/share the struct across threads.
unsafe impl Send for VtdInner {}
unsafe impl Sync for VtdInner {}

impl IntelVtdBackend {
    pub fn init(info: &IntelPlatformIommuInfo) -> Result<Self, IommuError> {
        let unit = info
            .remapper_units
            .iter()
            .find(|u| u.include_all)
            .or_else(|| info.remapper_units.first())
            .ok_or(IommuError::Unsupported)?;

        let reg_base = PhysAddr::new(unit.register_base);
        let reg_va = map_mmio_region(reg_base, 0x1000)
            .map_err(|_| IommuError::HardwareError)?
            .as_mut_ptr::<u8>();

        // Basic capability probe.
        let cap = unsafe { read_reg64(reg_va, CAP_REG) };
        let ecap = unsafe { read_reg64(reg_va, ECAP_REG) };
        let ver = unsafe { read_reg32(reg_va, VER_REG) };

        // CAP[IRO] is bits [43:33] (11 bits), scaled by 16 bytes.
        let iro = ((cap >> 33) & 0x3FF) as usize;
        let iotlb_reg_off = iro * 16 + 0x08;

        // CAP[SAGAW] bits [12:8] advertises supported AGAWs; bit 2 => 48-bit.
        let sagaw = ((cap >> 8) & 0x1F) as u32;
        if sagaw & (1 << 2) == 0 {
            // v1 only supports 4-level second-level paging.
            return Err(IommuError::Unsupported);
        }

        // CAP[MGAW] bits [21:16] => max guest address width - 1. Cap IOVA
        // arena to 2^(mgaw+1).
        let mgaw = ((cap >> 16) & 0x3F) as u32;
        let iova_end = if mgaw >= 47 {
            0x0000_8000_0000_0000 // 47-bit cap (safe under 48-bit limit)
        } else {
            1u64 << (mgaw + 1)
        };

        // Allocate zeroed root table.
        let root_phys = page_table::alloc_root_table()?;

        // Bring-up sequence (§10.4.5):
        //   1. RTADDR = root phys
        //   2. GCMD.SRTP → poll GSTS.RTPS
        //   3. Global CCMD invalidate → poll
        //   4. Global IOTLB invalidate → poll
        //   5. GCMD.TE → poll GSTS.TES
        unsafe {
            write_reg64(reg_va, RTADDR_REG, root_phys);
            write_reg32(reg_va, GCMD_REG, GCMD_SRTP);
            wait_bit_set32(reg_va, GSTS_REG, GSTS_RTPS);

            write_reg64(
                reg_va,
                CCMD_REG,
                CCMD_ICC | CCMD_CIRG_GLOBAL,
            );
            wait_bit_clear64(reg_va, CCMD_REG, CCMD_ICC);

            write_reg64(
                reg_va,
                iotlb_reg_off,
                IOTLB_IVT | IOTLB_IIRG_GLOBAL,
            );
            wait_bit_clear64(reg_va, iotlb_reg_off, IOTLB_IVT);

            write_reg32(reg_va, GCMD_REG, GCMD_TE);
            wait_bit_set32(reg_va, GSTS_REG, GSTS_TES);
        }

        let fsts = unsafe { read_reg32(reg_va, FSTS_REG) };
        println!(
            "iommu: Intel VT-d up at {:#x}, ver={:#x} cap={:#x} ecap={:#x} iro={:#x} mgaw={} fsts={:#x}",
            unit.register_base, ver, cap, ecap, iro, mgaw, fsts
        );

        Ok(Self {
            inner: Mutex::new(VtdInner {
                reg_base_va: reg_va,
                root_table_phys: root_phys,
                context_table_phys: [0u64; 256],
                iotlb_reg_off,
                iova_end,
            }),
        })
    }

    pub fn iova_end(&self) -> u64 {
        self.inner.lock().iova_end
    }

    pub fn create_domain(&self, requester_id: u16) -> Result<IommuDomain, IommuError> {
        let root_phys = page_table::alloc_root_table()?;
        let domain_id = NEXT_DOMAIN_ID.fetch_add(1, Ordering::Relaxed);
        let iova_end = self.inner.lock().iova_end;
        Ok(IommuDomain::new(
            root_phys,
            domain_id,
            requester_id,
            iova_end,
        ))
    }

    pub fn attach(&self, domain: &IommuDomain) -> Result<(), IommuError> {
        let bus = (domain.requester_id >> 8) as u8;
        let devfn = (domain.requester_id & 0xFF) as u8;

        let mut inner = self.inner.lock();

        // Find or create the per-bus context table.
        let ctx_phys = if inner.context_table_phys[bus as usize] != 0 {
            inner.context_table_phys[bus as usize]
        } else {
            let new_ctx = page_table::alloc_root_table()?;
            inner.context_table_phys[bus as usize] = new_ctx;

            // Install the root entry pointing at the new context table.
            let root_entry_ptr = unsafe {
                phys_to_mut::<u64>(inner.root_table_phys).add((bus as usize) * 2)
            };
            unsafe {
                root_entry_ptr.write_volatile((new_ctx & PTE_ADDR_MASK) | 1); // P=1
                root_entry_ptr.add(1).write_volatile(0);
            }
            new_ctx
        };

        // Populate the context entry.
        let ctx_entry_ptr = unsafe {
            phys_to_mut::<u64>(ctx_phys).add((devfn as usize) * 2)
        };
        let qw0 = (domain.root_phys & PTE_ADDR_MASK) | 1; // P=1, T=0 (legacy)
        let qw1 = AGAW_48 | ((domain.domain_id as u64) << 8);
        unsafe {
            ctx_entry_ptr.write_volatile(qw0);
            ctx_entry_ptr.add(1).write_volatile(qw1);
        }

        // Domain-selective context-cache and IOTLB invalidate.
        let ccmd = CCMD_ICC
            | CCMD_CIRG_DOMAIN
            | ((domain.domain_id as u64) << 16);
        unsafe {
            write_reg64(inner.reg_base_va, CCMD_REG, ccmd);
            wait_bit_clear64(inner.reg_base_va, CCMD_REG, CCMD_ICC);
        }

        let iotlb_off = inner.iotlb_reg_off;
        let iotlb = IOTLB_IVT
            | IOTLB_IIRG_DOMAIN
            | ((domain.domain_id as u64) << 32);
        unsafe {
            write_reg64(inner.reg_base_va, iotlb_off, iotlb);
            wait_bit_clear64(inner.reg_base_va, iotlb_off, IOTLB_IVT);
        }

        Ok(())
    }

    #[inline]
    pub fn map_pages(
        &self,
        domain: &IommuDomain,
        iova: u64,
        phys_pfns: &[u64],
    ) -> Result<(), IommuError> {
        let mut cur_iova = iova;
        for &pfn in phys_pfns {
            page_table::map_4k(domain.root_phys, cur_iova, pfn << 12, 0)?;
            cur_iova += 0x1000;
        }
        Ok(())
    }

    #[inline]
    pub fn unmap_pages(&self, domain: &IommuDomain, iova: u64, page_count: u32) {
        let mut cur = iova;
        for _ in 0..page_count {
            let _ = page_table::unmap_4k(domain.root_phys, cur);
            cur += 0x1000;
        }
    }

    pub fn invalidate(&self, domain: &IommuDomain, _iova: u64, _len: u64) {
        // Domain-selective IOTLB invalidate covers all pages in the domain.
        // Page-selective is a TODO — for now correctness over granularity.
        let inner = self.inner.lock();
        let iotlb_off = inner.iotlb_reg_off;
        let iotlb = IOTLB_IVT
            | IOTLB_IIRG_DOMAIN
            | ((domain.domain_id as u64) << 32);
        unsafe {
            write_reg64(inner.reg_base_va, iotlb_off, iotlb);
            wait_bit_clear64(inner.reg_base_va, iotlb_off, IOTLB_IVT);
        }
    }
}

// --- helpers ---------------------------------------------------------------

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
unsafe fn wait_bit_clear64(base: *mut u8, off: usize, bit: u64) {
    while unsafe { read_reg64(base, off) } & bit != 0 {
        core::hint::spin_loop();
    }
}

#[inline]
unsafe fn phys_to_mut<T>(phys: u64) -> *mut T {
    let off = crate::util::boot_info()
        .physical_memory_offset
        .into_option()
        .expect("phys memory offset missing");
    (off + phys) as *mut T
}
