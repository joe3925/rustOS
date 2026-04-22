use alloc::collections::BTreeMap;
use spin::Mutex;

use crate::structs::range_tracker::RangeTracker;

#[derive(Debug, Clone, Copy)]
pub enum IommuError {
    NoBackingFrame,
    IovaSpaceExhausted,
    NotMapped,
    HardwareError,
    Unsupported,
}

/// One record per call to `map_buffer` segment installer. Used by the
/// unmap path to walk pages and clear leaf PTEs. Deliberately lean —
/// four `u64`s — so a `BTreeMap` of these scales with device count
/// without meaningful per-mapping overhead.
#[derive(Debug, Clone, Copy)]
pub struct MappingRecord {
    pub iova_base: u64,
    pub page_count: u32,
    pub is_identity: bool,
}

pub struct IommuDomain {
    pub root_phys: u64,
    pub domain_id: u16,
    pub requester_id: u16,
    pub iova_tracker: RangeTracker,
    /// Mapping records keyed by IOVA base. Populated by `map_buffer`
    /// strategy paths and drained by `unmap_buffer`.
    pub mappings: Mutex<BTreeMap<u64, MappingRecord>>,
}

impl IommuDomain {
    pub fn new(root_phys: u64, domain_id: u16, requester_id: u16, iova_end: u64) -> Self {
        // IOVA allocations start above 4 GiB to sidestep legacy ISA DMA and
        // leave the low window for firmware-reserved / identity regions.
        Self {
            root_phys,
            domain_id,
            requester_id,
            iova_tracker: RangeTracker::new(0x1_0000_0000, iova_end),
            mappings: Mutex::new(BTreeMap::new()),
        }
    }

    #[inline]
    pub fn alloc_iova(&self, size: u64) -> Option<u64> {
        self.iova_tracker.alloc_auto(size).map(|va| va.as_u64())
    }

    #[inline]
    pub fn free_iova(&self, base: u64, size: u64) {
        self.iova_tracker.dealloc(base, size);
    }

    #[inline]
    pub fn record(&self, rec: MappingRecord) {
        self.mappings.lock().insert(rec.iova_base, rec);
    }

    #[inline]
    pub fn take(&self, iova_base: u64) -> Option<MappingRecord> {
        self.mappings.lock().remove(&iova_base)
    }
}
