use crate::memory::device_mmu::{DeviceMmuError, MappingRecord};

pub type IommuError = DeviceMmuError;

pub const X86_IOVA_START: u64 = 0x1_0000_0000;

pub struct IommuDomain {
    pub root_phys: u64,
    pub domain_id: u16,
    pub segment: u16,
    pub requester_id: u16,
    pub remapper_index: u32,
    pub iova_start: u64,
    pub iova_end: u64,
}

impl IommuDomain {
    pub fn new(
        root_phys: u64,
        domain_id: u16,
        segment: u16,
        requester_id: u16,
        remapper_index: u32,
        iova_end: u64,
    ) -> Self {
        Self {
            root_phys,
            domain_id,
            segment,
            requester_id,
            remapper_index,
            iova_start: X86_IOVA_START,
            iova_end,
        }
    }

    #[inline]
    pub fn contains_iova_range(&self, iova: u64, len: u64) -> bool {
        let Some(end) = iova.checked_add(len) else {
            return false;
        };

        iova >= self.iova_start && end <= self.iova_end
    }

    #[inline]
    pub fn mapping_record(
        &self,
        iova_base: u64,
        page_count: u32,
        is_identity: bool,
    ) -> MappingRecord {
        MappingRecord {
            iova_base,
            page_count,
            is_identity,
        }
    }
}
