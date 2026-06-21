pub const DISK_PROFILE_COUNTERS: usize = 26;
pub const DISK_PROFILE_BUCKETS: usize = 15;

pub const C_LOGICAL_FILE_WRITES: usize = 0;
pub const C_FS_CACHE_WRITES: usize = 1;
pub const C_BACKEND_BLOCK_REQUESTS: usize = 2;
pub const C_VIRTIO_SUBMISSIONS: usize = 3;
pub const C_VIRTIO_QUEUE_KICKS: usize = 4;
pub const C_VIRTIO_COMPLETIONS: usize = 5;
pub const C_FLUSH_BARRIER_REQUESTS: usize = 6;
pub const C_DMA_MAP_CALLS: usize = 7;
pub const C_DMA_UNMAP_CALLS: usize = 8;
pub const C_IOMMU_PAGE_TABLE_UPDATES: usize = 9;
pub const C_IOVA_ALLOCATIONS: usize = 10;
pub const C_IOVA_FREES: usize = 11;
pub const C_PHYSICAL_FRAME_TRANSLATIONS: usize = 12;
pub const C_SCATTER_GATHER_SEGMENTS: usize = 13;
pub const C_BYTES_COPIED: usize = 14;
pub const C_MEMCPY_CALLS: usize = 15;
pub const C_HEAP_ALLOCATIONS: usize = 16;
pub const C_ARC_CLONES: usize = 17;
pub const C_LOCK_ACQUISITIONS: usize = 18;
pub const C_SCHED_WAKEUPS_CONTEXT_SWITCHES: usize = 19;
pub const C_FAT_METADATA_WRITES: usize = 20;
pub const C_DIRECTORY_METADATA_WRITES: usize = 21;
pub const C_LOGICAL_WRITE_BYTES: usize = 22;
pub const C_BACKEND_WRITE_BYTES: usize = 23;
pub const C_IOMMU_INVALIDATIONS: usize = 24;
pub const C_VIRTIO_SUBMISSION_BYTES: usize = 25;

pub const B_FILE_WRITE_ENTRY_TO_CACHE_LOOKUP: usize = 0;
pub const B_FAT_CLUSTER_TRANSLATION: usize = 1;
pub const B_CACHE_PAGE_LOOKUP: usize = 2;
pub const B_DIRTY_PAGE_PREPARATION: usize = 3;
pub const B_IOBUFFER_CONSTRUCTION: usize = 4;
pub const B_VIRTUAL_TO_PHYSICAL_TRANSLATION: usize = 5;
pub const B_DMA_MAP: usize = 6;
pub const B_IOMMU_INVALIDATION: usize = 7;
pub const B_VIRTIO_DESCRIPTOR_SETUP: usize = 8;
pub const B_VIRTIO_QUEUE_NOTIFY: usize = 9;
pub const B_WAITING_FOR_COMPLETION: usize = 10;
pub const B_INTERRUPT_COMPLETION_HANDLING: usize = 11;
pub const B_DMA_UNMAP: usize = 12;
pub const B_FILE_FLUSH_WRITE_THROUGH: usize = 13;
pub const B_METADATA_FLUSH: usize = 14;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct DiskProfileSnapshot {
    pub active_size: u64,
    pub counters: [u64; DISK_PROFILE_COUNTERS],
    pub buckets_ns: [u64; DISK_PROFILE_BUCKETS],
}
