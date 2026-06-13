use kernel_types::arch::PageFlags;
use kernel_types::memory::PhysicalMappingCache;
use x86_64::structures::paging::PageTableFlags;

pub fn page_flags_to_x86(flags: PageFlags, cache: Option<PhysicalMappingCache>) -> PageTableFlags {
    let mut native = PageTableFlags::from_bits_truncate(flags.bits());
    if let Some(cache) = cache {
        native |= cache_to_flags(cache);
    }
    native
}

fn cache_to_flags(cache: PhysicalMappingCache) -> PageTableFlags {
    match cache {
        PhysicalMappingCache::Cached => PageTableFlags::empty(),
        PhysicalMappingCache::WriteCombining => {
            PageTableFlags::NO_CACHE | PageTableFlags::WRITE_THROUGH
        }
        PhysicalMappingCache::Uncached => PageTableFlags::NO_CACHE,
    }
}
