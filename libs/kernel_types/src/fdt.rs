#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FdtHeader {
    pub magic: u32,
    pub totalsize: u32,
    pub off_dt_struct: u32,
    pub off_dt_strings: u32,
    pub off_mem_rsvmap: u32,
    pub version: u32,
    pub last_comp_version: u32,
    pub boot_cpuid_phys: u32,
    pub size_dt_strings: u32,
    pub size_dt_struct: u32,
}

impl FdtHeader {
    pub const MAGIC: u32 = 0xd00d_feed;

    #[inline]
    pub fn magic(&self) -> u32 {
        u32::from_be(self.magic)
    }

    #[inline]
    pub fn total_size(&self) -> u32 {
        u32::from_be(self.totalsize)
    }

    #[inline]
    pub fn struct_offset(&self) -> u32 {
        u32::from_be(self.off_dt_struct)
    }

    #[inline]
    pub fn strings_offset(&self) -> u32 {
        u32::from_be(self.off_dt_strings)
    }

    #[inline]
    pub fn strings_size(&self) -> u32 {
        u32::from_be(self.size_dt_strings)
    }

    #[inline]
    pub fn struct_size(&self) -> u32 {
        u32::from_be(self.size_dt_struct)
    }
}
