use x86_64::{PhysAddr, VirtAddr};

pub(crate) struct Ioapic {
    base_addr: VirtAddr,
    gsi_base: u32,
    entry_count: u32,
}

impl Ioapic {
    pub fn new(phys: PhysAddr, gsi_base: u32) -> Result<Self, ()> {
        let virt = crate::memory::paging::map_physical_pages(
            phys.into(),
            0x2048,
            kernel_types::memory::PhysicalMappingCache::Uncached,
        )
        .map_err(|_| ())?;
        let mut result = Self {
            base_addr: virt.into(),
            gsi_base,
            entry_count: 0,
        };
        result.entry_count = ((result.read_register(1) >> 16) & 0xff) + 1;
        Ok(result)
    }

    fn ptr(&self) -> *mut u32 {
        self.base_addr.as_mut_ptr()
    }
    fn read_register(&self, register: u32) -> u32 {
        unsafe {
            let ioregsel = self.ptr();
            let iowin = (self.base_addr.as_u64() + 0x10) as *const u32;
            ioregsel.write_volatile(register);
            iowin.read_volatile()
        }
    }

    pub(super) fn owns(&self, source: u32) -> bool {
        source >= self.gsi_base && source < self.gsi_base + self.entry_count
    }

    pub fn unmask_irq_any_cpu(&self, source: u32, vector: u8, cpu_logical_mask: u8) {
        let irq = source - self.gsi_base;
        let reg_low = 0x10 + (irq as u32) * 2;
        let reg_high = reg_low + 1;

        const IOAPIC_DELIVERY_LOWEST: u32 = 1 << 8;
        const IOAPIC_DEST_LOGICAL: u32 = 1 << 11;
        const IOAPIC_MASKED: u32 = 1 << 16;

        let low = (vector as u32) | IOAPIC_DELIVERY_LOWEST | IOAPIC_DEST_LOGICAL;
        let high = (cpu_logical_mask as u32) << 24;

        unsafe {
            let ioregsel = self.ptr();
            let iowin = (self.base_addr.as_u64() + 0x10) as *mut u32;

            ioregsel.write_volatile(reg_high);
            iowin.write_volatile(high);

            ioregsel.write_volatile(reg_low);
            iowin.write_volatile(low & !IOAPIC_MASKED);
        }
    }

    pub fn mask_irq(&self, source: u32) {
        let irq = source - self.gsi_base;
        let reg_low = 0x10 + (irq as u32) * 2;
        unsafe {
            let ioregsel = self.ptr();
            let iowin = (self.base_addr.as_u64() + 0x10) as *mut u32;
            ioregsel.write_volatile(reg_low);
            let low = iowin.read_volatile();
            ioregsel.write_volatile(reg_low);
            iowin.write_volatile(low | (1 << 16));
        }
    }
}
