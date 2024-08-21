use core::arch::asm;

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub(crate) struct IdtEntry {
    pub(crate) offset_low: u16,
    pub(crate) selector: u16,
    pub(crate) ist: u8,
    pub(crate) options: u8,
    pub(crate) offset_mid: u16,
    pub(crate) offset_high: u32,
    pub(crate) reserved: u32,
}

#[repr(C, packed)]
struct IdtPointer {
    limit: u16,
    base: u64,
}
impl IdtEntry {
    pub(crate) fn set(&mut self, handler: u64, selector: u16, options: u8) {
        self.offset_low = handler as u16;
        self.selector = selector;
        self.ist = 0; // Usually 0 unless you're using the IST feature
        self.options = options;
        self.offset_mid = (handler >> 16) as u16;
        self.offset_high = (handler >> 32) as u32;
        self.reserved = 0;
    }
}
pub(crate) fn load_idt(idt: &[IdtEntry; 256]) {
    let idt_ptr = IdtPointer {
        limit: (core::mem::size_of::<[IdtEntry; 256]>() - 1) as u16,
        base: idt.as_ptr() as u64,
    };


    unsafe {
        asm!("lidt [{}]", in(reg) &idt_ptr, options(nostack, preserves_flags));
    }
}

