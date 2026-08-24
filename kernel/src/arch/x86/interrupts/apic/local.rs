use core::sync::atomic::{AtomicU64, Ordering};

use x86_64::{PhysAddr, VirtAddr};

use crate::arch::x86::timer::TIMER_FREQ;

pub(crate) static LAPIC_BASE_VA: AtomicU64 = AtomicU64::new(0);

pub(crate) trait LocalApic {
    unsafe fn init(&self, logical_id: u8);
    fn init_timer(&self);
    unsafe fn send_ipi(&self, dest: IpiDest, kind: IpiKind);
}

pub(crate) struct Lapic {
    pub(super) base_addr: VirtAddr,
}

impl Lapic {
    pub(crate) fn new(phys: PhysAddr) -> Result<Self, ()> {
        let virt = crate::memory::paging::map_physical_pages(
            phys.into(),
            0x1000,
            kernel_types::memory::PhysicalMappingCache::Uncached,
        )
        .map_err(|_| ())?;
        Ok(Self {
            base_addr: virt.into(),
        })
    }

    fn ptr(&self) -> *mut u32 {
        self.base_addr.as_mut_ptr()
    }

    pub(crate) unsafe fn wait_for_delivery(&self) {
        let icr1 = self.ptr().add(APICOffset::Icr1 as usize / 4);
        while (icr1.read_volatile() & (1 << 12)) != 0 {
            core::hint::spin_loop();
        }
    }
}

impl LocalApic for Lapic {
    unsafe fn init(&self, logical_id: u8) {
        let base = self.ptr();

        let svr = base.add(APICOffset::Svr as usize / 4);
        svr.write_volatile(svr.read_volatile() | 0x100);

        base.add(APICOffset::Dfr as usize / 4)
            .write_volatile(0xFFFF_FFFF);
        base.add(APICOffset::Ldr as usize / 4)
            .write_volatile((logical_id as u32) << 24);

        base.add(APICOffset::Tpr as usize / 4).write_volatile(0);
    }

    fn init_timer(&self) {
        unsafe {
            let base = self.ptr();
            base.add(APICOffset::Svr as usize / 4)
                .write_volatile(base.add(APICOffset::Svr as usize / 4).read_volatile() | 0x100);
            base.add(APICOffset::LvtT as usize / 4)
                .write_volatile(0x20 | (1 << 17));
            base.add(APICOffset::Tdcr as usize / 4).write_volatile(0x3);
            base.add(APICOffset::Ticr as usize / 4)
                .write_volatile(TIMER_FREQ as u32);
        }
    }

    unsafe fn send_ipi(&self, dest: IpiDest, kind: IpiKind) {
        let base = self.ptr();
        let icr1 = base.add(APICOffset::Icr1 as usize / 4);
        let icr2 = base.add(APICOffset::Icr2 as usize / 4);

        while (icr1.read_volatile() & (1 << 12)) != 0 {}

        let mut hi = 0u32;
        let shorthand = match dest {
            IpiDest::ApicId(id) => {
                hi = (id as u32) << 24;
                0u32
            }
            IpiDest::SelfOnly => 0b01 << 18,
            IpiDest::AllIncludingSelf => 0b10 << 18,
            IpiDest::AllExcludingSelf => 0b11 << 18,
        };

        let mut lo = 0u32;
        match kind {
            IpiKind::Fixed { vector } => {
                lo = (vector as u32);
            }
            IpiKind::Nmi => {
                lo = 0b100 << 8;
            }
            IpiKind::InitAssert => {
                lo = (0b101 << 8) | (1 << 14) | (1 << 15);
            }
            IpiKind::InitDeassert => {
                lo = (0b101 << 8) | (1 << 15);
            }
            IpiKind::Startup { vector_phys_addr } => {
                let v = ((vector_phys_addr.as_u64() >> 12) & 0xFF) as u32;
                lo = (0b110 << 8) | v;
            }
        }

        icr2.write_volatile(hi);
        icr1.write_volatile(shorthand | lo);
    }
}
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy)]
#[repr(isize)]
#[allow(dead_code)]
pub(crate) enum APICOffset {
    R0x00 = 0x0,      // RESERVED = 0x00
    R0x10 = 0x10,     // RESERVED = 0x10
    Ir = 0x20,        // ID Register
    Vr = 0x30,        // Version Register
    R0x40 = 0x40,     // RESERVED = 0x40
    R0x50 = 0x50,     // RESERVED = 0x50
    R0x60 = 0x60,     // RESERVED = 0x60
    R0x70 = 0x70,     // RESERVED = 0x70
    Tpr = 0x80,       // Text Priority Register
    Apr = 0x90,       // Arbitration Priority Register
    Ppr = 0xA0,       // Processor Priority Register
    Eoi = 0xB0,       // End of Interrupt
    Rrd = 0xC0,       // Remote Read Register
    Ldr = 0xD0,       // Logical Destination Register
    Dfr = 0xE0,       // DFR
    Svr = 0xF0,       // Spurious (Interrupt) Vector Register
    Isr1 = 0x100,     // In-Service Register 1
    Isr2 = 0x110,     // In-Service Register 2
    Isr3 = 0x120,     // In-Service Register 3
    Isr4 = 0x130,     // In-Service Register 4
    Isr5 = 0x140,     // In-Service Register 5
    Isr6 = 0x150,     // In-Service Register 6
    Isr7 = 0x160,     // In-Service Register 7
    Isr8 = 0x170,     // In-Service Register 8
    Tmr1 = 0x180,     // Trigger Mode Register 1
    Tmr2 = 0x190,     // Trigger Mode Register 2
    Tmr3 = 0x1A0,     // Trigger Mode Register 3
    Tmr4 = 0x1B0,     // Trigger Mode Register 4
    Tmr5 = 0x1C0,     // Trigger Mode Register 5
    Tmr6 = 0x1D0,     // Trigger Mode Register 6
    Tmr7 = 0x1E0,     // Trigger Mode Register 7
    Tmr8 = 0x1F0,     // Trigger Mode Register 8
    Irr1 = 0x200,     // Interrupt Request Register 1
    Irr2 = 0x210,     // Interrupt Request Register 2
    Irr3 = 0x220,     // Interrupt Request Register 3
    Irr4 = 0x230,     // Interrupt Request Register 4
    Irr5 = 0x240,     // Interrupt Request Register 5
    Irr6 = 0x250,     // Interrupt Request Register 6
    Irr7 = 0x260,     // Interrupt Request Register 7
    Irr8 = 0x270,     // Interrupt Request Register 8
    Esr = 0x280,      // Error Status Register
    R0x290 = 0x290,   // RESERVED = 0x290
    R0x2A0 = 0x2A0,   // RESERVED = 0x2A0
    R0x2B0 = 0x2B0,   // RESERVED = 0x2B0
    R0x2C0 = 0x2C0,   // RESERVED = 0x2C0
    R0x2D0 = 0x2D0,   // RESERVED = 0x2D0
    R0x2E0 = 0x2E0,   // RESERVED = 0x2E0
    LvtCmci = 0x2F0,  // LVT Corrected Machine Check Interrupt (CMCI) Register
    Icr1 = 0x300,     // Interrupt Command Register 1
    Icr2 = 0x310,     // Interrupt Command Register 2
    LvtT = 0x320,     // LVT Timer Register
    LvtTsr = 0x330,   // LVT Thermal Sensor Register
    LvtPmcr = 0x340,  // LVT Performance Monitoring Counters Register
    LvtLint0 = 0x350, // LVT LINT0 Register
    LvtLint1 = 0x360, // LVT LINT1 Register
    LvtE = 0x370,     // LVT Error Register
    Ticr = 0x380,     // Initial Count Register (for Timer)
    Tccr = 0x390,     // Current Count Register (for Timer)
    R0x3A0 = 0x3A0,   // RESERVED = 0x3A0
    R0x3B0 = 0x3B0,   // RESERVED = 0x3B0
    R0x3C0 = 0x3C0,   // RESERVED = 0x3C0
    R0x3D0 = 0x3D0,   // RESERVED = 0x3D0
    Tdcr = 0x3E0,     // Divide Configuration Register (for Timer)
    R0x3F0 = 0x3F0,   // RESERVED = 0x3F0
}
#[derive(Clone, Copy)]
pub(crate) enum IpiDest {
    ApicId(u8),
    SelfOnly,
    AllIncludingSelf,
    AllExcludingSelf,
}

#[derive(Clone, Copy)]
pub(crate) enum IpiKind {
    Fixed { vector: u8 },
    Nmi,
    InitAssert,
    InitDeassert,
    Startup { vector_phys_addr: PhysAddr },
}

#[inline(always)]
pub(crate) fn send_eoi(_vector: u8) {
    let base = LAPIC_BASE_VA.load(Ordering::Relaxed);
    if base != 0 {
        unsafe {
            ((base as *mut u32).add(APICOffset::Eoi as usize / 4)).write_volatile(0);
        }
    }
}
/// A faster send eoi for the timer interrupt
#[inline(always)]
pub(crate) extern "C" fn send_eoi_timer() {
    let base = LAPIC_BASE_VA.load(Ordering::Relaxed);
    if base != 0 {
        unsafe {
            ((base as *mut u32).add(APICOffset::Eoi as usize / 4)).write_volatile(0);
        }
    }
}
