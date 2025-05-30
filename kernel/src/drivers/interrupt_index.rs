use crate::cpu::get_cpu_info;
use crate::drivers::interrupt_index::ApicErrors::{
    AlreadyInit, BadInterruptModel, NoACPI, NoCPUID, NotAvailable,
};
use crate::drivers::ACPI::ACPI_TABLES;
use crate::memory::paging;
use crate::{print, println};
use acpi::platform::interrupt::Apic;
use alloc::alloc::Global;
use core::iter;
use core::sync::atomic::AtomicBool;
use pic8259::ChainedPics;
use spin::Mutex;
use x86_64::{PhysAddr, VirtAddr};

pub(crate) const PIC_1_OFFSET: u8 = 0x20;
pub(crate) const PIC_2_OFFSET: u8 = PIC_1_OFFSET + 0x8;

pub static PICS: Mutex<ChainedPics> =
    Mutex::new(unsafe { ChainedPics::new(PIC_1_OFFSET, PIC_2_OFFSET) });
pub static APIC: Mutex<Option<ApicImpl>> = Mutex::new(None);
pub static USE_APIC: AtomicBool = AtomicBool::new(false);
#[derive(Debug, Clone, Copy)]
#[repr(u8)]

pub enum InterruptIndex {
    Timer = PIC_1_OFFSET,
    KeyboardIndex = PIC_1_OFFSET + 0x1,
    PrimaryDrive = PIC_1_OFFSET + 0xE,
    SecondaryDrive = PIC_1_OFFSET + 0xF,
    SysCall = PIC_1_OFFSET + 0x60,
}

impl InterruptIndex {
    pub(crate) fn as_u8(self) -> u8 {
        self as u8
    }
}
#[inline(never)]
pub fn send_eoi(irq: u8) {
    unsafe {
        if let Some(apic) = APIC.lock().as_mut() {
            apic.end_interrupt();
        } else {
            PICS.force_unlock();
            PICS.lock().notify_end_of_interrupt(irq);
        }
    }
}
#[derive(Debug, Clone, Copy)]

pub enum ApicErrors {
    NotAvailable,
    NoCPUID,
    BadInterruptModel,
    NoACPI,
    AlreadyInit,
}
impl ApicErrors {
    pub fn to_str(&self) -> &'static str {
        match self {
            NotAvailable => "Apic is not supported by this CPU",
            NoCPUID => "CPU ID is not supported by this CPU",
            BadInterruptModel => "CPU has incorrect Interrupt model",
            NoACPI => "ACPI is not supported by this CPU",
            AlreadyInit => "The APIC has already been init",
        }
    }
}

pub struct ApicImpl {
    pub apic_info: Apic<'static, Global>,
    pub lapic_virt_addr: VirtAddr,
}

impl ApicImpl {
    fn new() -> Result<Self, ApicErrors> {
        if let info = get_cpu_info() {
            let features = info.get_feature_info().ok_or(NoCPUID)?;
            if (!features.has_apic()) {
                return Err(NotAvailable);
            }
            if (!features.has_acpi()) {
                return Err(NoACPI);
            }
            if let Some(table) = ACPI_TABLES.get_interrupt_model() {
                let lapic_vaddr =
                    paging::map_mmio_region(PhysAddr::new(table.local_apic_address), 0x1000)
                        .expect("failed to map local apic to mmio space"); // your MMIO mapper

                Ok(ApicImpl {
                    apic_info: table,
                    lapic_virt_addr: lapic_vaddr,
                })
            } else {
                Err(BadInterruptModel)
            }
        } else {
            Err(NoCPUID)
        }
    }

    fn init_local(&self) {
        if self.apic_info.also_has_legacy_pics {
            unsafe {
                PICS.lock().disable();
            }
        }

        // Map and enable the local APIC for the current CPU
        unsafe {
            self.init_lapic();
        }
    }
    unsafe fn init_lapic(&self) {
        let lapic_ptr = self.lapic_virt_addr.as_mut_ptr::<u32>();

        const LAPIC_SVR_OFFSET: usize = 0xF0 / 4;
        let svr = lapic_ptr.add(LAPIC_SVR_OFFSET);
        svr.write_volatile(svr.read_volatile() | 0x100); // enable LAPIC (bit 8)
    }
    unsafe fn init_timer(&self) {
        let lapic_pointer = self.lapic_virt_addr.as_mut_ptr::<u32>();
        let svr = lapic_pointer.offset(APICOffset::Svr as isize / 4);
        svr.write_volatile(svr.read_volatile() | 0x100);

        // Configure timer
        // Vector 0x20, Periodic Mode (bit 17), Not masked (bit 16 = 0)
        let lvt_timer = lapic_pointer.offset(APICOffset::LvtT as isize / 4);
        lvt_timer.write_volatile(0x20 | (1 << 17));

        // Set divider to 16
        let tdcr = lapic_pointer.offset(APICOffset::Tdcr as isize / 4);
        tdcr.write_volatile(0x3);

        // Set initial count - smaller value for more frequent interrupts
        let ticr = lapic_pointer.offset(APICOffset::Ticr as isize / 4);
        ticr.write_volatile(2400);
    }
    unsafe fn init_ioapic(&self) {
        let phys_addr = self.apic_info.io_apics[0].address;
        let virt_addr = paging::map_mmio_region(PhysAddr::new(phys_addr as u64), 0x2048)
            .expect("failed to map io apic");
        let ioapic_pointer = virt_addr.as_mut_ptr::<u32>();

        ioapic_pointer.offset(0).write_volatile(0x12);
        ioapic_pointer
            .offset(4)
            .write_volatile(InterruptIndex::KeyboardIndex as u8 as u32);
    }
    unsafe fn init_keyboard(&self) {
        let keyboard_register = self
            .lapic_virt_addr
            .as_mut_ptr::<u32>()
            .offset(APICOffset::LvtLint1 as isize / 4);
        keyboard_register.write_volatile(InterruptIndex::KeyboardIndex.as_u8() as u32);
    }
    pub fn end_interrupt(&self) {
        unsafe {
            let lapic_ptr = self.lapic_virt_addr.as_mut_ptr::<u32>();
            lapic_ptr
                .offset(APICOffset::Eoi as isize / 4)
                .write_volatile(0);
        }
    }
    pub fn init_apic_full() -> Result<(), ApicErrors> {
        x86_64::instructions::interrupts::disable();
        {
            if APIC.lock().is_some() {
                return Err(AlreadyInit);
            }
        }
        let apic_result = ApicImpl::new();
        match apic_result {
            Ok(apic) => unsafe {
                apic.init_local();
                apic.init_timer();

                apic.init_ioapic();
                apic.init_keyboard();
                APIC.lock().replace(apic);
            },
            Err(err) => return Err(err),
        }

        Ok(x86_64::instructions::interrupts::enable())
    }
    pub fn start_aps() -> Result<(), ()> {
        //TODO: add errors
        let apics = ACPI_TABLES
            .get_plat_info()
            .ok_or(())?
            .processor_info
            .ok_or(())?
            .application_processors;
        for apic in apics.iter().enumerate() {}
        Ok(())
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy)]
#[repr(isize)]
#[allow(dead_code)]
pub enum APICOffset {
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
