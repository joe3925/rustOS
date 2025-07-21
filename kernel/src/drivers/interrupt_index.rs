use crate::cpu::{self, get_cpu_info};
use crate::drivers::acpi::ACPI_TABLES;
use crate::drivers::interrupt_index::ApicErrors::{
    AlreadyInit, BadInterruptModel, NoACPI, NoCPUID, NotAvailable,
};
use crate::gdt::PER_CPU_GDT;
use crate::idt::IDT;
use crate::memory::paging::{self, allocate_kernel_stack, identity_map_page, unmap_range};
use crate::util::{AP_STARTUP_CODE, CORE_LOCK, INIT_LOCK};
use crate::{println, KERNEL_INITIALIZED};
use acpi::platform::interrupt::Apic;
use alloc::alloc::Global;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::{mem, ptr};
use pic8259::ChainedPics;
use spin::Mutex;
use x86_64::instructions::port::Port;
use x86_64::instructions::tables::sgdt;
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::{PageTableFlags, PhysFrame};
use x86_64::structures::DescriptorTablePointer;
use x86_64::{PhysAddr, VirtAddr};

pub(crate) const PIC_1_OFFSET: u8 = 0x20;
pub(crate) const PIC_2_OFFSET: u8 = PIC_1_OFFSET + 0x8;

pub static PICS: Mutex<ChainedPics> =
    Mutex::new(unsafe { ChainedPics::new(PIC_1_OFFSET, PIC_2_OFFSET) });
pub static APIC: Mutex<Option<ApicImpl>> = Mutex::new(None);
pub static USE_APIC: AtomicBool = AtomicBool::new(false);

pub static TSC_HZ: AtomicU64 = AtomicU64::new(0);

pub const TIMER_FREQ: u64 = 1200;

const PIT_FREQUENCY_HZ: u32 = 1_193_182;
const PIT_CONTROL_PORT: u16 = 0x43;
const PIT_CHANNEL2_PORT: u16 = 0x42;
const PIT_MODE_PORT: u16 = 0x61;

const TRAMPOLINE_BASE: u64 = 0x0000_8000;
const TRAMPOLINE_STEP: u64 = 0x1000;
const AP_STACK_SIZE: usize = 1024 * 1024;

const PAGEMAP_OFF: usize = 0x08;
const GDTR_LIMIT_OFF: usize = 0x10;
const GDTR_BASE_OFF: usize = 0x12;
const TEMP_STACK_OFF: usize = 0x1A;
const START_STACK_OFF: usize = 0x1E;
const START_ADDR_OFF: usize = 0x26;
const LONGMODE_GDTR_LIMIT_OFF: usize = 0x2E;
const LONGMODE_GDTR_BASE_OFF: usize = 0x30;

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct PassedInfo {
    pub pagemap: u64,
    pub gdtr_limit: u16,
    pub gdtr_base: u64,
    pub temp_stack: u32,
    pub start_stack: u64,
    pub start_address: u64,
    pub longmode_gdtr_limit: u16,
    pub longmode_gdtr_base: u64,
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]

pub enum InterruptIndex {
    Timer = PIC_1_OFFSET,
    KeyboardIndex = PIC_1_OFFSET + 0x1,
    PrimaryDrive = PIC_1_OFFSET + 0xE,
    SecondaryDrive = PIC_1_OFFSET + 0xF,
    SysCall = PIC_1_OFFSET + 0x60,
}
pub fn get_current_logical_id() -> u8 {
    let info = get_cpu_info();
    info.get_feature_info()
        .expect("cpu id not available?")
        .initial_local_apic_id()
}
impl InterruptIndex {
    pub(crate) fn as_u8(self) -> u8 {
        self as u8
    }
}
pub fn calibrate_tsc(tsc_start: u64, tsc_end: u64, delay_ms: u64) {
    let tsc_freq = (tsc_end - tsc_start) * 1000 / delay_ms;
    TSC_HZ.store(tsc_freq, Ordering::SeqCst);
}

pub fn wait_millis(ms: u64) {
    let tsc_freq = TSC_HZ.load(Ordering::SeqCst);
    if tsc_freq == 0 {
        panic!("TSC not calibrated");
    }

    let start = cpu::get_cycles();
    let target_delta = ms as u128 * tsc_freq as u128 / 1000;
    cpu::wait_cycle(target_delta);
}

pub fn wait_using_pit_50ms() {
    let counts_for_50ms: u16 = (PIT_FREQUENCY_HZ / 20) as u16;

    unsafe {
        let mut control = Port::new(PIT_CONTROL_PORT);
        let mut ch2 = Port::new(PIT_CHANNEL2_PORT);
        let mut mode = Port::new(PIT_MODE_PORT);

        // Configure channel 2, one-shot, binary, mode 0
        control.write(0b1011_0000u8);

        // Write count (low byte, high byte)
        ch2.write((counts_for_50ms & 0xFF) as u8);
        ch2.write((counts_for_50ms >> 8) as u8);

        // Set gate high (bit 0 = 1), speaker off (bit 1 = 0)
        let mut val: u8 = mode.read();
        val = (val & !0b11) | 0b01;
        mode.write(val);

        // Wait for OUT pin (bit 5) to go high
        loop {
            let status: u8 = mode.read();
            if (status & 0b0010_0000) != 0 {
                break;
            }
        }
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

pub trait LocalApic {
    unsafe fn init(&self, logical_id: u8);
    fn init_timer(&self);
    fn end_interrupt(&self);
    unsafe fn send_ipi(&self, apic_id: u8, kind: IpiKind);
    unsafe fn write(&self, offset: usize, value: u32);
}

pub trait IoApic {
    fn init_keyboard(&self);
}
pub struct Lapic {
    base_addr: VirtAddr,
}

impl Lapic {
    pub fn new(phys: PhysAddr) -> Result<Self, ()> {
        let virt = paging::map_mmio_region(phys, 0x1000).map_err(|_| ())?;
        Ok(Self { base_addr: virt })
    }

    fn ptr(&self) -> *mut u32 {
        self.base_addr.as_mut_ptr()
    }
}

impl LocalApic for Lapic {
    unsafe fn init(&self, logical_id: u8) {
        let base = self.ptr();

        // 1. enable LAPIC (SVR)
        let svr = base.add(APICOffset::Svr as usize / 4);
        svr.write_volatile(svr.read_volatile() | 0x100);

        // 2. flat logical mode (DFR = 0xFFFF_FFFF, LDR = bit per CPU)
        base.add(APICOffset::Dfr as usize / 4)
            .write_volatile(0xFFFF_FFFF);
        base.add(APICOffset::Ldr as usize / 4)
            .write_volatile((logical_id as u32) << 24);

        // 3. accept all interrupts
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

    fn end_interrupt(&self) {
        unsafe {
            self.ptr()
                .add(APICOffset::Eoi as usize / 4)
                .write_volatile(0);
        }
    }

    unsafe fn send_ipi(&self, apic_id: u8, kind: IpiKind) {
        let icr_base = self.ptr();

        let icr_low = icr_base.add(APICOffset::Icr1 as usize / 4);
        let icr_high = icr_base.add(APICOffset::Icr2 as usize / 4);

        icr_high.write_volatile((apic_id as u32) << 24);

        let icr_value = match kind {
            IpiKind::Init => {
                0b0000_0101_0000_0000u32 // INIT IPI
            }

            IpiKind::Startup { vector_phys_addr } => {
                let vector = (vector_phys_addr.as_u64() >> 12) as u8;
                (vector as u32) | 0b0000_0110_0000_0000u32
            }
        };

        icr_low.write_volatile(icr_value);
    }
    unsafe fn write(&self, offset: usize, value: u32) {
        self.ptr().add(offset / 4).write_volatile(value);
    }
}
pub struct Ioapic {
    base_addr: VirtAddr,
}

impl Ioapic {
    pub fn new(phys: PhysAddr) -> Result<Self, ()> {
        let virt = paging::map_mmio_region(phys, 0x2048).map_err(|_| ())?;
        Ok(Self { base_addr: virt })
    }

    fn ptr(&self) -> *mut u32 {
        self.base_addr.as_mut_ptr()
    }
}

impl IoApic for Ioapic {
    fn init_keyboard(&self) {
        unsafe {
            self.ptr().add(0).write_volatile(0x12);
            self.ptr()
                .add(4)
                .write_volatile(InterruptIndex::KeyboardIndex as u8 as u32);
        }
    }
}
pub struct ApicImpl {
    pub apic_info: Apic<'static, Global>,
    pub lapic: Lapic,
    pub ioapic: Ioapic,
}

impl ApicImpl {
    pub fn new() -> Result<Self, ApicErrors> {
        let info = get_cpu_info();
        let features = info.get_feature_info().ok_or(NoCPUID)?;

        if !features.has_apic() {
            return Err(NotAvailable);
        }
        if !features.has_acpi() {
            return Err(NoACPI);
        }

        let model = ACPI_TABLES.get_interrupt_model().ok_or(BadInterruptModel)?;
        let lapic =
            Lapic::new(PhysAddr::new(model.local_apic_address)).map_err(|_| BadInterruptModel)?;
        let ioapic = Ioapic::new(PhysAddr::new(model.io_apics[0].address as u64))
            .map_err(|_| BadInterruptModel)?;

        Ok(Self {
            apic_info: model,
            lapic,
            ioapic,
        })
    }
    pub fn init_apic_full() -> Result<(), ApicErrors> {
        use core::sync::atomic::Ordering;
        use x86_64::instructions::interrupts;

        interrupts::disable();

        // Already installed?  Nothing to do.
        if APIC.lock().is_some() {
            interrupts::enable();
            return Err(ApicErrors::AlreadyInit);
        }

        let first_time = !USE_APIC.load(Ordering::SeqCst);

        let apic = ApicImpl::new()?;

        unsafe {
            if apic.apic_info.also_has_legacy_pics {
                PICS.lock().disable();
            }

            let logical_id = get_current_logical_id();
            apic.lapic.init(logical_id);
            apic.lapic.init_timer();

            if first_time {
                apic.ioapic.init_keyboard();
            }
            APIC.lock().replace(apic);
            USE_APIC.store(true, Ordering::SeqCst);
        }

        interrupts::enable();
        Ok(())
    }

    pub fn end_interrupt(&self) {
        self.lapic.end_interrupt();
    }

    pub fn start_aps(&self) {
        identity_map_page(
            PhysAddr::new(0x6000),
            0x3000,
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_CACHE,
        )
        .expect("map low RAM");

        const GDT_PHYS: u64 = 0x6000;
        static GDT: [u64; 3] = [0, 0x00AF_9A00_0000_FFFF, 0x00AF_9200_0000_FFFF];
        unsafe {
            ptr::copy_nonoverlapping(
                GDT.as_ptr() as *const u8,
                GDT_PHYS as *mut u8,
                mem::size_of_val(&GDT),
            );
        }
        let gdtr = DescriptorTablePointer {
            base: VirtAddr::new(GDT_PHYS),
            limit: (mem::size_of::<[u64; 3]>() - 1) as u16,
        };
        let longmode_gdt = sgdt();

        let apics = ACPI_TABLES
            .get_plat_info()
            .expect("bad interrupt model")
            .processor_info
            .expect("bad interrupt model")
            .application_processors;

        for (idx, apic) in apics.iter().enumerate() {
            let tramp_phys = PhysAddr::new(TRAMPOLINE_BASE);
            unsafe {
                ptr::copy_nonoverlapping(
                    AP_STARTUP_CODE.as_ptr(),
                    tramp_phys.as_u64() as *mut u8,
                    AP_STARTUP_CODE.len(),
                );
            }
            unsafe {
                let info = tramp_phys.as_u64() as *mut u8;

                let (frame, _flags): (PhysFrame, u16) = Cr3::read_raw();
                ptr::write_unaligned(
                    info.add(PAGEMAP_OFF) as *mut u64,
                    frame.start_address().as_u64(),
                );

                ptr::write_unaligned(info.add(GDTR_LIMIT_OFF) as *mut u16, gdtr.limit);
                ptr::write_unaligned(info.add(GDTR_BASE_OFF) as *mut u64, gdtr.base.as_u64());

                ptr::write_unaligned(info.add(TEMP_STACK_OFF) as *mut u32, 0x7000u32);

                let stack_top = allocate_kernel_stack(AP_STACK_SIZE as u64)
                    .expect("AP stack")
                    .as_u64();
                ptr::write_unaligned(info.add(START_STACK_OFF) as *mut u64, stack_top);

                ptr::write_unaligned(info.add(START_ADDR_OFF) as *mut u64, ap_startup as u64);
                ptr::write_unaligned(
                    info.add(LONGMODE_GDTR_LIMIT_OFF) as *mut u16,
                    longmode_gdt.limit,
                );
                ptr::write_unaligned(
                    info.add(LONGMODE_GDTR_BASE_OFF) as *mut u64,
                    longmode_gdt.base.as_u64(),
                );
            }

            unsafe {
                self.lapic.send_ipi(apic.local_apic_id as u8, IpiKind::Init);
                wait_millis(10);

                self.lapic.send_ipi(
                    apic.local_apic_id as u8,
                    IpiKind::Startup {
                        vector_phys_addr: tramp_phys,
                    },
                );
                wait_millis(1);
            }
        }
        //TODO: properly wait for all cpus to finish
        wait_millis(100);
        unmap_range(VirtAddr::new(0x6000), 0x3000);
    }
}

extern "C" fn ap_startup() -> ! {
    CORE_LOCK.fetch_add(1, Ordering::SeqCst);
    INIT_LOCK.lock();
    {
        unsafe { PER_CPU_GDT.lock().init_gdt() };
        println!("gdt init");
        IDT.load();
        println!("idt load");

        unsafe {
            APIC.lock()
                .as_ref()
                .unwrap()
                .lapic
                .init(get_current_logical_id())
        };
        x86_64::instructions::interrupts::enable();
    }
    CORE_LOCK.fetch_sub(1, Ordering::SeqCst);
    while (!KERNEL_INITIALIZED.load(Ordering::SeqCst)) {}

    loop {

        //TODO: Set to same gdt, idt, and scheduler as the BSP
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
pub enum IpiKind {
    Init,
    Startup { vector_phys_addr: PhysAddr },
}
