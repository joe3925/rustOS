use super::cpu::{self, current_cpu_id, init_percpu_gs, platform_cpu_id};
use super::drivers::timer_driver::set_num_cores;
use super::gdt::PER_CPU_GDT;
use super::idt::table::load_idt;
use super::interrupts::apic::controller::{APIC, ApicImpl};
use super::interrupts::apic::local::{IpiDest, IpiKind, LocalApic};
use super::syscalls::syscall::syscall_init;
use super::timer::{
    APIC_START_PERIOD, apic_calibrate_ticks_per_ns_via_wait, apic_program_period_ns,
    duration_to_tsc_cycles,
};
use crate::KERNEL_INITIALIZED;
use crate::memory::paging::stack::{StackSize, allocate_kernel_stack};
use crate::scheduling::scheduler::SCHEDULER;
use crate::util::{CORE_LOCK, CPU_ID, INIT_LOCK, boot_info};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;
use core::{mem, ptr};
use x86_64::instructions::tables::sgdt;
use x86_64::registers::control::Cr3;
use x86_64::structures::DescriptorTablePointer;
use x86_64::structures::paging::{PageTableFlags, PhysFrame};
use x86_64::{PhysAddr, VirtAddr};

static AP_BOOTED: AtomicUsize = AtomicUsize::new(0);

fn wait_for_ap_booted(expected: usize, timeout: Duration) -> bool {
    if AP_BOOTED.load(Ordering::Acquire) >= expected {
        return true;
    }

    let target_delta = duration_to_tsc_cycles(timeout);
    let start = cpu::get_cycles() as u128;

    loop {
        if AP_BOOTED.load(Ordering::Acquire) >= expected {
            return true;
        }

        let elapsed = (cpu::get_cycles() as u128).saturating_sub(start);
        if elapsed >= target_delta {
            return false;
        }

        core::hint::spin_loop();
    }
}

const TRAMPOLINE_BASE: u64 = 0x0000_8000;
const TRAMPOLINE_STEP: u64 = 0x1000;
const TRAMPOLINE_EXPECTED_LEN: usize = 0xE4;
const FOUR_GIB: u64 = 0x1_0000_0000;
const PAGE_SIZE: u64 = 0x1000;
const AP_STACK_SIZE: usize = (2 * 1024 * 1024) - 0x1000;

const PAGEMAP_OFF: usize = 0x08;
const GDTR_LIMIT_OFF: usize = 0x10;
const GDTR_BASE_OFF: usize = 0x12;
const TEMP_STACK_OFF: usize = 0x1A;
const START_STACK_OFF: usize = 0x1E;
const START_ADDR_OFF: usize = 0x26;
const LONGMODE_GDTR_LIMIT_OFF: usize = 0x2E;
const LONGMODE_GDTR_BASE_OFF: usize = 0x30;
const TRAMPOLINE_DATA_END: usize = LONGMODE_GDTR_BASE_OFF + mem::size_of::<u64>();
core::arch::global_asm!(include_str!("ap_startup.s"));

fn virt_to_phys(addr: VirtAddr) -> Option<(u64, PhysAddr)> {
    crate::memory::paging::map::virt_to_phys(addr.into()).map(|(size, phys)| (size, phys.into()))
}

unsafe extern "C" {
    static trampoline: u8;
    static trampoline_end: u8;
}

pub fn trampoline_blob() -> &'static [u8] {
    let start = core::ptr::addr_of!(trampoline) as *const u8;
    let end = core::ptr::addr_of!(trampoline_end) as *const u8;

    let len = unsafe { end.offset_from(start) as usize };
    unsafe { core::slice::from_raw_parts(start, len) }
}
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

#[derive(Debug, Copy, Clone)]
struct TrampolinePatch {
    pagemap: u64,
    gdtr_limit: u16,
    gdtr_base: u64,
    temp_stack: u32,
    start_stack: u64,
    start_address: u64,
    longmode_gdtr_limit: u16,
    longmode_gdtr_base: u64,
}

fn verify_trampoline_static_layout(code: &[u8]) {
    assert_eq!(
        code.len(),
        TRAMPOLINE_EXPECTED_LEN,
        "AP trampoline blob size changed"
    );
    assert_eq!(PAGEMAP_OFF, 0x08);
    assert_eq!(GDTR_LIMIT_OFF, 0x10);
    assert_eq!(GDTR_BASE_OFF, 0x12);
    assert_eq!(TEMP_STACK_OFF, 0x1A);
    assert_eq!(START_STACK_OFF, 0x1E);
    assert_eq!(START_ADDR_OFF, 0x26);
    assert_eq!(LONGMODE_GDTR_LIMIT_OFF, 0x2E);
    assert_eq!(LONGMODE_GDTR_BASE_OFF, 0x30);
    assert_eq!(
        TRAMPOLINE_DATA_END - PAGEMAP_OFF,
        mem::size_of::<PassedInfo>()
    );
    assert_eq!(
        PAGEMAP_OFF + core::mem::offset_of!(PassedInfo, pagemap),
        PAGEMAP_OFF
    );
    assert_eq!(
        PAGEMAP_OFF + core::mem::offset_of!(PassedInfo, gdtr_limit),
        GDTR_LIMIT_OFF
    );
    assert_eq!(
        PAGEMAP_OFF + core::mem::offset_of!(PassedInfo, gdtr_base),
        GDTR_BASE_OFF
    );
    assert_eq!(
        PAGEMAP_OFF + core::mem::offset_of!(PassedInfo, temp_stack),
        TEMP_STACK_OFF
    );
    assert_eq!(
        PAGEMAP_OFF + core::mem::offset_of!(PassedInfo, start_stack),
        START_STACK_OFF
    );
    assert_eq!(
        PAGEMAP_OFF + core::mem::offset_of!(PassedInfo, start_address),
        START_ADDR_OFF
    );
    assert_eq!(
        PAGEMAP_OFF + core::mem::offset_of!(PassedInfo, longmode_gdtr_limit),
        LONGMODE_GDTR_LIMIT_OFF
    );
    assert_eq!(
        PAGEMAP_OFF + core::mem::offset_of!(PassedInfo, longmode_gdtr_base),
        LONGMODE_GDTR_BASE_OFF
    );
}

fn verify_trampoline_installed(code: &[u8]) {
    verify_trampoline_bytes(code, 0, code.len());
}

fn verify_kernel_image_mapped() {
    let boot = boot_info();
    let base = boot.kernel_image_base;
    let size = boot.kernel_image_size;
    let entry = boot.kernel_entry;
    assert!(base != 0, "kernel PE image base is not recorded");
    assert!(size != 0, "kernel PE image size is not recorded");
    let end = base
        .checked_add(size)
        .expect("kernel PE image range overflow");

    assert!(
        entry >= base && entry < end,
        "kernel PE entry address {:#x} is outside mapped image {:#x}..{:#x}",
        entry,
        base,
        end
    );
    assert!(
        virt_to_phys(VirtAddr::new(entry)).is_some(),
        "kernel PE entry address is not mapped in the AP page table"
    );

    let mut addr = base & !(PAGE_SIZE - 1);
    while addr < end {
        assert!(
            virt_to_phys(VirtAddr::new(addr)).is_some(),
            "kernel PE image page {:#x} is not mapped in the AP page table",
            addr
        );
        addr = addr
            .checked_add(PAGE_SIZE)
            .expect("kernel image walk overflow");
    }
}

fn verify_patched_trampoline(code: &[u8], patch: TrampolinePatch) {
    verify_trampoline_bytes(code, 0, PAGEMAP_OFF);
    verify_trampoline_bytes(code, TRAMPOLINE_DATA_END, code.len());

    assert_eq!(read_trampoline_u64(PAGEMAP_OFF), patch.pagemap);
    assert_eq!(read_trampoline_u16(GDTR_LIMIT_OFF), patch.gdtr_limit);
    assert_eq!(read_trampoline_u64(GDTR_BASE_OFF), patch.gdtr_base);
    assert_eq!(read_trampoline_u32(TEMP_STACK_OFF), patch.temp_stack);
    assert_eq!(read_trampoline_u64(START_STACK_OFF), patch.start_stack);
    assert_eq!(read_trampoline_u64(START_ADDR_OFF), patch.start_address);
    assert_eq!(
        read_trampoline_u16(LONGMODE_GDTR_LIMIT_OFF),
        patch.longmode_gdtr_limit
    );
    assert_eq!(
        read_trampoline_u64(LONGMODE_GDTR_BASE_OFF),
        patch.longmode_gdtr_base
    );
}

fn verify_trampoline_bytes(code: &[u8], start: usize, end: usize) {
    let mut idx = start;
    while idx < end {
        let actual = unsafe { ptr::read_volatile((TRAMPOLINE_BASE as *const u8).add(idx)) };
        assert_eq!(
            actual,
            code[idx],
            "AP trampoline byte mismatch at physical {:#x}",
            TRAMPOLINE_BASE + idx as u64
        );
        idx += 1;
    }
}

fn read_trampoline_u16(offset: usize) -> u16 {
    unsafe { ptr::read_unaligned((TRAMPOLINE_BASE as *const u8).add(offset) as *const u16) }
}

fn read_trampoline_u32(offset: usize) -> u32 {
    unsafe { ptr::read_unaligned((TRAMPOLINE_BASE as *const u8).add(offset) as *const u32) }
}

fn read_trampoline_u64(offset: usize) -> u64 {
    unsafe { ptr::read_unaligned((TRAMPOLINE_BASE as *const u8).add(offset) as *const u64) }
}

impl ApicImpl {
    pub fn start_aps(&self) {
        let topology = crate::machine::machine_info().cpu_topology();
        let apics: Vec<_> = topology
            .processors
            .iter()
            .filter(|processor| !processor.is_boot_processor)
            .copied()
            .collect();

        let ap_count = apics.len();
        set_num_cores(ap_count + 1);

        if ap_count == 0 {
            return;
        }

        // Reset boot tracker in case this is invoked again.
        AP_BOOTED.store(0, Ordering::SeqCst);

        let code = trampoline_blob();
        verify_trampoline_static_layout(code);
        assert!(code.len() <= TRAMPOLINE_STEP as usize);

        const GDT_PHYS: u64 = 0x6000;
        static GDT: [u64; 3] = [0, 0x00AF_9A00_0000_FFFF, 0x00AF_9200_0000_FFFF];

        let map_start = GDT_PHYS;
        // Single trampoline at 0x8000 reused per AP.
        let map_end = TRAMPOLINE_BASE + TRAMPOLINE_STEP;
        let mut map_len = (map_end - map_start) as usize;
        map_len = (map_len + 0x0FFF) & !0x0FFF;

        unsafe {
            crate::memory::paging::map::identity_map_page(
                PhysAddr::new(map_start).into(),
                map_len as usize,
                (PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_CACHE)
                    .into(),
            )
            .expect("map low RAM");
        }

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
        assert!(
            virt_to_phys(longmode_gdt.base).is_some(),
            "AP long-mode GDTR base is not mapped in the AP page table"
        );
        verify_kernel_image_mapped();

        // Install trampoline code once at the fixed address.
        unsafe {
            ptr::copy_nonoverlapping(code.as_ptr(), TRAMPOLINE_BASE as *mut u8, code.len());
        }
        verify_trampoline_installed(code);

        for apic in apics.iter() {
            let tramp_u64 = TRAMPOLINE_BASE;
            let tramp_phys = PhysAddr::new(tramp_u64);

            unsafe {
                let info = tramp_u64 as *mut u8;

                let (frame, _flags): (PhysFrame, u16) = Cr3::read_raw();
                let pagemap = frame.start_address().as_u64();
                assert!(
                    pagemap < FOUR_GIB,
                    "AP trampoline CR3 address {:#x} does not fit in mov cr3, eax",
                    pagemap
                );

                let temp_sp = (tramp_u64 + TRAMPOLINE_STEP - 0x10) as u32;
                assert!(
                    temp_sp <= u16::MAX as u32,
                    "AP real-mode temporary stack does not fit in 16-bit SP"
                );

                let stack_top = allocate_kernel_stack(StackSize::Medium)
                    .expect("AP stack")
                    .as_u64();
                assert!(stack_top != 0, "AP stack top is null");
                assert!(
                    virt_to_phys(VirtAddr::new(stack_top - 1)).is_some(),
                    "AP stack is not mapped in the AP page table"
                );

                let start_address = ap_startup as *const () as u64;
                assert!(
                    virt_to_phys(VirtAddr::new(start_address)).is_some(),
                    "AP entry address is not mapped in the AP page table"
                );

                let patch = TrampolinePatch {
                    pagemap,
                    gdtr_limit: gdtr.limit,
                    gdtr_base: gdtr.base.as_u64(),
                    temp_stack: temp_sp,
                    start_stack: stack_top,
                    start_address,
                    longmode_gdtr_limit: longmode_gdt.limit,
                    longmode_gdtr_base: longmode_gdt.base.as_u64(),
                };

                ptr::write_unaligned(info.add(PAGEMAP_OFF) as *mut u64, patch.pagemap);
                ptr::write_unaligned(info.add(GDTR_LIMIT_OFF) as *mut u16, patch.gdtr_limit);
                ptr::write_unaligned(info.add(GDTR_BASE_OFF) as *mut u64, patch.gdtr_base);
                ptr::write_unaligned(info.add(TEMP_STACK_OFF) as *mut u32, patch.temp_stack);
                ptr::write_unaligned(info.add(START_STACK_OFF) as *mut u64, patch.start_stack);
                ptr::write_unaligned(info.add(START_ADDR_OFF) as *mut u64, patch.start_address);
                ptr::write_unaligned(
                    info.add(LONGMODE_GDTR_LIMIT_OFF) as *mut u16,
                    patch.longmode_gdtr_limit,
                );
                ptr::write_unaligned(
                    info.add(LONGMODE_GDTR_BASE_OFF) as *mut u64,
                    patch.longmode_gdtr_base,
                );

                verify_patched_trampoline(code, patch);
            }

            unsafe {
                let dst = IpiDest::ApicId(apic.platform_cpu_id as u8);
                let expected = AP_BOOTED.load(Ordering::SeqCst) + 1;

                self.lapic.send_ipi(dst, IpiKind::InitAssert);
                self.lapic.wait_for_delivery();

                self.lapic.send_ipi(dst, IpiKind::InitDeassert);
                self.lapic.wait_for_delivery();

                self.lapic.send_ipi(
                    dst,
                    IpiKind::Startup {
                        vector_phys_addr: tramp_phys,
                    },
                );
                self.lapic.wait_for_delivery();

                if !wait_for_ap_booted(expected, Duration::from_millis(1)) {
                    self.lapic.send_ipi(
                        dst,
                        IpiKind::Startup {
                            vector_phys_addr: tramp_phys,
                        },
                    );
                    self.lapic.wait_for_delivery();
                }

                assert!(
                    wait_for_ap_booted(expected, Duration::from_millis(100)),
                    "AP with platform CPU id {} did not reach ap_startup",
                    apic.platform_cpu_id
                );
            }
        }

        unsafe {
            crate::memory::paging::map::unmap_range(VirtAddr::new(map_start).into(), map_len as u64)
        };
    }
}

extern "C" fn ap_startup() -> ! {
    cpu::enable_sse();
    CORE_LOCK.fetch_add(1, Ordering::SeqCst);
    // Signal that this AP is past the trampoline and safe to reuse it.
    // CORE_LOCK is already raised so the BSP cannot miss this AP before it
    // finishes serialized core initialization.
    AP_BOOTED.fetch_add(1, Ordering::SeqCst);
    {
        let _g = INIT_LOCK.lock();

        unsafe { PER_CPU_GDT.lock().init_gdt() };
        load_idt();

        let lapic_id = platform_cpu_id() as u32;
        init_percpu_gs(CPU_ID.fetch_add(1, Ordering::Acquire));

        unsafe {
            let mut guard = APIC.lock();
            if let Some(apic) = guard.as_mut() {
                apic.lapic.init(lapic_id as u8);
                apic.lapic.init_timer();
            }
        }

        syscall_init();
        // Register while still holding the lock that assigned this CPU's ID.
        // Scheduler storage requires contiguous insertion order; calibration
        // can finish in a different order on each AP.
        SCHEDULER.init_core(current_cpu_id());
    }
    // Timer storage was allocated for all CPUs before AP startup. Each AP
    // measures its own local timer without holding up the other APs.
    apic_calibrate_ticks_per_ns_via_wait(10);
    apic_program_period_ns(APIC_START_PERIOD);
    CORE_LOCK.fetch_sub(1, Ordering::SeqCst);

    while !KERNEL_INITIALIZED.load(Ordering::SeqCst) {
        core::hint::spin_loop()
    }
    x86_64::instructions::interrupts::enable();
    loop {
        x86_64::instructions::hlt();
    }
}
