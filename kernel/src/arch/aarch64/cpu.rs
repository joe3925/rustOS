use alloc::vec::Vec;
use core::arch::{asm, global_asm};
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use aarch64_cpu::asm::barrier::{ISH, SY, dsb, isb};
use aarch64_cpu::asm::wfi;
use aarch64_cpu::registers::{
    CNTFRQ_EL0, CNTVCT_EL0, MPIDR_EL1, PAR_EL1, Readable, SCTLR_EL1, TPIDR_EL1, Writeable,
};
use kernel_types::irq::PlatformCpuId;

use crate::machine::{PsciConduit, machine_info};
use crate::memory::paging::stack::{StackSize, allocate_kernel_stack};
use crate::platform::{CpuPlatform, CpuStartupError};
use crate::scheduling::scheduler::SCHEDULER;
use crate::structs::per_cpu::{PerCpu, alloc_or_get_percpu};
use crate::util::{CORE_LOCK, INIT_LOCK, KERNEL_INITIALIZED};

use super::platform::Aarch64Platform;

const MPIDR_AFFINITY_MASK: u64 = 0x0000_00ff_00ff_ffff;
const PSCI_CPU_ON_AARCH64: u64 = 0xc400_0003;
const AP_START_TIMEOUT_SECONDS: u64 = 1;
const TCR_T0SZ_MASK: u64 = 0x3f;
const TCR_EPD0: u64 = 1 << 7;
const TCR_IRGN0_MASK: u64 = 0x3 << 8;
const TCR_ORGN0_MASK: u64 = 0x3 << 10;
const TCR_SH0_MASK: u64 = 0x3 << 12;
const TCR_TG0_MASK: u64 = 0x3 << 14;
const TABLE_DESCRIPTOR: u64 = 0b11;
const BLOCK_DESCRIPTOR: u64 = 0b01;
const BLOCK_ACCESS_FLAG: u64 = 1 << 10;
const BLOCK_INNER_SHAREABLE: u64 = 0b11 << 8;
const TWO_MIB: u64 = 2 * 1024 * 1024;

#[thread_local]
static mut EXECUTOR_TASK_ID: u64 = 0;
#[thread_local]
static mut EXECUTOR_DOMAIN_ID: u64 = 0;

static ONLINE_CPU_COUNT: AtomicUsize = AtomicUsize::new(0);
static ONLINE_CPU_BITS: [AtomicU64; 4] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
static AP_HANDSHAKE_BITS: [AtomicU64; 4] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

#[repr(C, align(4096))]
struct StartupTable([u64; 512]);

#[repr(C)]
struct ApStartupRecord {
    ttbr0_el1: u64,
    ttbr1_el1: u64,
    tcr_el1: u64,
    mair_el1: u64,
    sctlr_el1: u64,
    stack_top: u64,
    entry_point: u64,
    cpu_id: u64,
}

#[repr(C, align(64))]
struct SharedStartupRecord(core::cell::UnsafeCell<ApStartupRecord>);

unsafe impl Sync for SharedStartupRecord {}

static mut AP_TTBR0_L0: StartupTable = StartupTable([0; 512]);
static mut AP_TTBR0_L1: StartupTable = StartupTable([0; 512]);
static mut AP_TTBR0_L2: StartupTable = StartupTable([0; 512]);
static AP_STARTUP_RECORD: SharedStartupRecord =
    SharedStartupRecord(core::cell::UnsafeCell::new(ApStartupRecord {
        ttbr0_el1: 0,
        ttbr1_el1: 0,
        tcr_el1: 0,
        mair_el1: 0,
        sctlr_el1: 0,
        stack_top: 0,
        entry_point: 0,
        cpu_id: 0,
    }));

global_asm!(
    ".global aarch64_ap_trampoline_start",
    ".global aarch64_ap_trampoline_end",
    "aarch64_ap_trampoline_start:",
    "ldr x9, [x0, #0]",
    "ldr x10, [x0, #8]",
    "ldr x11, [x0, #16]",
    "ldr x12, [x0, #24]",
    "ldr x13, [x0, #32]",
    "ldr x14, [x0, #40]",
    "ldr x15, [x0, #48]",
    "ldr x16, [x0, #56]",
    "msr daifset, #0xf",
    "msr mair_el1, x12",
    "msr ttbr0_el1, x9",
    "msr ttbr1_el1, x10",
    "msr tcr_el1, x11",
    "dsb sy",
    "tlbi vmalle1",
    "dsb sy",
    "isb",
    "msr sctlr_el1, x13",
    "isb",
    "mov sp, x14",
    "mov x0, x16",
    "br x15",
    "aarch64_ap_trampoline_end:",
);

unsafe extern "C" {
    static aarch64_ap_trampoline_start: u8;
    static aarch64_ap_trampoline_end: u8;
}

pub(crate) const fn normalize_mpidr(value: u64) -> u64 {
    value & MPIDR_AFFINITY_MASK
}

pub(crate) fn current_hardware_id() -> u64 {
    normalize_mpidr(MPIDR_EL1.get())
}

#[inline(always)]
unsafe fn set_per_cpu(ptr: *const PerCpu) {
    TPIDR_EL1.set(ptr as u64);
    unsafe {
        asm!(
            "mov x18, {ptr}",
            ptr = in(reg) ptr,
            options(nostack, preserves_flags)
        );
    }
}

#[inline(always)]
fn per_cpu_ptr() -> *const PerCpu {
    TPIDR_EL1.get() as *const PerCpu
}

fn mark_online(cpu_id: usize) {
    let word = cpu_id / 64;
    let bit = 1u64 << (cpu_id % 64);
    let previous = ONLINE_CPU_BITS[word].fetch_or(bit, Ordering::AcqRel);
    if previous & bit == 0 {
        ONLINE_CPU_COUNT.fetch_add(1, Ordering::AcqRel);
    }
}

fn mark_handshake(cpu_id: usize) {
    AP_HANDSHAKE_BITS[cpu_id / 64].fetch_or(1u64 << (cpu_id % 64), Ordering::Release);
}

fn handshake_complete(cpu_id: usize) -> bool {
    AP_HANDSHAKE_BITS[cpu_id / 64].load(Ordering::Acquire) & (1u64 << (cpu_id % 64)) != 0
}

impl CpuPlatform for Aarch64Platform {
    type PerCpuState = PerCpu;

    const MAX_CPUS: usize = 256;

    fn current_cpu_id() -> usize {
        *Self::current_percpu()
            .cpu_id
            .get()
            .expect("current CPU has no dense ID")
    }

    fn current_platform_cpu_id() -> PlatformCpuId {
        *Self::current_percpu()
            .platform_cpu_id
            .get()
            .expect("current CPU has no platform ID")
    }

    fn platform_cpu_ids() -> Vec<PlatformCpuId> {
        machine_info()
            .cpu_topology()
            .processors
            .iter()
            .map(|processor| processor.platform_cpu_id)
            .collect()
    }

    fn processor_count() -> usize {
        ONLINE_CPU_COUNT.load(Ordering::Acquire)
    }

    fn init_current_cpu_local_state(cpu_id: usize) {
        assert!(cpu_id < Self::MAX_CPUS);
        let hardware_id = current_hardware_id();
        let processor = machine_info()
            .cpu_topology()
            .processors
            .iter()
            .find(|processor| processor.hardware_id == hardware_id)
            .expect("current CPU is absent from firmware topology");
        assert_eq!(processor.cpu_id, cpu_id);
        let percpu = alloc_or_get_percpu(cpu_id, processor.platform_cpu_id);
        percpu.tls_array_pointer.store(0, Ordering::Relaxed);
        unsafe { set_per_cpu(percpu as *const PerCpu) };
        super::interrupts::init_current_cpu_interrupts();
        mark_online(cpu_id);
    }

    fn current_percpu() -> &'static Self::PerCpuState {
        let ptr = per_cpu_ptr();
        assert!(!ptr.is_null());
        unsafe { &*ptr }
    }

    fn swap_executor_context(task_id: u64, domain_id: u64) -> (u64, u64) {
        unsafe {
            let previous = (EXECUTOR_TASK_ID, EXECUTOR_DOMAIN_ID);
            EXECUTOR_TASK_ID = task_id;
            EXECUTOR_DOMAIN_ID = domain_id;
            previous
        }
    }

    fn current_executor_context() -> (u64, u64) {
        unsafe { (EXECUTOR_TASK_ID, EXECUTOR_DOMAIN_ID) }
    }

    fn start_secondary_cpus() -> Result<(), CpuStartupError> {
        let topology = machine_info().cpu_topology();
        if topology.processors.len() <= 1 {
            return Ok(());
        }
        let conduit = topology.psci_conduit.ok_or(CpuStartupError {
            platform_cpu_id: None,
            reason: "firmware does not provide PSCI",
            status: -1,
        })?;
        let trampoline_virt = unsafe { &aarch64_ap_trampoline_start as *const u8 as u64 };
        let trampoline_end = unsafe { &aarch64_ap_trampoline_end as *const u8 as u64 };
        let trampoline_phys = physical_address(trampoline_virt)?;
        let record_virt = AP_STARTUP_RECORD.0.get() as u64;
        let record_phys = physical_address(record_virt)?;
        prepare_identity_translation(trampoline_phys)?;
        for processor in topology
            .processors
            .iter()
            .filter(|processor| !processor.is_boot_processor)
        {
            let stack_top =
                allocate_kernel_stack(StackSize::Medium).map_err(|_| CpuStartupError {
                    platform_cpu_id: Some(processor.platform_cpu_id),
                    reason: "secondary CPU stack allocation failed",
                    status: -1,
                })?;
            let boot = crate::util::boot_info();
            unsafe {
                AP_STARTUP_RECORD.0.get().write(ApStartupRecord {
                    ttbr0_el1: physical_address(core::ptr::addr_of!(AP_TTBR0_L0) as u64)?,
                    ttbr1_el1: boot.arch_info.ttbr1_el1,
                    tcr_el1: startup_tcr(boot.arch_info.tcr_el1),
                    mair_el1: boot.arch_info.mair_el1,
                    sctlr_el1: current_sctlr() | 1 | (1 << 2) | (1 << 12),
                    stack_top: stack_top.as_u64(),
                    entry_point: aarch64_secondary_entry as *const () as u64,
                    cpu_id: processor.cpu_id as u64,
                });
            }
            clean_to_poc(record_virt, core::mem::size_of::<ApStartupRecord>());
            synchronize_instruction_range(
                trampoline_virt,
                trampoline_end.saturating_sub(trampoline_virt) as usize,
            );
            let status = psci_cpu_on(conduit, processor.hardware_id, trampoline_phys, record_phys);
            if status != 0 {
                return Err(CpuStartupError {
                    platform_cpu_id: Some(processor.platform_cpu_id),
                    reason: "PSCI CPU_ON failed",
                    status,
                });
            }
            wait_for_handshake(processor.cpu_id, processor.platform_cpu_id)?;
            crate::println!(
                "AArch64 CPU {} with platform ID {} and MPIDR {:#x} is online",
                processor.cpu_id,
                processor.platform_cpu_id,
                processor.hardware_id
            );
        }
        crate::println!(
            "AArch64 started {} secondary CPUs",
            topology.processors.len() - 1
        );
        Ok(())
    }

    fn halt() -> ! {
        super::debug::init_debug_metadata_transport();
        unsafe {
            asm!(
                "msr daifset, #0xf",
                options(nomem, nostack, preserves_flags)
            );
            loop {
                super::debug::poll_rx_once();
                wfi();
            }
        }
    }
}

fn physical_address(virtual_address: u64) -> Result<u64, CpuStartupError> {
    unsafe {
        asm!(
            "at s1e1r, {address}",
            address = in(reg) virtual_address,
            options(nostack, preserves_flags)
        );
    }
    isb(SY);
    let par = PAR_EL1.get();
    if par & 1 != 0 {
        Err(CpuStartupError {
            platform_cpu_id: None,
            reason: "secondary CPU startup object is not mapped",
            status: -1,
        })
    } else {
        let output_bits = crate::util::boot_info().arch_info.output_addr_bits.min(52);
        if output_bits < 32 {
            return Err(CpuStartupError {
                platform_cpu_id: None,
                reason: "AArch64 output address size is invalid",
                status: -1,
            });
        }
        let address_mask = ((1u64 << output_bits) - 1) & !0xfff;
        Ok((par & address_mask) | (virtual_address & 0xfff))
    }
}

fn startup_tcr(value: u64) -> u64 {
    let clear =
        TCR_T0SZ_MASK | TCR_EPD0 | TCR_IRGN0_MASK | TCR_ORGN0_MASK | TCR_SH0_MASK | TCR_TG0_MASK;
    (value & !clear) | 16 | (1 << 8) | (1 << 10) | (0b11 << 12)
}

fn current_sctlr() -> u64 {
    SCTLR_EL1.get()
}

fn prepare_identity_translation(entry_phys: u64) -> Result<(), CpuStartupError> {
    if entry_phys >= 1u64 << 48 {
        return Err(CpuStartupError {
            platform_cpu_id: None,
            reason: "secondary CPU entry exceeds the identity address range",
            status: -1,
        });
    }
    let l1_phys = physical_address(core::ptr::addr_of!(AP_TTBR0_L1) as u64)?;
    let l2_phys = physical_address(core::ptr::addr_of!(AP_TTBR0_L2) as u64)?;
    let l0_index = ((entry_phys >> 39) & 0x1ff) as usize;
    let l1_index = ((entry_phys >> 30) & 0x1ff) as usize;
    let l2_index = ((entry_phys >> 21) & 0x1ff) as usize;
    unsafe {
        core::ptr::write_bytes(core::ptr::addr_of_mut!(AP_TTBR0_L0.0).cast::<u8>(), 0, 4096);
        core::ptr::write_bytes(core::ptr::addr_of_mut!(AP_TTBR0_L1.0).cast::<u8>(), 0, 4096);
        core::ptr::write_bytes(core::ptr::addr_of_mut!(AP_TTBR0_L2.0).cast::<u8>(), 0, 4096);
        AP_TTBR0_L0.0[l0_index] = l1_phys | TABLE_DESCRIPTOR;
        AP_TTBR0_L1.0[l1_index] = l2_phys | TABLE_DESCRIPTOR;
        AP_TTBR0_L2.0[l2_index] = (entry_phys & !(TWO_MIB - 1))
            | BLOCK_DESCRIPTOR
            | BLOCK_ACCESS_FLAG
            | BLOCK_INNER_SHAREABLE;
    }
    clean_to_poc(core::ptr::addr_of!(AP_TTBR0_L0) as u64, 4096);
    clean_to_poc(core::ptr::addr_of!(AP_TTBR0_L1) as u64, 4096);
    clean_to_poc(core::ptr::addr_of!(AP_TTBR0_L2) as u64, 4096);
    Ok(())
}

fn psci_cpu_on(conduit: PsciConduit, target: u64, entry: u64, context: u64) -> i64 {
    psci_call(conduit, PSCI_CPU_ON_AARCH64, target, entry, context)
}

pub(crate) fn psci_call(
    conduit: PsciConduit,
    function: u64,
    argument0: u64,
    argument1: u64,
    argument2: u64,
) -> i64 {
    let mut result = function;
    unsafe {
        match conduit {
            PsciConduit::Smc => asm!(
                "smc #0",
                inout("x0") result,
                inlateout("x1") argument0 => _, inlateout("x2") argument1 => _, inlateout("x3") argument2 => _,
                lateout("x4") _, lateout("x5") _, lateout("x6") _, lateout("x7") _,
                lateout("x8") _, lateout("x9") _, lateout("x10") _, lateout("x11") _,
                lateout("x12") _, lateout("x13") _, lateout("x14") _, lateout("x15") _,
                lateout("x16") _, lateout("x17") _, options(nostack)
            ),
            PsciConduit::Hvc => asm!(
                "hvc #0",
                inout("x0") result,
                inlateout("x1") argument0 => _, inlateout("x2") argument1 => _, inlateout("x3") argument2 => _,
                lateout("x4") _, lateout("x5") _, lateout("x6") _, lateout("x7") _,
                lateout("x8") _, lateout("x9") _, lateout("x10") _, lateout("x11") _,
                lateout("x12") _, lateout("x13") _, lateout("x14") _, lateout("x15") _,
                lateout("x16") _, lateout("x17") _, options(nostack)
            ),
        }
    }
    result as i64
}

fn wait_for_handshake(
    cpu_id: usize,
    platform_cpu_id: PlatformCpuId,
) -> Result<(), CpuStartupError> {
    let frequency = CNTFRQ_EL0.get();
    let start = CNTVCT_EL0.get();
    let deadline = start.saturating_add(frequency.saturating_mul(AP_START_TIMEOUT_SECONDS));
    loop {
        if handshake_complete(cpu_id) {
            return Ok(());
        }
        let now = CNTVCT_EL0.get();
        if now >= deadline {
            return Err(CpuStartupError {
                platform_cpu_id: Some(platform_cpu_id),
                reason: "secondary CPU startup timed out",
                status: -1,
            });
        }
        core::hint::spin_loop();
    }
}

fn clean_to_poc(start: u64, length: usize) {
    let line_size = data_cache_line_size();
    let end = start.saturating_add(length as u64);
    let mut address = start & !(line_size - 1);
    unsafe {
        while address < end {
            asm!("dc civac, {address}", address = in(reg) address, options(nostack, preserves_flags));
            address += line_size;
        }
    }
    dsb(SY);
}

fn synchronize_instruction_range(start: u64, length: usize) {
    let data_line = data_cache_line_size();
    let instruction_line = instruction_cache_line_size();
    let end = start.saturating_add(length as u64);
    let mut address = start & !(data_line - 1);
    unsafe {
        while address < end {
            asm!("dc cvau, {address}", address = in(reg) address, options(nostack, preserves_flags));
            address += data_line;
        }
    }
    dsb(ISH);
    address = start & !(instruction_line - 1);
    unsafe {
        while address < end {
            asm!("ic ivau, {address}", address = in(reg) address, options(nostack, preserves_flags));
            address += instruction_line;
        }
    }
    dsb(ISH);
    isb(SY);
}

fn data_cache_line_size() -> u64 {
    let ctr: u64;
    unsafe {
        asm!("mrs {value}, ctr_el0", value = out(reg) ctr, options(nomem, nostack, preserves_flags))
    };
    4u64 << ((ctr >> 16) & 0xf)
}

fn instruction_cache_line_size() -> u64 {
    let ctr: u64;
    unsafe {
        asm!("mrs {value}, ctr_el0", value = out(reg) ctr, options(nomem, nostack, preserves_flags))
    };
    4u64 << (ctr & 0xf)
}

#[unsafe(no_mangle)]
extern "C" fn aarch64_secondary_entry(cpu_id: u64) -> ! {
    let cpu_id = cpu_id as usize;
    <Aarch64Platform as CpuPlatform>::init_current_cpu_local_state(cpu_id);
    CORE_LOCK.fetch_add(1, Ordering::SeqCst);
    mark_handshake(cpu_id);
    {
        let _guard = INIT_LOCK.lock();
        crate::platform::init_periodic_timer();
        SCHEDULER.init_core(cpu_id);
        CORE_LOCK.fetch_sub(1, Ordering::SeqCst);
    }
    while !KERNEL_INITIALIZED.load(Ordering::SeqCst) {
        core::hint::spin_loop();
    }
    crate::platform::enable_interrupts();
    loop {
        crate::platform::enable_interrupts_and_halt();
    }
}
