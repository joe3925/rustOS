use core::arch::asm;

use aarch64_cpu::asm::barrier::{SY, dsb, isb};
use kernel_types::arch::PhysAddr;
use kernel_types::irq::PlatformCpuId;
use kernel_types::memory::PhysicalMappingCache;
use spin::Mutex;

use crate::machine::machine_info;
use crate::memory::paging::mmio::map_physical_pages;

use super::controller::{
    PANIC_STOP_SGI, SCHEDULER_SGI, SPI_END, SPI_START, TLB_SHOOTDOWN_SGI, VIRTUAL_TIMER_PPI,
};
use super::discovery::GicDescription;
use super::entry::InterruptToken;

pub(crate) struct GicV3 {
    distributor: usize,
    redistributor: usize,
    redistributor_size: usize,
    distributor_lock: Mutex<()>,
}

unsafe impl Send for GicV3 {}
unsafe impl Sync for GicV3 {}

impl GicV3 {
    pub(crate) fn new(description: GicDescription) -> Self {
        let distributor = map_physical_pages(
            PhysAddr::new(description.distributor),
            0x1_0000,
            PhysicalMappingCache::Uncached,
        )
        .expect("failed to map GICv3 distributor");
        let redistributor = map_physical_pages(
            PhysAddr::new(description.redistributor),
            description.redistributor_size,
            PhysicalMappingCache::Uncached,
        )
        .expect("failed to map GICv3 redistributor range");
        Self {
            distributor: distributor.as_u64() as usize,
            redistributor: redistributor.as_u64() as usize,
            redistributor_size: description.redistributor_size as usize,
            distributor_lock: Mutex::new(()),
        }
    }

    pub(crate) fn init_distributor(&self) {
        let _lock = self.distributor_lock.lock();
        unsafe {
            self.write32(0, 0);
            self.wait_rwp();
            let lines = (((self.read32(4) & 0x1f) + 1) * 32).min(256);
            for intid in (SPI_START as u32..lines).step_by(32) {
                self.write32(0x80 + intid / 8, u32::MAX);
                self.write32(0x180 + intid / 8, u32::MAX);
            }
            for intid in SPI_START as u32..lines {
                self.write8(0x400 + intid, 0xa0);
                self.write64(0x6100 + (intid - 32) * 8, current_route_affinity());
            }
            self.write32(0, (1 << 4) | (1 << 1));
            self.wait_rwp();
        }
        dsb(SY);
        isb(SY);
    }

    pub(super) fn init_current_cpu(&self) {
        let frame = self.current_redistributor();
        unsafe {
            let waker = (frame + 0x14) as *mut u32;
            waker.write_volatile(waker.read_volatile() & !(1 << 1));
            while waker.read_volatile() & (1 << 2) != 0 {
                core::hint::spin_loop();
            }
            let sgi = frame + 0x1_0000;
            ((sgi + 0x80) as *mut u32).write_volatile(u32::MAX);
            ((sgi + 0x180) as *mut u32).write_volatile(u32::MAX);
            for intid in 0..32 {
                ((sgi + 0x400 + intid) as *mut u8).write_volatile(0xa0);
            }
            ((sgi + 0x100) as *mut u32).write_volatile(
                (1 << SCHEDULER_SGI)
                    | (1 << TLB_SHOOTDOWN_SGI)
                    | (1 << PANIC_STOP_SGI)
                    | (1 << VIRTUAL_TIMER_PPI),
            );
            write_icc_sre_el1(read_icc_sre_el1() | 1);
            isb(SY);
            write_icc_pmr_el1(0xff);
            write_icc_bpr1_el1(0);
            write_icc_igrpen1_el1(1);
        }
        dsb(SY);
        isb(SY);
    }

    pub(super) fn acknowledge(&self) -> Option<InterruptToken> {
        let raw = unsafe { read_icc_iar1_el1() };
        let intid = raw & 0x00ff_ffff;
        if intid >= 1020 {
            return None;
        }
        Some(InterruptToken {
            raw,
            interrupt_id: intid,
        })
    }

    pub(super) fn end_interrupt(&self, token: InterruptToken) {
        unsafe { write_icc_eoir1_el1(token.raw) };
        isb(SY);
    }

    pub(super) fn send_ipi(&self, target: PlatformCpuId, vector: u8) -> bool {
        if vector >= 16 {
            return false;
        }
        let Some(processor) = machine_info()
            .cpu_topology()
            .processors
            .iter()
            .find(|processor| processor.platform_cpu_id == target)
        else {
            return false;
        };
        let mpidr = processor.hardware_id;
        let aff0 = mpidr & 0xff;
        if aff0 >= 16 {
            return false;
        }
        let value = ((mpidr >> 32) & 0xff) << 48
            | ((mpidr >> 16) & 0xff) << 32
            | ((mpidr >> 8) & 0xff) << 16
            | (vector as u64) << 24
            | 1 << aff0;
        unsafe { write_icc_sgi1r_el1(value) };
        isb(SY);
        true
    }

    pub(super) fn broadcast_ipi(&self, vector: u8) {
        if vector < 16 {
            unsafe { write_icc_sgi1r_el1((vector as u64) << 24 | 1 << 40) };
            isb(SY);
        }
    }

    pub(super) fn unmask_spi(&self, intid: u32) {
        assert!((SPI_START..=SPI_END).contains(&intid));
        let _lock = self.distributor_lock.lock();
        unsafe {
            self.write64(0x6100 + (intid as u32 - 32) * 8, current_route_affinity());
            self.write32(0x100 + (intid as u32 / 32) * 4, 1 << (intid % 32));
            self.wait_rwp();
        }
        dsb(SY);
    }

    pub(super) fn mask_spi(&self, intid: u32) {
        assert!((SPI_START..=SPI_END).contains(&intid));
        let _lock = self.distributor_lock.lock();
        unsafe {
            self.write32(0x180 + (intid as u32 / 32) * 4, 1 << (intid % 32));
            self.wait_rwp();
        }
        dsb(SY);
    }

    fn current_redistributor(&self) -> usize {
        let affinity = current_affinity();
        let mut offset = 0usize;
        while offset + 0x2_0000 <= self.redistributor_size {
            let frame = self.redistributor + offset;
            let typer = unsafe { ((frame + 8) as *const u64).read_volatile() };
            if typer >> 32 == affinity {
                return frame;
            }
            let stride = if typer & (1 << 1) != 0 {
                0x4_0000
            } else {
                0x2_0000
            };
            if typer & (1 << 4) != 0 {
                break;
            }
            offset += stride;
        }
        panic!("current CPU has no GICv3 redistributor")
    }

    unsafe fn read32(&self, offset: u32) -> u32 {
        unsafe { ((self.distributor + offset as usize) as *const u32).read_volatile() }
    }
    unsafe fn write32(&self, offset: u32, value: u32) {
        unsafe { ((self.distributor + offset as usize) as *mut u32).write_volatile(value) }
    }
    unsafe fn write8(&self, offset: u32, value: u8) {
        unsafe { ((self.distributor + offset as usize) as *mut u8).write_volatile(value) }
    }
    unsafe fn write64(&self, offset: u32, value: u64) {
        unsafe { ((self.distributor + offset as usize) as *mut u64).write_volatile(value) }
    }
    unsafe fn wait_rwp(&self) {
        while unsafe { self.read32(0) } & (1 << 31) != 0 {
            core::hint::spin_loop();
        }
    }
}

fn current_affinity() -> u64 {
    let mpidr = crate::arch::aarch64::cpu::current_hardware_id();
    ((mpidr >> 32) & 0xff) << 24
        | ((mpidr >> 16) & 0xff) << 16
        | ((mpidr >> 8) & 0xff) << 8
        | mpidr & 0xff
}

fn current_route_affinity() -> u64 {
    let mpidr = crate::arch::aarch64::cpu::current_hardware_id();
    ((mpidr >> 32) & 0xff) << 32
        | ((mpidr >> 16) & 0xff) << 16
        | ((mpidr >> 8) & 0xff) << 8
        | mpidr & 0xff
}

unsafe fn read_icc_iar1_el1() -> u32 {
    let value: u64;
    unsafe {
        asm!("mrs {value}, ICC_IAR1_EL1", value = out(reg) value, options(nomem, nostack, preserves_flags))
    };
    value as u32
}
unsafe fn write_icc_eoir1_el1(value: u32) {
    unsafe {
        asm!("msr ICC_EOIR1_EL1, {value}", value = in(reg) value as u64, options(nomem, nostack, preserves_flags))
    }
}
unsafe fn read_icc_sre_el1() -> u64 {
    let value;
    unsafe {
        asm!("mrs {value}, ICC_SRE_EL1", value = out(reg) value, options(nomem, nostack, preserves_flags))
    };
    value
}
unsafe fn write_icc_sre_el1(value: u64) {
    unsafe {
        asm!("msr ICC_SRE_EL1, {value}", value = in(reg) value, options(nomem, nostack, preserves_flags))
    }
}
unsafe fn write_icc_pmr_el1(value: u64) {
    unsafe {
        asm!("msr ICC_PMR_EL1, {value}", value = in(reg) value, options(nomem, nostack, preserves_flags))
    }
}
unsafe fn write_icc_bpr1_el1(value: u64) {
    unsafe {
        asm!("msr ICC_BPR1_EL1, {value}", value = in(reg) value, options(nomem, nostack, preserves_flags))
    }
}
unsafe fn write_icc_igrpen1_el1(value: u64) {
    unsafe {
        asm!("msr ICC_IGRPEN1_EL1, {value}", value = in(reg) value, options(nomem, nostack, preserves_flags))
    }
}
unsafe fn write_icc_sgi1r_el1(value: u64) {
    unsafe {
        asm!("msr ICC_SGI1R_EL1, {value}", value = in(reg) value, options(nomem, nostack, preserves_flags))
    }
}
