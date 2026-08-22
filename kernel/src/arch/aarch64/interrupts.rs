use core::arch::{asm, global_asm};
use core::sync::atomic::Ordering;

use aarch64_cpu::asm::barrier::{SY, dsb, isb};
use aarch64_cpu::asm::wfi;
use aarch64_cpu::registers::{DAIF, Readable, VBAR_EL1, Writeable};
use acpi::madt::{Madt, MadtEntry};
use device_tree::{DeviceTree, Node};
use kernel_types::arch::PhysAddr;
use kernel_types::irq::{MsiMessage, MsiRequest, PlatformCpuId};
use kernel_types::memory::PhysicalMappingCache;
use spin::{Mutex, Once};

use crate::idt::{InterruptGuard, irq_dispatch};
use crate::machine::machine_info;
use crate::memory::paging::map_physical_pages;
use crate::platform::{CpuPlatform, InterruptPlatform};
use crate::util::boot_info;

use super::platform::Aarch64Platform;

const SCHEDULER_SGI: u8 = 1;
const TLB_SHOOTDOWN_SGI: u8 = 2;
const PANIC_STOP_SGI: u8 = 3;
const VIRTUAL_TIMER_PPI: u8 = 27;
const SPI_START: u8 = 32;
const SPI_END: u8 = 255;
const NO_ACTIVE_INTERRUPT: u32 = u32::MAX;

#[repr(C)]
pub struct InterruptFrame {
    pub x: [u64; 31],
    pub sp: u64,
    pub elr: u64,
    pub spsr: u64,
}

#[derive(Clone, Copy)]
struct InterruptToken {
    raw: u32,
    vector: u8,
}

#[derive(Clone, Copy)]
struct GicDescription {
    distributor: u64,
    redistributor: u64,
    redistributor_size: u64,
}

enum InterruptController {
    GicV3(GicV3),
}

struct GicV3 {
    distributor: usize,
    redistributor: usize,
    redistributor_size: usize,
    distributor_lock: Mutex<()>,
}

unsafe impl Send for GicV3 {}
unsafe impl Sync for GicV3 {}

static INTERRUPT_CONTROLLER: Once<InterruptController> = Once::new();

global_asm!(
    r#"
    .section .text.aarch64_vectors,"ax"
    .balign 2048
    .global aarch64_exception_vectors
aarch64_exception_vectors:
    b aarch64_unhandled_exception
    .balign 128
    b aarch64_irq_entry
    .balign 128
    b aarch64_unhandled_exception
    .balign 128
    b aarch64_unhandled_exception
    .balign 128
    b aarch64_unhandled_exception
    .balign 128
    b aarch64_irq_entry
    .balign 128
    b aarch64_unhandled_exception
    .balign 128
    b aarch64_unhandled_exception
    .balign 128
    b aarch64_unhandled_exception
    .balign 128
    b aarch64_irq_entry
    .balign 128
    b aarch64_unhandled_exception
    .balign 128
    b aarch64_unhandled_exception
    .balign 128
    b aarch64_unhandled_exception
    .balign 128
    b aarch64_irq_entry
    .balign 128
    b aarch64_unhandled_exception
    .balign 128
    b aarch64_unhandled_exception

    .balign 16
aarch64_irq_entry:
    sub sp, sp, #272
    stp x0, x1, [sp, #0]
    stp x2, x3, [sp, #16]
    stp x4, x5, [sp, #32]
    stp x6, x7, [sp, #48]
    stp x8, x9, [sp, #64]
    stp x10, x11, [sp, #80]
    stp x12, x13, [sp, #96]
    stp x14, x15, [sp, #112]
    stp x16, x17, [sp, #128]
    stp x18, x19, [sp, #144]
    stp x20, x21, [sp, #160]
    stp x22, x23, [sp, #176]
    stp x24, x25, [sp, #192]
    stp x26, x27, [sp, #208]
    stp x28, x29, [sp, #224]
    str x30, [sp, #240]
    add x1, sp, #272
    str x1, [sp, #248]
    mrs x1, elr_el1
    str x1, [sp, #256]
    mrs x1, spsr_el1
    str x1, [sp, #264]
    mov x0, sp
    bl aarch64_irq_handler
    ldr x1, [sp, #256]
    msr elr_el1, x1
    ldr x1, [sp, #264]
    msr spsr_el1, x1
    ldp x0, x1, [sp, #0]
    ldp x2, x3, [sp, #16]
    ldp x4, x5, [sp, #32]
    ldp x6, x7, [sp, #48]
    ldp x8, x9, [sp, #64]
    ldp x10, x11, [sp, #80]
    ldp x12, x13, [sp, #96]
    ldp x14, x15, [sp, #112]
    ldp x16, x17, [sp, #128]
    ldp x18, x19, [sp, #144]
    ldp x20, x21, [sp, #160]
    ldp x22, x23, [sp, #176]
    ldp x24, x25, [sp, #192]
    ldp x26, x27, [sp, #208]
    ldp x28, x29, [sp, #224]
    ldr x30, [sp, #240]
    add sp, sp, #272
    eret

aarch64_unhandled_exception:
    msr daifset, #0xf
1:
    wfi
    b 1b
"#
);

unsafe extern "C" {
    static aarch64_exception_vectors: u8;
}

fn controller() -> &'static InterruptController {
    INTERRUPT_CONTROLLER.get().expect("GIC is not initialized")
}

impl InterruptController {
    fn acknowledge(&self) -> Option<InterruptToken> {
        match self {
            Self::GicV3(gic) => gic.acknowledge(),
        }
    }

    fn end_interrupt(&self, token: InterruptToken) {
        match self {
            Self::GicV3(gic) => gic.end_interrupt(token),
        }
    }

    fn init_current_cpu(&self) {
        match self {
            Self::GicV3(gic) => gic.init_current_cpu(),
        }
    }

    fn send_ipi(&self, target: PlatformCpuId, vector: u8) -> bool {
        match self {
            Self::GicV3(gic) => gic.send_ipi(target, vector),
        }
    }

    fn broadcast_ipi(&self, vector: u8) {
        match self {
            Self::GicV3(gic) => gic.broadcast_ipi(vector),
        }
    }

    fn unmask_spi(&self, intid: u8) {
        match self {
            Self::GicV3(gic) => gic.unmask_spi(intid),
        }
    }
}

impl GicV3 {
    fn new(description: GicDescription) -> Self {
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

    fn init_distributor(&self) {
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

    fn init_current_cpu(&self) {
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

    fn acknowledge(&self) -> Option<InterruptToken> {
        let raw = unsafe { read_icc_iar1_el1() };
        let intid = raw & 0x00ff_ffff;
        if intid >= 1020 || intid > u8::MAX as u32 {
            return None;
        }
        Some(InterruptToken {
            raw,
            vector: intid as u8,
        })
    }

    fn end_interrupt(&self, token: InterruptToken) {
        unsafe { write_icc_eoir1_el1(token.raw) };
        isb(SY);
    }

    fn send_ipi(&self, target: PlatformCpuId, vector: u8) -> bool {
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

    fn broadcast_ipi(&self, vector: u8) {
        if vector < 16 {
            unsafe { write_icc_sgi1r_el1((vector as u64) << 24 | 1 << 40) };
            isb(SY);
        }
    }

    fn unmask_spi(&self, intid: u8) {
        assert!((SPI_START..=SPI_END).contains(&intid));
        let _lock = self.distributor_lock.lock();
        unsafe {
            self.write64(0x6100 + (intid as u32 - 32) * 8, current_route_affinity());
            self.write32(0x100 + (intid as u32 / 32) * 4, 1 << (intid % 32));
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

pub(crate) fn init_boot_interrupts() {
    VBAR_EL1.set(&raw const aarch64_exception_vectors as u64);
    isb(SY);
    let description = discover_gicv3().expect("firmware does not describe a supported GICv3");
    let gic = GicV3::new(description);
    gic.init_distributor();
    INTERRUPT_CONTROLLER.call_once(|| InterruptController::GicV3(gic));
    kernel_types::irq::set_irq_context_query(irq_context_query);
    kernel_types::irq::set_irq_interrupt_control(
        irq_interrupts_enabled,
        irq_interrupts_disable,
        irq_interrupts_enable,
        irq_interrupts_enable_and_halt,
    );
}

pub(crate) fn init_current_cpu_interrupts() {
    controller().init_current_cpu();
}

#[unsafe(no_mangle)]
extern "C" fn aarch64_irq_handler(frame: &mut InterruptFrame) {
    let Some(token) = controller().acknowledge() else {
        return;
    };
    let percpu = Aarch64Platform::current_percpu();
    let previous = percpu
        .active_interrupt_token
        .swap(token.raw, Ordering::AcqRel);
    assert_eq!(previous, NO_ACTIVE_INTERRUPT);
    let _interrupt_guard = InterruptGuard::new();
    irq_dispatch(token.vector, frame);
}

extern "C" fn irq_context_query() -> bool {
    Aarch64Platform::current_is_in_interrupt()
}

extern "C" fn irq_interrupts_enabled() -> bool {
    Aarch64Platform::interrupts_enabled()
}

extern "C" fn irq_interrupts_disable() {
    Aarch64Platform::disable_interrupts();
}

extern "C" fn irq_interrupts_enable() {
    Aarch64Platform::enable_interrupts();
}

extern "C" fn irq_interrupts_enable_and_halt() {
    Aarch64Platform::enable_interrupts_and_halt();
}

fn discover_gicv3() -> Option<GicDescription> {
    discover_gicv3_acpi().or_else(discover_gicv3_fdt)
}

fn discover_gicv3_acpi() -> Option<GicDescription> {
    let tables = machine_info().firmware().acpi_tables()?;
    let madt = tables.find_table::<Madt>().ok()?;
    let mut distributor = None;
    let mut redistributor = None;
    let mut gicc_redistributor = None;
    for entry in madt.get().entries() {
        match entry {
            MadtEntry::Gicd(gicd) if gicd.gic_version == 3 || gicd.gic_version == 4 => {
                distributor = Some(gicd.physical_base_address)
            }
            MadtEntry::GicRedistributor(gicr) => {
                redistributor = Some((
                    gicr.discovery_range_base_address,
                    gicr.discovery_range_length as u64,
                ))
            }
            MadtEntry::Gicc(gicc) if gicc.gicr_base_address != 0 => {
                gicc_redistributor = Some(gicc.gicr_base_address)
            }
            _ => {}
        }
    }
    let (redistributor, redistributor_size) = redistributor.or_else(|| {
        let base = gicc_redistributor?;
        let cpu_count = machine_info().cpu_topology().processors.len() as u64;
        Some((base, cpu_count * 0x2_0000))
    })?;
    Some(GicDescription {
        distributor: distributor?,
        redistributor,
        redistributor_size,
    })
}

fn discover_gicv3_fdt() -> Option<GicDescription> {
    let header = boot_info().fdt_header.into_option()?;
    let header = unsafe { &*header.cast::<kernel_types::fdt::FdtHeader>() };
    let blob = unsafe {
        core::slice::from_raw_parts(
            header as *const _ as *const u8,
            header.total_size() as usize,
        )
    };
    let tree = DeviceTree::load(blob).ok()?;
    find_gicv3_node(&tree.root, 2, 2)
}

fn find_gicv3_node(
    node: &Node,
    parent_address_cells: u32,
    parent_size_cells: u32,
) -> Option<GicDescription> {
    let address_cells = node_u32(node, "#address-cells").unwrap_or(parent_address_cells);
    let size_cells = node_u32(node, "#size-cells").unwrap_or(parent_size_cells);
    if node.prop_raw("compatible").is_some_and(|value| {
        value
            .split(|byte| *byte == 0)
            .any(|part| part == b"arm,gic-v3")
    }) {
        let reg = node.prop_raw("reg")?;
        let stride = (parent_address_cells + parent_size_cells) as usize * 4;
        if stride == 0 || reg.len() < stride * 2 {
            return None;
        }
        return Some(GicDescription {
            distributor: read_cells(reg, 0, parent_address_cells)?,
            redistributor: read_cells(reg, stride, parent_address_cells)?,
            redistributor_size: read_cells(
                reg,
                stride + parent_address_cells as usize * 4,
                parent_size_cells,
            )?,
        });
    }
    node.children
        .iter()
        .find_map(|child| find_gicv3_node(child, address_cells, size_cells))
}

fn node_u32(node: &Node, name: &str) -> Option<u32> {
    let value = node.prop_raw(name)?;
    Some(u32::from_be_bytes(value.get(0..4)?.try_into().ok()?))
}

fn read_cells(value: &[u8], offset: usize, cells: u32) -> Option<u64> {
    if cells == 0 || cells > 2 {
        return None;
    }
    let mut result = 0u64;
    for index in 0..cells as usize {
        result = result << 32
            | u32::from_be_bytes(
                value
                    .get(offset + index * 4..offset + index * 4 + 4)?
                    .try_into()
                    .ok()?,
            ) as u64;
    }
    Some(result)
}

fn current_affinity() -> u64 {
    let mpidr = super::cpu::current_hardware_id();
    ((mpidr >> 32) & 0xff) << 24
        | ((mpidr >> 16) & 0xff) << 16
        | ((mpidr >> 8) & 0xff) << 8
        | mpidr & 0xff
}

fn current_route_affinity() -> u64 {
    let mpidr = super::cpu::current_hardware_id();
    ((mpidr >> 32) & 0xff) << 32
        | ((mpidr >> 16) & 0xff) << 16
        | ((mpidr >> 8) & 0xff) << 8
        | mpidr & 0xff
}

impl InterruptPlatform for Aarch64Platform {
    type InterruptFrame = InterruptFrame;
    const DYNAMIC_VECTOR_START: u8 = SPI_START;
    const DYNAMIC_VECTOR_END: u8 = SPI_END;
    fn scheduler_ipi_vector() -> u8 {
        SCHEDULER_SGI
    }
    fn timer_interrupt_vector() -> u8 {
        VIRTUAL_TIMER_PPI
    }
    fn tlb_shootdown_vector() -> u8 {
        TLB_SHOOTDOWN_SGI
    }
    fn interrupts_enabled() -> bool {
        DAIF.get() & (1 << 7) == 0
    }
    fn current_is_in_interrupt() -> bool {
        Self::current_percpu()
            .is_in_interrupt
            .load(Ordering::Relaxed)
    }
    fn disable_interrupts() {
        DAIF.set(DAIF.get() | (1 << 7));
    }
    fn enable_interrupts() {
        DAIF.set(DAIF.get() & !(1 << 7));
    }
    fn with_interrupts_disabled<T>(f: impl FnOnce() -> T) -> T {
        let enabled = Self::interrupts_enabled();
        Self::disable_interrupts();
        let result = f();
        if enabled {
            Self::enable_interrupts();
        }
        result
    }
    fn enable_interrupts_and_halt() {
        Self::enable_interrupts();
        isb(SY);
        wfi();
    }
    fn end_interrupt(vector: u8) {
        let raw = Self::current_percpu()
            .active_interrupt_token
            .swap(NO_ACTIVE_INTERRUPT, Ordering::AcqRel);
        assert_ne!(raw, NO_ACTIVE_INTERRUPT);
        let token = InterruptToken {
            raw,
            vector: (raw & 0xff) as u8,
        };
        assert_eq!(token.vector, vector);
        controller().end_interrupt(token);
    }
    fn send_ipi(target: PlatformCpuId, vector: u8) -> bool {
        controller().send_ipi(target, vector)
    }
    fn broadcast_panic_stop() {
        controller().broadcast_ipi(PANIC_STOP_SGI);
    }
    fn compose_msi_message(_request: &MsiRequest) -> Option<MsiMessage> {
        None
    }
    fn is_reserved_vector(vector: u8) -> bool {
        vector < SPI_START
    }
    fn gsi_to_vector(gsi: u8) -> Option<u8> {
        (SPI_START..=SPI_END).contains(&gsi).then_some(gsi)
    }
    fn vector_to_gsi(vector: u8) -> Option<u8> {
        (SPI_START..=SPI_END).contains(&vector).then_some(vector)
    }
    fn unmask_gsi_any_cpu(gsi: u8, vector: u8) {
        assert_eq!(gsi, vector);
        controller().unmask_spi(vector);
    }
    fn enter_interrupt() -> bool {
        Self::current_percpu()
            .is_in_interrupt
            .swap(true, Ordering::AcqRel)
    }
    fn leave_interrupt(was_in_interrupt: bool) {
        if !was_in_interrupt {
            Self::current_percpu()
                .is_in_interrupt
                .store(false, Ordering::Release);
        }
    }
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
