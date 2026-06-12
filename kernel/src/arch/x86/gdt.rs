use crate::benchmarking::BENCH_ENABLED;

use alloc::boxed::Box;
use lazy_static::lazy_static;
use spin::Mutex;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;

use crate::cpu::get_cpu_info;
use crate::memory::paging::stack::{StackSize, allocate_kernel_stack};
use crate::structs::per_cpu_vec::PerCpuVec;

use x86_64::instructions::segmentation::{CS, SS, Segment};
use x86_64::instructions::tables::load_tss;
pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;
pub const TIMER_IST_INDEX: u16 = 1;
pub const PAGE_FAULT_IST_INDEX: u16 = 2;
pub const YIELD_IST_INDEX: u16 = 3;
pub const SCHED_IPI_IST_INDEX: u16 = 4;
lazy_static! {
    pub static ref PER_CPU_GDT: Mutex<(GDTTracker)> = Mutex::new(GDTTracker::new());
}

pub struct GDTTracker {
    pub gdt_array: PerCpuVec<*const GlobalDescriptorTable>,
    pub selectors_per_cpu: PerCpuVec<Selectors>,
}
unsafe impl Send for GDTTracker {}
impl Default for GDTTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl GDTTracker {
    pub fn new() -> Self {
        GDTTracker {
            gdt_array: PerCpuVec::new(),
            selectors_per_cpu: PerCpuVec::new(),
        }
    }
    pub unsafe fn init_gdt(&mut self) {
        let tss_static: &'static mut TaskStateSegment =
            Box::leak(Box::new(TaskStateSegment::new()));
        // Stacks

        // This needs to be done because interrupt stacks aren't allowed to grow and the bench submit puts a bunch on the stack to prevent alloc in interrupts.
        // TODO: consider allowing interrupt stacks to grow or reducing bench submits footprint.
        let timer_stack_size = if BENCH_ENABLED {
            StackSize::Huge2M
        } else {
            StackSize::Medium
        };
        let timer_stack =
            allocate_kernel_stack(timer_stack_size).expect("Failed to alloc timer stack");

        let yield_stack =
            allocate_kernel_stack(StackSize::Medium).expect("Failed to alloc yield stack");

        let sched_ipi_stack =
            allocate_kernel_stack(StackSize::Medium).expect("Failed to alloc sched ipi stack");

        let privilege_stack =
            allocate_kernel_stack(StackSize::Medium).expect("Failed to alloc privilege stack");

        let double_fault_stack =
            allocate_kernel_stack(StackSize::Medium).expect("Failed to alloc double fault stack");

        let page_stack =
            allocate_kernel_stack(StackSize::Medium).expect("Failed to alloc page fault stack");

        tss_static.interrupt_stack_table[TIMER_IST_INDEX as usize] = timer_stack;
        tss_static.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = double_fault_stack;
        tss_static.interrupt_stack_table[PAGE_FAULT_IST_INDEX as usize] = page_stack;
        tss_static.interrupt_stack_table[YIELD_IST_INDEX as usize] = yield_stack;
        tss_static.interrupt_stack_table[SCHED_IPI_IST_INDEX as usize] = sched_ipi_stack;
        tss_static.privilege_stack_table[0] = privilege_stack;

        let gdt: &'static mut GlobalDescriptorTable =
            Box::leak(Box::new(GlobalDescriptorTable::new()));

        let kernel_code_selector = gdt.append(Descriptor::kernel_code_segment());
        let kernel_data_selector = gdt.append(Descriptor::kernel_data_segment());
        let user_data_selector = gdt.append(Descriptor::user_data_segment());
        let user_code_selector = gdt.append(Descriptor::user_code_segment());

        let tss_selector = gdt.append(Descriptor::tss_segment(tss_static));
        gdt.load();

        CS::set_reg(kernel_code_selector);
        SS::set_reg(kernel_data_selector);
        load_tss(tss_selector);
        let selectors = Selectors {
            kernel_code_selector,
            kernel_data_selector,
            user_code_selector,
            user_data_selector,
            tss_selector,
        };
        let id = get_cpu_info()
            .get_feature_info()
            .expect("NO CPUID")
            .initial_local_apic_id() as usize;
        self.gdt_array
            .set_by_id(id, gdt as *const GlobalDescriptorTable, core::ptr::null);
        self.selectors_per_cpu
            .set_by_id(id, selectors, Selectors::default);
    }
}
pub struct Selectors {
    pub(crate) kernel_code_selector: SegmentSelector,
    pub(crate) kernel_data_selector: SegmentSelector,
    pub(crate) user_code_selector: SegmentSelector,
    pub(crate) user_data_selector: SegmentSelector,
    tss_selector: SegmentSelector,
}

impl Default for Selectors {
    fn default() -> Self {
        use x86_64::PrivilegeLevel;
        Self {
            kernel_code_selector: SegmentSelector::new(0, PrivilegeLevel::Ring0),
            kernel_data_selector: SegmentSelector::new(0, PrivilegeLevel::Ring0),
            user_code_selector: SegmentSelector::new(0, PrivilegeLevel::Ring0),
            user_data_selector: SegmentSelector::new(0, PrivilegeLevel::Ring0),
            tss_selector: SegmentSelector::new(0, PrivilegeLevel::Ring0),
        }
    }
}
