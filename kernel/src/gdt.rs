use core::{mem, ptr};

use lazy_static::lazy_static;
use spin::Mutex;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::paging::PageTableFlags;
use x86_64::structures::tss::TaskStateSegment;
use x86_64::VirtAddr;

use crate::cpu::get_cpu_info;
use crate::memory::paging::constants::KERNEL_STACK_SIZE;
use crate::memory::paging::paging::align_up_2mib;
use crate::memory::paging::stack::allocate_kernel_stack;
use crate::memory::paging::virt_tracker::allocate_auto_kernel_range_mapped;
use crate::structs::per_core_storage::PCS;

use x86_64::instructions::segmentation::{Segment, CS, SS};
use x86_64::instructions::tables::load_tss;
pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;
pub const TIMER_IST_INDEX: u16 = 1;

lazy_static! {
    pub static ref PER_CPU_GDT: Mutex<(GDTTracker)> = Mutex::new(GDTTracker::new());
}

pub struct GDTTracker {
    pub gdt_array: PCS<*const GlobalDescriptorTable>,
    pub selectors_per_cpu: PCS<Selectors>,
    pub base: *mut u8,
    pub size: usize,
}
unsafe impl Send for GDTTracker {}
impl GDTTracker {
    pub fn new() -> Self {
        let base = allocate_auto_kernel_range_mapped(
            0x1000,
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
        )
        .expect("failed to alloc GDT page")
        .as_mut_ptr::<u8>();
        GDTTracker {
            gdt_array: PCS::new(),
            selectors_per_cpu: PCS::new(),
            base,
            size: 0,
        }
    }
    pub unsafe fn init_gdt(&mut self) {
        static mut DOUBLE_FAULT_STACK: [u8; KERNEL_STACK_SIZE as usize] =
            [0; KERNEL_STACK_SIZE as usize];

        let tss_size = core::mem::size_of::<TaskStateSegment>();
        let tss_ptr = self.base.add(self.size) as *mut TaskStateSegment;
        ptr::write(tss_ptr, TaskStateSegment::new());
        let tss_static: &'static mut TaskStateSegment = &mut *tss_ptr;
        let kernel_stack_size = align_up_2mib(KERNEL_STACK_SIZE);
        // Stacks
        let timer_stack =
            allocate_kernel_stack(kernel_stack_size).expect("Failed to alloc timer stack");

        let privilege_stack =
            allocate_kernel_stack(kernel_stack_size).expect("Failed to alloc privilege stack ");

        let double_fault_stack = unsafe {
            let stack_end =
                VirtAddr::new(DOUBLE_FAULT_STACK.as_mut_ptr() as u64 + KERNEL_STACK_SIZE as u64);
            let stack_start = stack_end - KERNEL_STACK_SIZE;
            stack_end
        };

        tss_static.interrupt_stack_table[TIMER_IST_INDEX as usize] =
            timer_stack + kernel_stack_size;
        tss_static.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] =
            double_fault_stack + KERNEL_STACK_SIZE;
        //tss_static.privilege_stack_table[0] = privilege_stack + kernel_stack_size;

        let tss_size = core::mem::size_of::<TaskStateSegment>();
        let gdt_max_entries = 12; // actually 8 but is set to 12 to account for the internal counters in the struct
        let gdt_size_bytes = gdt_max_entries * mem::size_of::<u64>();

        let gdt_ptr_base = self.base.add(self.size + tss_size) as *mut GlobalDescriptorTable;
        ptr::write(gdt_ptr_base, GlobalDescriptorTable::new());

        let kernel_code_selector = (*gdt_ptr_base).append(Descriptor::kernel_code_segment());
        let kernel_data_selector = (*gdt_ptr_base).append(Descriptor::kernel_data_segment());
        // Swap this append order if it causes issues
        let user_data_selector = (*gdt_ptr_base).append(Descriptor::user_data_segment());
        let user_code_selector = (*gdt_ptr_base).append(Descriptor::user_code_segment());

        let tss_selector = (*gdt_ptr_base).append(Descriptor::tss_segment(tss_static));
        (*gdt_ptr_base).load();

        self.size += tss_size + gdt_size_bytes;

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
        self.gdt_array.set(id, gdt_ptr_base);
        self.selectors_per_cpu.set(id, selectors);
    }
}
pub struct Selectors {
    pub(crate) kernel_code_selector: SegmentSelector,
    pub(crate) kernel_data_selector: SegmentSelector,
    pub(crate) user_code_selector: SegmentSelector,
    pub(crate) user_data_selector: SegmentSelector,
    tss_selector: SegmentSelector,
}
