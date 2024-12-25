use lazy_static::lazy_static;
use x86_64::instructions::segmentation::SS;
use x86_64::structures::tss::TaskStateSegment;
use x86_64::VirtAddr;

pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;
pub const TIMER_IST_INDEX: u16 = 1;



lazy_static! {
    static ref TSS: TaskStateSegment = {
        let mut tss = TaskStateSegment::new();

        // Static memory for stacks
        static mut TIMER_STACK: [u8; KERNEL_STACK_SIZE as usize] = [0; KERNEL_STACK_SIZE as usize];
        static mut DOUBLE_FAULT_STACK: [u8; KERNEL_STACK_SIZE as usize] = [0; KERNEL_STACK_SIZE as usize];
        static mut PRIVILEGE_STACK: [u8; KERNEL_STACK_SIZE as usize] = [0; KERNEL_STACK_SIZE as usize];

        // Set up the stack for the timer interrupt (int 0x20) using the IST.
        tss.interrupt_stack_table[TIMER_IST_INDEX as usize] = unsafe {
            let stack_end = VirtAddr::new(TIMER_STACK.as_ptr() as u64 + KERNEL_STACK_SIZE as u64);
            let stack_start = stack_end - KERNEL_STACK_SIZE;
            println!(
                "TIMER_STACK: start = 0x{:x}, end = 0x{:x}",
                stack_start.as_u64(),
                stack_end.as_u64()
            );
            stack_end
        };

        // Set up the stack for the double fault handler using the IST.
        tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = unsafe {
            let stack_end =
                VirtAddr::new(DOUBLE_FAULT_STACK.as_ptr() as u64 + KERNEL_STACK_SIZE as u64);
            let stack_start = stack_end - KERNEL_STACK_SIZE;
            println!(
                "DOUBLE_FAULT_STACK: start = 0x{:x}, end = 0x{:x}",
                stack_start.as_u64(),
                stack_end.as_u64()
            );
            stack_end
        };

        // Set up the privilege stack for ring 0 (used when transitioning from ring 3 to ring 0).
        tss.privilege_stack_table[0] = unsafe {
            let stack_end =
                VirtAddr::new(PRIVILEGE_STACK.as_ptr() as u64 + KERNEL_STACK_SIZE as u64);
            let stack_start = stack_end - KERNEL_STACK_SIZE;
            println!(
                "PRIVILEGE_STACK: start = 0x{:x}, end = 0x{:x}",
                stack_start.as_u64(),
                stack_end.as_u64()
            );
            stack_end
        };

        tss
    };
}


use crate::println;
use x86_64::structures::gdt::SegmentSelector;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable};
use crate::memory::paging::KERNEL_STACK_SIZE;

lazy_static! {
    pub static ref GDT: (GlobalDescriptorTable, Selectors) = {
        let mut gdt = GlobalDescriptorTable::new();

        // Kernel mode segments
        let kernel_code_selector = gdt.append(Descriptor::kernel_code_segment());
        let kernel_data_selector = gdt.append(Descriptor::kernel_data_segment());

        // User mode segments (ring 3)
        // Define 64-bit code segment for user mode
        let user_code_selector = gdt.append(Descriptor::user_code_segment());

        // Manually define a 64-bit compatible data segment for user mode
        let user_data_selector = gdt.append(Descriptor::user_data_segment());

        // Task state segment (TSS)
        let tss_selector = gdt.append(Descriptor::tss_segment(&TSS));

        (
            gdt,
            Selectors {
                kernel_code_selector,
                kernel_data_selector,
                user_code_selector,
                user_data_selector,
                tss_selector,
            }
        )
    };
}

// Struct to hold all the segment selectors (for kernel and user mode)
pub struct Selectors {
    pub(crate) kernel_code_selector: SegmentSelector,
    pub(crate) kernel_data_selector: SegmentSelector,
    pub(crate) user_code_selector: SegmentSelector,
    pub(crate) user_data_selector: SegmentSelector,
    tss_selector: SegmentSelector,
}


pub fn init() {
    use x86_64::instructions::segmentation::{Segment, CS};
    use x86_64::instructions::tables::load_tss;

    // Load the GDT
    GDT.0.load();

    // Reload segment registers
    unsafe {
        CS::set_reg(GDT.1.kernel_code_selector);
        SS::set_reg(GDT.1.kernel_data_selector);

        // Load the TSS
        load_tss(GDT.1.tss_selector);
    }

}