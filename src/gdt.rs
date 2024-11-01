use core::ptr::addr_of;
use lazy_static::lazy_static;
use x86_64::instructions::segmentation::SS;
use x86_64::structures::tss::TaskStateSegment;
use x86_64::VirtAddr;

pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

lazy_static! {
    static ref TSS: TaskStateSegment = {
        let mut tss = TaskStateSegment::new();

        // Set up the stack for the double fault handler using the IST.
        const DOUBLE_FAULT_STACK_SIZE: usize = 4096 * 5; // 20 KB stack
        static DOUBLE_FAULT_STACK: [u8; DOUBLE_FAULT_STACK_SIZE] = [0; DOUBLE_FAULT_STACK_SIZE];
        println!("DOUBLE_FAULT_STACK AT: {:#?}", addr_of!(DOUBLE_FAULT_STACK));
        tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = {
            let stack_start = VirtAddr::from_ptr(addr_of!(DOUBLE_FAULT_STACK));
            let stack_end = stack_start + DOUBLE_FAULT_STACK_SIZE as u64;
            stack_end
        };

        // Set up the privilege stack for ring 0 (used when transitioning from ring 3 to ring 0).
        const PRIVILEGE_STACK_SIZE: usize = 4096 * 10; // 20 KB stack
        static PRIVILEGE_STACK: [u8; PRIVILEGE_STACK_SIZE] = [0; PRIVILEGE_STACK_SIZE];
        println!("PRIVILEGE_STACK AT: {:#?}", addr_of!(PRIVILEGE_STACK) );
        tss.privilege_stack_table[0] = {
            let stack_start = VirtAddr::from_ptr(addr_of!(PRIVILEGE_STACK) );
            let stack_end = stack_start + PRIVILEGE_STACK_SIZE as u64;
            stack_end
        };

        tss
    };
}

use crate::println;
use x86_64::structures::gdt::SegmentSelector;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable};

lazy_static! {
    pub static ref GDT: (GlobalDescriptorTable, Selectors) = {
        let mut gdt = GlobalDescriptorTable::new();

        // Kernel mode segments
        let kernel_code_selector = gdt.append(Descriptor::kernel_code_segment());
        let kernel_data_selector = gdt.append(Descriptor::kernel_data_segment());

        // User mode segments (ring 3)
        // Define 64-bit code segment for user mode
        let user_code_selector = gdt.append(Descriptor::UserSegment(0x00AFFA000000FFFF));

        // Manually define a 64-bit compatible data segment for user mode
        let user_data_selector = gdt.append(Descriptor::UserSegment(0x00CFF3000000FFFF));

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

    println!("Loaded GDT and TSS with user-mode support");
}