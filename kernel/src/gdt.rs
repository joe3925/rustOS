use lazy_static::lazy_static;
use x86_64::instructions::segmentation::SS;
use x86_64::structures::tss::TaskStateSegment;
use x86_64::VirtAddr;

pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;
pub const TIMER_IST_INDEX: u16 = 1;



lazy_static! {
    static ref TSS: TaskStateSegment = {
        let mut tss = TaskStateSegment::new();

        static mut TIMER_STACK: [u8; KERNEL_STACK_SIZE as usize] = [0; KERNEL_STACK_SIZE as usize];
        static mut DOUBLE_FAULT_STACK: [u8; KERNEL_STACK_SIZE as usize] = [0; KERNEL_STACK_SIZE as usize];
        static mut PRIVILEGE_STACK: [u8; KERNEL_STACK_SIZE as usize] = [0; KERNEL_STACK_SIZE as usize];

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

        // (used when transitioning from ring 3 to ring 0).
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


use crate::memory::paging::KERNEL_STACK_SIZE;
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
        let user_code_selector = gdt.append(Descriptor::user_code_segment());

        let user_data_selector = gdt.append(Descriptor::user_data_segment());

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

    GDT.0.load();

    unsafe {
        CS::set_reg(GDT.1.kernel_code_selector);
        SS::set_reg(GDT.1.kernel_data_selector);

        load_tss(GDT.1.tss_selector);
    }
}