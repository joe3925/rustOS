use spin::Once;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame};
use x86_64::VirtAddr;

use crate::drivers;
use crate::drivers::interrupt_index::InterruptIndex;
use crate::drivers::timer_driver::timer_interrupt_entry;
use crate::exception_handlers::exception_handlers;
use crate::gdt::{DOUBLE_FAULT_IST_INDEX, PAGE_FAULT_IST_INDEX, TIMER_IST_INDEX, YIELD_IST_INDEX};
use crate::scheduling::scheduler::{ipi_entry, yield_interrupt_entry, KernelFpuGuard};

mod interrupt_impl;
pub use interrupt_impl::*;

// =============================================================================
// IRQ VECTOR STUBS
// =============================================================================

macro_rules! gen_irq_stub {
    ($name:ident, $vec:expr) => {
        extern "x86-interrupt" fn $name(mut frame: InterruptStackFrame) {
            let _fpu_guard = KernelFpuGuard::new();
            x86_64::instructions::interrupts::without_interrupts(|| {
                irq_dispatch($vec, &mut frame);
            });
        }
    };
}

macro_rules! gen_irq_stubs {
    ($(($name:ident, $vec:expr)),+ $(,)?) => {
        $(gen_irq_stub!($name, $vec);)+
        type IrqStub = extern "x86-interrupt" fn(InterruptStackFrame);
        const IRQ_VECTOR_STUBS: &[(u8, IrqStub)] = &[ $(($vec, $name)),+ ];
    };
}

gen_irq_stubs!(
    (irq_vec_33, 33),
    (irq_vec_34, 34),
    (irq_vec_35, 35),
    (irq_vec_36, 36),
    (irq_vec_37, 37),
    (irq_vec_38, 38),
    (irq_vec_39, 39),
    (irq_vec_40, 40),
    (irq_vec_41, 41),
    (irq_vec_42, 42),
    (irq_vec_43, 43),
    (irq_vec_44, 44),
    (irq_vec_45, 45),
    (irq_vec_46, 46),
    (irq_vec_47, 47),
    (irq_vec_48, 48),
    (irq_vec_49, 49),
    (irq_vec_50, 50),
    (irq_vec_51, 51),
    (irq_vec_52, 52),
    (irq_vec_53, 53),
    (irq_vec_54, 54),
    (irq_vec_55, 55),
    (irq_vec_56, 56),
    (irq_vec_57, 57),
    (irq_vec_58, 58),
    (irq_vec_59, 59),
    (irq_vec_60, 60),
    (irq_vec_61, 61),
    (irq_vec_62, 62),
    (irq_vec_63, 63),
    (irq_vec_64, 64),
    (irq_vec_65, 65),
    (irq_vec_66, 66),
    (irq_vec_67, 67),
    (irq_vec_68, 68),
    (irq_vec_69, 69),
    (irq_vec_70, 70),
    (irq_vec_71, 71),
    (irq_vec_72, 72),
    (irq_vec_73, 73),
    (irq_vec_74, 74),
    (irq_vec_75, 75),
    (irq_vec_76, 76),
    (irq_vec_77, 77),
    (irq_vec_78, 78),
    (irq_vec_79, 79),
    (irq_vec_80, 80),
    (irq_vec_81, 81),
    (irq_vec_82, 82),
    (irq_vec_83, 83),
    (irq_vec_84, 84),
    (irq_vec_85, 85),
    (irq_vec_86, 86),
    (irq_vec_87, 87),
    (irq_vec_88, 88),
    (irq_vec_89, 89),
    (irq_vec_90, 90),
    (irq_vec_91, 91),
    (irq_vec_92, 92),
    (irq_vec_93, 93),
    (irq_vec_94, 94),
    (irq_vec_95, 95),
    (irq_vec_96, 96),
    (irq_vec_97, 97),
    (irq_vec_98, 98),
    (irq_vec_99, 99),
    (irq_vec_100, 100),
    (irq_vec_101, 101),
    (irq_vec_102, 102),
    (irq_vec_103, 103),
    (irq_vec_104, 104),
    (irq_vec_105, 105),
    (irq_vec_106, 106),
    (irq_vec_107, 107),
    (irq_vec_108, 108),
    (irq_vec_109, 109),
    (irq_vec_110, 110),
    (irq_vec_111, 111),
    (irq_vec_112, 112),
    (irq_vec_113, 113),
    (irq_vec_114, 114),
    (irq_vec_115, 115),
    (irq_vec_116, 116),
    (irq_vec_117, 117),
    (irq_vec_118, 118),
    (irq_vec_119, 119),
    (irq_vec_120, 120),
    (irq_vec_121, 121),
    (irq_vec_122, 122),
    (irq_vec_123, 123),
    (irq_vec_124, 124),
    (irq_vec_125, 125),
    (irq_vec_126, 126),
    (irq_vec_127, 127),
    (irq_vec_129, 129),
    (irq_vec_130, 130),
    (irq_vec_131, 131),
    (irq_vec_132, 132),
    (irq_vec_133, 133),
    (irq_vec_134, 134),
    (irq_vec_135, 135),
    (irq_vec_136, 136),
    (irq_vec_137, 137),
    (irq_vec_138, 138),
    (irq_vec_139, 139),
    (irq_vec_140, 140),
    (irq_vec_141, 141),
    (irq_vec_142, 142),
    (irq_vec_143, 143),
    (irq_vec_144, 144),
    (irq_vec_145, 145),
    (irq_vec_146, 146),
    (irq_vec_147, 147),
    (irq_vec_148, 148),
    (irq_vec_149, 149),
    (irq_vec_150, 150),
    (irq_vec_151, 151),
    (irq_vec_152, 152),
    (irq_vec_153, 153),
    (irq_vec_154, 154),
    (irq_vec_155, 155),
    (irq_vec_156, 156),
    (irq_vec_157, 157),
    (irq_vec_158, 158),
    (irq_vec_159, 159),
    (irq_vec_160, 160),
    (irq_vec_161, 161),
    (irq_vec_162, 162),
    (irq_vec_163, 163),
    (irq_vec_164, 164),
    (irq_vec_165, 165),
    (irq_vec_166, 166),
    (irq_vec_167, 167),
    (irq_vec_168, 168),
    (irq_vec_169, 169),
    (irq_vec_170, 170),
    (irq_vec_171, 171),
    (irq_vec_172, 172),
    (irq_vec_173, 173),
    (irq_vec_174, 174),
    (irq_vec_175, 175),
    (irq_vec_176, 176),
    (irq_vec_177, 177),
    (irq_vec_178, 178),
    (irq_vec_179, 179),
    (irq_vec_180, 180),
    (irq_vec_181, 181),
    (irq_vec_182, 182),
    (irq_vec_183, 183),
    (irq_vec_184, 184),
    (irq_vec_185, 185),
    (irq_vec_186, 186),
    (irq_vec_187, 187),
    (irq_vec_188, 188),
    (irq_vec_189, 189),
    (irq_vec_190, 190),
    (irq_vec_191, 191),
    (irq_vec_192, 192),
    (irq_vec_193, 193),
    (irq_vec_194, 194),
    (irq_vec_195, 195),
    (irq_vec_196, 196),
    (irq_vec_197, 197),
    (irq_vec_198, 198),
    (irq_vec_199, 199),
    (irq_vec_200, 200),
    (irq_vec_201, 201),
    (irq_vec_202, 202),
    (irq_vec_203, 203),
    (irq_vec_204, 204),
    (irq_vec_205, 205),
    (irq_vec_206, 206),
    (irq_vec_207, 207),
    (irq_vec_208, 208),
    (irq_vec_209, 209),
    (irq_vec_210, 210),
    (irq_vec_211, 211),
    (irq_vec_212, 212),
    (irq_vec_213, 213),
    (irq_vec_214, 214),
    (irq_vec_215, 215),
    (irq_vec_216, 216),
    (irq_vec_217, 217),
    (irq_vec_218, 218),
    (irq_vec_219, 219),
    (irq_vec_220, 220),
    (irq_vec_221, 221),
    (irq_vec_222, 222),
    (irq_vec_223, 223),
    (irq_vec_224, 224),
    (irq_vec_225, 225),
    (irq_vec_226, 226),
    (irq_vec_227, 227),
    (irq_vec_228, 228),
    (irq_vec_229, 229),
    (irq_vec_230, 230),
    (irq_vec_231, 231),
    (irq_vec_232, 232),
    (irq_vec_233, 233),
    (irq_vec_234, 234),
    (irq_vec_235, 235),
    (irq_vec_236, 236),
    (irq_vec_237, 237),
    (irq_vec_238, 238),
    (irq_vec_239, 239),
);

// =============================================================================
// IDT SETUP
// =============================================================================

static IDT: Once<InterruptDescriptorTable> = Once::new();

fn init_idt() -> InterruptDescriptorTable {
    let mut idt = InterruptDescriptorTable::new();

    idt.divide_error
        .set_handler_fn(exception_handlers::divide_by_zero_fault);
    idt.debug
        .set_handler_fn(exception_handlers::debug_exception);
    idt.non_maskable_interrupt
        .set_handler_fn(exception_handlers::non_maskable_interrupt);
    idt.breakpoint
        .set_handler_fn(exception_handlers::breakpoint_exception)
        .set_privilege_level(x86_64::PrivilegeLevel::Ring3);
    idt.overflow
        .set_handler_fn(exception_handlers::overflow_exception);
    idt.bound_range_exceeded
        .set_handler_fn(exception_handlers::bound_range_exceeded_exception);
    idt.invalid_opcode
        .set_handler_fn(exception_handlers::invalid_opcode_exception);
    idt.device_not_available
        .set_handler_fn(exception_handlers::device_not_available_exception);
    unsafe {
        idt.double_fault
            .set_handler_fn(exception_handlers::double_fault)
            .set_stack_index(DOUBLE_FAULT_IST_INDEX);
    }
    idt.invalid_tss
        .set_handler_fn(exception_handlers::invalid_tss_exception);
    idt.segment_not_present
        .set_handler_fn(exception_handlers::segment_not_present_exception);
    idt.stack_segment_fault
        .set_handler_fn(exception_handlers::stack_segment_fault);
    idt.general_protection_fault
        .set_handler_fn(exception_handlers::general_protection_fault);
    unsafe {
        idt.page_fault
            .set_handler_fn(exception_handlers::page_fault)
            .set_stack_index(PAGE_FAULT_IST_INDEX);
    }
    idt.x87_floating_point
        .set_handler_fn(exception_handlers::x87_floating_point_exception);
    idt.alignment_check
        .set_handler_fn(exception_handlers::alignment_check_exception);
    idt.machine_check
        .set_handler_fn(exception_handlers::machine_check_exception);
    idt.simd_floating_point
        .set_handler_fn(exception_handlers::simd_floating_point_exception);
    idt.virtualization
        .set_handler_fn(exception_handlers::virtualization_exception);

    unsafe {
        idt[InterruptIndex::Timer.as_u8()]
            .set_handler_addr(VirtAddr::new(timer_interrupt_entry as *const () as u64))
            .set_stack_index(TIMER_IST_INDEX);
    }
    for (vec, stub) in IRQ_VECTOR_STUBS {
        idt[*vec].set_handler_fn(*stub);
    }

    unsafe {
        idt[SCHED_IPI_VECTOR]
            .set_handler_addr(VirtAddr::new(ipi_entry as *const () as u64))
            .set_stack_index(YIELD_IST_INDEX);

        idt[0x80]
            .set_handler_addr(VirtAddr::new(yield_interrupt_entry as *const () as u64))
            .set_stack_index(YIELD_IST_INDEX);
    }

    idt
}

pub fn load_idt() {
    IDT.call_once(init_idt).load();
}
