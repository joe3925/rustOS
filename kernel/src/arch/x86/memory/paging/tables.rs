use core::sync::atomic::{AtomicU64, Ordering};

use spin::Once;
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::{PhysFrame, Size4KiB};

pub static KERNEL_CR3_U64: AtomicU64 = AtomicU64::new(0);
static PAGING_PROPERTIES: Once<PagingProperties> = Once::new();

pub(super) struct PagingProperties {
    pub(super) output_address_bits: u8,
    pub(super) supports_1g_pages: bool,
}

pub(super) fn paging_properties() -> &'static PagingProperties {
    PAGING_PROPERTIES.call_once(|| {
        let cpu = super::super::super::cpu::get_cpu_info();
        PagingProperties {
            output_address_bits: cpu
                .get_processor_capacity_feature_info()
                .map(|capacity| capacity.physical_address_bits())
                .unwrap_or(48),
            supports_1g_pages: cpu
                .get_extended_processor_and_feature_identifiers()
                .is_some_and(|features| features.has_1gib_pages()),
        }
    })
}

pub fn init_kernel_cr3() {
    paging_properties();
    let (frame, _) = Cr3::read();
    KERNEL_CR3_U64.store(frame.start_address().as_u64(), Ordering::SeqCst);
}

pub fn kernel_cr3() -> PhysFrame<Size4KiB> {
    PhysFrame::containing_address(x86_64::PhysAddr::new(KERNEL_CR3_U64.load(Ordering::SeqCst)))
}
