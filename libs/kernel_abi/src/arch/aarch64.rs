use aarch64_vmsa::address::TranslationGranule;
use aarch64_vmsa::table::{TableAddr, TableAllocLayout, TableFrameProvider, TableReclaim};
use core::arch::asm;
use core::marker::PhantomData;
use core::ptr::NonNull;

use crate::layout::aarch64::BOOT_VIRTUAL_LAYOUT;
use crate::{BootArchInfo, Optional};

const PAGE_DESCRIPTOR_FLAGS: u64 = 0b11 | (0b11 << 8) | (1 << 10) | (1 << 53) | (1 << 54);

pub unsafe trait RawTableFrameProvider<G: TranslationGranule> {
    type Error;

    fn allocate_table_frame(
        &mut self,
        layout: TableAllocLayout,
    ) -> Result<TableAddr<G>, Self::Error>;

    fn reclaim_table_frame(&mut self, reclaim: TableReclaim<G>) -> Result<(), Self::Error>;
}

pub struct RecursiveFrameZeroProvider<S, G: TranslationGranule> {
    source: S,
    scratch_page: u64,
    scratch_descriptor: NonNull<u64>,
    granule: PhantomData<G>,
}

impl<S, G: TranslationGranule> RecursiveFrameZeroProvider<S, G> {
    pub const unsafe fn new(
        source: S,
        scratch_page: u64,
        scratch_descriptor: NonNull<u64>,
    ) -> Self {
        Self {
            source,
            scratch_page,
            scratch_descriptor,
            granule: PhantomData,
        }
    }

    pub fn source(&self) -> &S {
        &self.source
    }

    pub fn source_mut(&mut self) -> &mut S {
        &mut self.source
    }

    pub fn into_source(self) -> S {
        self.source
    }
}

unsafe impl<S, G> TableFrameProvider<G> for RecursiveFrameZeroProvider<S, G>
where
    S: RawTableFrameProvider<G>,
    G: TranslationGranule,
{
    type Error = S::Error;

    fn allocate_zeroed_table(
        &mut self,
        layout: TableAllocLayout,
    ) -> Result<TableAddr<G>, Self::Error> {
        let frame = self.source.allocate_table_frame(layout)?;

        unsafe {
            self.scratch_descriptor
                .write_volatile(frame.raw() | PAGE_DESCRIPTOR_FLAGS);
            synchronize_scratch_mapping::<G>(self.scratch_page);
            core::ptr::write_bytes(self.scratch_page as *mut u8, 0, layout.bytes() as usize);
            self.scratch_descriptor.write_volatile(0);
            synchronize_scratch_mapping::<G>(self.scratch_page);
        }

        Ok(frame)
    }

    fn reclaim_table(&mut self, reclaim: TableReclaim<G>) -> Result<(), Self::Error> {
        self.source.reclaim_table_frame(reclaim)
    }
}

unsafe fn synchronize_scratch_mapping<G: TranslationGranule>(virtual_address: u64) {
    let operand = virtual_address >> G::SHIFT;
    unsafe {
        asm!(
            "dsb ishst",
            "tlbi vaae1is, {operand}",
            "dsb ish",
            "isb",
            operand = in(reg) operand,
            options(nostack, preserves_flags),
        );
    }
}

pub const KERNEL_PE_BASE: u64 = BOOT_VIRTUAL_LAYOUT.kernel_image_base;
pub const STUB_IMAGE_BASE: u64 = BOOT_VIRTUAL_LAYOUT.stub_image_base;

pub const STUB_DYNAMIC_RANGE_START: u64 = BOOT_VIRTUAL_LAYOUT.stub_dynamic_range_start;
pub const STUB_DYNAMIC_RANGE_END: u64 = BOOT_VIRTUAL_LAYOUT.stub_dynamic_range_end;

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Aarch64BootArchInfo {
    pub root_table: u64,
    pub recursive_base: u64,
    pub scratch_page: u64,
    pub recursive_index: u16,
    pub granule_shift: u8,
    pub input_addr_bits: u8,
    pub output_addr_bits: u8,
    pub mair_el1: u64,
    pub tcr_el1: u64,
    pub tcr2_el1: u64,
    pub ttbr1_el1: u64,
    pub pe_tls_directory: Optional<Aarch64PeTlsDirectory>,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Aarch64PeTlsDirectory {
    pub start_address_of_raw_data: u64,
    pub end_address_of_raw_data: u64,
    pub address_of_index: u64,
    pub address_of_callbacks: u64,
    pub size_of_zero_fill: u32,
    pub characteristics: u32,
}

impl Aarch64BootArchInfo {
    pub const fn empty() -> Self {
        Self {
            root_table: 0,
            recursive_base: 0,
            scratch_page: 0,
            recursive_index: 0,
            granule_shift: 0,
            input_addr_bits: 0,
            output_addr_bits: 0,
            mair_el1: 0,
            tcr_el1: 0,
            tcr2_el1: 0,
            ttbr1_el1: 0,
            pe_tls_directory: Optional::None,
        }
    }
}

impl BootArchInfo for Aarch64BootArchInfo {
    const EMPTY: Self = Self::empty();
}
