use core::mem::transmute;

use crate::file_system::file::{File, OpenFlags};
use crate::memory::paging::{init_mapper, map_page, map_page_in_page_table, new_user_mode_page_table, BootInfoFrameAllocator, RangeTracker};
use crate::util::boot_info;
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use goblin::pe::PE;
use goblin::Object;
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::mapper::MapToError;
use x86_64::structures::paging::{FrameAllocator, Mapper, Page, PageTable, PageTableFlags};
use x86_64::VirtAddr;

pub struct PELoader {
    buffer: Box<[u8]>,
    pe: PE<'static>,
    path: String,
}


impl PELoader {
    /// Opens and prepares a PE loader from the given path.
    pub fn new(path: &str) -> Option<Self> {
        let open_flags = [OpenFlags::Open, OpenFlags::ReadOnly];
        let file_handle = File::open(path, &open_flags).ok()?;
        let file_data: Vec<u8> = file_handle.read().ok()?;

        let boxed: Box<[u8]> = file_data.into_boxed_slice();

        let slice: &[u8] = &boxed;

        let pe = match Object::parse(slice).ok()? {
            Object::PE(pe) => pe,
            _ => return None,
        };

        let pe_static: PE<'static> = unsafe { transmute::<PE<'_>, PE<'static>>(pe) };

        Some(Self {
            buffer: boxed,
            pe: pe_static,
            path: path.to_string(),
        })
    }


    pub fn get_path(&self) -> String {
        self.path.clone()
    }

    /// Loads the PE into memory and prepares it for execution.
    /// 
    /// Error: LoadError
    /// 
    /// Ok: PID of the loaded program
    pub fn load(&self) -> Result<u64, LoadError> {
        let pe = &self.pe;
        if pe.is_lib {
            return Err(LoadError::IsNotExecutable);
        }

        if !pe.is_64 {
            return Err(LoadError::Not64Bit);
        }

        let entry = pe.entry;
        if entry == 0 {
            return Err(LoadError::NoEntryPoint);
        }

        let opt_hdr = pe.header.optional_header.as_ref().ok_or(LoadError::MissingSections)?;

        if pe.sections.is_empty() {
            return Err(LoadError::MissingSections);
        }

        let image_base = opt_hdr.windows_fields.image_base;
        if image_base % 0x10000 != 0 {
            return Err(LoadError::UnsupportedImageBase);
        }

        let (table_phys, table_virt) = new_user_mode_page_table().unwrap();
        let page_table: &mut PageTable = unsafe { &mut *(table_virt.as_mut_ptr()) };
        let range_tracker = RangeTracker::new(0x0u64, 0x00007FFFFFFFFFFFu64);
        let image_size = opt_hdr.windows_fields.size_of_image as u64;
        let required_frames_4kib = (image_size) / 0x1000;
        range_tracker.alloc(image_base, image_size);

        unsafe { Cr3::write(flags) };
    let boot_info = boot_info();
    let phys_mem_offset = VirtAddr::new(
        boot_info
            .physical_memory_offset
            .into_option()
            .ok_or(LoadError::NoMemory)?,
    );

    let mut frame_allocator = BootInfoFrameAllocator::init(&boot_info.memory_regions);
    let mut mapper = init_mapper(phys_mem_offset);

        for i in 0..required_frames_4kib {
            let required_address = image_base + (i * 0x1000);
            let page = Page::containing_address(VirtAddr::new(required_address));
            let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;
            map_page(&mut mapper, page, &mut frame_allocator, flags)
                .map_err(|_| LoadError::NoMemory)?;
        }
        Err(LoadError::NotImplemented)
    }
}

/// Placeholder error type for loading failures.
#[derive(Debug)]
pub enum LoadError {
    IsNotExecutable,
    Not64Bit,
    NoEntryPoint,
    InvalidSubsystem,
    InvalidDllCharacteristics,
    UnsupportedRelocationFormat,
    MissingSections,
    UnsupportedImageBase,
    NotImplemented,
    NoMemory,
}

