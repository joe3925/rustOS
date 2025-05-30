use core::mem::transmute;
use core::ptr::copy_nonoverlapping;

use crate::file_system::file::{File, OpenFlags};
use crate::memory::allocator;
use crate::memory::paging::{
    init_mapper, map_page, map_page_in_page_table, new_user_mode_page_table,
    BootInfoFrameAllocator, RangeTracker,
};
use crate::scheduling::scheduler::{self, SCHEDULER};
use crate::scheduling::task::Task;
use crate::util::boot_info;
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use bitflags::Flags;
use embedded_graphics::pixelcolor::raw::LittleEndian;
use goblin::pe::data_directories::DataDirectory;
use goblin::pe::dll_characteristic::IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
use goblin::pe::{relocation, PE};
use goblin::Object;
use spin::mutex::Mutex;
use x86_64::registers::control::{Cr2, Cr3, Cr3Flags};
use x86_64::structures::paging::mapper::MapToError;
use x86_64::structures::paging::{
    FrameAllocator, Mapper, Page, PageTable, PageTableFlags, PhysFrame,
};
use x86_64::VirtAddr;

use super::program::{Module, Program, PROGRAM_MANAGER};

pub struct PELoader {
    buffer: Box<[u8]>,
    pe: PE<'static>,
    path: String,
    current_base: VirtAddr,
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
        let base = VirtAddr::new(pe_static.image_base as u64);

        Some(Self {
            buffer: boxed,
            pe: pe_static,
            path: path.to_string(),
            current_base: base,
        })
    }
    pub fn is_pic(&self) -> bool {
        let dynbase = {
            let dll_chars = self
                .pe
                .header
                .optional_header
                .as_ref()
                .map(|h| h.windows_fields.dll_characteristics)
                .unwrap_or(0);
            dll_chars & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE != 0
        };

        if !dynbase {
            return false; // fixed-base executable
        }
        if let Some(_) = (self.reloc_table()) {
            return false;
        }
        true
    }
    pub fn is_aslr(&self) -> bool {
        // `optional_header` does not exist for ROM images, so default to 0.
        let dll_chars = self
            .pe
            .header
            .optional_header
            .as_ref()
            .map(|h| h.windows_fields.dll_characteristics)
            .unwrap_or(0);

        dll_chars & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE != 0
    }

    pub fn needs_relocation(&self) -> bool {
        self.is_aslr() && self.reloc_table().is_some()
    }
    /// Returns the .reloc section data if present.
    pub fn reloc_table(&self) -> Option<impl Iterator<Item = RelocationEntry> + '_> {
        let section = self
            .pe
            .sections
            .iter()
            .find(|s| matches!(s.name(), Ok(".reloc")))?;

        let start = section.pointer_to_raw_data as usize;
        let size = section.size_of_raw_data as usize;
        let buffer = self.buffer.get(start..start + size)?;

        Some(parse_base_relocations(buffer))
    }

    pub fn dll_load(&mut self, pid: u64) -> Result<Module, LoadError> {
        if !self.pe.is_lib {
            return Err(LoadError::NotDLL);
        }

        if !self.pe.is_64 {
            return Err(LoadError::Not64Bit);
        }

        let binding = PROGRAM_MANAGER.read();
        let program = binding.get(pid).ok_or(LoadError::BadPID)?;
        let cr3 = program.cr3;

        let opt_hdr = self
            .pe
            .header
            .optional_header
            .as_ref()
            .ok_or(LoadError::MissingSections)?;
        let image_size = opt_hdr.windows_fields.size_of_image as u64;

        unsafe { Cr3::write(cr3, Cr3::read().1) };
        if (program
            .tracker
            .alloc(opt_hdr.windows_fields.image_base, image_size)
            .is_err()
            || self.needs_relocation())
        {
            let relocation = self.calculate_relocation_base(&program.tracker)?;
            self.current_base = relocation;
            program.virtual_map_alloc(relocation, image_size as usize);

            self.load_sections();
            self.relocate();
            let module = Module {
                title: File::remove_file_from_path(self.path.as_str()).to_string(),
                image_path: self.path.clone(),
                parent_pid: pid,
                image_base: relocation,
            };
            return Ok(module);
        }

        unsafe {
            program.virtual_map(
                VirtAddr::new(opt_hdr.windows_fields.image_base),
                image_size as usize,
            )
        };
        self.load_sections();
        let module = Module {
            title: File::remove_file_from_path(self.path.as_str()).to_string(),
            image_path: self.path.clone(),
            parent_pid: pid,
            image_base: VirtAddr::new(opt_hdr.windows_fields.image_base),
        };
        return Ok(module);
    }

    /// Loads the PE into memory and prepares it for execution.
    ///
    /// Error: LoadError
    ///
    /// Ok: PID of the loaded program
    pub fn load(&mut self) -> Result<u64, LoadError> {
        x86_64::instructions::interrupts::disable();
        if self.pe.is_lib {
            return Err(LoadError::IsNotExecutable);
        }

        if !self.pe.is_64 {
            return Err(LoadError::Not64Bit);
        }

        let entry = self.pe.entry;
        if entry == 0 {
            return Err(LoadError::NoEntryPoint);
        }

        let opt_hdr = self
            .pe
            .header
            .optional_header
            .ok_or(LoadError::MissingSections)?;

        if self.pe.sections.is_empty() {
            return Err(LoadError::MissingSections);
        }
        let range_tracker = Arc::new(RangeTracker::new(0x1000u64, 0x00007FFFFFFFFFFFu64));
        self.current_base = if (self.needs_relocation()) {
            self.calculate_relocation_base(&range_tracker)?
        } else {
            VirtAddr::new(opt_hdr.windows_fields.image_base)
        };

        let (table_phys, table_virt) = new_user_mode_page_table().unwrap();
        let page_table: &mut PageTable = unsafe { &mut *(table_virt.as_mut_ptr()) };

        let image_size = opt_hdr.windows_fields.size_of_image as u64;

        let new_frame = PhysFrame::containing_address(table_phys);
        let old_cr3 = Cr3::read();

        unsafe { Cr3::write(new_frame, old_cr3.1) };

        let stack_size = opt_hdr.windows_fields.size_of_stack_reserve;
        let stack_addr = self.current_base + image_size + 0x1000 + stack_size;

        let heap_size = opt_hdr.windows_fields.size_of_heap_reserve;
        let heap_addr = self.current_base + image_size + 0x1000 + stack_size + 0x10;

        let mut program = Program {
            title: File::remove_file_from_path(self.path.as_str()).to_string(),
            image_path: self.path.clone(),
            pid: 0,
            image_base: self.current_base,
            main_thread: None,
            managed_threads: Mutex::new(Vec::new()),
            modules: Mutex::new(Vec::new()),
            cr3: new_frame,
            tracker: range_tracker,
        };

        // Allocates the image + a guard page + the stack + the heap
        match program.virtual_map_alloc(
            program.image_base,
            (image_size + 0x1000 + stack_size + heap_size) as usize,
        ) {
            Err(MapToError::FrameAllocationFailed) => return Err(LoadError::NoMemory),
            Err(_) => (),
            Ok(_) => (),
        }

        let thread = Task::new_usermode(
            (self.pe.entry as i64 + self.current_base.as_u64() as i64) as usize,
            stack_size,
            File::remove_file_from_path(self.path.as_str()).to_string(),
            stack_addr,
            0,
        );
        program.main_thread = Some(thread);
        self.load_sections()?;

        if (self.needs_relocation()) {
            self.relocate()?;
        }
        unsafe { Cr3::write(old_cr3.0, old_cr3.1) };

        let pid = PROGRAM_MANAGER.write().add_program(program);
        PROGRAM_MANAGER.write().start_pid(pid);

        x86_64::instructions::interrupts::enable();
        Err(LoadError::NotImplemented)
    }
    pub fn calculate_allocation_size(&self) -> Result<usize, LoadError> {
        let opt_hdr = self
            .pe
            .header
            .optional_header
            .ok_or(LoadError::MissingSections)?;
        let stack_size = opt_hdr.windows_fields.size_of_stack_reserve;
        let heap_size = opt_hdr.windows_fields.size_of_heap_reserve;
        let image_size = opt_hdr.windows_fields.size_of_image as u64;

        return Ok((image_size + 0x1000 + stack_size + heap_size) as usize);
    }

    pub fn load_sections(&self) -> Result<(), LoadError> {
        let base = self.current_base;
        let buffer = &self.buffer;

        for section in &self.pe.sections {
            let virt_offset = section.virtual_address as u64;
            let virt_size = section.virtual_size as usize;
            let raw_offset = section.pointer_to_raw_data as usize;
            let raw_size = section.size_of_raw_data as usize;

            let dst = (base + virt_offset).as_mut_ptr::<u8>();

            if raw_offset + raw_size > buffer.len() {
                return Err(LoadError::MissingSections);
            }

            unsafe {
                let src_ptr = buffer.as_ptr().add(raw_offset);
                copy_nonoverlapping(src_ptr, dst, raw_size);

                if virt_size > raw_size {
                    dst.add(raw_size).write_bytes(0, virt_size - raw_size);
                }
            }
        }

        Ok(())
    }
    pub fn relocate(&mut self) -> Result<(), LoadError> {
        let opt_hdr = self
            .pe
            .header
            .optional_header
            .ok_or(LoadError::MissingSections)?;
        let old_base = opt_hdr.windows_fields.image_base as u64;
        let addr_delta: i64 = self.current_base.as_u64() as i64 - old_base as i64;
        let relocation_table = self
            .reloc_table()
            .ok_or(LoadError::UnsupportedRelocationFormat)?;

        for entry in relocation_table {
            if let Ok(RelocTypeAmd64::Addr64) = RelocTypeAmd64::try_from(entry.relocation_type) {
                let target_va = self.current_base.as_u64() + entry.virtual_address as u64;
                let ptr = target_va as *mut u64;
                unsafe {
                    let value = ptr.read();
                    ptr.write((value as i64 + addr_delta) as u64);
                }
            }
        }
        Ok(())
    }
    pub fn calculate_relocation_base(
        &mut self,
        range_tracker: &RangeTracker,
    ) -> Result<VirtAddr, LoadError> {
        let opt_hdr = self
            .pe
            .header
            .optional_header
            .ok_or(LoadError::MissingSections)?;
        let alloc_size = if (self.pe.is_lib) {
            self.calculate_allocation_size()?
        } else {
            opt_hdr.windows_fields.image_base as usize
        };
        let new_base = range_tracker
            .alloc_auto(alloc_size as u64)
            .ok_or(LoadError::NoMemory)?;
        range_tracker.dealloc(new_base.as_u64(), alloc_size as u64);
        Ok(new_base)
    }
}
pub struct RelocationEntry {
    pub relocation_type: RelocTypeAmd64,
    pub virtual_address: u32,
}

pub fn parse_base_relocations(reloc_data: &[u8]) -> impl Iterator<Item = RelocationEntry> + '_ {
    let mut offset = 0;
    core::iter::from_fn(move || {
        if offset + 8 > reloc_data.len() {
            return None;
        }

        let va = u32::from_le_bytes(reloc_data[offset..offset + 4].try_into().unwrap());
        let block_size = u32::from_le_bytes(reloc_data[offset + 4..offset + 8].try_into().unwrap());
        let entry_count = ((block_size - 8) / 2) as usize;

        if offset + block_size as usize > reloc_data.len() {
            return None;
        }

        let entries_start = offset + 8;
        offset += block_size as usize;

        Some((0..entry_count).map(move |i| {
            let raw = u16::from_le_bytes(
                reloc_data[entries_start + i * 2..entries_start + i * 2 + 2]
                    .try_into()
                    .unwrap(),
            );
            let reloc_offset = raw & 0x0FFF;
            let reloc_type = RelocTypeAmd64::try_from(raw >> 12).unwrap();
            RelocationEntry {
                relocation_type: reloc_type,
                virtual_address: va + reloc_offset as u32,
            }
        }))
    })
    .flatten()
}

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
    BadPID,
    NotDLL,
    NoFile,
}

#[derive(Debug)]
pub enum RelocTypeAmd64 {
    Absolute = 0x0000, // ignored
    Addr64 = 0x0001,   // 64-bit VA
    Addr32 = 0x0002,   // 32-bit VA
    Addr32Nb = 0x0003, // 32-bit RVA (no image base)
    Rel32 = 0x0004,    // PC-relative +0
    Rel32_1 = 0x0005,  // PC-relative −1
    Rel32_2 = 0x0006,  // PC-relative −2
    Rel32_3 = 0x0007,  // PC-relative −3
    Rel32_4 = 0x0008,  // PC-relative −4
    Rel32_5 = 0x0009,  // PC-relative −5
    Section = 0x000A,  // 16-bit section index (debug only)
    SecRel = 0x000B,   // 32-bit offset from start of section
    SecRel7 = 0x000C,  // 7-bit section-relative offset (debug)
    Token = 0x000D,    // CLR token
    SRel32 = 0x000E,   // span-dependent (object files)
    Pair = 0x000F,     // must follow span-dependent entry
    SSpan32 = 0x0010,  // linker-applied span value
}
impl core::convert::TryFrom<u16> for RelocTypeAmd64 {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        use RelocTypeAmd64::*;
        match value {
            0x0000 => Ok(Absolute),
            0x0001 => Ok(Addr64),
            0x0002 => Ok(Addr32),
            0x0003 => Ok(Addr32Nb),
            0x0004 => Ok(Rel32),
            0x0005 => Ok(Rel32_1),
            0x0006 => Ok(Rel32_2),
            0x0007 => Ok(Rel32_3),
            0x0008 => Ok(Rel32_4),
            0x0009 => Ok(Rel32_5),
            0x000A => Ok(Section),
            0x000B => Ok(SecRel),
            0x000C => Ok(SecRel7),
            0x000D => Ok(Token),
            0x000E => Ok(SRel32),
            0x000F => Ok(Pair),
            0x0010 => Ok(SSpan32),
            _ => Err(()),
        }
    }
}
