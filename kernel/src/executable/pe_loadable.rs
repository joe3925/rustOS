use core::mem::transmute;
use core::ptr::copy_nonoverlapping;

use crate::file_system::file::{file_parser, File, OpenFlags};
use crate::memory::paging::tables::new_user_mode_page_table;
use crate::println;
use crate::scheduling::scheduler::{self, SCHEDULER};
use crate::scheduling::task::Task;
use crate::structs::range_tracker::RangeTracker;
use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use goblin::pe::dll_characteristic::IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
use goblin::pe::PE;
use goblin::Object;
use spin::mutex::Mutex;
use spin::rwlock::RwLock;
use x86_64::instructions::interrupts;
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::mapper::MapToError;
use x86_64::structures::paging::{PageTable, PhysFrame};
use x86_64::VirtAddr;

use super::program::{HandleTable, Module, ModuleHandle, Program, PROGRAM_MANAGER};

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
    pub fn list_import_dlls(&self) -> Vec<String> {
        let mut dlls = Vec::new();
        for imp in &self.pe.imports {
            let name = imp.dll.to_string();
            dlls.push(name.to_ascii_lowercase());
        }
        dlls
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
    pub fn dll_load(&mut self, program: &mut Program) -> Result<ModuleHandle, LoadError> {
        // ---------- sanity checks ----------
        if !self.pe.is_lib {
            return Err(LoadError::NotDLL);
        }
        if !self.pe.is_64 {
            return Err(LoadError::Not64Bit);
        }

        let new_cr3 = program.cr3; // target address space
        let exports = self.collect_exports(); // (name, rva) list

        let opt = self
            .pe
            .header
            .optional_header
            .as_ref()
            .ok_or(LoadError::MissingSections)?;
        let image_size = opt.windows_fields.size_of_image as u64;
        let preferred_base = opt.windows_fields.image_base; // u32

        let old_cr3 = Cr3::read();
        unsafe { Cr3::write(new_cr3, old_cr3.1) };

        let result = (|| {
            let need_reloc = program.tracker.alloc(preferred_base, image_size).is_err()
                || self.needs_relocation();

            if need_reloc {
                // ----- relocated path -----
                let new_base = self.calculate_relocation_base(&program.tracker)?;
                self.current_base = new_base;

                program
                    .virtual_map_alloc(new_base, image_size as usize)
                    .map_err(|_| LoadError::NoMemory)?;

                self.load_sections()?;
                self.relocate()?;
                self.resolve_imports(program);
                self.patch_imports(program);
                let module = Module {
                    title: file_parser(&self.path).last().unwrap().to_string(),
                    image_path: self.path.clone(),
                    parent_pid: program.pid,
                    image_base: self.current_base,
                    symbols: exports,
                };
                let handle = Arc::new(RwLock::new(module));
                program.modules.write().push(handle.clone());
                return Ok(handle);
            }

            unsafe {
                program
                    .virtual_map(VirtAddr::new(preferred_base), image_size as usize)
                    .map_err(|e| match e {
                        MapToError::PageAlreadyMapped(_) => LoadError::UnsupportedImageBase,
                        _ => LoadError::NoMemory,
                    })?;
            }
            self.current_base = VirtAddr::new(preferred_base);
            self.load_sections()?;
            self.resolve_imports(program);
            self.patch_imports(program);
            let module = Module {
                title: file_parser(&self.path).last().unwrap().to_string(),
                image_path: self.path.clone(),
                parent_pid: program.pid,
                image_base: self.current_base,
                symbols: exports,
            };
            let handle = Arc::new(RwLock::new(module));
            program.modules.write().push(handle.clone());
            Ok(handle)
        })();

        unsafe { Cr3::write(old_cr3.0, old_cr3.1) };

        result
    }

    /// Loads the PE into memory and prepares it for execution.
    ///
    /// Error: LoadError
    ///
    /// Ok: PID of the loaded program
    pub fn load(&mut self) -> Result<u64, LoadError> {
        let were_enabled = interrupts::are_enabled();
        if were_enabled {
            interrupts::disable();
        }
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

        let title = file_parser(&self.path).last().unwrap().to_string();

        let mut program = Program::new(
            title,
            self.path.clone(),
            self.current_base,
            new_frame,
            range_tracker,
        );

        // Allocates the image + a guard page + the stack + the heap
        match program.virtual_map_alloc(
            program.image_base,
            (image_size + 0x1000 + stack_size + heap_size) as usize,
        ) {
            Err(MapToError::FrameAllocationFailed) => return Err(LoadError::NoMemory),
            Err(_) => (),
            Ok(_) => (),
        }

        let thread = Task::new_user_mode(
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
        self.resolve_imports(&mut program);
        self.patch_imports(&mut program);

        unsafe { Cr3::write(old_cr3.0, old_cr3.1) };

        let pid = PROGRAM_MANAGER.add_program(program);
        {
            PROGRAM_MANAGER.start_pid(pid);
        }
        if were_enabled {
            interrupts::enable();
        }

        Ok(pid)
    }
    pub fn resolve_imports(&mut self, program: &mut Program) -> Result<(), LoadError> {
        loop {
            let mut added = false;

            let (dlls, present): (Vec<String>, alloc::collections::BTreeSet<String>) = {
                let snapshot = program.modules.read();
                let dlls = self.list_import_dlls();
                let present = snapshot.iter().map(|m| m.read().title.clone()).collect();
                (dlls, present)
            };

            for dll in dlls {
                if present.contains(&dll) {
                    continue;
                }
                let path = alloc::format!(r"C:\BIN\MOD\{}", dll);
                program.load_module(path)?;
                added = true;
            }

            if !added {
                break;
            }
        }
        Ok(())
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
        let delta = self.current_base.as_u64().wrapping_sub(old_base);

        let relocs = self
            .reloc_table()
            .ok_or(LoadError::UnsupportedRelocationFormat)?;

        for entry in relocs {
            match entry.relocation_type {
                BaseRelocType::Absolute => continue,
                BaseRelocType::Dir64 => {
                    let target = self.current_base.as_u64() + entry.virtual_address as u64;
                    unsafe {
                        let p = target as *mut u64;
                        p.write(p.read().wrapping_add(delta));
                    }
                }
                _ => return Err(LoadError::UnsupportedRelocationFormat),
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
    fn collect_exports(&self) -> Vec<(String, usize)> {
        let mut out = Vec::new();
        for export in &self.pe.exports {
            if let Some(name) = export.name {
                out.push((name.to_string(), export.rva));
            }
        }
        out
    }
    pub fn patch_imports(&mut self, program: &mut Program) -> Result<(), LoadError> {
        for imp in &self.pe.imports {
            let dll_name = imp.dll.to_ascii_lowercase();
            let symbol_name = &imp.name;

            let abs_addr = program
                .find_import(dll_name.as_str(), symbol_name.to_string().as_str())
                .ok_or(LoadError::NoSuchSymbol)?;

            let slot_va = self.current_base.as_u64() + imp.offset as u64;
            unsafe { (slot_va as *mut u64).write(abs_addr.as_u64()) };
        }
        Ok(())
    }
}
pub struct RelocationEntry {
    pub relocation_type: BaseRelocType,
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
        if block_size < 8 {
            return None;
        }
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
            let reloc_type = BaseRelocType::try_from(raw >> 12).unwrap();
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
    NoMainThread,
    NoSuchSymbol,
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]

pub enum BaseRelocType {
    Absolute = 0x0000,
    HighLow = 0x0003,
    Dir64 = 0x000A,
}

impl core::convert::TryFrom<u16> for BaseRelocType {
    type Error = ();

    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            0x0000 => Ok(BaseRelocType::Absolute),
            0x0003 => Ok(BaseRelocType::HighLow),
            0x000A => Ok(BaseRelocType::Dir64),
            _ => Err(()), // unknown/unsupported code
        }
    }
}
